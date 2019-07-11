//
// MIT License
//
// Copyright (c) 2019 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::error::*;
use failure::Error;
use log::*;
use stegos_blockchain::Timestamp;
use stegos_blockchain::{Block, BlockError, Blockchain, MacroBlock, Output, Transaction};
use stegos_consensus::MacroBlockProposal;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;

pub fn create_macro_block_proposal(
    chain: &Blockchain,
    view_change: u32,
    account_pkey: &scc::PublicKey,
    network_skey: &pbc::SecretKey,
    network_pkey: &pbc::PublicKey,
    timestamp: Timestamp,
) -> (MacroBlock, MacroBlockProposal) {
    assert!(chain.is_epoch_full());
    debug!(
        "Creating a new macro block proposal: epoch={}, view_change={}",
        chain.epoch(),
        view_change,
    );

    let (block, transactions) = chain.create_macro_block(
        view_change,
        account_pkey,
        network_skey,
        network_pkey.clone(),
        timestamp,
    );

    // Create block proposal.
    let block_proposal = MacroBlockProposal {
        header: block.header.clone(),
        transactions,
    };

    info!(
        "Created a new macro block proposal: epoch={}, view_change={}, hash={}",
        chain.epoch(),
        view_change,
        Hash::digest(&block)
    );

    (block, block_proposal)
}

///
/// Validate proposed macro block.
///
pub fn validate_proposed_macro_block(
    chain: &Blockchain,
    view_change: u32,
    block_hash: &Hash,
    block_proposal: &MacroBlockProposal,
) -> Result<MacroBlock, Error> {
    if block_proposal.header.epoch != chain.epoch() {
        return Err(
            NodeBlockError::InvalidBlockEpoch(block_proposal.header.epoch, chain.epoch()).into(),
        );
    }
    assert!(chain.is_epoch_full());
    let epoch = block_proposal.header.epoch;

    // Ensure that block was produced at round lower than current.
    if block_proposal.header.view_change > view_change {
        return Err(NodeBlockError::OutOfSyncViewChange(
            epoch,
            block_hash.clone(),
            block_proposal.header.view_change,
            view_change,
        )
        .into());
    }

    //
    // Validate base header.
    //
    let current_timestamp = Timestamp::now();
    chain.validate_macro_block_header(
        block_hash,
        &block_proposal.header,
        false,
        current_timestamp,
    )?;

    // validate award.
    let (activity_map, winner) = chain.awards_from_active_epoch(&block_proposal.header.random);

    //
    // Validate transactions.
    //

    let mut transactions = block_proposal.transactions.clone();

    let mut tx_len = 1;
    // Coinbase.
    if let Some(Transaction::CoinbaseTransaction(tx)) = transactions.get(0) {
        tx.validate()?;
        if tx.block_reward != chain.cfg().block_reward {
            return Err(BlockError::InvalidMacroBlockReward(
                epoch,
                block_hash.clone(),
                tx.block_reward,
                chain.cfg().block_reward,
            )
            .into());
        }

        if tx.block_fee != 0 {
            return Err(BlockError::InvalidMacroBlockFee(
                epoch,
                block_hash.clone(),
                tx.block_fee,
                0,
            )
            .into());
        }
    } else {
        // Force coinbase if reward is not zero.
        return Err(BlockError::CoinbaseMustBeFirst(block_hash.clone()).into());
    }
    let mut full_reward =
        chain.cfg().block_reward * (chain.cfg().micro_blocks_in_epoch as i64 + 1i64);

    // Add tx if winner found.
    if let Some((k, reward)) = winner {
        tx_len += 1;
        full_reward += reward;
        if let Some(Transaction::ServiceAwardTransaction(tx)) = transactions.get(1) {
            if tx.winner_reward.len() != 1 {
                return Err(BlockError::AwardMoreThanOneWinner(
                    block_hash.clone(),
                    tx.winner_reward.len(),
                )
                .into());
            }
            let ref output = tx.winner_reward[0];

            if let Output::PublicPaymentOutput(out) = output {
                if out.recipient != k {
                    return Err(BlockError::AwardDifferentWinner(
                        block_hash.clone(),
                        out.recipient,
                        k,
                    )
                    .into());
                }
                if out.amount != reward {
                    return Err(BlockError::AwardDifferentReward(
                        block_hash.clone(),
                        out.amount,
                        reward,
                    )
                    .into());
                }
            } else {
                return Err(BlockError::AwardDifferentOutputType(block_hash.clone()).into());
            }
        } else {
            return Err(BlockError::NoServiceAwardTx(block_hash.clone()).into());
        }
    }

    if transactions.len() > tx_len {
        return Err(BlockError::InvalidBlockBalance(epoch, block_hash.clone()).into());
    }

    // Collect transactions from epoch.
    let count = chain.cfg().micro_blocks_in_epoch as usize;
    let blocks: Vec<Block> = chain.blocks_starting(epoch, 0).take(count).collect();
    for (offset, block) in blocks.into_iter().enumerate() {
        let block = if let Block::MicroBlock(block) = block {
            block
        } else {
            panic!("Expected micro block: epoch={}, offset={}", epoch, offset);
        };

        transactions.extend(block.transactions);
    }

    // Re-create original block.
    let block = MacroBlock::from_transactions(
        block_proposal.header.previous,
        epoch,
        block_proposal.header.view_change,
        block_proposal.header.pkey,
        block_proposal.header.random,
        block_proposal.header.difficulty,
        block_proposal.header.timestamp,
        full_reward,
        activity_map,
        &transactions,
    )?;

    // Check that block has the same hash.
    let expected_block_hash = Hash::digest(&block);
    if block_hash != &expected_block_hash {
        return Err(NodeBlockError::InvalidBlockProposal(
            block.header.epoch,
            expected_block_hash,
            block_hash.clone(),
        )
        .into());
    }

    debug!("Macro block proposal is valid: block={:?}", block_hash);
    Ok(block)
}

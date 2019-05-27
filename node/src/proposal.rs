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

use crate::config::ChainConfig;
use crate::error::*;
use failure::Error;
use log::*;
use std::time::SystemTime;
use stegos_blockchain::{
    mix, BaseBlockHeader, BlockError, Blockchain, CoinbaseTransaction, MacroBlock, PaymentOutput,
    PaymentPayloadData, Transaction, VERSION,
};
use stegos_consensus::MacroBlockProposal;
use stegos_crypto::curve1174;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

pub fn create_macro_block_proposal(
    chain: &Blockchain,
    view_change: u32,
    block_reward: i64,
    recipient_pkey: &curve1174::PublicKey,
    network_skey: &pbc::SecretKey,
    network_pkey: &pbc::PublicKey,
) -> (MacroBlock, MacroBlockProposal) {
    let timestamp = SystemTime::now();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&network_skey, &seed);

    let previous = chain.last_block_hash();
    let height = chain.height();
    let epoch = chain.epoch() + 1;
    let base = BaseBlockHeader::new(VERSION, previous, height, view_change, timestamp, random);
    debug!(
        "Creating a new macro block proposal: height={}, view_change={}, epoch={}",
        height,
        view_change,
        chain.epoch() + 1,
    );

    // Coinbase.
    let coinbase_tx = {
        let data = PaymentPayloadData::Comment("Block reward".to_string());
        let (output, gamma) =
            PaymentOutput::with_payload(&recipient_pkey, block_reward, data.clone())
                .expect("invalid keys");

        info!(
            "Created reward UTXO: hash={}, amount={}, data={:?}",
            Hash::digest(&output),
            block_reward,
            data
        );

        CoinbaseTransaction {
            block_reward,
            block_fee: 0,
            gamma: -gamma,
            txouts: vec![output.into()],
        }
    };

    let transactions = vec![coinbase_tx.into()];

    let block =
        MacroBlock::from_transactions(base, &transactions, block_reward, network_pkey.clone())
            .expect("Invalid block");
    let block_hash = Hash::digest(&block);

    // Create block proposal.
    let block_proposal = MacroBlockProposal {
        header: block.header.clone(),
        transactions,
    };

    info!(
        "Created a new macro block proposal: height={}, view_change={}, epoch={}, hash={}",
        height, view_change, epoch, block_hash
    );

    (block, block_proposal)
}

///
/// Validate proposed macro block.
///
pub fn validate_proposed_macro_block(
    cfg: &ChainConfig,
    chain: &Blockchain,
    view_change: u32,
    block_hash: &Hash,
    block_proposal: &MacroBlockProposal,
) -> Result<MacroBlock, Error> {
    let height = block_proposal.header.base.height;

    // Ensure that block was produced at round lower than current.
    if block_proposal.header.base.view_change > view_change {
        return Err(NodeBlockError::OutOfSyncViewChange(
            height,
            block_hash.clone(),
            block_proposal.header.base.view_change,
            view_change,
        )
        .into());
    }

    //
    // Validate timestamp.
    //
    let block_timestamp = block_proposal.header.base.timestamp;
    let last_block_timestamp = chain.last_macro_block_timestamp();
    let current_timestamp = SystemTime::now();
    if block_timestamp <= last_block_timestamp {
        return Err(NodeBlockError::OutdatedBlock(
            height,
            block_hash.clone(),
            block_timestamp,
            last_block_timestamp,
        )
        .into());
    }
    if block_timestamp >= current_timestamp {
        let duration = block_timestamp.duration_since(current_timestamp).unwrap();
        if duration > cfg.macro_block_timeout {
            return Err(NodeBlockError::OutOfSyncTimestamp(
                height,
                block_hash.clone(),
                block_timestamp,
                current_timestamp,
            )
            .into());
        }
    }

    //
    // Validate base header.
    //
    chain.validate_macro_block_header(block_hash, &block_proposal.header)?;

    //
    // Validate transactions.
    //

    // Coinbase.
    if let Some(Transaction::CoinbaseTransaction(tx)) = block_proposal.transactions.get(0) {
        tx.validate()?;
        if tx.block_reward != cfg.block_reward {
            return Err(NodeBlockError::InvalidBlockReward(
                height,
                block_hash.clone(),
                tx.block_reward,
                cfg.block_reward,
            )
            .into());
        }

        if tx.block_fee != 0 {
            return Err(NodeBlockError::InvalidBlockFee(
                height,
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

    // TODO: support slashing && service awards.
    if block_proposal.transactions.len() > 1 {
        return Err(BlockError::InvalidBlockBalance(height, block_hash.clone()).into());
    }

    // Re-create original block.
    let leader = chain.select_leader(block_proposal.header.base.view_change);
    let block = MacroBlock::from_transactions(
        block_proposal.header.base.clone(),
        &block_proposal.transactions,
        cfg.block_reward,
        leader,
    )?;

    // Check that block has the same hash.
    let expected_block_hash = Hash::digest(&block);
    if block_hash != &expected_block_hash {
        return Err(NodeBlockError::InvalidBlockProposal(
            block.header.base.height,
            expected_block_hash,
            block_hash.clone(),
        )
        .into());
    }

    debug!("Macro block proposal is valid: block={:?}", block_hash);
    Ok(block)
}

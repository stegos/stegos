//! Blockchain - Validation.

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

use crate::block::{Block, MacroBlock, MacroBlockHeader, MicroBlock, VERSION};
use crate::blockchain::{Blockchain, ChainInfo};
use crate::election::mix;
use crate::error::{BlockError, BlockchainError, SlashingError, TransactionError};
use crate::multisignature::check_multi_signature;
use crate::output::{Output, PublicPaymentOutput};
use crate::slashing::confiscate_tx;
use crate::timestamp::Timestamp;
use crate::transaction::{
    CoinbaseTransaction, PaymentTransaction, RestakeTransaction, SlashingTransaction, Transaction,
};
use crate::Merkle;
use log::*;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::{HashMap, HashSet};
use stegos_crypto::bulletproofs::{fee_a, simple_commit};
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::{Fr, Pt};
use stegos_crypto::{pbc, scc};

impl CoinbaseTransaction {
    pub fn validate(&self) -> Result<(), BlockchainError> {
        let tx_hash = Hash::digest(&self);

        // Validate that reward is not negative.
        // Exact value is checked by upper levels (Node).
        if self.block_reward < 0 {
            return Err(TransactionError::NegativeReward(tx_hash).into());
        }

        // Validate that fee is not negative.
        // Exact value is checked by upper levels (validate_micro_block()).
        if self.block_fee < 0 {
            return Err(TransactionError::NegativeFee(tx_hash).into());
        }

        // Validate outputs.
        let mut mined: Pt = Pt::inf();
        for output in &self.txouts {
            let output_hash = Hash::digest(output);
            match output {
                Output::PaymentOutput(_o) => {
                    output.validate()?;
                    mined += output.pedersen_commitment()?;
                }
                _ => {
                    return Err(
                        TransactionError::NonPaymentOutputInCoinbase(tx_hash, output_hash).into(),
                    );
                }
            }
        }

        // Validate monetary balance.
        let total_fee = self.block_reward + self.block_fee;
        if mined + self.gamma * Pt::one() != fee_a(total_fee) {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }

        Ok(())
    }
}

impl PaymentTransaction {
    /// Validate the monetary balance and signature of transaction.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.txins, in the same order as in self.txins.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<(), BlockchainError> {
        //
        // Validation checklist:
        //
        // - At least one input or output is present.
        // - Inputs can be resolved.
        // - Inputs have not been spent by blocks.
        // - Inputs are unique.
        // - Outputs are unique.
        // - Bulletpoofs/amounts are valid.
        // - UTXO-specific checks.
        // - Monetary balance is valid.
        // - Signature is valid.
        //

        let tx_hash = Hash::digest(&self);

        assert_eq!(self.txins.len(), inputs.len());

        // Check that transaction has inputs.
        if self.txins.is_empty() {
            return Err(TransactionError::NoInputs(tx_hash).into());
        }

        // Check fee.
        if self.fee < 0 {
            return Err(TransactionError::NegativeFee(tx_hash).into());
        }

        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = \sum C_i - \sum C_o - fee * A
        //
        // Calculate `P_eff` to validate transaction's signature:
        //
        //     P_eff = pedersen_commitment_diff + \sum P_i
        //

        let mut eff_pkey = Pt::inf();
        let mut txin_sum = Pt::inf();
        let mut txout_sum = Pt::inf();

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(TransactionError::DuplicateInput(tx_hash, *txin_hash).into());
            }
            if cfg!(debug_assertions) {
                txin.validate()?;
            }
            let cmt = txin.pedersen_commitment()?;
            txin_sum += cmt;
            eff_pkey += txin.recipient_pkey()? + cmt;
        }
        drop(txins_set);

        // -\sum{C_o} for o in txouts
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for txout in &self.txouts {
            let txout_hash = Hash::digest(txout);
            if !txouts_set.insert(txout_hash) {
                return Err(TransactionError::DuplicateOutput(tx_hash, txout_hash).into());
            }
            let cmt = txout.pedersen_commitment()?;
            txout_sum += cmt;
            eff_pkey -= cmt;
        }
        drop(txouts_set);

        // C(fee, gamma_adj) = fee * A + gamma_adj * G
        let adj: Pt = simple_commit(&self.gamma, &Fr::from(self.fee));

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum + adj {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }
        eff_pkey -= adj;

        // Create public key and check signature
        let eff_pkey: scc::PublicKey = eff_pkey.into();

        // Check signature
        scc::validate_sig(&tx_hash, &self.sig, &eff_pkey)
            .map_err(|_e| TransactionError::InvalidSignature(tx_hash))?;

        // Transaction is valid.
        Ok(())
    }
}

impl RestakeTransaction {
    /// Validate the monetary balance and signature of transaction.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.txins, in the same order as in self.txins.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<(), BlockchainError> {
        //
        // Validation checklist:
        //
        // - At least one input or output is present.
        // - Inputs can be resolved.
        // - Inputs have not been spent by blocks.
        // - Inputs are unique.
        // - Outputs are unique.
        // - UTXO-specific checks.
        // - Monetary balance is valid.
        // - Signature is valid.
        //

        let tx_hash = Hash::digest(&self);

        assert_eq!(self.txins.len(), inputs.len());

        // Check that transaction has inputs.
        if self.txins.is_empty() {
            return Err(TransactionError::NoInputs(tx_hash).into());
        }

        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = \sum C_i - \sum C_o - fee * A
        //
        // Calculate `P_eff` to validate transaction's signature:
        //
        //     P_eff = pedersen_commitment_diff + \sum P_i
        //

        let mut eff_vkey = None;
        let mut txin_sum = 0;
        let mut txout_sum = 0;

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(TransactionError::DuplicateInput(tx_hash, *txin_hash).into());
            }
            if cfg!(debug_assertions) {
                txin.validate()?;
            }
            match txin {
                Output::PaymentOutput(_) | Output::PublicPaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingInput(tx_hash, *txin_hash).into());
                }
                Output::StakeOutput(o) => {
                    match eff_vkey {
                        None => {
                            eff_vkey = Some(o.validator);
                        }
                        Some(v) => {
                            if v != o.validator {
                                return Err(TransactionError::MixedRestakingOwners(
                                    tx_hash, *txin_hash,
                                )
                                .into());
                            }
                        }
                    }
                    txin_sum += o.amount;
                }
            };
        }
        drop(txins_set);

        let eff_vkey = {
            match eff_vkey {
                None => {
                    return Err(TransactionError::NoRestakingTxins(tx_hash).into());
                }
                Some(v) => v,
            }
        };

        let mut out_pkey = None;
        // -\sum{C_o} for o in txouts
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for txout in &self.txouts {
            let txout_hash = Hash::digest(txout);
            if !txouts_set.insert(txout_hash) {
                return Err(TransactionError::DuplicateOutput(tx_hash, txout_hash).into());
            }
            txout.validate()?;
            match txout {
                Output::PaymentOutput(_) | Output::PublicPaymentOutput(_) => {
                    return Err(
                        TransactionError::InvalidRestakingOutput(tx_hash, txout_hash).into(),
                    );
                }
                Output::StakeOutput(o) => {
                    match out_pkey {
                        None => {
                            out_pkey = Some(o.validator);
                        }
                        Some(v) => {
                            if v != o.validator {
                                return Err(TransactionError::MixedRestakingOwners(
                                    tx_hash, txout_hash,
                                )
                                .into());
                            }
                        }
                    }
                    txout_sum += o.amount;
                }
            };
        }
        drop(txouts_set);

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }

        // Check signature
        pbc::check_hash(&tx_hash, &self.sig, &eff_vkey)
            .map_err(|_e| TransactionError::InvalidSignature(tx_hash))?;

        // Transaction is valid.
        Ok(())
    }
}

impl SlashingTransaction {
    pub fn validate(
        &self,
        blockchain: &Blockchain,
        leader: pbc::PublicKey,
    ) -> Result<(), BlockchainError> {
        // validate proof
        self.proof.validate(blockchain)?;

        // recreate transaction
        let tx = confiscate_tx(blockchain, &leader, self.proof.clone())?;

        let tx_hash = Hash::digest(self);
        // found incorrect formed slashing transaction.
        if tx.txins != self.txins {
            return Err(SlashingError::IncorrectTxins(tx_hash).into());
        }
        // Try to find unhonest devided stake.
        // Txouts is ordered by recipient validator id.
        for txs in tx.txouts.iter().zip(self.txouts.iter()) {
            match txs {
                (
                    // compare all fields except serno.
                    // Keep all fields in compare, in case of future extension.
                    Output::PublicPaymentOutput(PublicPaymentOutput {
                        recipient: recipient1,
                        amount: amount1,
                        serno: _,
                    }),
                    Output::PublicPaymentOutput(PublicPaymentOutput {
                        recipient: recipient2,
                        amount: amount2,
                        serno: _,
                    }),
                ) => {
                    if recipient1 != recipient2 || amount1 != amount2 {
                        return Err(SlashingError::IncorrectTxins(tx_hash).into());
                    }
                }
                _ => return Err(SlashingError::IncorrectTxouts(tx_hash).into()),
            }
        }

        // Transaction is valid.
        Ok(())
    }
}

impl MacroBlock {
    ///
    /// Validate the block monetary balance.
    ///
    /// This function is a lightweight version of Blockchain.validate_micro_block().
    /// The only monetary balance is validated. For test purposes only.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.inputs, in the same order as in self.inputs.
    ///
    pub fn validate_balance(&self, inputs: &[Output]) -> Result<(), BlockchainError> {
        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = block_reward + \sum C_i - \sum C_o
        //

        let mut pedersen_commitment_diff: Pt = fee_a(self.header.block_reward);

        // +\sum{C_i} for i in txins
        for (txin_hash, txin) in self.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            pedersen_commitment_diff += txin.pedersen_commitment()?;
        }

        // -\sum{C_o} for o in txouts
        for txout in &self.outputs {
            txout.validate()?;
            pedersen_commitment_diff -= txout.pedersen_commitment()?;
        }

        // Check the monetary balance
        if pedersen_commitment_diff != self.header.gamma * Pt::one() {
            let block_hash = Hash::digest(&self);
            return Err(BlockError::InvalidBlockBalance(self.header.epoch, block_hash).into());
        }

        Ok(())
    }
}

impl Blockchain {
    pub(crate) fn validate_block_timestamp(
        &self,
        epoch: u64,
        block_hash: &Hash,
        block_timestamp: Timestamp,
        timestamp: Timestamp,
    ) -> Result<(), BlockError> {
        let last_block_timestamp = self.last_block_timestamp();
        if block_timestamp <= last_block_timestamp {
            return Err(BlockError::OutdatedBlock(
                epoch,
                block_hash.clone(),
                block_timestamp,
                last_block_timestamp,
            )
            .into());
        }
        if block_timestamp >= timestamp {
            let duration = block_timestamp.duration_since(timestamp);
            if duration > self.cfg().vetted_timestamp_delta {
                return Err(BlockError::OutOfSyncTimestamp(
                    epoch,
                    block_hash.clone(),
                    block_timestamp,
                    timestamp,
                )
                .into());
            }
        }
        Ok(())
    }

    ///
    /// A common part of validate_macro_block() and validate_proposed_macro_block().
    ///
    fn validate_macro_block_basic(
        &self,
        block_hash: &Hash,
        header: &MacroBlockHeader,
        timestamp: Timestamp,
    ) -> Result<(), BlockchainError> {
        let epoch = header.epoch;

        // Check block version.
        if header.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                epoch,
                *block_hash,
                header.version,
                VERSION,
            )
            .into());
        }

        // Check epoch.
        if epoch != self.epoch() {
            return Err(BlockError::OutOfOrderMacroBlock(*block_hash, epoch, self.epoch()).into());
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::MacroBlockHashCollision(epoch, *block_hash).into());
        }

        // Check previous hash.
        let previous_hash = self.last_macro_block_hash();
        if previous_hash != header.previous {
            return Err(BlockError::InvalidMacroBlockPreviousHash(
                epoch,
                *block_hash,
                header.previous,
                previous_hash,
            )
            .into());
        }

        // Validate timestamp.
        self.validate_block_timestamp(epoch, block_hash, header.timestamp, timestamp)?;

        // Check that VDF difficulty is constant.
        if epoch > 0 && header.difficulty != self.difficulty() {
            return Err(BlockError::UnexpectedVDFComplexity(
                epoch,
                *block_hash,
                self.difficulty(),
                header.difficulty,
            )
            .into());
        }

        // Check VRF.
        let seed = mix(self.last_macro_block_random(), header.view_change);
        if !pbc::validate_VRF_source(&header.random, &header.pkey, &seed).is_ok() {
            return Err(BlockError::IncorrectRandom(epoch, *block_hash).into());
        }

        Ok(())
    }

    ///
    /// Validate a macro block from the disk.
    ///
    pub(crate) fn validate_macro_block(
        &mut self,
        block: &MacroBlock,
        timestamp: Timestamp,
    ) -> Result<(), BlockchainError> {
        let block_hash = Hash::digest(&block);
        assert_eq!(self.epoch(), block.header.epoch);
        let epoch = block.header.epoch;
        assert_eq!(self.offset(), 0);

        debug!(
            "Validating a macro block: epoch={}, block={}",
            epoch, &block_hash
        );

        //
        // Validate multi-signature.
        //
        if epoch > 0 {
            // Validate signature (already checked by Node).
            check_multi_signature(
                &block_hash,
                &block.multisig,
                &block.multisigmap,
                &self.validators_at_epoch_start(),
                self.total_slots(),
            )
            .map_err(|e| BlockError::InvalidBlockSignature(e, epoch, block_hash))?;
        }

        //
        // Basic validation.
        //
        self.validate_macro_block_basic(&block_hash, &block.header, timestamp)?;

        //
        // Validate Awards.
        //
        if epoch > 0 {
            let validators_activity =
                self.epoch_activity_from_macro_block(&block.header.activity_map)?;
            let mut service_awards = self.service_awards().clone();
            service_awards.finalize_epoch(self.cfg().service_award_per_epoch, validators_activity);
            let winner = service_awards.check_winners(block.header.random.rand);

            // calculate block reward + service award.
            let full_reward = self.cfg().block_reward
                * (self.cfg().micro_blocks_in_epoch as i64 + 1i64)
                + winner.map(|(_, a)| a).unwrap_or(0);

            if block.header.block_reward != full_reward {
                return Err(BlockError::InvalidMacroBlockReward(
                    epoch,
                    block_hash,
                    block.header.block_reward,
                    full_reward,
                )
                .into());
            }
        }

        //
        // Validate outputs.
        //
        if block.header.outputs_len as usize != block.outputs.len() {
            return Err(BlockError::InvalidMacroBlockInputsLen(
                epoch,
                block_hash,
                block.header.outputs_len as usize,
                block.inputs.len(),
            )
            .into());
        }
        let output_hashes: Vec<Hash> = block.outputs.iter().map(Hash::digest).collect();
        let outputs_range_hash = Merkle::root_hash_from_array(&output_hashes);
        if block.header.outputs_range_hash != outputs_range_hash {
            return Err(BlockError::InvalidMacroBlockOutputsHash(
                epoch,
                block_hash,
                outputs_range_hash,
                block.header.outputs_range_hash,
            )
            .into());
        }
        let canary_hashes: Vec<Hash> = block
            .outputs
            .iter()
            .map(|o| Hash::digest(&o.canary()))
            .collect();
        let canaries_range_hash = Merkle::root_hash_from_array(&canary_hashes);
        if block.header.canaries_range_hash != canaries_range_hash {
            return Err(BlockError::InvalidMacroBlockCanariesHash(
                epoch,
                block_hash,
                canaries_range_hash,
                block.header.canaries_range_hash,
            )
            .into());
        }
        block.outputs.par_iter().try_for_each(Output::validate)?;

        //
        // Validate inputs.
        //
        if block.header.inputs_len as usize != block.inputs.len() {
            return Err(BlockError::InvalidMacroBlockInputsLen(
                epoch,
                block_hash,
                block.header.inputs_len as usize,
                block.inputs.len(),
            )
            .into());
        }
        let inputs_range_hash = Merkle::root_hash_from_array(&block.inputs);
        if block.header.inputs_range_hash != inputs_range_hash {
            return Err(BlockError::InvalidMacroBlockInputsHash(
                epoch,
                block_hash,
                inputs_range_hash,
                block.header.inputs_range_hash,
            )
            .into());
        }
        let outputs: HashMap<Hash, Output> = block
            .outputs
            .iter()
            .map(|o| (Hash::digest(o), o.clone()))
            .collect();
        let mut inputs: Vec<Output> = Vec::new();
        for input_hash in block.inputs.iter() {
            let input = if let Some(input) = outputs.get(input_hash) {
                input.clone()
            } else {
                match self.output_by_hash(&input_hash)? {
                    Some(r) => r,
                    None => {
                        return Err(BlockError::MissingBlockInput(
                            epoch,
                            block_hash,
                            input_hash.clone(),
                        )
                        .into())
                    }
                }
            };
            inputs.push(input);
        }

        //
        // Validate balance.
        //
        block.validate_balance(&inputs)?;

        //
        // Sic: the following fields can't be validated properly
        // without processing the block itself:
        // - validators_len
        // - validators_range_hash
        // We blindly rely on consensus here.
        //

        Ok(())
    }

    ///
    /// Validate proposed macro block.
    ///
    pub fn validate_proposed_macro_block(
        &self,
        view_change: u32,
        block_hash: &Hash,
        header: &MacroBlockHeader,
        transactions: &[Transaction],
    ) -> Result<MacroBlock, BlockchainError> {
        if header.epoch != self.epoch() {
            return Err(BlockError::InvalidBlockEpoch(header.epoch, self.epoch()).into());
        }
        assert!(self.is_epoch_full());
        let epoch = header.epoch;

        // Ensure that block was produced at round lower than current.
        if header.view_change > view_change {
            return Err(BlockError::OutOfSyncViewChange(
                epoch,
                block_hash.clone(),
                header.view_change,
                view_change,
            )
            .into());
        }

        let validators_at_start = self.validators_at_epoch_start();
        if header.activity_map.len() != validators_at_start.len() {
            return Err(BlockError::TooBigActivitymap(
                header.activity_map.len(),
                validators_at_start.len(),
            )
            .into());
        }

        //
        // Validate base header.
        //
        let current_timestamp = Timestamp::now();
        self.validate_macro_block_basic(block_hash, &header, current_timestamp)?;

        // validate award.
        let (activity_map, winner) = self.awards_from_active_epoch(&header.random);

        //
        // Validate transactions.
        //

        let mut transactions = transactions.to_vec();

        let mut tx_len = 1;
        // Coinbase.
        if let Some(Transaction::CoinbaseTransaction(tx)) = transactions.get(0) {
            tx.validate()?;
            if tx.block_reward != self.cfg().block_reward {
                return Err(BlockError::InvalidMacroBlockReward(
                    epoch,
                    block_hash.clone(),
                    tx.block_reward,
                    self.cfg().block_reward,
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
            self.cfg().block_reward * (self.cfg().micro_blocks_in_epoch as i64 + 1i64);

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
        let count = self.cfg().micro_blocks_in_epoch as usize;
        let blocks: Vec<Block> = self.blocks_starting(epoch, 0).take(count).collect();
        for (offset, block) in blocks.into_iter().enumerate() {
            let block = if let Block::MicroBlock(block) = block {
                block
            } else {
                panic!("Expected micro block: epoch={}, offset={}", epoch, offset);
            };

            transactions.extend(block.transactions);
        }

        // Select validators.
        let validators = self.next_election_result(header.random).validators;

        // Re-create original block.
        let block = MacroBlock::from_transactions(
            header.previous,
            epoch,
            header.view_change,
            header.pkey,
            header.random,
            header.difficulty,
            header.timestamp,
            full_reward,
            activity_map,
            validators,
            &transactions,
        )?;

        // Check that block has the same hash.
        let expected_block_hash = Hash::digest(&block);
        if block_hash != &expected_block_hash {
            return Err(BlockError::InvalidBlockProposal(
                block.header.epoch,
                expected_block_hash,
                block_hash.clone(),
            )
            .into());
        }

        Ok(block)
    }

    ///
    /// A helper for validate_micro_block().
    ///
    fn validate_micro_block_tx<'a>(
        &self,
        tx: &'a Transaction,
        leader: pbc::PublicKey,
        inputs_set: &mut HashSet<Hash>,
        outputs_set: &mut HashMap<Hash, &'a Output>,
    ) -> Result<(), BlockchainError> {
        let tx_hash = Hash::digest(&tx);
        let mut inputs: Vec<Output> = Vec::new();

        // Validate inputs.
        for input_hash in tx.txins() {
            // Check that the input can be resolved.
            let input = match self.output_by_hash(input_hash)? {
                Some(input) => input,
                None => {
                    return Err(TransactionError::MissingInput(tx_hash, input_hash.clone()).into());
                }
            };

            // Check that the input is not claimed by other transactions.
            if inputs_set.contains(input_hash) {
                return Err(TransactionError::DuplicateInput(tx_hash, input_hash.clone()).into());
            }

            inputs_set.insert(input_hash.clone());
            inputs.push(input);
        }

        // Check for overlapping outputs.
        for output in tx.txouts() {
            let output_hash = Hash::digest(output);
            // Check that the output is unique and don't overlap with other transactions.
            if outputs_set.contains_key(&output_hash) || self.contains_output(&output_hash) {
                return Err(TransactionError::OutputHashCollision(tx_hash, output_hash).into());
            }
            outputs_set.insert(output_hash.clone(), output);
        }

        match tx {
            // Staking balance of cheater was already validated in tx.validate()
            Transaction::SlashingTransaction(_) => {}
            _ => self.validate_stakes(inputs.iter(), tx.txouts().iter())?,
        }

        match tx {
            Transaction::CoinbaseTransaction(tx) => {
                assert_eq!(inputs.len(), 0);
                tx.validate()?;
            }
            Transaction::PaymentTransaction(tx) => tx.validate(&inputs)?,
            Transaction::RestakeTransaction(tx) => tx.validate(&inputs)?,
            Transaction::SlashingTransaction(tx) => tx.validate(self, leader)?,
            Transaction::ServiceAwardTransaction(_) => {
                return Err(TransactionError::UnexpectedTxType.into())
            }
        }

        // Transaction is valid.
        debug!("Transaction is valid: tx={}", tx_hash);
        Ok(())
    }

    ///
    /// Validate signed micro block.
    ///
    /// # Arguments
    ///
    /// * `block` - block to validate.
    /// * `timestamp` - current time.
    ///                         Used to validating escrow.
    ///
    pub fn validate_micro_block(
        &self,
        block: &MicroBlock,
        timestamp: Timestamp,
        validate_utxo: bool,
    ) -> Result<(), BlockchainError> {
        let epoch = block.header.epoch;
        let offset = block.header.offset;
        let block_hash = Hash::digest(&block);

        // Check block version.
        if block.header.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                epoch,
                block_hash,
                block.header.version,
                VERSION,
            )
            .into());
        }

        // Check the block order.
        if self.is_epoch_full() {
            return Err(BlockchainError::ExpectedMacroBlock(
                self.epoch(),
                self.offset(),
                block_hash,
            ));
        }

        // Check epoch and offset.
        if epoch != self.epoch() || offset != self.offset() {
            return Err(BlockError::OutOfOrderMicroBlock(
                block_hash,
                epoch,
                offset,
                self.epoch(),
                self.offset(),
            )
            .into());
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::MicroBlockHashCollision(epoch, offset, block_hash).into());
        }

        // Check previous hash.
        let previous_hash = self.last_block_hash();
        if previous_hash != block.header.previous {
            return Err(BlockError::InvalidMicroBlockPreviousHash(
                epoch,
                offset,
                block_hash,
                block.header.previous,
                previous_hash,
            )
            .into());
        }

        // Check view change.
        if block.header.view_change < self.view_change() {
            return Err(BlockError::InvalidViewChange(
                epoch,
                block_hash,
                block.header.view_change,
                self.view_change(),
            )
            .into());
        } else if block.header.view_change > 0 {
            match block.header.view_change_proof {
                Some(ref proof) => {
                    let chain = ChainInfo::from_micro_block(&block);
                    if let Err(e) = proof.validate(&chain, &self) {
                        return Err(
                            BlockError::InvalidViewChangeProof(epoch, proof.clone(), e).into()
                        );
                    }
                }
                None => {
                    return Err(BlockError::NoProofWasFound(
                        epoch,
                        offset,
                        block_hash,
                        block.header.view_change,
                        self.view_change(),
                    )
                    .into());
                }
            }
        }

        // Check signature.
        let leader = self.select_leader(block.header.view_change);
        if leader != block.header.pkey {
            return Err(BlockError::DifferentPublicKey(leader, block.header.pkey).into());
        }
        if let Err(_e) = pbc::check_hash(&block_hash, &block.sig, &leader) {
            return Err(BlockError::InvalidLeaderSignature(epoch, block_hash).into());
        }
        // Check block reward.
        if let Some(Transaction::CoinbaseTransaction(tx)) = block.transactions.get(0) {
            if tx.block_reward != self.cfg().block_reward {
                return Err(BlockError::InvalidMicroBlockReward(
                    epoch,
                    offset,
                    block_hash,
                    tx.block_reward,
                    self.cfg().block_reward,
                )
                .into());
            }
        } else {
            // Force coinbase if reward is not zero.
            return Err(BlockError::CoinbaseMustBeFirst(block_hash).into());
        }

        // Validate timestamp.
        self.validate_block_timestamp(epoch, &block_hash, block.header.timestamp, timestamp)?;

        // Check random.
        let last_random = self.last_random();
        let seed = mix(last_random, block.header.view_change);
        if !pbc::validate_VRF_source(&block.header.random, &leader, &seed).is_ok() {
            return Err(BlockError::IncorrectRandom(epoch, block_hash).into());
        }

        // Check VDF solution.
        let challenge = last_random.to_bytes();
        self.vdf
            .verify(&challenge, self.difficulty(), &block.header.solution)
            .map_err(|_| BlockError::InvalidVDFProof(epoch, block_hash))?;

        // Validate transactions_len.
        if block.header.transactions_len as usize != block.transactions.len() {
            return Err(BlockError::InvalidMicroBlockTransactionsLen(
                epoch,
                offset,
                block_hash,
                block.header.transactions_len as usize,
                block.transactions.len(),
            )
            .into());
        }

        let (
            transactions_range_hash,
            inputs_range_hash,
            outputs_range_hash,
            canaries_range_hash,
            _transaction_hashes,
            input_hashes,
            output_hashes,
            _canary_hashes,
        ) = MicroBlock::calculate_range_hashes(&block.transactions);

        // Validate transactions_range_hash.
        if block.header.transactions_range_hash != transactions_range_hash {
            return Err(BlockError::InvalidMicroBlockTransactionsHash(
                epoch,
                offset,
                block_hash,
                transactions_range_hash,
                block.header.transactions_range_hash,
            )
            .into());
        }

        // Validate inputs_len.
        if block.header.inputs_len as usize != input_hashes.len() {
            return Err(BlockError::InvalidMicroBlockInputsLen(
                epoch,
                offset,
                block_hash,
                block.header.inputs_len as usize,
                input_hashes.len(),
            )
            .into());
        }

        // Validate inputs_range_hash.
        if block.header.inputs_range_hash != inputs_range_hash {
            return Err(BlockError::InvalidMicroBlockInputsHash(
                epoch,
                offset,
                block_hash,
                inputs_range_hash,
                block.header.inputs_range_hash,
            )
            .into());
        }

        // Validate outputs_len.
        if block.header.outputs_len as usize != output_hashes.len() {
            return Err(BlockError::InvalidMicroBlockOutputsLen(
                epoch,
                offset,
                block_hash,
                block.header.outputs_len as usize,
                output_hashes.len(),
            )
            .into());
        }

        // Validate outputs_range_hash.
        if block.header.outputs_range_hash != outputs_range_hash {
            return Err(BlockError::InvalidMicroBlockOutputsHash(
                epoch,
                offset,
                block_hash,
                outputs_range_hash,
                block.header.outputs_range_hash,
            )
            .into());
        }

        // Validate canaries_range_hash.
        if block.header.canaries_range_hash != canaries_range_hash {
            return Err(BlockError::InvalidMicroBlockCanariesHash(
                epoch,
                offset,
                block_hash,
                canaries_range_hash,
                block.header.canaries_range_hash,
            )
            .into());
        }

        let mut inputs_set: HashSet<Hash> = HashSet::new();
        let mut outputs_set: HashMap<Hash, &Output> = HashMap::new();
        let mut fee: i64 = 0;

        //
        // Validate transactions.
        //
        let mut coinbase_fee: i64 = 0;
        for (i, tx) in block.transactions.iter().enumerate() {
            if let Transaction::CoinbaseTransaction(tx) = tx {
                // Coinbase transaction must be a first.
                if i > 0 {
                    return Err(BlockError::CoinbaseMustBeFirst(block_hash).into());
                }
                coinbase_fee += tx.block_fee;
            }
            self.validate_micro_block_tx(tx, block.header.pkey, &mut inputs_set, &mut outputs_set)?;
            fee += tx.fee();
        }
        if coinbase_fee != fee {
            return Err(BlockError::InvalidMicroBlockFee(
                epoch,
                offset,
                block_hash,
                fee,
                coinbase_fee,
            )
            .into());
        }

        //
        // Validate outputs.
        //
        if validate_utxo {
            outputs_set
                .into_par_iter()
                .try_for_each(|(_hash, o)| o.validate())?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::block::MacroBlock;
    use crate::output::OutputError;
    use crate::output::PaymentOutput;
    use crate::output::StakeOutput;
    use crate::timestamp::Timestamp;
    use bit_vec::BitVec;
    use stegos_crypto::pbc;

    ///
    /// Tests that transactions without inputs are prohibited.
    ///
    #[test]
    pub fn no_inputs() {
        let (skey, pkey) = scc::make_random_keys();
        let amount: i64 = 1_000_000;
        let fee: i64 = amount;
        let (input, _gamma1) = Output::new_payment(&pkey, amount).expect("keys are valid");
        let inputs = [input];
        let mut tx =
            PaymentTransaction::new(&skey, &inputs, &[], &Fr::zero(), fee).expect("keys are valid");
        tx.txins.clear(); // remove all inputs
        tx.validate(&[]).expect_err("tx is invalid");
    }

    ///
    /// Tests that transactions without outputs are allowed.
    ///
    #[test]
    pub fn no_outputs() {
        // No outputs
        let (skey, pkey) = scc::make_random_keys();
        let (tx, inputs, _outputs) = PaymentTransaction::new_test(&skey, &pkey, 100, 1, 0, 0, 100)
            .expect("transaction is valid");
        tx.validate(&inputs).expect("transaction is valid");
    }

    ///
    /// Tests validation of PaymentOutput.
    ///
    #[test]
    pub fn payment_utxo() {
        let (skey0, pkey0) = scc::make_random_keys();
        let (skey1, pkey1) = scc::make_random_keys();
        let (_skey2, pkey2) = scc::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        //
        // Invalid BulletProof.
        //
        let (mut output, _gamma) = PaymentOutput::new(&pkey1, 100).unwrap();
        output.proof.vcmt = Pt::random();
        match output.validate().unwrap_err() {
            BlockchainError::OutputError(OutputError::InvalidBulletProof(output_hash)) => {
                assert_eq!(output_hash, Hash::digest(&output));
            }
            e => panic!("{}", e),
        };

        //
        // Zero amount.
        //
        {
            let (tx, inputs, _outputs) =
                PaymentTransaction::new_test(&skey0, &pkey0, 0, 2, 0, 1, 0)
                    .expect("transaction is valid");
            tx.validate(&inputs).expect("transaction is valid");
        }

        //
        // Non-zero amount.
        //
        {
            let (tx, inputs, _outputs) =
                PaymentTransaction::new_test(&skey0, &pkey0, 100, 2, 200, 1, 0)
                    .expect("transaction is valid");
            tx.validate(&inputs).expect("transaction is valid");
        }

        //
        // Negative amount.
        //
        // {
        //     match PaymentTransaction::new_test(&skey0, &pkey0, 0, 1, -1, 1, 0) {
        //         Err(e) => match e.downcast::<CryptoError>().unwrap() {
        //             CryptoError::NegativeAmount => {}
        //             _ => panic!(),
        //         },
        //         _ => {}
        //     }
        // }

        //
        // Mutated recipient.
        //
        {
            let (mut tx, inputs, _outputs) =
                PaymentTransaction::new_test(&skey0, &pkey0, 100, 1, 100, 1, 0)
                    .expect("transaction is valid");
            let output = &mut tx.txouts[0];
            match output {
                Output::PaymentOutput(ref mut o) => {
                    let pt = scc::Pt::random();
                    o.recipient = pt.into();
                }
                _ => panic!(),
            };
            let e = tx.validate(&inputs).expect_err("transaction is invalid");
            match e {
                BlockchainError::TransactionError(TransactionError::InvalidSignature(tx_hash)) => {
                    // the hash of a transaction excludes its signature
                    assert_eq!(tx_hash, Hash::digest(&tx))
                }
                _ => panic!(),
            }
        }

        // "genesis" output by 0
        let (output0, _gamma0) = Output::new_payment(&pkey1, amount).expect("keys are valid");

        //
        // Valid transaction from 1 to 2
        //
        let inputs1 = [output0.clone()];
        let (output1, gamma1) = Output::new_payment(&pkey2, amount - fee).expect("keys are valid");
        let outputs_gamma = gamma1;
        let mut tx = PaymentTransaction::new(&skey1, &inputs1, &[output1], &outputs_gamma, fee)
            .expect("keys are valid");

        // Validation
        tx.validate(&inputs1).expect("keys are valid");

        //
        // Invalid fee
        //
        let fee = tx.fee;
        tx.fee = -1i64;
        match tx.validate(&inputs1).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::NegativeFee(_)) => {}
            _ => panic!(),
        };
        tx.fee = fee;

        //
        // Duplicate input
        //
        tx.txins.push(tx.txins.last().unwrap().clone());
        let inputs11 = &[output0.clone(), output0.clone()];
        match tx.validate(inputs11).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::DuplicateInput(
                _tx_hash,
                txin_hash,
            )) => {
                assert_eq!(&txin_hash, tx.txins.last().unwrap());
            }
            _ => panic!(),
        };
        tx.txins.pop().unwrap();

        //
        // Duplicate output
        //
        tx.txouts.push(tx.txouts.last().unwrap().clone());
        match tx.validate(&inputs1).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::DuplicateOutput(
                _tx_hash,
                txout_hash,
            )) => {
                assert_eq!(txout_hash, Hash::digest(tx.txouts.last().unwrap()));
            }
            _ => panic!(),
        };
        tx.txouts.pop().unwrap();

        //
        // Invalid signature
        //
        tx.sig.u = Fr::zero();
        match tx.validate(&inputs1).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::InvalidSignature(_tx_hash)) => {}
            _ => panic!(),
        };

        //
        // Invalid gamma
        //
        let (mut tx, inputs, _outputs) =
            PaymentTransaction::new_test(&skey0, &pkey0, 100, 2, 200, 1, 0)
                .expect("transaction is valid");
        tx.gamma = Fr::random();
        match tx.validate(&inputs).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::InvalidMonetaryBalance(
                _tx_hash,
            )) => {}
            _ => panic!(),
        };

        //
        // Invalid monetary balance
        //
        let (output_invalid1, gamma_invalid1) =
            Output::new_payment(&pkey2, amount - fee - 1).expect("keys are valid");
        let outputs = [output_invalid1];
        let outputs_gamma = gamma_invalid1;
        let tx = PaymentTransaction::new(&skey1, &inputs1, &outputs, &outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs1).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::InvalidMonetaryBalance(
                _tx_hash,
            )) => {}
            _ => panic!(),
        };
    }

    ///
    /// Tests validation of StakeOutput.
    ///
    #[test]
    pub fn stake_utxo() {
        let (skey1, pkey1) = scc::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        //
        // Canaries.
        //
        let output = StakeOutput::new(&pkey1, &nskey, &npkey, amount).unwrap();
        assert!(output.canary().is_my(&pkey1));
        let (_skey2, pkey2) = scc::make_random_keys();
        assert!(!output.canary().is_my(&pkey2));

        //
        // Invalid amount.
        //
        let mut output = StakeOutput::new(&pkey1, &nskey, &npkey, 100).expect("keys are valid");
        output.amount = 0; // mutate amount.
        match output.validate().unwrap_err() {
            BlockchainError::OutputError(OutputError::InvalidAmount(_output_hash, _)) => {}
            e => panic!("{:?}", e),
        };

        //
        // Invalid signature.
        //
        let mut output = StakeOutput::new(&pkey1, &nskey, &npkey, 100).expect("keys are valid");
        output.amount = 10; // mutate amount.
        match output.validate().unwrap_err() {
            BlockchainError::OutputError(OutputError::InvalidStakeSignature(_output_hash)) => {}
            e => panic!("{:?}", e),
        };

        //
        // StakeUTXO as an input.
        //
        let input = Output::new_stake(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
        let inputs = [input];
        let (output, outputs_gamma) =
            Output::new_payment(&pkey1, amount - fee).expect("keys are valid");
        let tx = PaymentTransaction::new(&skey1, &inputs, &[output], &outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // StakeUTXO as an output.
        //
        let (input, _inputs_gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output =
            Output::new_stake(&pkey1, &nskey, &npkey, amount - fee).expect("keys are valid");
        let outputs_gamma = Fr::zero();
        let tx = PaymentTransaction::new(&skey1, &inputs, &[output], &outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // Invalid monetary balance.
        //
        let (input, _inputs_gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output =
            StakeOutput::new(&pkey1, &nskey, &npkey, amount - fee - 1).expect("keys are valid");
        output.validate().expect("Invalid keys");
        let output = Output::StakeOutput(output);
        let outputs = [output];
        let outputs_gamma = Fr::zero();
        let tx = PaymentTransaction::new(&skey1, &inputs, &outputs, &outputs_gamma, fee)
            .expect("Invalid keys");
        match tx.validate(&inputs).unwrap_err() {
            BlockchainError::TransactionError(TransactionError::InvalidMonetaryBalance(
                _tx_hash,
            )) => {}
            e => panic!("{:?}", e),
        };

        //
        // Mutated recipient.
        //
        let (input, _inputs_gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output =
            Output::new_stake(&pkey1, &nskey, &npkey, amount - fee).expect("keys are valid");
        let outputs_gamma = Fr::zero();
        let mut tx = PaymentTransaction::new(&skey1, &inputs, &[output], &outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");
        let output = &mut tx.txouts[0];
        match output {
            Output::StakeOutput(ref mut o) => {
                let pt = scc::Pt::random();
                o.recipient = pt.into();
            }
            _ => panic!(),
        };
        match tx.validate(&inputs).expect_err("transaction is invalid") {
            BlockchainError::TransactionError(TransactionError::InvalidSignature(tx_hash)) => {
                assert_eq!(tx_hash, Hash::digest(&tx));
            }
            e => panic!("{:?}", e),
        }
    }

    ///
    /// Tests validation of PublicPaymentOutput
    #[test]
    fn public_payment() {
        let (_skey, pkey) = scc::make_random_keys();
        let amount = 100;

        //
        // Canaries.
        //
        let output = PublicPaymentOutput::new(&pkey, amount);
        assert!(output.canary().is_my(&pkey));
        let (_skey2, pkey2) = scc::make_random_keys();
        assert!(!output.canary().is_my(&pkey2));

        //
        // Invalid amount.
        //
        let mut output = PublicPaymentOutput::new(&pkey, amount);
        output.amount = 0; // mutate amount.
        match output.validate().unwrap_err() {
            BlockchainError::OutputError(OutputError::InvalidAmount(_output_hash, _)) => {}
            e => panic!("{:?}", e),
        };
    }

    #[test]
    fn test_supertransaction() {
        let (skey1, pkey1) = scc::make_random_keys();
        let (skey2, pkey2) = scc::make_random_keys();
        let (skey3, pkey3) = scc::make_random_keys();

        let err_utxo = "Can't construct UTXO";
        let iamt1 = 101;
        let iamt2 = 102;
        let iamt3 = 103;
        let (inp1, gamma_i1) = Output::new_payment(&pkey1, iamt1).expect(err_utxo);
        let (inp2, gamma_i2) = Output::new_payment(&pkey2, iamt2).expect(err_utxo);
        let (inp3, gamma_i3) = Output::new_payment(&pkey3, iamt3).expect(err_utxo);

        let decr_err = "Can't decrypt UTXO payload";
        let skeff1: scc::SecretKey = match inp1.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&pkey1, &skey1).expect(decr_err);
                assert!(payload.gamma == gamma_i1);
                let skeff: scc::SecretKey =
                    (Fr::from(skey1.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff2: scc::SecretKey = match inp2.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&pkey2, &skey2).expect(decr_err);
                assert!(payload.gamma == gamma_i2);
                let skeff: scc::SecretKey =
                    (Fr::from(skey2.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff3: scc::SecretKey = match inp3.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&pkey3, &skey3).expect(decr_err);
                assert!(payload.gamma == gamma_i3);
                let skeff: scc::SecretKey =
                    (Fr::from(skey3.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let total_fee = 10;
        let oamt1 = 51;
        let oamt2 = 52;
        let oamt3 = 53;
        let oamt4 = (iamt1 + iamt2 + iamt3) - (total_fee + oamt1 + oamt2 + oamt3);
        let (out1, gamma_o1) = Output::new_payment(&pkey2, oamt1).expect(err_utxo);
        let (out2, gamma_o2) = Output::new_payment(&pkey3, oamt2).expect(err_utxo);
        let (out3, gamma_o3) = Output::new_payment(&pkey3, oamt3).expect(err_utxo);
        let (out4, gamma_o4) = Output::new_payment(&pkey1, oamt4).expect(err_utxo);

        let inputs = [inp1, inp2, inp3];
        let outputs = [out1, out2, out3, out4];
        let gamma_adj =
            (gamma_i1 + gamma_i2 + gamma_i3) - (gamma_o1 + gamma_o2 + gamma_o3 + gamma_o4);

        let k_val1 = Fr::random();
        let k_val2 = Fr::random();
        let k_val3 = Fr::random();
        let sum_cap_k = simple_commit(&(k_val1 + k_val2 + k_val3), &Fr::zero());

        let err_stx = "Can't construct supertransaction";
        let mut stx1 = PaymentTransaction::new_super_transaction(
            &skeff1, &k_val1, &sum_cap_k, &inputs, &outputs, &gamma_adj, total_fee,
        )
        .expect(err_stx);
        let stx2 = PaymentTransaction::new_super_transaction(
            &skeff2, &k_val2, &sum_cap_k, &inputs, &outputs, &gamma_adj, total_fee,
        )
        .expect(err_stx);
        let stx3 = PaymentTransaction::new_super_transaction(
            &skeff3, &k_val3, &sum_cap_k, &inputs, &outputs, &gamma_adj, total_fee,
        )
        .expect(err_stx);

        let sig1 = stx1.sig;
        let sig2 = stx2.sig;
        let sig3 = stx3.sig;
        let final_sig = sig1 + sig2 + sig3;
        stx1.sig = final_sig;
        dbg!(&stx1.validate(&inputs));
    }

    #[test]
    fn create_validate_macro_block() {
        let (_skey1, pkey1) = scc::make_random_keys();
        let (_skey2, pkey2) = scc::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let epoch: u64 = 0;
        let timestamp = Timestamp::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest("test");
        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);
        let complexity = 1235;

        //
        // Valid block with transaction from 1 to 2
        //
        {
            let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();
            let inputs1 = vec![Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(&pkey2, amount).unwrap();
            let outputs1 = vec![output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                inputs1,
                outputs1,
            );
            block.validate_balance(&[output0]).expect("block is valid");
        }

        //
        // Block with invalid monetary balance
        //
        {
            let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();
            let inputs1 = vec![Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(&pkey2, amount - 1).unwrap();
            let outputs1 = vec![output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                inputs1,
                outputs1,
            );
            match block.validate_balance(&[output0]).unwrap_err() {
                BlockchainError::BlockError(BlockError::InvalidBlockBalance(_epoch, _hash)) => {}
                _ => panic!(),
            }
        }
    }

    #[test]
    fn create_validate_macro_block_with_staking() {
        let (_skey1, pkey1) = scc::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let epoch: u64 = 0;
        let timestamp = Timestamp::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());
        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);
        let complexity = 100500;

        //
        // Escrow as an input.
        //
        {
            let input = Output::new_stake(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            let input_hashes = vec![Hash::digest(&input)];
            let inputs = [input];
            let inputs_gamma = Fr::zero();
            let (output, outputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let outputs = vec![output];
            let gamma = inputs_gamma - outputs_gamma;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                input_hashes,
                outputs,
            );
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Escrow as an output.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = vec![Hash::digest(&input)];
            let inputs = vec![input];
            let output = Output::new_stake(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            let outputs_gamma = Fr::zero();
            let outputs = vec![output];
            let gamma = inputs_gamma - outputs_gamma;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                input_hashes,
                outputs,
            );
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Invalid monetary balance.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = vec![Hash::digest(&input)];
            let inputs = [input];
            let output =
                StakeOutput::new(&pkey1, &nskey, &npkey, amount - 1).expect("keys are valid");
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = vec![output];
            let gamma = inputs_gamma - outputs_gamma;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                input_hashes,
                outputs,
            );
            match block.validate_balance(&inputs).unwrap_err() {
                BlockchainError::BlockError(BlockError::InvalidBlockBalance(_epoch, _hash)) => {}
                _ => panic!(),
            };
        }

        //
        // Invalid stake.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = vec![Hash::digest(&input)];
            let inputs = [input];
            let mut output =
                StakeOutput::new(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            output.amount = 0;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = vec![output];
            let gamma = inputs_gamma - outputs_gamma;
            let block = MacroBlock::new(
                previous,
                epoch,
                view_change,
                npkey,
                random,
                complexity,
                timestamp,
                0,
                gamma,
                BitVec::new(),
                Vec::new(),
                input_hashes,
                outputs,
            );
            match block.validate_balance(&inputs).unwrap_err() {
                BlockchainError::OutputError(OutputError::InvalidAmount(_output_hash, _)) => {}
                e => panic!("{}", e),
            };
        }
    }

    #[test]
    fn create_money() {
        let input_amount: i64 = 100;
        let output_amount: i64 = 200;
        let (_skey, pkey) = scc::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let epoch: u64 = 0;
        let timestamp = Timestamp::now();
        let view_change = 0;
        let previous = Hash::digest(&"test".to_string());

        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);
        let complexity = 100500;
        let block_reward: i64 = output_amount - input_amount;

        let (input, input_gamma) = Output::new_payment(&pkey, input_amount).unwrap();
        let input_hashes = vec![Hash::digest(&input)];
        let inputs = [input];
        let (output, output_gamma) = Output::new_payment(&pkey, output_amount).unwrap();
        let outputs = vec![output];
        let gamma = input_gamma - output_gamma;
        let block = MacroBlock::new(
            previous,
            epoch,
            view_change,
            npkey,
            random,
            complexity,
            timestamp,
            block_reward,
            gamma,
            BitVec::new(),
            Vec::new(),
            input_hashes,
            outputs,
        );
        block.validate_balance(&inputs).expect("block is valid");
    }
}

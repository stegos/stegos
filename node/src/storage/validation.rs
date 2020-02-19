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

use super::{Blockchain, ChainInfo};
use log::*;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::{HashMap, HashSet};
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

impl Blockchain {
    pub fn validate_slashing_proof(&self, proof: &SlashingProof) -> Result<(), BlockchainError> {
        let epoch = proof.block1.header.epoch;
        let offset = proof.block1.header.offset;

        if proof.block1.header.epoch != proof.block2.header.epoch {
            return Err(SlashingError::DifferentEpoch(
                proof.block1.header.epoch,
                proof.block2.header.epoch,
            )
            .into());
        }

        if proof.block1.header.offset != proof.block2.header.offset {
            return Err(SlashingError::DifferentOffset(
                proof.block1.header.offset,
                proof.block2.header.offset,
            )
            .into());
        }

        if epoch != self.epoch() {
            return Err(SlashingError::InvalidProofEpoch(epoch, self.epoch()).into());
        }

        if proof.block1.header.previous != proof.block2.header.previous {
            return Err(SlashingError::DifferentHistory(
                proof.block1.header.previous,
                proof.block2.header.previous,
            )
            .into());
        }

        if proof.block1.header.view_change != proof.block2.header.view_change {
            return Err(SlashingError::DifferentLeader(
                proof.block1.header.view_change,
                proof.block2.header.view_change,
            )
            .into());
        }

        let block1_hash = Hash::digest(&proof.block1);

        let block2_hash = Hash::digest(&proof.block2);
        if block1_hash == block2_hash {
            return Err(SlashingError::BlockWithoutConflicts(epoch, offset, block1_hash).into());
        }

        let election_result = self.election_result_by_offset(offset)?;

        let ref leader_pk = election_result.select_leader(proof.block1.header.view_change);

        pbc::check_hash(&block1_hash, &proof.block1.sig, leader_pk)?;
        pbc::check_hash(&block2_hash, &proof.block2.sig, leader_pk)?;
        Ok(())
    }

    pub fn confiscate_tx(
        &self,
        our_key: &pbc::PublicKey, // our key, used to add change to payment utxo.
        proof: SlashingProof,
    ) -> Result<SlashingTransaction, BlockchainError> {
        assert_eq!(proof.block1.header.pkey, proof.block2.header.pkey);
        let ref cheater = proof.block1.header.pkey;
        let epoch = self.epoch();
        let (inputs, stake) = self.iter_validator_stakes(cheater).fold(
            (Vec::<Hash>::new(), 0i64),
            |(mut result, mut stake), (hash, amount, _, active_until_epoch)| {
                if active_until_epoch >= epoch {
                    stake += amount;
                    result.push(hash.clone());
                }
                (result, stake)
            },
        );
        let validators: Vec<_> = self
            .validators()
            .iter()
            .map(|(k, _v)| *k)
            .filter(|k| k != cheater)
            .collect();

        if validators.is_empty() {
            return Err(SlashingError::LastValidator(*cheater).into());
        }

        if inputs.is_empty() {
            return Err(SlashingError::NotValidator(*cheater).into());
        }

        self.validate_slashing_proof(&proof)?;
        assert!(stake > 0);
        let piece = stake / validators.len() as i64;
        let change = stake % validators.len() as i64;

        let mut outputs = Vec::new();
        for validator in &validators {
            let key = self
                .account_by_network_key(validator)
                .expect("validator has account key");
            let mut output = PublicPaymentOutput::new(&key, piece);
            if validator == our_key {
                output.amount += change
            }
            outputs.push(output.into());
        }
        debug!("Creating confiscate transaction: cheater = {}, piece = {}, change = {}, num_validators = {}", cheater, piece, change, outputs.len());

        Ok(SlashingTransaction {
            proof,
            txins: inputs,
            txouts: outputs,
        })
    }

    pub(crate) fn validate_slashing_tx(
        &self,
        tx: &SlashingTransaction,
        leader: pbc::PublicKey,
    ) -> Result<(), BlockchainError> {
        // validate proof
        self.validate_slashing_proof(&tx.proof)?;

        // recreate transaction
        let tx2 = self.confiscate_tx(&leader, tx.proof.clone())?;

        let tx_hash = Hash::digest(tx);
        // found incorrect formed slashing transaction.
        if tx.txins != tx2.txins {
            return Err(SlashingError::IncorrectTxins(tx_hash).into());
        }
        // Try to find unhonest devided stake.
        // Txouts is ordered by recipient validator id.
        for txs in tx2.txouts.iter().zip(tx.txouts.iter()) {
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
            Transaction::SlashingTransaction(tx) => self.validate_slashing_tx(&tx, leader)?,
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
                    if let Err(e) = self.validate_view_change_proof(proof, &chain) {
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

    pub fn validate_view_change_proof(
        &self,
        view_change: &ViewChangeProof,
        chain_info: &ChainInfo,
    ) -> Result<(), failure::Error> {
        let hash = Hash::digest(chain_info);

        let validators = self.election_result_by_offset(chain_info.offset)?;

        check_multi_signature(
            &hash,
            &view_change.multisig,
            &view_change.multimap,
            &validators.validators,
            self.total_slots(),
        )?;
        Ok(())
    }
}

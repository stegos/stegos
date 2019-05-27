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

use crate::block::{MacroBlock, MacroBlockHeader, MicroBlock, VERSION};
use crate::blockchain::{Balance, Blockchain, ChainInfo};
use crate::election::mix;
use crate::error::{BlockError, BlockchainError, SlashingError, TransactionError};
use crate::multisignature::check_multi_signature;
use crate::output::{Output, PublicPaymentOutput};
use crate::slashing::confiscate_tx;
use crate::transaction::{
    CoinbaseTransaction, PaymentTransaction, RestakeTransaction, SlashingTransaction, Transaction,
};
use log::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use stegos_crypto::bulletproofs::{fee_a, simple_commit};
use stegos_crypto::curve1174::{ECp, Fr, G};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::{curve1174, pbc};

pub type StakingBalance = HashMap<pbc::PublicKey, i64>;

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
        let mut mined: ECp = ECp::inf();
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
        if mined + &self.gamma * (*G) != fee_a(total_fee) {
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
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
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

        let mut eff_pkey = ECp::inf();
        let mut txin_sum = ECp::inf();
        let mut txout_sum = ECp::inf();

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(TransactionError::DuplicateInput(tx_hash, *txin_hash).into());
            }
            txin.validate()?;
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
            txout.validate()?;
            let cmt = txout.pedersen_commitment()?;
            txout_sum += cmt;
            eff_pkey -= cmt;
        }
        drop(txouts_set);

        // C(fee, gamma_adj) = fee * A + gamma_adj * G
        let adj: ECp = simple_commit(&self.gamma, &Fr::from(self.fee));

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum + adj {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }
        eff_pkey -= adj;

        // Create public key and check signature
        let eff_pkey: curve1174::PublicKey = eff_pkey.into();

        // Check signature
        curve1174::validate_sig(&tx_hash, &self.sig, &eff_pkey)
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
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
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
            txin.validate()?;
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
    /// * - `inputs` - UTXOs referred by self.body.inputs, in the same order as in self.body.inputs.
    ///
    pub fn validate_balance(&self, inputs: &[Output]) -> Result<(), BlockchainError> {
        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = block_reward + \sum C_i - \sum C_o
        //

        let mut pedersen_commitment_diff: ECp = fee_a(self.header.block_reward);

        // +\sum{C_i} for i in txins
        for (txin_hash, txin) in self.body.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            pedersen_commitment_diff += txin.pedersen_commitment()?;
        }

        // -\sum{C_o} for o in txouts
        for (txout, _) in self.body.outputs.leafs() {
            txout.validate()?;
            pedersen_commitment_diff -= txout.pedersen_commitment()?;
        }

        // Check the monetary balance
        if pedersen_commitment_diff != &self.header.gamma * (*G) {
            let block_hash = Hash::digest(&self);
            return Err(
                BlockError::InvalidBlockBalance(self.header.base.height, block_hash).into(),
            );
        }

        Ok(())
    }
}

impl Blockchain {
    /// Validate that staker didn't try to spent locked stake.
    /// Validate that staker has only one key.
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
    ///
    pub fn validate_staker(
        &self,
        tx: &Transaction,
        inputs: &[Output],
    ) -> Result<(), BlockchainError> {
        let mut staking_balance = StakingBalance::new();
        for txin in inputs {
            match txin {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake -= o.amount;
                }
            }
        }
        for txout in tx.txouts() {
            match txout {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    if let Some(wallet) = self.validator_wallet(&o.validator) {
                        if wallet != o.recipient {
                            let tx_hash = Hash::digest(tx);
                            let utxo_hash = Hash::digest(txout);
                            return Err(TransactionError::StakeOutputWithDifferentWalletKey(
                                wallet,
                                o.recipient,
                                tx_hash,
                                utxo_hash,
                            )
                            .into());
                        }
                    }
                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake += o.amount;
                }
            };
        }
        match tx {
            // Staking balance of cheater was already validated in tx.validate()
            Transaction::SlashingTransaction(_) => {}
            _ => self.validate_staking_balance(staking_balance.iter())?,
        }
        Ok(())
    }
    /// Check that the stake can be unstaked.
    fn validate_staking_balance<'a, StakeIter>(
        &self,
        staking_balance: StakeIter,
    ) -> Result<(), BlockchainError>
    where
        StakeIter: Iterator<Item = (&'a pbc::PublicKey, &'a i64)>,
    {
        for (validator_pkey, balance) in staking_balance {
            let (active_balance, expired_balance) = self.get_stake(validator_pkey);
            let expected_balance = active_balance + expired_balance + balance;
            if expected_balance < active_balance {
                return Err(BlockchainError::StakeIsLocked(
                    *validator_pkey,
                    expected_balance,
                    active_balance,
                ));
            }
        }

        Ok(())
    }

    ///
    /// Validate base block header.
    ///
    pub fn validate_macro_block_header(
        &self,
        block_hash: &Hash,
        header: &MacroBlockHeader,
    ) -> Result<(), BlockchainError> {
        let height = header.base.height;

        // Check block version.
        if header.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                *block_hash,
                header.base.version,
                VERSION,
            )
            .into());
        }

        // Check height.
        if height != self.height() {
            return Err(BlockError::OutOfOrderBlock(*block_hash, height, self.height()).into());
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, *block_hash).into());
        }

        // Check previous hash (skip for genesis).
        if height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != header.base.previous {
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    *block_hash,
                    header.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check random (skip for genesis).
        if height > 0 {
            let leader = self.select_leader(header.base.view_change);
            let seed = mix(self.last_random(), header.base.view_change);
            if !pbc::validate_VRF_source(&header.base.random, &leader, &seed) {
                return Err(BlockError::IncorrectRandom(height, *block_hash).into());
            }
        }

        Ok(())
    }

    ///
    /// A helper for validate_micro_block().
    ///
    fn validate_micro_block_tx(
        &self,
        tx: &Transaction,
        _timestamp: SystemTime,
        leader: pbc::PublicKey,
        inputs_set: &mut HashSet<Hash>,
        outputs_set: &mut HashSet<Hash>,
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
                return Err(TransactionError::MissingInput(tx_hash, input_hash.clone()).into());
            }

            inputs_set.insert(input_hash.clone());
            inputs.push(input);
        }

        // Check for overlapping outputs.
        for output in tx.txouts() {
            let output_hash = Hash::digest(output);
            // Check that the output is unique and don't overlap with other transactions.
            if outputs_set.contains(&output_hash) || self.contains_output(&output_hash) {
                return Err(TransactionError::OutputHashCollision(tx_hash, output_hash).into());
            }
            outputs_set.insert(output_hash.clone());
        }
        self.validate_staker(tx, &inputs)?;

        match tx {
            Transaction::CoinbaseTransaction(tx) => {
                assert_eq!(inputs.len(), 0);
                tx.validate()?;
            }
            Transaction::PaymentTransaction(tx) => tx.validate(&inputs)?,
            Transaction::RestakeTransaction(tx) => tx.validate(&inputs)?,
            Transaction::SlashingTransaction(tx) => tx.validate(self, leader)?,
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
        timestamp: SystemTime,
    ) -> Result<(), BlockchainError> {
        let height = block.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a micro block: height={}, block={}",
            height, &block_hash
        );

        // Check block version.
        if block.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                block_hash,
                block.base.version,
                VERSION,
            )
            .into());
        }

        // Check height.
        if height != self.height() {
            return Err(BlockError::OutOfOrderBlock(block_hash, height, self.height()).into());
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, block_hash).into());
        }

        // Check previous hash (skip for genesis).
        if height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.base.previous {
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    block_hash,
                    block.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check random (skip for genesis).
        if height > 0 {
            let leader = self.select_leader(block.base.view_change);
            let seed = mix(self.last_random(), block.base.view_change);
            if !pbc::validate_VRF_source(&block.base.random, &leader, &seed) {
                return Err(BlockError::IncorrectRandom(height, block_hash).into());
            }
        }

        // Check signature (exclude epoch == 0 for genesis).
        if self.epoch() > 0 {
            let leader = match block.base.view_change.cmp(&self.view_change()) {
                Ordering::Equal => self.leader(),
                Ordering::Greater => {
                    let chain = ChainInfo::from_micro_block(&block);
                    match block.view_change_proof {
                        Some(ref proof) => {
                            if let Err(e) = proof.validate(&chain, &self) {
                                return Err(BlockError::InvalidViewChangeProof(
                                    height,
                                    proof.clone(),
                                    e,
                                )
                                .into());
                            }
                            self.select_leader(block.base.view_change)
                        }
                        _ => {
                            return Err(BlockError::NoProofWasFound(
                                height,
                                block_hash,
                                block.base.view_change,
                                self.view_change(),
                            )
                            .into());
                        }
                    }
                }
                Ordering::Less => {
                    return Err(BlockError::InvalidViewChange(
                        height,
                        block_hash,
                        block.base.view_change,
                        self.view_change(),
                    )
                    .into());
                }
            };

            if leader != block.pkey {
                return Err(BlockError::DifferentPublicKey(leader, block.pkey).into());
            }

            if let Err(_e) = pbc::check_hash(&block_hash, &block.sig, &leader) {
                return Err(BlockError::InvalidLeaderSignature(height, block_hash).into());
            }
        }

        let mut inputs_set: HashSet<Hash> = HashSet::new();
        let mut outputs_set: HashSet<Hash> = HashSet::new();
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
            self.validate_micro_block_tx(
                tx,
                timestamp,
                block.pkey,
                &mut inputs_set,
                &mut outputs_set,
            )?;
            fee += tx.fee();
        }
        if coinbase_fee != fee {
            return Err(BlockError::InvalidFee(block_hash, fee, coinbase_fee).into());
        }

        debug!(
            "The micro block is valid: height={}, block={}",
            height, &block_hash
        );

        Ok(())
    }

    ///
    /// Validate signed macro block.
    ///
    /// # Arguments
    ///
    /// * `block` - block to validate.
    /// * `is_proposal` - don't check for the supermajority of votes.
    ///                          Used to validate block proposals.
    /// * `timestamp` - current time.
    ///                          Used to validate escrow.
    ///
    pub fn validate_macro_block(
        &self,
        block: &MacroBlock,
        _timestamp: SystemTime,
    ) -> Result<(), BlockchainError> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a macro block: height={}, block={}",
            height, &block_hash
        );

        // Validate base header.
        self.validate_macro_block_header(&block_hash, &block.header)?;

        // Validate multi-signature (skip for genesis).
        if height > 0 {
            // Validate signature.
            check_multi_signature(
                &block_hash,
                &block.body.multisig,
                &block.body.multisigmap,
                self.validators(),
                self.total_slots(),
            )
            .map_err(|e| BlockError::InvalidBlockSignature(e, height, block_hash))?;
        }

        let mut burned = ECp::inf();
        let mut created = ECp::inf();
        let mut staking_balance: HashMap<pbc::PublicKey, i64> = HashMap::new();

        //
        // Validate inputs.
        //
        let mut hasher = Hasher::new();
        let inputs_count: u64 = block.body.inputs.len() as u64;
        inputs_count.hash(&mut hasher);
        let mut input_set: HashSet<Hash> = HashSet::new();
        for input_hash in block.body.inputs.iter() {
            let input = match self.output_by_hash(input_hash)? {
                Some(input) => input,
                None => {
                    return Err(
                        BlockError::MissingBlockInput(height, block_hash, *input_hash).into(),
                    );
                }
            };
            // Check for the duplicate input.
            if !input_set.insert(*input_hash) {
                return Err(
                    BlockError::DuplicateBlockInput(height, block_hash, *input_hash).into(),
                );
            }
            input.validate()?;
            burned += input.pedersen_commitment()?;

            // Check UTXO.
            match input {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    let entry = staking_balance.entry(o.validator).or_insert(0);
                    *entry -= o.amount;
                }
            }
            input_hash.hash(&mut hasher);
        }
        drop(input_set);
        let inputs_range_hash = hasher.result();
        if block.header.inputs_range_hash != inputs_range_hash {
            let expected = block.header.inputs_range_hash.clone();
            let got = inputs_range_hash;
            return Err(
                BlockError::InvalidBlockInputsHash(height, block_hash, expected, got).into(),
            );
        }

        //
        // Validate outputs.
        //
        let mut output_set: HashSet<Hash> = HashSet::new();
        for (output, _path) in block.body.outputs.leafs() {
            // Check that hash is unique.
            let output_hash = Hash::digest(output.as_ref());
            if self.contains_output(&output_hash) {
                return Err(
                    BlockError::OutputHashCollision(height, block_hash, output_hash).into(),
                );
            }
            // Check for the duplicate output.
            if !output_set.insert(output_hash) {
                return Err(
                    BlockError::DuplicateBlockOutput(height, block_hash, output_hash).into(),
                );
            }

            output.validate()?;
            // Update balance.
            // Update balance.
            created += output.pedersen_commitment()?;

            // Check UTXO.
            match output.as_ref() {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    // Validated staking balance.
                    let entry = staking_balance.entry(o.validator).or_insert(0);
                    *entry += o.amount;
                }
            }
        }
        drop(output_set);
        if block.header.outputs_range_hash != *block.body.outputs.roothash() {
            let expected = block.header.outputs_range_hash.clone();
            let got = block.body.outputs.roothash().clone();
            return Err(
                BlockError::InvalidBlockOutputsHash(height, block_hash, expected, got).into(),
            );
        }

        //
        // Validate block monetary balance.
        //
        if fee_a(block.header.block_reward) + burned - created != &block.header.gamma * (*G) {
            return Err(BlockError::InvalidBlockBalance(height, block_hash).into());
        }

        //
        // Validate the global monetary balance.
        //
        let orig_balance = self.balance();
        let balance = Balance {
            created: orig_balance.created + created,
            burned: orig_balance.burned + burned,
            gamma: &orig_balance.gamma + &block.header.gamma,
            block_reward: orig_balance.block_reward + block.header.block_reward,
        };
        if fee_a(balance.block_reward) + balance.burned - balance.created != balance.gamma * (*G) {
            panic!(
                "Invalid global monetary balance: height={}, block={}",
                height, &block_hash
            );
        }

        // Checks staking balance.
        self.validate_staking_balance(staking_balance.iter())?;

        debug!(
            "The macro block is valid: height={}, block={}",
            height, &block_hash
        );
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::block::{BaseBlockHeader, MacroBlock};
    use crate::output::OutputError;
    use crate::output::StakeOutput;
    use std::time::SystemTime;
    use stegos_crypto::pbc;

    ///
    /// Tests that transactions without inputs are prohibited.
    ///
    #[test]
    pub fn no_inputs() {
        let (skey, pkey) = curve1174::make_random_keys();
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
        let (skey, pkey) = curve1174::make_random_keys();
        let (tx, inputs, _outputs) = PaymentTransaction::new_test(&skey, &pkey, 100, 1, 0, 0, 100)
            .expect("transaction is valid");
        tx.validate(&inputs).expect("transaction is valid");
    }

    ///
    /// Tests validation of PaymentOutput.
    ///
    #[test]
    pub fn payment_utxo() {
        let (skey0, pkey0) = curve1174::make_random_keys();
        let (skey1, pkey1) = curve1174::make_random_keys();
        let (_skey2, pkey2) = curve1174::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

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
        {
            match PaymentTransaction::new_test(&skey0, &pkey0, 0, 1, -1, 1, 0) {
                Err(e) => match e.downcast::<OutputError>().unwrap() {
                    OutputError::InvalidBulletProof(_output_hash) => {}
                    _ => panic!(),
                },
                _ => {}
            }
        }

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
                    let pt = curve1174::Pt::random();
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
        let (skey1, pkey1) = curve1174::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

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
            _ => panic!(),
        };

        //
        // Invalid stake.
        //
        let (input, _inputs_gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let mut output =
            StakeOutput::new(&pkey1, &nskey, &npkey, amount - fee).expect("keys are valid");
        output.amount = 0;
        let output = Output::StakeOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = PaymentTransaction::new(&skey1, &inputs, &[output], &outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs).unwrap_err() {
            BlockchainError::OutputError(OutputError::InvalidStake(_output_hash)) => {}
            e => panic!("{}", e),
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
                let pt = curve1174::Pt::random();
                o.recipient = pt.into();
            }
            _ => panic!(),
        };
        let e = tx.validate(&inputs).expect_err("transaction is invalid");
        dbg!(&e);
        match e {
            BlockchainError::OutputError(OutputError::InvalidStakeSignature(_output_hash)) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn test_supertransaction() {
        let (skey1, pkey1) = curve1174::make_random_keys();
        let (skey2, pkey2) = curve1174::make_random_keys();
        let (skey3, pkey3) = curve1174::make_random_keys();

        let err_utxo = "Can't construct UTXO";
        let iamt1 = 101;
        let iamt2 = 102;
        let iamt3 = 103;
        let (inp1, gamma_i1) = Output::new_payment(&pkey1, iamt1).expect(err_utxo);
        let (inp2, gamma_i2) = Output::new_payment(&pkey2, iamt2).expect(err_utxo);
        let (inp3, gamma_i3) = Output::new_payment(&pkey3, iamt3).expect(err_utxo);

        let decr_err = "Can't decrypt UTXO payload";
        let skeff1: curve1174::SecretKey = match inp1.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey1).expect(decr_err);
                assert!(payload.gamma == gamma_i1);
                let skeff: curve1174::SecretKey =
                    (Fr::from(skey1) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff2: curve1174::SecretKey = match inp2.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey2).expect(decr_err);
                assert!(payload.gamma == gamma_i2);
                let skeff: curve1174::SecretKey =
                    (Fr::from(skey2) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff3: curve1174::SecretKey = match inp3.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey3).expect(decr_err);
                assert!(payload.gamma == gamma_i3);
                let skeff: curve1174::SecretKey =
                    (Fr::from(skey3) + payload.gamma * payload.delta).into();
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
        let sum_cap_k = simple_commit(&(&k_val1 + &k_val2 + &k_val3), &Fr::zero());

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
        let (_skey1, pkey1) = curve1174::make_random_keys();
        let (_skey2, pkey2) = curve1174::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest("test");
        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);

        //
        // Valid block with transaction from 1 to 2
        //
        {
            let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();
            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(&pkey2, amount).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(base, gamma, 0, &inputs1, &outputs1, npkey);
            block.validate_balance(&[output0]).expect("block is valid");
        }

        //
        // Block with invalid monetary balance
        //
        {
            let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();
            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(&pkey2, amount - 1).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(base, gamma, 0, &inputs1, &outputs1, npkey);
            match block.validate_balance(&[output0]).unwrap_err() {
                BlockchainError::BlockError(BlockError::InvalidBlockBalance(_height, _hash)) => {}
                _ => panic!(),
            }
        }
    }

    #[test]
    fn validate_pruned_micro_block() {
        let (_skey, pkey) = curve1174::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);

        let (input, gamma0) = Output::new_payment(&pkey, amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, gamma1) = Output::new_payment(&pkey, amount).unwrap();
        let outputs = [output];
        let gamma = gamma0 - gamma1;
        let block = MacroBlock::new(base, gamma, 0, &input_hashes, &outputs, npkey);
        block.validate_balance(&inputs).expect("block is valid");

        {
            // Prune an output.
            let mut block2 = block.clone();
            let (_output, path) = block2.body.outputs.leafs()[0];
            block2.body.outputs.prune(&path).expect("output exists");
            match block2.validate_balance(&inputs).unwrap_err() {
                BlockchainError::BlockError(BlockError::InvalidBlockBalance(_height, _hash)) => {}
                _ => panic!(),
            }
        }
    }

    #[test]
    fn create_validate_macro_block_with_staking() {
        let (_skey1, pkey1) = curve1174::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());
        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);

        //
        // Escrow as an input.
        //
        {
            let input = Output::new_stake(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let inputs_gamma = Fr::zero();
            let (output, outputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..], npkey);
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Escrow as an output.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let output = Output::new_stake(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..], npkey);
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Invalid monetary balance.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let output =
                StakeOutput::new(&pkey1, &nskey, &npkey, amount - 1).expect("keys are valid");
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..], npkey);
            match block.validate_balance(&inputs).unwrap_err() {
                BlockchainError::BlockError(BlockError::InvalidBlockBalance(_height, _hash)) => {}
                _ => panic!(),
            };
        }

        //
        // Invalid stake.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(&pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let mut output =
                StakeOutput::new(&pkey1, &nskey, &npkey, amount).expect("keys are valid");
            output.amount = 0;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..], npkey);
            match block.validate_balance(&inputs).unwrap_err() {
                BlockchainError::OutputError(OutputError::InvalidStake(_output_hash)) => {}
                e => panic!("{}", e),
            };
        }
    }

    fn create_burn_money(input_amount: i64, output_amount: i64) {
        let (_skey, pkey) = curve1174::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let previous = Hash::digest(&"test".to_string());

        let seed = mix(Hash::zero(), view_change);
        let random = pbc::make_VRF(&nskey, &seed);
        let block_reward: i64 = output_amount - input_amount;

        let (input, input_gamma) = Output::new_payment(&pkey, input_amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, output_gamma) = Output::new_payment(&pkey, output_amount).unwrap();
        let outputs = [output];
        let gamma = input_gamma - output_gamma;
        let block = MacroBlock::new(base, gamma, block_reward, &input_hashes, &outputs, npkey);
        block.validate_balance(&inputs).expect("block is valid");
    }

    #[test]
    fn create_money() {
        create_burn_money(100, 200);
    }

    #[test]
    fn burn_money() {
        create_burn_money(200, 100);
    }
}

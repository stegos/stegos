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

use crate::block::{MacroBlock, VERSION};
use crate::blockchain::{Balance, Blockchain, ChainInfo};
use crate::election::mix;
use crate::error::TransactionError;
use crate::error::{BlockError, BlockchainError};
use crate::multisignature::check_multi_signature;
use crate::output::{Output, OutputError, PAYMENT_PAYLOAD_LEN, STAKE_PAYLOAD_LEN};
use crate::transaction::Transaction;
use failure::Error;
use log::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use stegos_crypto::bulletproofs::{fee_a, simple_commit, validate_range_proof};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::{cpt, G};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;

pub type StakingBalance = HashMap<secure::PublicKey, i64>;

impl Transaction {
    /// Validate the monetary balance and signature of transaction.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<StakingBalance, Error> {
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

        assert_eq!(self.body.txins.len(), inputs.len());

        // Check that transaction has inputs.
        if self.body.txins.is_empty() {
            return Err(TransactionError::NoInputs(tx_hash).into());
        }

        // Check fee.
        if self.body.fee < 0 {
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
        let mut staking_balance: StakingBalance = HashMap::new();

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.body.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(TransactionError::DuplicateInput(tx_hash, *txin_hash).into());
            }
            match txin {
                Output::PaymentOutput(o) => {
                    let cmt = o.proof.vcmt.decompress()?;
                    txin_sum += cmt;
                    eff_pkey += cpt::Pt::from(o.recipient).decompress()? + cmt;
                }
                Output::StakeOutput(o) => {
                    o.validate_pkey()?;
                    let cmt = fee_a(o.amount);
                    txin_sum += cmt;
                    eff_pkey += cpt::Pt::from(o.recipient).decompress()? + cmt;

                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake -= o.amount;
                }
            };
        }
        drop(txins_set);

        // -\sum{C_o} for o in txouts
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for txout in &self.body.txouts {
            let txout_hash = Hash::digest(txout);
            if !txouts_set.insert(txout_hash) {
                return Err(TransactionError::DuplicateOutput(tx_hash, txout_hash).into());
            }
            match txout {
                Output::PaymentOutput(o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof(txout_hash).into());
                    }
                    if o.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            txout_hash,
                            PAYMENT_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    let cmt = cpt::Pt::decompress(o.proof.vcmt)?;
                    txout_sum += cmt;
                    eff_pkey -= cmt;
                }
                Output::StakeOutput(o) => {
                    o.validate_pkey()?; // need to prove that we own SecurePublicKey
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake(txout_hash).into());
                    }
                    if o.payload.ctxt.len() != STAKE_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            txout_hash,
                            STAKE_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    let cmt = fee_a(o.amount);
                    txout_sum += cmt;
                    eff_pkey -= cmt;

                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake += o.amount;
                }
            };
        }
        drop(txouts_set);

        // C(fee, gamma_adj) = fee * A + gamma_adj * G
        let adj: ECp = simple_commit(self.body.gamma, Fr::from(self.body.fee));

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum + adj {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }
        eff_pkey -= adj;

        // Create public key and check signature
        let eff_pkey: cpt::PublicKey = eff_pkey.into();

        // Check signature
        cpt::validate_sig(&tx_hash, &self.sig, &eff_pkey)
            .map_err(|_e| TransactionError::InvalidSignature(tx_hash))?;

        // Transaction is valid.
        Ok(staking_balance)
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
    pub fn validate_balance(&self, inputs: &[Output]) -> Result<(), Error> {
        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = monetary_adjustment + \sum C_i - \sum C_o
        //

        let mut pedersen_commitment_diff: ECp = fee_a(self.header.monetary_adjustment);

        // +\sum{C_i} for i in txins
        for (txin_hash, txin) in self.body.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            match txin {
                Output::PaymentOutput(o) => {
                    pedersen_commitment_diff += cpt::Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    pedersen_commitment_diff += fee_a(o.amount);
                }
            };
        }

        // -\sum{C_o} for o in txouts
        for (txout, _) in self.body.outputs.leafs() {
            let output_hash = Hash::digest(&*txout);
            match **txout {
                Output::PaymentOutput(ref o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof(output_hash).into());
                    }
                    pedersen_commitment_diff -= cpt::Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(ref o) => {
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake(output_hash).into());
                    }
                    pedersen_commitment_diff -= fee_a(o.amount);
                }
            };
        }

        // Check the monetary balance
        if pedersen_commitment_diff != self.header.gamma * (*G) {
            let block_hash = Hash::digest(&self);
            return Err(
                BlockError::InvalidBlockBalance(self.header.base.height, block_hash).into(),
            );
        }

        Ok(())
    }
}

impl Blockchain {
    /// Check that the stake can be unstaked.
    pub fn validate_staking_balance<'a, StakeIter>(
        &self,
        staking_balance: StakeIter,
    ) -> Result<(), BlockchainError>
    where
        StakeIter: Iterator<Item = (&'a secure::PublicKey, &'a i64)>,
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
        block: &MacroBlock,
        timestamp: SystemTime,
    ) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a micro block: height={}, block={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                block_hash,
                block.header.base.version,
                VERSION,
            )
            .into());
        }

        // Check height.
        if height != self.height() {
            return Err(BlockError::OutOfOrderBlock(block_hash, height, self.height()).into());
        }

        // Check previous hash.
        if self.height() > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    block_hash,
                    block.header.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, block_hash).into());
        }

        // Check signature (exclude epoch == 0 for genesis).
        if self.epoch() > 0 {
            let leader = match block.header.base.view_change.cmp(&self.view_change()) {
                Ordering::Equal => self.leader(),
                Ordering::Greater => {
                    let chain = ChainInfo::from_micro_block(&block);
                    match block.header.proof {
                        Some(ref proof) => {
                            if let Err(e) = proof.validate(&chain, &self) {
                                return Err(BlockError::InvalidViewChangeProof(
                                    height,
                                    block_hash,
                                    proof.clone(),
                                    e,
                                )
                                .into());
                            }
                            self.select_leader(block.header.base.view_change)
                        }
                        _ => {
                            return Err(BlockError::NoProofWasFound(
                                height,
                                block_hash,
                                block.header.base.view_change,
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
                        block.header.base.view_change,
                        self.view_change(),
                    )
                    .into());
                }
            };

            if let Err(_e) = secure::check_hash(&block_hash, &block.body.multisig, &leader) {
                return Err(BlockError::InvalidLeaderSignature(height, block_hash).into());
            }

            debug!(
                "Validating VRF: leader={}, round={}",
                leader, block.header.base.view_change
            );
            let seed = mix(self.last_random(), block.header.base.view_change);
            if !secure::validate_VRF_source(&block.header.base.random, &leader, &seed) {
                return Err(BlockError::IncorrectRandom(height, block_hash).into());
            }
        }

        self.validate_macro_block_payments(block, timestamp)?;

        debug!(
            "The micro block is valid: height={}, block={}",
            height, &block_hash
        );

        Ok(())
    }

    fn validate_macro_block_payments(
        &self,
        block: &MacroBlock,
        _timestamp: SystemTime,
    ) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);

        let mut burned = ECp::inf();
        let mut created = ECp::inf();
        let mut staking_balance: HashMap<secure::PublicKey, i64> = HashMap::new();

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
            // Check UTXO.
            match input {
                Output::PaymentOutput(o) => {
                    burned += cpt::Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    // Validate staking signature.
                    o.validate_pkey()?;
                    burned += fee_a(o.amount);
                    // Validate staking balance.
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
            // Check UTXO.
            match output.as_ref() {
                Output::PaymentOutput(o) => {
                    // Validate bullet proofs.
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof(output_hash).into());
                    }
                    // Validate payload.
                    if o.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            output_hash,
                            PAYMENT_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    // Update balance.
                    created += cpt::Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    // Validate staking signature.
                    o.validate_pkey()?;
                    // Validate payload.
                    if o.payload.ctxt.len() != STAKE_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            output_hash,
                            STAKE_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    // Validate amount.
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake(output_hash).into());
                    }
                    // Validated staking balance.
                    let entry = staking_balance.entry(o.validator).or_insert(0);
                    *entry += o.amount;
                    // Update balance.
                    created += fee_a(o.amount);
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
        if fee_a(block.header.monetary_adjustment) + burned - created != block.header.gamma * (*G) {
            return Err(BlockError::InvalidBlockBalance(height, block_hash).into());
        }

        //
        // Validate the global monetary balance.
        //
        let orig_balance = self.balance();
        let balance = Balance {
            created: orig_balance.created + created,
            burned: orig_balance.burned + burned,
            gamma: orig_balance.gamma + block.header.gamma,
            monetary_adjustment: orig_balance.monetary_adjustment
                + block.header.monetary_adjustment,
        };
        if fee_a(balance.monetary_adjustment) + balance.burned - balance.created
            != balance.gamma * (*G)
        {
            panic!(
                "Invalid global monetary balance: height={}, block={}",
                height, &block_hash
            );
        }

        // Checks staking balance.
        self.validate_staking_balance(staking_balance.iter())?;

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
        timestamp: SystemTime,
        is_proposal: bool,
    ) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a micro block: height={}, block={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                block_hash,
                block.header.base.version,
                VERSION,
            )
            .into());
        }

        // Check height.
        if height != self.height() {
            return Err(BlockError::OutOfOrderBlock(block_hash, height, self.height()).into());
        }

        // Check previous hash.
        if self.height() > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    block_hash,
                    block.header.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check new hash.
        if self.contains_block(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, block_hash).into());
        }

        // skip leader selection and signature checking for genesis block.
        if self.epoch() > 0 {
            // Skip view change check, just check supermajority.
            let leader = self.select_leader(block.header.base.view_change);

            debug!(
                "Validating VRF: leader={}, round={}",
                leader, block.header.base.view_change
            );
            let seed = mix(self.last_random(), block.header.base.view_change);
            if !secure::validate_VRF_source(&block.header.base.random, &leader, &seed) {
                return Err(BlockError::IncorrectRandom(height, block_hash).into());
            }

            // Currently macro block consensus uses public key as peer id.
            // This adaptor allows converting PublicKey into integer identifier.
            let validators_map: HashMap<secure::PublicKey, u32> = self
                .validators()
                .iter()
                .enumerate()
                .map(|(id, (pk, _))| (*pk, id as u32))
                .collect();

            if let Some(leader_id) = validators_map.get(&leader) {
                // bit of leader should be always set.
                if !block.body.multisigmap.contains(*leader_id as usize) {
                    return Err(BlockError::NoLeaderSignatureFound(height, block_hash).into());
                }
            } else {
                return Err(BlockError::LeaderIsNotValidator(height, block_hash).into());
            }

            // checks that proposal is signed only by leader.
            if is_proposal {
                if block.body.multisigmap.len() != 1 {
                    return Err(
                        BlockError::MoreThanOneSignatureAtPropose(height, block_hash).into(),
                    );
                }
                if let Err(_e) = secure::check_hash(&block_hash, &block.body.multisig, &leader) {
                    return Err(BlockError::InvalidLeaderSignature(height, block_hash).into());
                }
            } else {
                check_multi_signature(
                    &block_hash,
                    &block.body.multisig,
                    &block.body.multisigmap,
                    self.validators(),
                    self.total_slots(),
                )
                .map_err(|e| BlockError::InvalidBlockSignature(e, height, block_hash))?;
            }
        }

        self.validate_macro_block_payments(block, timestamp)?;

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
    use crate::block::BaseBlockHeader;
    use crate::output::StakeOutput;
    use std::time::SystemTime;
    use stegos_crypto::pbc::secure;

    ///
    /// Tests that transactions without inputs are prohibited.
    ///
    #[test]
    pub fn no_inputs() {
        let (skey, pkey) = cpt::make_random_keys();
        let timestamp = SystemTime::now();
        let amount: i64 = 1_000_000;
        let fee: i64 = amount;
        let (input, _gamma1) =
            Output::new_payment(timestamp, &skey, &pkey, amount).expect("keys are valid");
        let inputs = [input];
        let mut tx =
            Transaction::new(&skey, &inputs, &[], Fr::zero(), fee).expect("keys are valid");
        tx.body.txins.clear(); // remove all inputs
        tx.validate(&[]).expect_err("tx is invalid");
    }

    ///
    /// Tests that transactions without outputs are allowed.
    ///
    #[test]
    pub fn no_outputs() {
        // No outputs
        let (skey, pkey) = cpt::make_random_keys();
        let (tx, inputs, _outputs) =
            Transaction::new_test(&skey, &pkey, 100, 1, 0, 0, 100).expect("transaction is valid");
        tx.validate(&inputs).expect("transaction is valid");
    }

    ///
    /// Tests validation of PaymentOutput.
    ///
    #[test]
    pub fn payment_utxo() {
        let (skey0, pkey0) = cpt::make_random_keys();
        let (skey1, pkey1) = cpt::make_random_keys();
        let (_skey2, pkey2) = cpt::make_random_keys();

        let timestamp = SystemTime::now();
        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        //
        // Zero amount.
        //
        {
            let (tx, inputs, _outputs) =
                Transaction::new_test(&skey0, &pkey0, 0, 2, 0, 1, 0).expect("transaction is valid");
            tx.validate(&inputs).expect("transaction is valid");
        }

        //
        // Non-zero amount.
        //
        {
            let (tx, inputs, _outputs) = Transaction::new_test(&skey0, &pkey0, 100, 2, 200, 1, 0)
                .expect("transaction is valid");
            tx.validate(&inputs).expect("transaction is valid");
        }

        //
        // Negative amount.
        //
        {
            match Transaction::new_test(&skey0, &pkey0, 0, 1, -1, 1, 0) {
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
                Transaction::new_test(&skey0, &pkey0, 100, 1, 100, 1, 0)
                    .expect("transaction is valid");
            let output = &mut tx.body.txouts[0];
            match output {
                Output::PaymentOutput(ref mut o) => {
                    let pt = cpt::Pt::random();
                    o.recipient = pt.into();
                }
                _ => panic!(),
            };
            let e = tx.validate(&inputs).expect_err("transaction is invalid");
            match e.downcast::<TransactionError>().unwrap() {
                TransactionError::InvalidSignature(tx_hash) => {
                    // the hash of a transaction excludes its signature
                    assert_eq!(tx_hash, Hash::digest(&tx.body))
                }
                _ => panic!(),
            }
        }

        // "genesis" output by 0
        let (output0, _gamma0) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        //
        // Valid transaction from 1 to 2
        //
        let inputs1 = [output0.clone()];
        let (output1, gamma1) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount - fee).expect("keys are valid");
        let outputs_gamma = gamma1;
        let mut tx = Transaction::new(&skey1, &inputs1, &[output1], outputs_gamma, fee)
            .expect("keys are valid");

        // Validation
        tx.validate(&inputs1).expect("keys are valid");

        //
        // Invalid fee
        //
        let fee = tx.body.fee;
        tx.body.fee = -1i64;
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::NegativeFee(_) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };
        tx.body.fee = fee;

        //
        // Duplicate input
        //
        tx.body.txins.push(tx.body.txins.last().unwrap().clone());
        let inputs11 = &[output0.clone(), output0.clone()];
        match tx.validate(inputs11) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::DuplicateInput(_tx_hash, txin_hash) => {
                    assert_eq!(&txin_hash, tx.body.txins.last().unwrap());
                }
                _ => panic!(),
            },
            _ => panic!(),
        };
        tx.body.txins.pop().unwrap();

        //
        // Duplicate output
        //
        tx.body.txouts.push(tx.body.txouts.last().unwrap().clone());
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::DuplicateOutput(_tx_hash, txout_hash) => {
                    assert_eq!(txout_hash, Hash::digest(tx.body.txouts.last().unwrap()));
                }
                _ => panic!(),
            },
            _ => panic!(),
        };
        tx.body.txouts.pop().unwrap();

        //
        // Invalid signature
        //
        tx.sig.u = Fr::zero();
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::InvalidSignature(_tx_hash) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };

        //
        // Invalid gamma
        //
        let (mut tx, inputs, _outputs) =
            Transaction::new_test(&skey0, &pkey0, 100, 2, 200, 1, 0).expect("transaction is valid");
        tx.body.gamma = Fr::random();
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::InvalidMonetaryBalance(_tx_hash) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };

        //
        // Invalid monetary balance
        //
        let (output_invalid1, gamma_invalid1) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount - fee - 1)
                .expect("keys are valid");
        let outputs = [output_invalid1];
        let outputs_gamma = gamma_invalid1;
        let tx = Transaction::new(&skey1, &inputs1, &outputs, outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::InvalidMonetaryBalance(_tx_hash) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };
    }

    ///
    /// Tests validation of StakeOutput.
    ///
    #[test]
    pub fn stake_utxo() {
        let (skey0, _pkey0) = cpt::make_random_keys();
        let (skey1, pkey1) = cpt::make_random_keys();
        let (secure_skey1, secure_pkey1) = secure::make_random_keys();

        let timestamp = SystemTime::now();
        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        //
        // StakeUTXO as an input.
        //
        let input = Output::new_stake(
            timestamp,
            &skey0,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount,
        )
        .expect("keys are valid");
        let inputs = [input];
        let (output, outputs_gamma) =
            Output::new_payment(timestamp, &skey1, &pkey1, amount - fee).expect("keys are valid");
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // StakeUTXO as an output.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output = Output::new_stake(
            timestamp,
            &skey1,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount - fee,
        )
        .expect("keys are valid");
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // Invalid monetary balance.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let mut output = StakeOutput::new(
            timestamp,
            &skey1,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount - fee,
        )
        .expect("keys are valid");
        output.amount = amount - fee - 1;
        let output = Output::StakeOutput(output);
        let outputs = [output];
        let outputs_gamma = Fr::zero();
        let tx =
            Transaction::new(&skey1, &inputs, &outputs, outputs_gamma, fee).expect("Invalid keys");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<TransactionError>().unwrap() {
                TransactionError::InvalidMonetaryBalance(_tx_hash) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };

        //
        // Invalid stake.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let mut output = StakeOutput::new(
            timestamp,
            &skey1,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount - fee,
        )
        .expect("keys are valid");
        output.amount = 0;
        let output = Output::StakeOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<OutputError>().unwrap() {
                OutputError::InvalidStake(_output_hash) => {}
                _ => panic!(),
            },
            _ => panic!(),
        };

        //
        // Mutated recipient.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output = Output::new_stake(
            timestamp,
            &skey1,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount - fee,
        )
        .expect("keys are valid");
        let outputs_gamma = Fr::zero();
        let mut tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");
        let output = &mut tx.body.txouts[0];
        match output {
            Output::StakeOutput(ref mut o) => {
                let pt = cpt::Pt::random();
                o.recipient = pt.into();
            }
            _ => panic!(),
        };
        let e = tx.validate(&inputs).expect_err("transaction is invalid");
        dbg!(&e);
        match e.downcast::<OutputError>().unwrap() {
            OutputError::InvalidStakeSignature(_output_hash) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn test_supertransaction() {
        let (skey1, pkey1) = cpt::make_random_keys();
        let (skey2, pkey2) = cpt::make_random_keys();
        let (skey3, pkey3) = cpt::make_random_keys();
        let timestamp = SystemTime::now();
        let err_utxo = "Can't construct UTXO";
        let iamt1 = 101;
        let iamt2 = 102;
        let iamt3 = 103;
        let (inp1, gamma_i1) =
            Output::new_payment(timestamp, &skey2, &pkey1, iamt1).expect(err_utxo);
        let (inp2, gamma_i2) =
            Output::new_payment(timestamp, &skey1, &pkey2, iamt2).expect(err_utxo);
        let (inp3, gamma_i3) =
            Output::new_payment(timestamp, &skey1, &pkey3, iamt3).expect(err_utxo);

        let decr_err = "Can't decrypt UTXO payload";
        let skeff1: cpt::SecretKey = match inp1.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey1).expect(decr_err);
                assert!(payload.gamma == gamma_i1);
                let skeff: cpt::SecretKey =
                    (Fr::from(skey1.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff2: cpt::SecretKey = match inp2.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey2).expect(decr_err);
                assert!(payload.gamma == gamma_i2);
                let skeff: cpt::SecretKey =
                    (Fr::from(skey2.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff3: cpt::SecretKey = match inp3.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey3).expect(decr_err);
                assert!(payload.gamma == gamma_i3);
                let skeff: cpt::SecretKey =
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
        let (out1, gamma_o1) =
            Output::new_payment(timestamp, &skey1, &pkey2, oamt1).expect(err_utxo);
        let (out2, gamma_o2) =
            Output::new_payment(timestamp, &skey2, &pkey3, oamt2).expect(err_utxo);
        let (out3, gamma_o3) =
            Output::new_payment(timestamp, &skey2, &pkey3, oamt3).expect(err_utxo);
        let (out4, gamma_o4) =
            Output::new_payment(timestamp, &skey3, &pkey1, oamt4).expect(err_utxo);

        let inputs = [inp1, inp2, inp3];
        let outputs = [out1, out2, out3, out4];
        let gamma_adj =
            (gamma_i1 + gamma_i2 + gamma_i3) - (gamma_o1 + gamma_o2 + gamma_o3 + gamma_o4);

        let k_val1 = Fr::random();
        let k_val2 = Fr::random();
        let k_val3 = Fr::random();
        let sum_cap_k = simple_commit(k_val1 + k_val2 + k_val3, Fr::zero());

        let err_stx = "Can't construct supertransaction";
        let mut stx1 = Transaction::new_super_transaction(
            &skeff1, k_val1, &sum_cap_k, &inputs, &outputs, gamma_adj, total_fee,
        )
        .expect(err_stx);
        let stx2 = Transaction::new_super_transaction(
            &skeff2, k_val2, &sum_cap_k, &inputs, &outputs, gamma_adj, total_fee,
        )
        .expect(err_stx);
        let stx3 = Transaction::new_super_transaction(
            &skeff3, k_val3, &sum_cap_k, &inputs, &outputs, gamma_adj, total_fee,
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
    fn create_validate_micro_block() {
        let (skey0, _pkey0) = cpt::make_random_keys();
        let (skey1, pkey1) = cpt::make_random_keys();
        let (_skey2, pkey2) = cpt::make_random_keys();
        let (pbc_skey, pbc_pkey) = secure::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest("test");
        let seed = mix(Hash::zero(), view_change);
        let random = secure::make_VRF(&pbc_skey, &seed);

        //
        // Valid block with transaction from 1 to 2
        //
        {
            let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();
            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(timestamp, &skey1, &pkey2, amount).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(base, gamma, 0, &inputs1, &outputs1, None, pbc_pkey);
            block.validate_balance(&[output0]).expect("block is valid");
        }

        //
        // Block with invalid monetary balance
        //
        {
            let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();
            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) =
                Output::new_payment(timestamp, &skey1, &pkey2, amount - 1).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MacroBlock::new(base, gamma, 0, &inputs1, &outputs1, None, pbc_pkey);
            match block.validate_balance(&[output0]) {
                Err(e) => match e.downcast::<BlockError>().unwrap() {
                    BlockError::InvalidBlockBalance(_height, _hash) => {}
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }
    }

    #[test]
    fn validate_pruned_micro_block() {
        let (skey, pkey) = cpt::make_random_keys();
        let (pbc_skey, pbc_pkey) = secure::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        let seed = mix(Hash::zero(), view_change);
        let random = secure::make_VRF(&pbc_skey, &seed);

        let (input, gamma0) = Output::new_payment(timestamp, &skey, &pkey, amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, gamma1) = Output::new_payment(timestamp, &skey, &pkey, amount).unwrap();
        let outputs = [output];
        let gamma = gamma0 - gamma1;
        let block = MacroBlock::new(base, gamma, 0, &input_hashes, &outputs, None, pbc_pkey);
        block.validate_balance(&inputs).expect("block is valid");

        {
            // Prune an output.
            let mut block2 = block.clone();
            let (_output, path) = block2.body.outputs.leafs()[0];
            block2.body.outputs.prune(&path).expect("output exists");
            match block2.validate_balance(&inputs) {
                Err(e) => match e.downcast::<BlockError>().unwrap() {
                    BlockError::InvalidBlockBalance(_height, _hash) => {}
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }
    }

    #[test]
    fn create_validate_micro_block_with_escrow() {
        let (skey0, _pkey0) = cpt::make_random_keys();
        let (skey1, pkey1) = cpt::make_random_keys();
        let (secure_skey1, secure_pkey1) = secure::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());
        let seed = mix(Hash::zero(), view_change);
        let random = secure::make_VRF(&secure_skey1, &seed);

        //
        // Escrow as an input.
        //
        {
            let input = Output::new_stake(
                timestamp,
                &skey0,
                &pkey1,
                &secure_pkey1,
                &secure_skey1,
                amount,
            )
            .expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let inputs_gamma = Fr::zero();
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey1, &pkey1, amount).expect("keys are valid");
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(
                base,
                gamma,
                0,
                &input_hashes[..],
                &outputs[..],
                None,
                secure_pkey1,
            );
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Escrow as an output.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let output = Output::new_stake(
                timestamp,
                &skey1,
                &pkey1,
                &secure_pkey1,
                &secure_skey1,
                amount,
            )
            .expect("keys are valid");
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(
                base,
                gamma,
                0,
                &input_hashes[..],
                &outputs[..],
                None,
                secure_pkey1,
            );
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Invalid monetary balance.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let mut output = StakeOutput::new(
                timestamp,
                &skey1,
                &pkey1,
                &secure_pkey1,
                &secure_skey1,
                amount,
            )
            .expect("keys are valid");
            output.amount = amount - 1;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(
                base,
                gamma,
                0,
                &input_hashes[..],
                &outputs[..],
                None,
                secure_pkey1,
            );
            match block.validate_balance(&inputs) {
                Err(e) => match e.downcast::<BlockError>().unwrap() {
                    BlockError::InvalidBlockBalance(_height, _hash) => {}
                    _ => panic!(),
                },
                _ => panic!(),
            };
        }

        //
        // Invalid stake.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let mut output = StakeOutput::new(
                timestamp,
                &skey1,
                &pkey1,
                &secure_pkey1,
                &secure_skey1,
                amount,
            )
            .expect("keys are valid");
            output.amount = 0;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base =
                BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
            let block = MacroBlock::new(
                base,
                gamma,
                0,
                &input_hashes[..],
                &outputs[..],
                None,
                secure_pkey1,
            );
            match block.validate_balance(&inputs) {
                Err(e) => match e.downcast::<OutputError>().unwrap() {
                    OutputError::InvalidStake(_output_hash) => {}
                    _ => panic!(),
                },
                _ => panic!(),
            };
        }
    }

    fn create_burn_money(input_amount: i64, output_amount: i64) {
        let (skey, pkey) = cpt::make_random_keys();
        let (secure_skey1, secure_pkey1) = secure::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let previous = Hash::digest(&"test".to_string());

        let seed = mix(Hash::zero(), view_change);
        let random = secure::make_VRF(&secure_skey1, &seed);
        let monetary_adjustment: i64 = output_amount - input_amount;

        let (input, input_gamma) =
            Output::new_payment(timestamp, &skey, &pkey, input_amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, output_gamma) =
            Output::new_payment(timestamp, &skey, &pkey, output_amount).unwrap();
        let outputs = [output];
        let gamma = input_gamma - output_gamma;
        let block = MacroBlock::new(
            base,
            gamma,
            monetary_adjustment,
            &input_hashes,
            &outputs,
            None,
            secure_pkey1,
        );
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

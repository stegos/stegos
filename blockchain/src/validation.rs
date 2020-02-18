//! Blockchain - Validation.

//
// Copyright (c) 2018-2020 Stegos AG
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

use super::error::{BlockError, BlockchainError, TransactionError};
use super::output::Output;
use super::transaction::{CoinbaseTransaction, PaymentTransaction, RestakeTransaction};
use super::MacroBlock;
use std::collections::HashSet;
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

#[cfg(test)]
pub mod tests {
    use super::super::block::MacroBlock;
    use super::super::election::mix;
    use super::super::output::OutputError;
    use super::super::output::PaymentOutput;
    use super::super::output::PublicPaymentOutput;
    use super::super::output::StakeOutput;
    use super::super::timestamp::Timestamp;
    use super::super::*;
    use bit_vec::BitVec;
    use stegos_crypto::bulletproofs::simple_commit;
    use stegos_crypto::hash::Hash;
    use stegos_crypto::scc::{Fr, Pt};
    use stegos_crypto::{pbc, scc};

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

//! Transactions.

//
// Copyright (c) 2018 Stegos AG
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

use crate::output::*;
use failure::Error;
use failure::Fail;
use std::collections::HashSet;
use std::time::SystemTime;
use stegos_crypto::bulletproofs::{fee_a, simple_commit, validate_range_proof};
use stegos_crypto::curve1174::cpt::{
    sign_hash, sign_hash_with_kval, validate_sig, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

/// Transaction errors.
#[derive(Debug, Fail)]
pub enum TransactionError {
    #[fail(display = "Invalid signature: tx={}", _0)]
    InvalidSignature(Hash),
    #[fail(display = "Invalid monetary balance: tx={}", _0)]
    InvalidMonetaryBalance(Hash),
    #[fail(display = "Negative fee: tx={}", _0)]
    NegativeFee(Hash),
    #[fail(display = "No inputs: tx={}", _0)]
    NoInputs(Hash),
    #[fail(display = "Duplicate input: tx={}, utxo={}", _0, _1)]
    DuplicateInput(Hash, Hash),
    #[fail(display = "Duplicate output: tx={}, utxo={}", _0, _1)]
    DuplicateOutput(Hash, Hash),
}

/// Transaction body.
#[derive(Clone, Debug)]
pub struct TransactionBody {
    /// List of inputs.
    pub txins: Vec<Hash>,
    /// List of outputs.
    pub txouts: Vec<Output>,
    /// Sum of gamma adjustment for txins minus sum of gamma adjustment for outs.
    pub gamma: Fr,
    /// Fee.
    pub fee: i64,
}

impl Hashable for TransactionBody {
    fn hash(&self, state: &mut Hasher) {
        // Sign txins.
        let txins_count: u64 = self.txins.len() as u64;
        txins_count.hash(state);
        for txin_hash in &self.txins {
            txin_hash.hash(state);
        }

        // Sign txouts.
        let txouts_count: u64 = self.txouts.len() as u64;
        txouts_count.hash(state);
        for txout in &self.txouts {
            txout.hash(state);
        }

        // Sign gamma.
        self.gamma.hash(state);

        // Sign fee.
        (self.fee as u64).hash(state);
    }
}

/// Transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction body.
    pub body: TransactionBody,
    /// Transaction signature.
    pub sig: SchnorrSig,
}

impl Hashable for Transaction {
    fn hash(&self, state: &mut Hasher) {
        self.body.hash(state);
    }
}

impl Transaction {
    pub fn dum() -> Self {
        Transaction {
            body: TransactionBody {
                txins: Vec::new(),
                txouts: Vec::new(),
                gamma: Fr::zero(),
                fee: 0,
            },
            sig: SchnorrSig::new(),
        }
    }

    /// Create a new transaction.
    ///
    /// # Arguments
    ///
    /// * `skey` - Sender's secret key
    /// * `inputs` - UXTO to spent
    /// * `outputs` - UXTO to create
    /// * `outputs_gamma` - gamma adjustment for outputs
    /// * `fee` - Total Fee
    ///
    pub fn new(
        skey: &SecretKey,
        inputs: &[Output],
        outputs: &[Output],
        outputs_gamma: Fr, // = sum(outputs.gamma)
        fee: i64,
    ) -> Result<Self, Error> {
        assert!(fee >= 0);
        let tx = Self::unchecked(skey, inputs, outputs, outputs_gamma, fee)?;
        // just let validate() find any problems...
        tx.validate(inputs)?;
        Ok(tx)
    }

    /// Same as new(), but without checks and assertions.
    pub fn unchecked(
        skey: &SecretKey,
        inputs: &[Output],
        outputs: &[Output],
        outputs_gamma: Fr, // = sum(outputs.gamma)
        fee: i64,
    ) -> Result<Self, Error> {
        //
        // Compute S_eff = N * S_M + \sum{\delta_i * gamma_i},
        // where i in txins
        //

        let mut eff_skey = Fr::zero();
        let mut gamma_adj: Fr = Fr::zero();
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());

        for txin in inputs {
            eff_skey += Fr::from(skey.clone());
            match txin {
                Output::PaymentOutput(o) => {
                    let payload = o.decrypt_payload(skey)?;
                    gamma_adj += payload.gamma;
                    eff_skey += payload.delta * payload.gamma;
                }
                Output::StakeOutput(o) => {
                    let payload = o.decrypt_payload(skey)?;
                    eff_skey += payload.delta;
                }
            }
            let hash = Hasher::digest(txin);
            txins.push(hash);
        }

        // gamma_adj == \sum(gamma_in) - \sum(gamma_out)
        gamma_adj -= outputs_gamma;

        // Create a transaction body and calculate the hash.
        let body = TransactionBody {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj,
            fee,
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&body);
        let eff_skey: SecretKey = eff_skey.into();
        let sig = sign_hash(&tx_hash, &eff_skey);

        // Create signed transaction.
        let tx = Transaction { body, sig };
        Ok(tx)
    }

    /// Validate the monetary balance and signature of transaction.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<(), Error> {
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
                    eff_pkey += Pt::from(o.recipient).decompress()? + cmt;
                }
                Output::StakeOutput(o) => {
                    o.validate_pkey()?;
                    let cmt = fee_a(o.amount);
                    txin_sum += cmt;
                    eff_pkey += Pt::from(o.recipient).decompress()? + cmt;
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
                    let cmt = Pt::decompress(o.proof.vcmt)?;
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
                }
            };
        }
        drop(txouts_set);

        // C(fee, gamma_adj) = fee * A + gamma_adj * G
        let adj = simple_commit(self.body.gamma, Fr::from(self.body.fee));

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum + adj {
            return Err(TransactionError::InvalidMonetaryBalance(tx_hash).into());
        }
        eff_pkey -= adj;

        // Create public key and check signature
        let eff_pkey: PublicKey = eff_pkey.into();

        // Check signature
        match validate_sig(&tx_hash, &self.sig, &eff_pkey)? {
            true => Ok(()),
            false => Err(TransactionError::InvalidSignature(tx_hash).into()),
        }
    }

    /// Create a new super-transaction.
    ///
    /// # Arguments
    ///
    /// * `skey` - Sender's secret key to be used for partial signature
    /// * `k_val` - Sender's k seed for the partial signature
    /// * `sum_cap_k` - sum of all k*G from all participants
    /// * `inputs` - UXTOs to spend
    /// * `outputs` - UXTOs to create
    /// * `gamma_adj` - gamma adjustment
    /// * `total_fee` - Total Fee
    ///
    /// This produces a skeletal super-transaction (an otherwise normal
    /// Transaction), but the signature is just the fragment produced by
    /// the callers SecretKey.
    ///
    /// It will be necessary to accumulate additional signatures before this
    /// super-transaction could pass validation.
    ///
    /// Note that skey must be the \sum(skey_i + gamma_i * delta_i),
    /// from each input that belongs to the client. This is the SecretKey
    /// corresponding to the cloaked recipient PublicKey in each TXIN.
    ///
    pub fn new_super_transaction(
        skey: &SecretKey,
        k_val: Fr,
        sum_cap_k: &ECp,
        inputs: &[Output],
        outputs: &[Output],
        gamma_adj: Fr,
        total_fee: i64,
    ) -> Result<Self, Error> {
        assert!(total_fee >= 0);
        assert!(inputs.len() > 0 || outputs.len() > 0);

        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut sum_pkey = ECp::inf();

        // check that each TXIN is unique
        for txin in inputs {
            let hash = Hasher::digest(txin);
            txins.push(hash);
            let pkey = match txin {
                Output::PaymentOutput(o) => o.recipient,
                Output::StakeOutput(o) => o.recipient,
            };
            sum_pkey += Pt::from(pkey).decompress()?;
        }

        // Create a transaction body and calculate the hash.
        let body = TransactionBody {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj,
            fee: total_fee,
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&body);
        let sig = sign_hash_with_kval(&tx_hash, &skey, k_val, sum_cap_k, &sum_pkey);

        // Create signed transaction.
        let tx = Transaction { body, sig };
        Ok(tx)
    }

    /// Used only for tests.
    //#[cfg(test)]
    #[doc(hidden)]
    pub fn new_test(
        skey: &SecretKey,
        pkey: &PublicKey,
        input_amount: i64,
        input_count: usize,
        output_amount: i64,
        output_count: usize,
        fee: i64,
    ) -> Result<(Transaction, Vec<Output>, Vec<Output>), Error> {
        let mut inputs: Vec<Output> = Vec::with_capacity(input_count);
        let mut outputs: Vec<Output> = Vec::with_capacity(output_count);

        let timestamp = SystemTime::now();

        for _ in 0..input_count {
            let (input, _gamma) =
                Output::new_payment(timestamp, &skey, &pkey, input_amount).expect("keys are valid");
            inputs.push(input);
        }

        let mut outputs_gamma: Fr = Fr::zero();
        for _ in 0..output_count {
            let (output, gamma) = Output::new_payment(timestamp, &skey, &pkey, output_amount)
                .expect("keys are valid");
            outputs.push(output);
            outputs_gamma += gamma;
        }

        match Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee) {
            Err(e) => Err(e),
            Ok(tx) => Ok((tx, inputs, outputs)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::pbc::secure;

    ///
    /// Tests that transactions without inputs are prohibited.
    ///
    #[test]
    pub fn no_inputs() {
        let (skey, pkey, _sig) = make_random_keys();
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
        let (skey, pkey, _sig) = make_random_keys();
        let (tx, inputs, _outputs) =
            Transaction::new_test(&skey, &pkey, 100, 1, 0, 0, 100).expect("transaction is valid");
        tx.validate(&inputs).expect("transaction is valid");
    }

    ///
    /// Tests validation of PaymentOutput.
    ///
    #[test]
    pub fn payment_utxo() {
        let (skey0, pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

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
                    let pt = Pt::random();
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
        let outputs_gamma = gamma_invalid1;
        match Transaction::new(&skey1, &inputs1, &[output_invalid1], outputs_gamma, fee) {
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
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (secure_skey1, secure_pkey1, _secure_sig1) = secure::make_random_keys();

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
        let outputs_gamma = Fr::zero();
        match Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee) {
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
        match Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee) {
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
                let pt = Pt::random();
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
        let (skey1, pkey1, _) = make_random_keys();
        let (skey2, pkey2, _) = make_random_keys();
        let (skey3, pkey3, _) = make_random_keys();
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
        let skeff1: SecretKey = match inp1.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey1).expect(decr_err);
                assert!(payload.gamma == gamma_i1);
                let skeff: SecretKey =
                    (Fr::from(skey1.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff2: SecretKey = match inp2.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey2).expect(decr_err);
                assert!(payload.gamma == gamma_i2);
                let skeff: SecretKey =
                    (Fr::from(skey2.clone()) + payload.gamma * payload.delta).into();
                skeff
            }
            _ => panic!("Invalid UTXO"),
        };

        let skeff3: SecretKey = match inp3.clone() {
            Output::PaymentOutput(o) => {
                let payload = o.decrypt_payload(&skey3).expect(decr_err);
                assert!(payload.gamma == gamma_i3);
                let skeff: SecretKey =
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
}

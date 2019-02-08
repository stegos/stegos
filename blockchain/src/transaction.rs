//! Transactions.

//
// Copyright (c) 2018 Stegos
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
use crate::output::*;
use chrono::Utc;
use failure::Error;
use std::collections::HashSet;
use stegos_crypto::bulletproofs::{fee_a, simple_commit, validate_range_proof};
use stegos_crypto::curve1174::cpt::{
    sign_hash, sign_hash_with_kval, validate_sig, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

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

impl Transaction {
    /// Create a new transaction.
    ///
    /// # Arguments
    ///
    /// * `inputs` - UXTO to spend, accompanied by SecretKey for the payee
    /// * `outputs` - UXTO to create
    /// * `outputs_gamma` - sum of output gammas
    /// * `fee` - Total Fee
    ///
    pub fn new(
        inputs: &[(Output, SecretKey)],
        outputs: &[Output],
        outputs_gamma: Fr, // = \sum(gamma_j), j in outputs
        fee: i64,
    ) -> Result<Self, Error> {
        assert!(fee >= 0);
        assert!(inputs.len() > 0 || outputs.len() > 0);

        //
        // Compute s_eff = \sum{s_i + \delta_i * gamma_i},
        // where i in txins
        //
        // Recall that each TXIN could have been sent to a different
        // public key, all owned by the spender, and each has a different
        // associated secret key
        //

        let mut eff_skey = Fr::zero();

        let mut gamma_adj: Fr = Fr::zero();
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut txouts: Vec<Output> = Vec::with_capacity(outputs.len());

        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin, skey) in inputs {
            eff_skey += Fr::from(*skey);
            match txin {
                Output::PaymentOutput(o) => {
                    let payload = o.decrypt_payload(skey)?;
                    gamma_adj += payload.gamma;
                    eff_skey += payload.delta * payload.gamma;
                }
                Output::StakeOutput(o) => {
                    let delta = o.decrypt_payload(skey)?;
                    eff_skey += delta;
                }
            }

            let hash = Hasher::digest(txin);
            let uniq = txins_set.insert(hash);
            assert!(uniq, "inputs must be unique");
            txins.push(hash);
        }
        drop(txins_set);

        // gamma_adj == \sum(gamma_in) - \sum(gamma_out)
        gamma_adj -= outputs_gamma;

        // Clone created UTXOs
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for txout in outputs {
            let hash = Hasher::digest(txout);
            assert!(txouts_set.insert(hash), "inputs must be unique");
            txouts.push(txout.clone());
        }
        drop(txouts_set);

        // Create a transaction body and calculate the hash.
        let body = TransactionBody {
            txins,
            txouts,
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
        assert_eq!(self.body.txins.len(), inputs.len());

        // Check fee.
        if self.body.fee < 0 {
            return Err(BlockchainError::InvalidTransactionFee.into());
        }

        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = \sum C_i - \sum C_o - (fee * A + gamma_adj * G)
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
                return Err(BlockchainError::DuplicateTransactionInput(*txin_hash).into());
            }
            match txin {
                Output::PaymentOutput(o) => {
                    let cmt = o.proof.vcmt.decompress()?;
                    txin_sum += cmt;
                    eff_pkey += Pt::from(o.recipient).decompress()? + cmt;
                }
                Output::StakeOutput(o) => {
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
                return Err(BlockchainError::DuplicateTransactionOutput(txout_hash).into());
            }
            match txout {
                Output::PaymentOutput(o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(BlockchainError::InvalidBulletProof.into());
                    }
                    if o.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
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
                    if o.amount <= 0 {
                        return Err(BlockchainError::InvalidStake.into());
                    }
                    if o.payload.ctxt.len() != STAKE_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
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

        // C(fee, gamma_adj) = -(fee * A + gamma_adj * G)
        let adj = simple_commit(self.body.gamma, Fr::from(self.body.fee));

        // technically, this test is no longer needed since it has been
        // absorbed into the signature check...
        if txin_sum != txout_sum + adj {
            return Err(BlockchainError::InvalidTransactionBalance.into());
        }
        eff_pkey -= adj;

        // Create public key and check signature
        let eff_pkey: PublicKey = eff_pkey.into();
        let tx_hash = Hash::digest(&self.body);

        // Check signature
        match validate_sig(&tx_hash, &self.sig, &eff_pkey)? {
            true => Ok(()),
            false => Err(BlockchainError::InvalidTransactionSignature.into()),
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
        let mut txouts: Vec<Output> = Vec::with_capacity(outputs.len());
        let mut sum_pkey = ECp::inf();

        // check that each TXIN is unique
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for txin in inputs {
            let hash = Hasher::digest(txin);
            let uniq = txins_set.insert(hash);
            assert!(uniq, "inputs must be unique");
            txins.push(hash);
            let pkey = match txin {
                Output::PaymentOutput(o) => o.recipient,
                Output::StakeOutput(o) => o.recipient,
            };
            sum_pkey += match Pt::from(pkey).decompress() {
                Ok(pt) => pt,
                _ => ECp::inf(), // this will probably fail in transacton validation
            };
        }
        drop(txins_set);

        // Clone created UTXOs
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for txout in outputs {
            let hash = Hasher::digest(txout);
            assert!(txouts_set.insert(hash), "inputs must be unique");
            txouts.push(txout.clone());
        }
        drop(txouts_set);

        // Create a transaction body and calculate the hash.
        let body = TransactionBody {
            txins,
            txouts,
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
        my_skey: &SecretKey,    // spender skey
        payee_pkey: &PublicKey, // payee pkey
        input_amount: i64,
        input_count: usize,
        output_amount: i64,
        output_count: usize,
        fee: i64,
    ) -> (Transaction, Vec<Output>, Vec<Output>) {
        // as per old expectations:
        //    inputs = Vec<Outputs> which are the UTXO's of the TXINS
        //    inputsc = creation inputs = pairs (Output, SecretKey)

        let mut inputsc: Vec<(Output, SecretKey)> = Vec::with_capacity(input_count);
        let mut outputs: Vec<Output> = Vec::with_capacity(output_count);
        let (anon_creator_skey, _, _) = stegos_crypto::curve1174::cpt::make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;

        // make UTXO's payable to spender (me)...
        let my_pkey = PublicKey::from(*my_skey);
        for _ in 0..input_count {
            let (input, _gamma) =
                Output::new_payment(timestamp, &anon_creator_skey, &my_pkey, input_amount)
                    .expect("keys are valid");
            inputsc.push((input, my_skey.clone()));
        }

        let mut outputs_gamma: Fr = Fr::zero();
        for _ in 0..output_count {
            let (output, gamma) =
                Output::new_payment(timestamp, &my_skey, &payee_pkey, output_amount)
                    .expect("keys are valid");
            outputs.push(output);
            outputs_gamma += gamma;
        }

        let tx = Transaction::new(&inputsc, &outputs, outputs_gamma, fee).expect("keys are valid");
        let inputs: Vec<Output> = inputsc.iter().map(|(o, _)| o.clone()).collect();
        (tx, inputs, outputs)
    }
}

impl Hashable for Transaction {
    fn hash(&self, state: &mut Hasher) {
        self.body.hash(state);
        self.sig.hash(state);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::pbc::secure;

    /// Check transaction signing and validation.
    #[test]
    pub fn basic_validate() {
        let (skey, pkey, _sig) = make_random_keys();
        let (tx, inputs, _outputs) = Transaction::new_test(&skey, &pkey, 100, 2, 200, 1, 0);
        tx.validate(&inputs).expect("transaction is valid");
    }

    /// Check transaction signing and validation.
    #[test]
    pub fn create_validate() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        // "genesis" output by 0
        let (output0, _gamma0) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        //
        // Valid transaction from 1 to 2
        //
        let inputs1c = [(output0.clone(), skey1.clone())]; // TX creation inputs
        let (output1, gamma1) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount - fee).expect("keys are valid");
        let outputs_gamma = gamma1;
        let mut tx =
            Transaction::new(&inputs1c, &[output1], outputs_gamma, fee).expect("keys are valid");

        // Validation
        let inputs1 = [output0.clone()]; // TX validation inputs
        tx.validate(&inputs1).expect("keys are valid");

        //
        // Invalid fee
        //
        let fee = tx.body.fee;
        tx.body.fee = -1i64;
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionFee => {}
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
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::DuplicateTransactionInput(txin_hash) => {
                    assert_eq!(&txin_hash, tx.body.txins.last().unwrap());
                }
                _ => panic!(),
            },
            _ => panic!(),
        };
        drop(inputs11);
        tx.body.txins.pop().unwrap();

        //
        // Duplicate output
        //
        tx.body.txouts.push(tx.body.txouts.last().unwrap().clone());
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::DuplicateTransactionOutput(txout_hash) => {
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
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionSignature => {}
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
        let tx = Transaction::new(&inputs1c, &[output_invalid1], outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionBalance => {}
                // BlockchainError::InvalidTransactionSignature => {}
                _ => panic!(),
            },
            _ => panic!(),
        };
    }

    #[test]
    pub fn escrow_create_validate() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_secure_skey1, secure_pkey1, _secure_sig1) = secure::make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let fee: i64 = 1;

        //
        // Escrow as an input.
        //
        let input = Output::new_stake(timestamp, &skey0, &pkey1, &secure_pkey1, amount)
            .expect("keys are valid");
        let inputs = [input.clone()];
        let inputsc = [(input.clone(), skey1.clone())];
        let (output, outputs_gamma) =
            Output::new_payment(timestamp, &skey1, &pkey1, amount - fee).expect("keys are valid");
        let tx = Transaction::new(&inputsc, &[output], outputs_gamma, fee).expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // Escrow as an output.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input.clone()];
        let inputsc = [(input.clone(), skey1.clone())];
        let output = Output::new_stake(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
            .expect("keys are valid");
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&inputsc, &[output], outputs_gamma, fee).expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // Invalid monetary balance.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input.clone()];
        let inputsc = [(input.clone(), skey1.clone())];
        let mut output = StakeOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
            .expect("keys are valid");
        output.amount = amount - fee - 1;
        let output = Output::StakeOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&inputsc, &[output], outputs_gamma, fee).expect("keys are valid");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionBalance => {}
                // BlockchainError::InvalidTransactionSignature => {}
                _ => panic!(),
            },
            _ => panic!(),
        };

        //
        // Invalid stake.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input.clone()];
        let inputsc = [(input.clone(), skey1.clone())];
        let mut output = StakeOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
            .expect("keys are valid");
        output.amount = 0;
        let output = Output::StakeOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&inputsc, &[output], outputs_gamma, fee).expect("keys are valid");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidStake => {}
                _ => panic!(),
            },
            _ => panic!(),
        };
    }
}

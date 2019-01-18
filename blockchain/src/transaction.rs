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
use failure::Error;
use std::collections::HashSet;
use stegos_crypto::bulletproofs::{fee_a, validate_range_proof};
use stegos_crypto::curve1174::cpt::{
    sign_hash, validate_sig, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
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
        outputs_gamma: Fr,
        fee: i64,
    ) -> Result<Self, Error> {
        assert!(fee >= 0);
        assert!(inputs.len() > 0 || outputs.len() > 0);

        //
        // Compute S_eff = N * S_M + \sum{\delta_i * gamma_i} + \sum{\gamma_i} - \sum{gamma_j},
        // where i in txins, j in txouts
        //

        let skey_fr: Fr = (*skey).into();
        let mut eff_skey: Fr = skey_fr * (inputs.len() as i64); // N * s_M

        let mut tx_gamma: Fr = Fr::zero();
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut txouts: Vec<Output> = Vec::with_capacity(outputs.len());

        let mut txins_set: HashSet<Hash> = HashSet::new();
        for txin in inputs {
            match txin {
                Output::PaymentOutput(o) => {
                    let (delta, gamma, _amount) = o.decrypt_payload(skey)?;
                    tx_gamma += gamma;
                    eff_skey += delta * gamma;
                    eff_skey += gamma;
                }
                Output::DataOutput(o) => {
                    let (delta, gamma, _data) = o.decrypt_payload(skey)?;
                    tx_gamma += gamma;
                    eff_skey += delta * gamma;
                    eff_skey += gamma;
                }
                Output::EscrowOutput(o) => {
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

        // gamma adjustment == \sum \gamma_j for j in txouts
        tx_gamma -= outputs_gamma;
        eff_skey -= outputs_gamma;

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
            gamma: tx_gamma,
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
        //     pedersen_commitment_diff = \sum C_i - \sum C_o - fee * A
        //
        // Calculate `P_eff` to validate transaction's signature:
        //
        //     P_eff = pedersen_commitment_diff + \sum P_i
        //

        let mut pedersen_commitment_diff = ECp::inf();

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.body.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(BlockchainError::DuplicateTransactionInput(*txin_hash).into());
            }
            match txin {
                Output::PaymentOutput(o) => {
                    pedersen_commitment_diff += Pt::decompress(o.proof.vcmt)?;
                }
                Output::DataOutput(o) => {
                    pedersen_commitment_diff += Pt::decompress(o.vcmt)?;
                }
                Output::EscrowOutput(o) => {
                    pedersen_commitment_diff += fee_a(o.amount);
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
                    pedersen_commitment_diff -= Pt::decompress(o.proof.vcmt)?;
                }
                Output::DataOutput(o) => {
                    pedersen_commitment_diff -= Pt::decompress(o.vcmt)?;
                }
                Output::EscrowOutput(o) => {
                    if o.amount <= 0 {
                        return Err(BlockchainError::InvalidStake.into());
                    }
                    pedersen_commitment_diff -= fee_a(o.amount);
                }
            };
        }
        drop(txouts_set);

        // -fee * A
        pedersen_commitment_diff -= fee_a(self.body.fee);

        // Check the monetary balance
        if pedersen_commitment_diff != self.body.gamma * (*G) {
            return Err(BlockchainError::InvalidTransactionBalance.into());
        }

        // Create public key and check signature
        let mut eff_pkey = pedersen_commitment_diff;
        // +\sum{P_i} for i in txins
        for txin in inputs.iter() {
            let recipient = match txin {
                Output::PaymentOutput(o) => o.recipient,
                Output::DataOutput(o) => o.recipient,
                Output::EscrowOutput(o) => o.recipient,
            };
            let recipient: Pt = recipient.into();
            let recipient: ECp = Pt::decompress(recipient)?;
            eff_pkey += recipient;
        }
        let eff_pkey: PublicKey = eff_pkey.into();
        let tx_hash = Hash::digest(&self.body);

        // Check signature
        match validate_sig(&tx_hash, &self.sig, &eff_pkey)? {
            true => Ok(()),
            false => Err(BlockchainError::InvalidTransactionSignature.into()),
        }
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

    use chrono::Utc;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::pbc::secure;

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
        let tx = Transaction::new(&skey1, &inputs1, &[output_invalid1], outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs1) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionBalance => {}
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
        let input = Output::new_escrow(timestamp, &skey0, &pkey1, &secure_pkey1, amount)
            .expect("keys are valid");
        let inputs = [input];
        let (output, outputs_gamma) =
            Output::new_payment(timestamp, &skey1, &pkey1, amount - fee).expect("keys are valid");
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs).expect("tx is valid");

        //
        // Escrow as an output.
        //
        let (input, _inputs_gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        let inputs = [input];
        let output = Output::new_escrow(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
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
        let mut output = EscrowOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
            .expect("keys are valid");
        output.amount = amount - fee - 1;
        let output = Output::EscrowOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidTransactionBalance => {}
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
        let mut output = EscrowOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount - fee)
            .expect("keys are valid");
        output.amount = 0;
        let output = Output::EscrowOutput(output);
        let outputs_gamma = Fr::zero();
        let tx = Transaction::new(&skey1, &inputs, &[output], outputs_gamma, fee)
            .expect("keys are valid");
        match tx.validate(&inputs) {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidStake => {}
                _ => panic!(),
            },
            _ => panic!(),
        };
    }
}

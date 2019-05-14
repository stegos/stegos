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
use stegos_crypto::curve1174::cpt::{
    sign_hash, sign_hash_with_kval, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

/// PaymentTransaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// List of inputs.
    pub txins: Vec<Hash>,
    /// List of outputs.
    pub txouts: Vec<Output>,
    /// Sum of gamma adjustment for txins minus sum of gamma adjustment for outs.
    pub gamma: Fr,
    /// Fee.
    pub fee: i64,
    /// Transaction signature.
    pub sig: SchnorrSig,
}

impl Hashable for Transaction {
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

impl Transaction {
    pub fn dum() -> Self {
        Transaction {
            txins: Vec::new(),
            txouts: Vec::new(),
            gamma: Fr::zero(),
            fee: 0,
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
                Output::PublicPaymentOutput(_) => {}
                Output::StakeOutput(_o) => {}
            }
            let hash = Hasher::digest(txin);
            txins.push(hash);
        }

        // gamma_adj == \sum(gamma_in) - \sum(gamma_out)
        gamma_adj -= outputs_gamma;

        // Create a transaction body and calculate the hash.
        let mut tx = Transaction {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj,
            fee,
            sig: SchnorrSig::new(),
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&tx);
        let eff_skey: SecretKey = eff_skey.into();
        tx.sig = sign_hash(&tx_hash, &eff_skey);

        Ok(tx)
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
            sum_pkey += txin.recipient_pkey()?;
        }

        // Create a transaction body and calculate the hash.
        let mut tx = Transaction {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj.clone(),
            fee: total_fee,
            sig: SchnorrSig::new(),
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&tx);
        tx.sig = sign_hash_with_kval(&tx_hash, &skey, k_val, sum_cap_k, &sum_pkey);

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

        for _ in 0..input_count {
            let (input, _gamma) = Output::new_payment(&pkey, input_amount).expect("keys are valid");
            inputs.push(input);
        }

        let mut outputs_gamma: Fr = Fr::zero();
        for _ in 0..output_count {
            let (output, gamma) =
                Output::new_payment(&pkey, output_amount).expect("keys are valid");
            outputs.push(output);
            outputs_gamma += gamma;
        }

        match Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee) {
            Err(e) => Err(e),
            Ok(tx) => Ok((tx, inputs, outputs)),
        }
    }
}

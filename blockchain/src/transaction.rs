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
use stegos_crypto::curve1174::cpt::{
    sign_hash, validate_sig, Pt, PublicKey, SchnorrSig, SecretKey,
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
    /// * `skey` - Sender's secret key
    /// * `inputs` - UXTO to spent
    /// * `outputs` - UXTO to create
    /// * `adjustment` - gamma adjustment for outputs
    /// * `fee` - Total Fee
    ///
    pub fn new(
        skey: &SecretKey,
        inputs: &[Output],
        outputs: &[Output],
        adjustment: Fr,
        fee: i64,
    ) -> Result<Self, Error> {
        // TODO: fee is not used yet

        //
        // Compute S_eff = N * S_M + \sum{\delta_i} + \sum{\gamma_i} - \sum{gamma_j},
        // where i in txins, j in txouts
        //

        let skey_fr: Fr = (*skey).into();
        let mut eff_skey: Fr = skey_fr * (inputs.len() as i64); // N * s_M

        let mut tx_gamma: Fr = Fr::zero();
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut txouts: Vec<Output> = Vec::with_capacity(outputs.len());

        for txin in inputs {
            let (delta, gamma, _amount) = txin.decrypt_payload(skey)?;
            let hash = Hasher::digest(txin);

            txins.push(hash);

            tx_gamma += gamma;
            eff_skey += delta;
            eff_skey += gamma;
        }

        // gamma adjustment == \sum \gamma_j for j in txouts
        tx_gamma -= adjustment;
        eff_skey -= adjustment;

        // Clone created UTXOs
        for txout in outputs {
            txouts.push(txout.clone());
        }

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

    /// Validate transaction.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.txins, in the same order as in self.body.txins.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<(), Error> {
        //
        // Calculate P_eff = \sum P_i + \sum C_i + \sum C_j - fee, where i in txins, j in txouts
        //

        let mut eff_pkey = ECp::inf();

        // \sum {P_i} + \sum{C_i} for i in txins
        for (txin_hash, txin) in self.body.txins.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);

            let pedersen_commitment: Pt = txin.proof.pedersen_commitment();
            let pedersen_commitment: ECp = Pt::decompress(pedersen_commitment)?;
            let recipient: Pt = txin.recipient.into();
            let recipient: ECp = Pt::decompress(recipient)?;
            eff_pkey += recipient;
            eff_pkey += pedersen_commitment;
        }

        // -\sum{C_j} for j in txouts
        for txout in &self.body.txouts {
            let pedersen_commitment: Pt = txout.proof.pedersen_commitment();
            let pedersen_commitment: ECp = Pt::decompress(pedersen_commitment)?;
            eff_pkey -= pedersen_commitment;
            // TODO: add bullet proof validation
        }

        // TODO: add fee

        // Create public key and check signature
        let eff_pkey: PublicKey = eff_pkey.into();
        let tx_hash = Hash::digest(&self.body);

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

    /// Check transaction signing and validation.
    #[test]
    pub fn create_validate() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _delta0) =
            Output::new(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output1, delta1) =
            Output::new(timestamp, &skey1, &pkey2, amount).expect("keys are valid");
        let tx =
            Transaction::new(&skey1, &inputs1, &[output1], delta1, fee).expect("keys are valid");

        // Validation
        tx.validate(&inputs1).expect("keys are valid");
    }
}

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

use crate::error::TransactionError;
use crate::output::*;
use failure::Error;
use stegos_crypto::curve1174::cpt::{
    sign_hash, sign_hash_with_kval, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::sign_hash as network_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as NetworkPublicKey;
use stegos_crypto::pbc::secure::SecretKey as NetworkSecretKey;
use stegos_crypto::pbc::secure::Signature as BlsSignature;

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

/// PaymentTransaction.
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

/// Transaction body.
#[derive(Clone, Debug)]
pub struct RestakeTransactionBody {
    /// List of inputs.
    pub txins: Vec<Hash>,
    /// List of outputs.
    pub txouts: Vec<Output>,
}

impl Hashable for RestakeTransactionBody {
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
    }
}

#[derive(Clone, Debug)]
pub struct RestakeTransaction {
    // Transaction body.
    pub body: RestakeTransactionBody,
    // Validator public key
    pub sig: BlsSignature,
}

impl Hashable for RestakeTransaction {
    fn hash(&self, state: &mut Hasher) {
        self.body.hash(state);
    }
}

#[derive(Clone, Debug)]
pub enum XTransaction {
    Transaction(Transaction),
    RestakeTransaction(RestakeTransaction),
}

impl RestakeTransaction {
    pub fn new(
        inputs: &[Output],
        outputs: &[Output],
        pkey: &NetworkPublicKey,
        skey: &NetworkSecretKey,
    ) -> Result<RestakeTransaction, Error> {
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut inp_amt = 0;
        let mut owner = None;
        for txin in inputs {
            txin.validate()?;
            match txin {
                Output::PaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingInput.into());
                }
                Output::PublicPaymentOutput(_) => {}
                Output::StakeOutput(o) => {
                    inp_amt += o.amount;
                    if *pkey != o.validator {
                        return Err(TransactionError::RestakingValidatorKeyMismatch.into());
                    }
                    match owner {
                        None => {
                            owner = Some(o.recipient_pkey()?);
                        }
                        Some(owner_ecp) => {
                            if owner_ecp != o.recipient_pkey()? {
                                return Err(TransactionError::MixedRestakingOwners.into());
                            }
                        }
                    }
                    let hash = Hasher::digest(txin);
                    txins.push(hash);
                }
            }
        }
        let owner = match owner {
            Some(o) => o,
            None => {
                return Err(TransactionError::NoRestakingTxins.into());
            }
        };
        let mut out_amt = 0;
        let mut new_owner = None;
        for txout in outputs {
            txout.validate()?;
            match txout {
                Output::PaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingOutput.into())
                }
                Output::PublicPaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingInput.into())
                }
                Output::StakeOutput(o) => {
                    if o.recipient_pkey()? != owner {
                        return Err(TransactionError::MixedRestakingOwners.into());
                    }
                    match new_owner {
                        None => {
                            new_owner = Some(o.validator);
                        }
                        Some(no) => {
                            if no != o.validator {
                                return Err(TransactionError::MixedTxoutValidators.into());
                            }
                        }
                    }
                    out_amt += o.amount;
                }
            }
        }
        if out_amt != inp_amt {
            return Err(TransactionError::ImbalancedRestaking.into());
        };
        let body = RestakeTransactionBody {
            txins,
            txouts: outputs.to_vec(),
        };
        let h = Hash::digest(&body);
        let sig = network_sign_hash(&h, skey);
        Ok(RestakeTransaction { body, sig })
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
        outputs_gamma: &Fr, // = sum(outputs.gamma)
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
        outputs_gamma: &Fr, // = sum(outputs.gamma)
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
            eff_skey += &Fr::from(skey);
            match txin {
                Output::PaymentOutput(o) => {
                    let payload = o.decrypt_payload(skey)?;
                    gamma_adj += &payload.gamma;
                    eff_skey += &payload.delta * &payload.gamma;
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
        let body = TransactionBody {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj,
            fee,
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&body);
        let eff_skey: SecretKey = (&eff_skey).into();
        let sig = sign_hash(&tx_hash, &eff_skey);

        // Create signed transaction.
        let tx = Transaction { body, sig };
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
        k_val: &Fr,
        sum_cap_k: &ECp,
        inputs: &[Output],
        outputs: &[Output],
        gamma_adj: &Fr,
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
        let body = TransactionBody {
            txins,
            txouts: outputs.to_vec(),
            gamma: gamma_adj.clone(),
            fee: total_fee,
        };

        // Create an effective private key and sign transaction.
        let tx_hash = Hasher::digest(&body);
        let sig = sign_hash_with_kval(&tx_hash, &skey, &k_val, sum_cap_k, &sum_pkey);

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

        for _ in 0..input_count {
            let (input, _gamma) = Output::new_payment(&pkey, input_amount).expect("keys are valid");
            inputs.push(input);
        }

        let mut outputs_gamma: Fr = Fr::zero();
        for _ in 0..output_count {
            let (output, gamma) =
                Output::new_payment(&pkey, output_amount).expect("keys are valid");
            outputs.push(output);
            outputs_gamma += &gamma;
        }

        match Transaction::new(&skey, &inputs, &outputs, &outputs_gamma, fee) {
            Err(e) => Err(e),
            Ok(tx) => Ok((tx, inputs, outputs)),
        }
    }
}

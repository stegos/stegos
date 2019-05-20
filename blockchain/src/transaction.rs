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

use crate::error::*;
use crate::output::*;
use failure::Error;
use stegos_crypto::curve1174::{
    sign_hash, sign_hash_with_kval, ECp, Fr, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

//--------------------------------------------------------------------------------------------------
// Coinbase Transaction.
//--------------------------------------------------------------------------------------------------

/// Coinbase Transaction.
#[derive(Debug, Clone)]
pub struct CoinbaseTransaction {
    /// Block reward.
    pub block_reward: i64,

    /// Sum of fees from all block transactions.
    pub block_fee: i64,

    /// Minus sum of gamma adjustments in outputs.
    pub gamma: Fr,

    /// Coinbase UTXOs.
    pub txouts: Vec<Output>,
}

impl Default for CoinbaseTransaction {
    fn default() -> Self {
        CoinbaseTransaction {
            block_reward: 0,
            block_fee: 0,
            gamma: Fr::zero(),
            txouts: Vec::new(),
        }
    }
}

impl Hashable for CoinbaseTransaction {
    fn hash(&self, state: &mut Hasher) {
        self.block_reward.hash(state);
        self.block_fee.hash(state);
        self.gamma.hash(state);
        let outputs_count: u64 = self.txouts.len() as u64;
        outputs_count.hash(state);
        for output in &self.txouts {
            let output_hash = Hash::digest(&output);
            output_hash.hash(state);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Payment Transaction.
//--------------------------------------------------------------------------------------------------

/// PaymentTransaction.
#[derive(Clone, Debug)]
pub struct PaymentTransaction {
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

impl Hashable for PaymentTransaction {
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

impl PaymentTransaction {
    pub fn dum() -> Self {
        PaymentTransaction {
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
        let mut tx = PaymentTransaction {
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
        let mut tx = PaymentTransaction {
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
    ) -> Result<(PaymentTransaction, Vec<Output>, Vec<Output>), Error> {
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

        match PaymentTransaction::new(&skey, &inputs, &outputs, outputs_gamma, fee) {
            Err(e) => Err(e),
            Ok(tx) => Ok((tx, inputs, outputs)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Restake Transaction.
//--------------------------------------------------------------------------------------------------

/// RestakeTransaction.
#[derive(Clone, Debug)]
pub struct RestakeTransaction {
    /// List of inputs.
    pub txins: Vec<Hash>,
    /// List of outputs.
    pub txouts: Vec<Output>,
    /// Transaction signature.
    pub sig: pbc::Signature,
}

impl Hashable for RestakeTransaction {
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

impl RestakeTransaction {
    /// Create a new transaction.
    ///
    /// # Arguments
    ///
    /// * `skey` - Validator's secret key
    /// * `pkey` - Validator's public key
    /// * `inputs` - UXTO to spent
    /// * `outputs` - UXTO to create
    ///
    pub fn new(
        skey: &pbc::SecretKey,
        pkey: &pbc::PublicKey,
        inputs: &[Output],
        outputs: &[Output],
    ) -> Result<Self, Error> {
        let tx = Self::unchecked(skey, pkey, inputs, outputs)?;
        Ok(tx)
    }

    /// Same as new(), but without checks and assertions.
    pub fn unchecked(
        skey: &pbc::SecretKey,
        pkey: &pbc::PublicKey,
        inputs: &[Output],
        outputs: &[Output],
    ) -> Result<Self, Error> {
        let mut txins: Vec<Hash> = Vec::with_capacity(inputs.len());
        let mut inp_amt = 0;
        let mut owner = None;
        let htx = Hash::digest("");
        for txin in inputs {
            txin.validate()?;
            let h = Hash::digest(&txin);
            match txin {
                Output::PaymentOutput(_) | Output::PublicPaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingInput(htx, h).into());
                }
                Output::StakeOutput(o) => {
                    inp_amt += o.amount;
                    if *pkey != o.validator {
                        return Err(TransactionError::RestakingValidatorKeyMismatch(htx, h).into());
                    }
                    match owner {
                        None => {
                            owner = Some(txin.recipient_pkey()?);
                        }
                        Some(owner_ecp) => {
                            if owner_ecp != txin.recipient_pkey()? {
                                return Err(TransactionError::MixedRestakingOwners(htx, h).into());
                            }
                        }
                    }
                    txins.push(h);
                }
            }
        }
        let owner = match owner {
            Some(o) => o,
            None => {
                return Err(TransactionError::NoRestakingTxins(htx).into());
            }
        };
        let mut out_amt = 0;
        let mut new_validator = None;
        for txout in outputs {
            txout.validate()?;
            let h = Hash::digest(txout);
            match txout {
                Output::PaymentOutput(_) | Output::PublicPaymentOutput(_) => {
                    return Err(TransactionError::InvalidRestakingOutput(htx, h).into())
                }
                Output::StakeOutput(o) => {
                    if txout.recipient_pkey()? != owner {
                        return Err(TransactionError::MixedRestakingOwners(htx, h).into());
                    }
                    match new_validator {
                        None => {
                            new_validator = Some(o.validator);
                        }
                        Some(nv) => {
                            if nv != o.validator {
                                return Err(TransactionError::MixedTxoutValidators(htx, h).into());
                            }
                        }
                    }
                    out_amt += o.amount;
                }
            }
        }
        if out_amt != inp_amt {
            return Err(TransactionError::ImbalancedRestaking(htx).into());
        };
        let mut tx = RestakeTransaction {
            txins,
            txouts: outputs.to_vec(),
            sig: pbc::Signature::new(),
        };
        let h = Hash::digest(&tx);
        tx.sig = pbc::sign_hash(&h, skey);
        Ok(tx)
    }

    /// Used only for tests.
    //#[cfg(test)]
    #[doc(hidden)]
    pub fn new_test(
        pkey: PublicKey,
        nskey: &pbc::SecretKey,
        npkey: &pbc::PublicKey,
        input_amount: i64,
        input_count: usize,
        output_amount: i64,
        output_count: usize,
    ) -> Result<(RestakeTransaction, Vec<Output>, Vec<Output>), Error> {
        let mut inputs: Vec<Output> = Vec::with_capacity(input_count);
        let mut outputs: Vec<Output> = Vec::with_capacity(output_count);

        for _ in 0..input_count {
            let input =
                Output::new_stake(&pkey, &nskey, &npkey, input_amount).expect("keys are valid");
            inputs.push(input);
        }

        for _ in 0..output_count {
            let output =
                Output::new_stake(&pkey, &nskey, &npkey, output_amount).expect("keys are valid");
            outputs.push(output);
        }

        match RestakeTransaction::new(&nskey, &npkey, &inputs, &outputs) {
            Err(e) => Err(e),
            Ok(tx) => Ok((tx, inputs, outputs)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Transaction (enum).
//--------------------------------------------------------------------------------------------------

/// Transaction.
#[derive(Clone, Debug)]
pub enum Transaction {
    CoinbaseTransaction(CoinbaseTransaction),
    PaymentTransaction(PaymentTransaction),
    RestakeTransaction(RestakeTransaction),
}

impl Transaction {
    #[inline]
    pub fn fee(&self) -> i64 {
        match self {
            Transaction::CoinbaseTransaction(_tx) => 0,
            Transaction::PaymentTransaction(tx) => tx.fee,
            Transaction::RestakeTransaction(_tx) => 0,
        }
    }

    #[inline]
    pub fn txins(&self) -> &[Hash] {
        match self {
            Transaction::CoinbaseTransaction(_tx) => &[],
            Transaction::PaymentTransaction(tx) => &tx.txins,
            Transaction::RestakeTransaction(tx) => &tx.txins,
        }
    }

    #[inline]
    pub fn txouts(&self) -> &[Output] {
        match self {
            Transaction::CoinbaseTransaction(tx) => &tx.txouts,
            Transaction::PaymentTransaction(tx) => &tx.txouts,
            Transaction::RestakeTransaction(tx) => &tx.txouts,
        }
    }
}

impl Hashable for Transaction {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Transaction::CoinbaseTransaction(tx) => tx.hash(state),
            Transaction::PaymentTransaction(tx) => tx.hash(state),
            Transaction::RestakeTransaction(tx) => tx.hash(state),
        }
    }
}

impl From<CoinbaseTransaction> for Transaction {
    fn from(tx: CoinbaseTransaction) -> Self {
        Transaction::CoinbaseTransaction(tx)
    }
}

impl From<PaymentTransaction> for Transaction {
    fn from(tx: PaymentTransaction) -> Self {
        Transaction::PaymentTransaction(tx)
    }
}

impl From<RestakeTransaction> for Transaction {
    fn from(tx: RestakeTransaction) -> Transaction {
        Transaction::RestakeTransaction(tx)
    }
}

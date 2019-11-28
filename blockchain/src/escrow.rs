//! Node - Escrow.

//
// MIT License
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

use crate::error::BlockchainError;
use crate::mvcc::MultiVersionedMap;
use crate::output::Output;
use log::*;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub(crate) struct EscrowKey {
    pub(crate) validator_pkey: pbc::PublicKey,
    pub(crate) output_hash: Hash,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EscrowValue {
    pub(crate) account_pkey: scc::PublicKey,
    pub(crate) active_until_epoch: u64,
    pub(crate) amount: i64,
}

use crate::LSN;
pub(crate) type EscrowMap = MultiVersionedMap<EscrowKey, EscrowValue, LSN>;

#[derive(Debug, Clone)]
pub struct Escrow {
    /// Stakes.
    pub(crate) escrow: EscrowMap,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EscrowInfo {
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub network_pkey: pbc::PublicKey,
    pub active_stake: i64,
    pub expired_stake: i64,
    pub stakes: Vec<StakeInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StakeInfo {
    pub output_hash: Hash,
    pub account_pkey: scc::PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_until_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    pub amount: i64,
}

impl Escrow {
    ///
    /// Create a new escrow.
    pub(crate) fn new() -> Self {
        let set = EscrowMap::new();
        Escrow { escrow: set }
    }

    ///
    /// Stake money into escrow.
    ///
    pub(crate) fn stake(
        &mut self,
        lsn: LSN,
        validator_pkey: pbc::PublicKey,
        account_pkey: scc::PublicKey,
        output_hash: Hash,
        epoch: u64,
        stakes_epoch: u64,
        amount: i64,
    ) {
        let active_until_epoch = epoch + stakes_epoch;
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };
        let value = EscrowValue {
            account_pkey,
            active_until_epoch,
            amount,
        };

        if let Some(v) = self.escrow.insert(lsn, key, value) {
            panic!(
                "Stake already exists: validator={}, utxo={}, amount={}",
                &validator_pkey, &output_hash, v.amount
            );
        }

        let (active_balance, expired_balance) = self.validator_balance(&validator_pkey, epoch);
        debug!(
            "Staked: utxo={}, validator={}, amount={}, active_until_epoch={}, active_balance={}, expired_balance={}",
            output_hash, &validator_pkey, amount, active_until_epoch, active_balance, expired_balance
        );
    }

    ///
    /// Unstake money from the escrow.
    ///
    pub(crate) fn unstake(
        &mut self,
        lsn: LSN,
        validator_pkey: pbc::PublicKey,
        output_hash: Hash,
        epoch: u64,
    ) {
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };
        let val = self.escrow.remove(lsn, &key).expect("stake exists");

        let (active_balance, expired_balance) = self.validator_balance(&validator_pkey, epoch);
        debug!(
            "Unstaked: utxo={}, validator={}, amount={}, active_balance={}, expired_balance={}",
            output_hash, validator_pkey, val.amount, active_balance, expired_balance
        );
    }

    ///
    /// Iterate over stakes of specified validator.
    ///
    pub fn iter_validator_stakes(
        &self,
        validator_pkey: &pbc::PublicKey,
    ) -> impl Iterator<Item = (&Hash, i64, &scc::PublicKey, u64)> {
        let (hash_min, hash_max) = Hash::bounds();
        let key_min = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_min,
        };
        let key_max = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_max,
        };

        self.escrow.range(&key_min..=&key_max).map(|(key, value)| {
            (
                &key.output_hash,
                value.amount,
                &value.account_pkey,
                value.active_until_epoch,
            )
        })
    }

    ///
    /// Get staked value for validator.
    ///
    /// Returns (active_balance, expired_balance) stake.
    ///
    pub fn validator_balance(&self, validator_pkey: &pbc::PublicKey, epoch: u64) -> (i64, i64) {
        self.iter_validator_stakes(validator_pkey).fold(
            (0i64, 0i64),
            |(active_balance, expired_balance), (_, amount, _, active_until_epoch)| {
                if active_until_epoch >= epoch {
                    (active_balance + amount, expired_balance)
                } else {
                    (active_balance, expired_balance + amount)
                }
            },
        )
    }

    ///
    /// Return an account key by network key.
    ///
    pub fn account_by_network_key(
        &self,
        validator_pkey: &pbc::PublicKey,
    ) -> Option<scc::PublicKey> {
        self.iter_validator_stakes(&validator_pkey)
            .next()
            .map(|(_hash, _amount, account_pkey, _active_until_epoch)| account_pkey.clone())
    }

    ///
    /// Update prometheus metrics.
    ///
    pub(crate) fn get_stakers(&self, epoch: u64) -> BTreeMap<pbc::PublicKey, i64> {
        let mut stakes: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
        for (k, v) in self.escrow.iter() {
            if v.active_until_epoch < epoch {
                // Skip expired stakes.
                continue;
            }
            let entry = stakes.entry(k.validator_pkey).or_insert(0);
            *entry += v.amount;
        }
        stakes
    }

    ///
    /// Get all staked values of all validators.
    /// Filter out stakers with stake lower than min_stake_amount.
    ///
    pub fn get_stakers_majority(
        &self,
        epoch: u64,
        min_stake_amount: i64,
    ) -> Vec<(pbc::PublicKey, i64)> {
        let mut stakes: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
        for (k, v) in self.escrow.iter() {
            if v.active_until_epoch < epoch {
                // Skip expired stakes.
                continue;
            }
            let entry = stakes.entry(k.validator_pkey).or_insert(0);
            *entry += v.amount;
        }

        // filter out validators with low stake.
        stakes
            .into_iter()
            .filter(|(_, amount)| *amount >= min_stake_amount)
            .collect()
    }

    /// Validate that staker didn't try to spent locked stake.
    /// Validate that staker has only one key.
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.txins, in the same order as in self.txins.
    ///
    pub fn validate_stakes<'a, OutputIter>(
        &self,
        inputs: OutputIter,
        outputs: OutputIter,
        epoch: u64,
    ) -> Result<(), BlockchainError>
    where
        OutputIter: Iterator<Item = &'a Output>,
    {
        let mut staking_balance: HashMap<pbc::PublicKey, i64> = HashMap::new();
        for input in inputs {
            match input {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake -= o.amount;
                }
            }
        }
        for output in outputs {
            match output {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    if let Some(account_pkey) = self.account_by_network_key(&o.validator) {
                        if account_pkey != o.recipient {
                            let utxo_hash = Hash::digest(output);
                            return Err(BlockchainError::StakeOutputWithDifferentAccountKey(
                                account_pkey,
                                o.recipient,
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

        for (validator_pkey, balance) in &staking_balance {
            let (active_balance, expired_balance) = self.validator_balance(validator_pkey, epoch);
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

    /// Returns an object that represent printable part of the state.
    pub fn info(&self, epoch: u64) -> EscrowInfo {
        let mut validators: HashMap<pbc::PublicKey, ValidatorInfo> = HashMap::new();
        for (k, v) in self.escrow.iter() {
            let entry = validators
                .entry(k.validator_pkey.clone())
                .or_insert(ValidatorInfo {
                    network_pkey: k.validator_pkey.clone(),
                    stakes: Default::default(),
                    active_stake: Default::default(),
                    expired_stake: Default::default(),
                });
            let is_active = v.active_until_epoch >= epoch;
            let stake = StakeInfo {
                output_hash: k.output_hash,
                account_pkey: v.account_pkey,
                active_until_epoch: v.active_until_epoch.into(),
                is_active: is_active.into(),
                amount: v.amount,
            };
            (*entry).stakes.push(stake);
            if is_active {
                (*entry).active_stake += v.amount;
            } else {
                (*entry).expired_stake += v.amount;
            }
        }
        let mut validators: Vec<ValidatorInfo> = validators.into_iter().map(|(_k, v)| v).collect();
        validators.sort_by_key(|x| -x.active_stake);
        EscrowInfo { validators }
    }

    #[inline]
    pub(crate) fn current_lsn(&self) -> LSN {
        self.escrow.current_lsn()
    }

    #[inline]
    pub(crate) fn checkpoint(&mut self) -> BTreeMap<EscrowKey, Option<EscrowValue>> {
        self.escrow.checkpoint()
    }

    #[inline]
    pub(crate) fn rollback_to_lsn(&mut self, to_lsn: LSN) {
        self.escrow.rollback_to_lsn(to_lsn);
    }
}

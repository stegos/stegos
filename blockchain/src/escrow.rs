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

use chrono::NaiveDateTime;
use failure::Fail;
use log::*;
use serde_derive::Serialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct EscrowKey {
    validator_pkey: secure::PublicKey,
    output_hash: Hash,
}

struct EscrowValue {
    bonding_timestamp: u64,
    amount: i64,
}

type EscrowMap = BTreeMap<EscrowKey, EscrowValue>;

pub struct Escrow {
    /// Stakes.
    escrow: EscrowMap,
}

#[derive(Serialize, Clone, Debug)]
pub struct EscrowInfo {
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ValidatorInfo {
    pub network_pkey: String,
    pub total: i64,
    pub stakes: Vec<StakeInfo>,
}

#[derive(Serialize, Clone, Debug)]
pub struct StakeInfo {
    pub output_hash: String,
    pub locked_until: String,
    pub amount: i64,
}

impl Escrow {
    ///
    /// Create a new escrow.
    pub fn new() -> Self {
        let set = EscrowMap::new();
        Escrow { escrow: set }
    }

    ///
    /// Stake money into escrow.
    ///
    pub fn stake(
        &mut self,
        validator_pkey: secure::PublicKey,
        output_hash: Hash,
        bonding_timestamp: u64,
        amount: i64,
    ) {
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };
        let value = EscrowValue {
            bonding_timestamp,
            amount,
        };

        if let Some(v) = self.escrow.insert(key, value) {
            panic!(
                "Stake already exists: validator={}, utxo={}, amount={}",
                &validator_pkey, &output_hash, v.amount
            );
        }

        let total = self.get(&validator_pkey);
        info!(
            "Stake: validator={}, staked={}, total={}",
            &validator_pkey, amount, total
        );
    }

    ///
    /// Check that the stake is not locked.
    ///
    /// # Panics
    ///
    /// Panics if the stake doesn't exist.
    ///
    pub fn validate_unstake(
        &self,
        validator_pkey: &secure::PublicKey,
        output_hash: &Hash,
        timestamp: u64,
    ) -> Result<(), EscrowError> {
        let key = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: output_hash.clone(),
        };

        // The stake must exists.
        let val = self.escrow.get(&key).expect("stake exists");

        // Check bonding time.
        if val.bonding_timestamp >= timestamp {
            return Err(EscrowError::StakeIsLocked(
                key.validator_pkey,
                key.output_hash,
                val.bonding_timestamp,
                timestamp,
            ));
        }

        Ok(())
    }

    ///
    /// Unstake money from the escrow.
    ///
    pub fn unstake(
        &mut self,
        validator_pkey: secure::PublicKey,
        output_hash: Hash,
        timestamp: u64,
    ) {
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };

        let val = self.escrow.remove(&key).expect("stake exists");
        if val.bonding_timestamp >= timestamp {
            panic!("stake is locked");
        }

        let total = self.get(&validator_pkey);
        info!(
            "Unstake: validator={}, unstaked={}, total={}",
            validator_pkey, val.amount, total
        );
    }

    ///
    /// Get staked value for validator.
    ///
    pub fn get(&self, validator_pkey: &secure::PublicKey) -> i64 {
        let (hash_min, hash_max) = Hash::bounds();
        let key_min = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_min,
        };
        let key_max = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_max,
        };

        let mut stake: i64 = 0;
        for (key, value) in self.escrow.range(&key_min..=&key_max) {
            assert_eq!(&key.validator_pkey, validator_pkey);
            stake += value.amount;
        }

        stake
    }

    ///
    /// Get staked values for specified validators.
    ///
    pub fn multiget<'a, I>(&self, validators: I) -> BTreeMap<secure::PublicKey, i64>
    where
        I: IntoIterator<Item = &'a secure::PublicKey>,
    {
        // TODO: optimize using two iterator.
        let mut stakes = BTreeMap::<secure::PublicKey, i64>::new();
        for validator in validators {
            let stake = self.get(validator);
            stakes.insert(validator.clone(), stake);
        }
        stakes
    }

    ///
    /// Get all staked values of all validators.
    /// Filter out stakers with stake lower than min_stake_amount.
    ///
    pub fn get_stakers_majority(&self, min_stake_amount: i64) -> Vec<(secure::PublicKey, i64)> {
        let mut stakes: BTreeMap<secure::PublicKey, i64> = BTreeMap::new();
        for (k, v) in self.escrow.iter() {
            let entry = stakes.entry(k.validator_pkey).or_insert(0);
            *entry += v.amount;
        }

        // filter out validators with low stake.
        stakes
            .into_iter()
            .filter(|(_, amount)| *amount >= min_stake_amount)
            .collect()
    }

    /// Returns an object that represent printable part of the state.
    pub fn info(&self) -> EscrowInfo {
        let mut validators: HashMap<String, ValidatorInfo> = HashMap::new();
        for (k, v) in self.escrow.iter() {
            let validator_pkey = format!("{}", &k.validator_pkey);
            let entry = validators
                .entry(validator_pkey.clone())
                .or_insert(Default::default());
            let locked_until = NaiveDateTime::from_timestamp(v.bonding_timestamp as i64, 0);
            let stake = StakeInfo {
                output_hash: format!("{}", &k.output_hash),
                locked_until: format!("{}", &locked_until),
                amount: v.amount,
            };
            (*entry).network_pkey = validator_pkey;
            (*entry).stakes.push(stake);
            (*entry).total += v.amount;
        }
        let mut validators: Vec<ValidatorInfo> = validators.into_iter().map(|(_k, v)| v).collect();
        validators.sort_by_key(|x| -x.total);
        EscrowInfo { validators }
    }
}

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum EscrowError {
    #[fail(
        display = "Stake is locked: validator={}, stake={}, bonding_time={}, current_time={}",
        _0, _1, _2, _3
    )]
    StakeIsLocked(secure::PublicKey, Hash, u64, u64),
}

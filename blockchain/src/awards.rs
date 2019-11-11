//
// Copyright (c) 2019 Stegos AG
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

// TODO: Choose difficulty.
use crate::metrics;
use log::{debug, info, trace};
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::mem;
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::PublicKey;
use stegos_crypto::utils::print_nbits;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status")]
#[serde(rename_all = "snake_case")]
pub enum ValidatorAwardState {
    /// Validator has failed at: epoch, offset.
    Failed { epoch: u64, offset: u32 },
    /// Validator is active.
    Active,
}

/// Current award state, and budget count.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Awards {
    pub budget: i64,
    // num of bits to be zero in VRF.
    pub difficulty: usize,
    pub validators_activity: BTreeMap<PublicKey, ValidatorAwardState>,
}

impl Awards {
    pub fn new(difficulty: usize) -> Awards {
        // difficulty should be less than hash size in bits.
        assert!(difficulty < mem::size_of::<Hash>() * 8);
        Awards {
            budget: 0,
            difficulty,
            validators_activity: BTreeMap::new(),
        }
    }

    pub fn validators_activivty(&self) -> &BTreeMap<PublicKey, ValidatorAwardState> {
        &self.validators_activity
    }

    pub fn budget(&self) -> i64 {
        self.budget
    }

    fn add_reward(&mut self, piece: i64) {
        assert!(piece > 0);
        self.budget += piece;
        debug!(
            "Adding reward to service awards budget: amount={}, total_budget={}",
            piece, self.budget
        );
    }

    /// Update reward state, set epoch activity.
    /// Add reward to service award budget.
    pub fn finalize_epoch<'a, I>(&mut self, reward: i64, epoch_activity: I)
    where
        I: IntoIterator<Item = (PublicKey, ValidatorAwardState)>,
    {
        let epoch_activity = epoch_activity.into_iter();

        self.add_reward(reward);
        for (validator, state) in epoch_activity {
            match self.validators_activity.get(&validator) {
                Some(ValidatorAwardState::Failed { epoch, offset }) => {
                    trace!(
                        "Found validator, that already failed his slot: epoch={}, offset={}",
                        epoch,
                        offset
                    );
                }
                _ => {
                    trace!(
                        "Set validator to state: validator={}, state={:?}",
                        validator,
                        state
                    );
                    self.validators_activity.insert(validator, state);
                }
            }
        }

        metrics::AWARD_VALIDATORS_COUNT.set(self.validators_activity.len() as i64);
        let failed_count = self
            .validators_activity
            .iter()
            .filter(|(_, s)| s != &&ValidatorAwardState::Active)
            .map(|(k, _)| k)
            .count();
        metrics::AWARD_FAILED_COUNT.set(failed_count as i64);
    }

    /// Checks if current random decide to pay award.
    /// Returns PublicKey of service award winner, with service award budget.
    /// Returns None if no winner yet.
    ///
    /// If this function returns winners PublicKey,
    /// then new service award budget would be set to zero.
    pub fn check_winners(&mut self, random: Hash) -> Option<(PublicKey, i64)> {
        if !chkbits(random.base_vector(), self.difficulty) {
            debug!(
                "Not lucky random in service award: difficulty={}, random_bytes={}",
                self.difficulty,
                print_nbits(random.base_vector(), self.difficulty).unwrap()
            );
            return None;
        }

        // after this point, validators_activity will be destroyed, and unusable for future usage.
        let array: Vec<_> = mem::replace(&mut self.validators_activity, BTreeMap::new())
            .into_iter()
            .filter(|(_, s)| s == &ValidatorAwardState::Active)
            .inspect(|k| trace!("Service awards participant = {:?}", k))
            .map(|(k, _)| k)
            .collect();

        if array.is_empty() {
            info!("No honest validators was found, for awarding.");
            return None;
        }
        let winner_num = crate::election::shrink_hash(random);
        let winner_num = winner_num.checked_abs().unwrap_or(0) as usize;
        let winner = winner_num % array.len();
        let winner_pk = array[winner];
        trace!(
            "Service award produce winner: num_validators={}, winner={}, winner_pk={}",
            array.len(),
            winner,
            winner_pk
        );
        Some((winner_pk, mem::replace(&mut self.budget, 0)))
    }
}

pub fn chkbits(h: &[u8], nbits: usize) -> bool {
    for i in 0..nbits {
        let byte = i / 8;
        let bit = i % 8;
        if 0 != (h[byte] & (1 << bit)) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;

    use stegos_crypto::scc;

    fn testing_keys() -> Vec<PublicKey> {
        vec![
            scc::make_random_keys().1,
            scc::make_random_keys().1,
            scc::make_random_keys().1,
            scc::make_random_keys().1,
        ]
    }

    /// Set first `difficulty` bits, of array to ones.
    fn winning_hash(seed: Hash, difficulty: usize) -> Hash {
        let num_bytes = (difficulty + 7) / 8;
        let mut array = seed.bits();
        for i in 0..num_bytes {
            array[i] = 0;
        }
        Hash::try_from_bytes(&array).unwrap()
    }

    /// Set first byte to zeros, its enough to loose in hashcash.
    fn loosing_hash(seed: Hash) -> Hash {
        let mut array = seed.bits();
        array[0] = 0xFF;
        Hash::try_from_bytes(&array).unwrap()
    }

    fn active_validators(awards: &Awards) -> usize {
        awards
            .validators_activity
            .iter()
            .filter(|v| *v.1 == ValidatorAwardState::Active)
            .count()
    }
    #[test]
    fn smoke_award() {
        let _ = simple_logger::init();
        let difficulty = 10;
        let keys = testing_keys();

        // make new epoch with active validators list.
        let first_epoch: BTreeMap<_, _> = keys
            .into_iter()
            .map(|k| (k, ValidatorAwardState::Active))
            .collect();
        let mut award = Awards::new(difficulty);

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());

        award.finalize_epoch(100, first_epoch.clone());

        assert_eq!(award.budget, 100);
        assert_eq!(award.validators_activity, first_epoch);

        // check that award pay out all budget.
        assert_eq!(
            award
                .check_winners(winning_hash(Hash::digest("seed"), difficulty))
                .unwrap()
                .1,
            100
        );
        // checks that state is cleared after selecting winner.

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());
    }

    // check that with loosing hash no award are triggered.
    #[test]
    fn smoke_test_negative() {
        let _ = simple_logger::init();
        let difficulty = 10;
        let keys = testing_keys();

        // make new epoch with active validators list.
        let first_epoch: BTreeMap<_, _> = keys
            .into_iter()
            .map(|k| (k, ValidatorAwardState::Active))
            .collect();
        let mut award = Awards::new(difficulty);

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());

        award.finalize_epoch(100, first_epoch.clone());

        assert_eq!(award.budget, 100);
        assert_eq!(award.validators_activity, first_epoch);

        assert!(award
            .check_winners(loosing_hash(Hash::digest("seed")))
            .is_none());
        // checks that state is not cleared after selecting winner.

        assert_eq!(award.budget, 100);
        assert_eq!(award.validators_activity, first_epoch);
    }

    // check that after triggering service award, without winner,
    // validators_activity vector is cleared, but budget is ok.
    #[test]
    fn check_no_active() {
        let _ = simple_logger::init();
        let difficulty = 10;
        let keys = testing_keys();

        // make new epoch with active validators list.
        let first_epoch: BTreeMap<_, _> = keys
            .into_iter()
            .map(|k| {
                (
                    k,
                    ValidatorAwardState::Failed {
                        epoch: 12,
                        offset: 12,
                    },
                )
            })
            .collect();
        let mut award = Awards::new(difficulty);

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());

        award.finalize_epoch(100, first_epoch.clone());

        assert_eq!(award.budget, 100);
        assert_eq!(award.validators_activity, first_epoch);

        assert!(award
            .check_winners(winning_hash(Hash::digest("seed"), difficulty))
            .is_none());
        // checks that state is not cleared after selecting winner.

        assert_eq!(award.budget, 100);
        assert_eq!(award.validators_activity, BTreeMap::new());
    }

    // check that after multiple rounds, budget is increased,
    // and failedat state is accumulated.
    #[test]
    fn checks_multiple_rounds() {
        let _ = simple_logger::init();
        let difficulty = 10;
        let keys = testing_keys();

        // make new epoch with active validators list.
        let first_epoch: BTreeMap<_, _> = keys
            .into_iter()
            .map(|k| (k, ValidatorAwardState::Active))
            .collect();
        let mut award = Awards::new(difficulty);

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());

        let mut old_budget = 0;
        let starting_len = first_epoch.len();
        for (n, (validator, _)) in first_epoch
            .clone()
            .into_iter()
            .enumerate()
            .take(starting_len - 1)
        {
            let mut new_epoch = first_epoch.clone();

            info!("N={}", n);
            new_epoch.insert(
                validator,
                ValidatorAwardState::Failed {
                    epoch: 12,
                    offset: 12,
                },
            );
            award.finalize_epoch(100, new_epoch.clone());

            old_budget += 100;
            assert_eq!(award.budget, old_budget);
            assert_eq!(active_validators(&award), starting_len - (n + 1));

            // check that award will not pay out budget.
            assert!(award
                .check_winners(loosing_hash(Hash::digest("seed")))
                .is_none());

            assert_eq!(award.budget, old_budget);
            assert_eq!(active_validators(&award), starting_len - (n + 1));
        }

        let winner = award
            .check_winners(winning_hash(Hash::digest("seed"), difficulty))
            .unwrap();

        // check that award pay out all budget.
        assert_eq!(winner.0, *first_epoch.iter().last().unwrap().0);

        // check that amaunt is equal to reward * epoch count.
        assert_eq!(winner.1, 100 * (first_epoch.len() as i64 - 1));

        assert_eq!(award.budget, 0);
        assert_eq!(award.validators_activity, BTreeMap::new());
    }
}

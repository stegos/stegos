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

//! Leader election and group formation algorithms and tests.

use crate::block::StakersGroup;
use log::error;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

/// User-friendly printable representation of state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ElectionInfo {
    pub epoch: u64,
    pub offset: u32,
    pub view_change: u32,
    pub slots_count: i64,
    pub current_leader: pbc::PublicKey,
    pub next_leader: pbc::PublicKey,
}

/// Result of election.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElectionResult {
    /// Initial random of election
    pub random: pbc::VRF,
    /// Count of retries, during creating new epoch.
    pub view_change: u32,
    /// List of Validators
    pub validators: StakersGroup,
    /// Facilitator of the transaction pool
    pub facilitator: pbc::PublicKey,
}

impl Default for ElectionResult {
    fn default() -> Self {
        let facilitator: pbc::PublicKey = pbc::G2::generator().into(); // some fake key
        let view_change = 0;
        let validators = Vec::new();
        let random = pbc::VRF {
            rand: Hash::digest("random"),
            proof: pbc::G1::zero(),
        };
        ElectionResult {
            facilitator,
            validators,
            view_change,
            random,
        }
    }
}

pub fn select_leader(validators: &StakersGroup, random: &Hash, view_change: u32) -> pbc::PublicKey {
    let random = generate_u64(*random, view_change);
    let leader_id = select_winner(validators.iter().map(|(_k, slots)| slots), random).unwrap();
    validators[leader_id].0
}

impl ElectionResult {
    pub fn select_leader(&self, view_change: u32) -> pbc::PublicKey {
        select_leader(&self.validators, &self.random.rand, view_change)
    }

    /// Returns true if peer is validator in current epoch.
    #[inline]
    pub fn is_validator(&self, peer: &pbc::PublicKey) -> bool {
        self.validators
            .iter()
            .find(|item| item.0 == *peer)
            .is_some()
    }
}

/// Choose random validator, based on `random_number`.
/// Accepts list of validators stakes consistently sorted on all participants,
/// Returns index of the validator which stake are won.
fn select_winner<'a, I>(stakers: I, random_number: i64) -> Option<usize>
where
    I: IntoIterator<Item = &'a i64>,
    <I as IntoIterator>::IntoIter: Clone,
{
    let stakers = stakers.into_iter();
    let random = random_number.checked_abs().unwrap_or(0);

    let sum_stakes: i64 = stakers.clone().sum();
    if sum_stakes == 0 {
        error!("Nobody place a stack, we can't choose a leader.");
        return None;
    }

    let need_stake = random % sum_stakes;

    let mut accumulator: i64 = 0;
    for (num, validator_stake) in stakers.enumerate() {
        assert!(
            *validator_stake >= 0,
            "Processing invalid validator stake < 0."
        );
        if accumulator + validator_stake > need_stake {
            return Some(num);
        }
        accumulator += validator_stake;
    }
    unreachable!("Validator should be found in loop.")
}

/// Choose numbers of slots, limited by `slot_count` out of active stakers list.
/// Stakers array should not be empty, and every staker should have stake more than 0.
/// Stakers array should contain unique PublicKey.
///
/// Returns array of validators slots, this array will contain pair of (PublicKey, slots_count).
/// Where PublicKey is unique among array network identifier of validators,
/// slots_count is a count of slots owned by specific validator.
pub fn select_validators_slots(
    mut stakers: StakersGroup,
    random: pbc::VRF,
    slot_count: i64,
) -> ElectionResult {
    assert!(!stakers.is_empty(), "Have stakes");
    assert!(slot_count > 0);
    // Sort the source list to get predictable result.
    // Does nothing if stakers were derived from Escrow.
    stakers.sort();
    // Using BTreeMap to keep order.
    let mut validators = BTreeMap::new();

    let seed = random.rand;
    for i in 0..slot_count {
        let rand = generate_u64(seed, i as u32);
        let index = select_winner(stakers.iter().map(|(_k, stake)| stake), rand).unwrap();

        let winner = stakers[index].0;

        // Increase slot counter of validator.
        *validators.entry(winner).or_insert(0) += 1;
    }
    // Convert Map -> Vec. Deterministically ordered.
    let validators: Vec<_> = validators.into_iter().collect();
    let facilitator = select_facilitator(&seed, &validators);
    ElectionResult {
        validators,
        random,
        view_change: 0,
        facilitator,
    }
}

pub fn select_facilitator(random: &Hash, validators: &StakersGroup) -> pbc::PublicKey {
    // generate special random for facilitator.
    let mut hasher = Hasher::new();
    random.hash(&mut hasher);
    "facilitator".hash(&mut hasher);
    let seed = hasher.result();
    let rand = shrink_hash(seed);
    let facilitator_id = select_winner(validators.iter().map(|(_k, slots)| slots), rand).unwrap();
    validators[facilitator_id].0.clone()
}

/// Mix seed hash with round value to produce new hash.
pub fn mix(random: Hash, round: u32) -> Hash {
    let mut hasher = Hasher::new();
    random.hash(&mut hasher);
    round.hash(&mut hasher);
    hasher.result()
}

/// Shrink hash to size of u64, internally takes 8 most significant bytes.
#[inline(always)]
pub fn shrink_hash(hash: Hash) -> i64 {
    let slice = hash.base_vector();
    let mut result = 0;
    for i in 0..8 {
        result |= (slice[8 - i] as i64) << (i * 8);
    }
    result
}

fn generate_u64(seed: Hash, index: u32) -> i64 {
    let new_random = mix(seed, index);
    shrink_hash(new_random)
}

#[cfg(test)]
mod test {
    use super::{select_validators_slots, select_winner};
    use std::collections::{HashMap, HashSet};

    use stegos_crypto::hash::Hash;
    use stegos_crypto::pbc;

    fn broken_random(nums: i64) -> impl Iterator<Item = i64> {
        (0..nums).into_iter()
    }

    /// If no one nodes found, nobody could be an leader.
    #[test]
    fn test_empty_validators() {
        let validators = vec![];

        assert!(select_winner(&validators, 0).is_none());
        assert!(select_winner(&validators, 2).is_none());
        assert!(select_winner(&validators, 5).is_none());
    }

    /// If all nodes didn't give any stakes algorithm should return None.
    #[test]
    fn test_empty_stakes() {
        let validators = vec![0, 0, 0, 0];
        // init 4 validators stakes

        assert!(select_winner(&validators, 0).is_none());
        assert!(select_winner(&validators, 2).is_none());
        assert!(select_winner(&validators, 5).is_none());
    }

    /// If only one man give a stake, make them new leader.
    #[test]
    fn test_only_one_rich() {
        let validators = vec![1, 0, 0, 0];

        assert_eq!(select_winner(&validators, 0), Some(0));
        assert_eq!(select_winner(&validators, 2), Some(0));
        assert_eq!(select_winner(&validators, 5), Some(0));
    }

    /// All validators should can be a leader.
    #[test]
    fn test_all_validators() {
        let validators = vec![1, 2, 3, 4];

        let mut leaders = HashSet::new();

        let random = broken_random(validators.len() as i64 * 50);

        for leader in random {
            leaders.insert(select_winner(&validators, leader).unwrap());
        }
        assert_eq!(leaders.len(), validators.len())
    }

    /// With same stake probability should be the same
    /// .
    #[test]
    fn test_probability_simple() {
        let validators = vec![1, 1, 1, 1];

        let mut leaders = HashMap::new();

        let random = broken_random(validators.len() as i64 * 50);

        for leader in random {
            *leaders
                .entry(select_winner(&validators, leader).unwrap())
                .or_insert(0) += 1;
        }

        assert_eq!(leaders[&0], leaders[&1]);
        assert_eq!(leaders[&1], leaders[&2]);
        assert_eq!(leaders[&2], leaders[&3]);
    }

    /// Probability of leader should be the same as it's stake.
    #[test]
    fn test_probability_complex() {
        let validators = vec![1, 2, 3, 4];

        let mut leaders = HashMap::new();

        let random = broken_random(validators.len() as i64 * 10);

        for leader in random {
            *leaders
                .entry(select_winner(&validators, leader).unwrap())
                .or_insert(0) += 1;
        }

        assert!(leaders[&3] == leaders[&0] * 4);
        assert_eq!(leaders[&2], leaders[&0] * 3);
        assert_eq!(leaders[&1], leaders[&0] * 2);
    }

    /// Check if group size actually depends on limit.
    #[test]
    fn test_group_size() {
        let (skey, _pkey) = pbc::make_random_keys();
        let key = pbc::PublicKey::dum();
        let keys = vec![(key, 1), (key, 2), (key, 3), (key, 4)];
        let rand = pbc::make_VRF(&skey, &Hash::zero());
        for i in 1..5 {
            assert!(
                select_validators_slots(keys.clone(), rand, i)
                    .validators
                    .len()
                    <= i as usize
            )
        }
        for i in 5..10 {
            assert!(
                select_validators_slots(keys.clone(), rand, i)
                    .validators
                    .len()
                    <= 4 as usize
            )
        }

        for i in &[1, 5, 10, 100, 1000, 5000] {
            let validators = select_validators_slots(keys.clone(), rand, *i).validators;
            let acc = validators.into_iter().fold(0, |acc, (_, v)| acc + v) as usize;
            assert_eq!(acc, *i as usize)
        }
    }
}

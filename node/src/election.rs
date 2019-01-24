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

//! Leader election and group formation algorithms and tests.

use log::error;
use stegos_crypto::hash::Hash;

use rand::{Rng, SeedableRng};
use rand_isaac::IsaacRng;

use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

pub type StakersGroup = Vec<(SecurePublicKey, i64)>;

#[derive(Debug, Eq, PartialEq)]
pub struct ConsensusGroup {
    /// List of Validators
    pub witnesses: StakersGroup,
    /// Leader public key
    pub leader: SecurePublicKey,
    /// Facilitator of the transaction pool
    pub facilitator: SecurePublicKey,
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

/// Choose a random group limited by `max_count` out of active stakers list.
/// Stakers consist of pair (stake, PublikKey).
/// Stakers array should not be empty, and every staker should have stake more than 0.
///
/// Returns Group of validators, and new leader
pub fn choose_validators(
    mut stakers: StakersGroup,
    random: Hash,
    max_group_size: usize,
) -> ConsensusGroup {
    assert!(!stakers.is_empty());
    assert!(max_group_size > 0);
    let mut witnesses = Vec::new();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(random.base_vector());

    let mut rng = IsaacRng::from_seed(seed);

    for _ in 0..max_group_size {
        let rand = rng.gen::<i64>();
        let index = select_winner(stakers.iter().map(|(_k, stake)| stake), rand).unwrap();

        let winner = stakers.remove(index);
        witnesses.push(winner);

        if stakers.is_empty() {
            break;
        }
    }
    let rand = rng.gen::<i64>();
    let leader = select_winner(witnesses.iter().map(|(_k, stake)| stake), rand).unwrap();

    let rand = rng.gen::<i64>();
    let facilitator = select_winner(witnesses.iter().map(|(_k, stake)| stake), rand).unwrap();

    let leader = witnesses[leader].0;
    let facilitator = witnesses[facilitator].0;
    ConsensusGroup {
        witnesses,
        leader,
        facilitator,
    }
}

#[cfg(test)]
mod test {
    use super::{choose_validators, select_winner};
    use std::collections::{HashMap, HashSet};

    use stegos_crypto::hash::Hash;
    use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

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
        const PUBLIC_KEY_SIZE: usize = 65;

        let key = SecurePublicKey::try_from_bytes(&[0; PUBLIC_KEY_SIZE]).unwrap();
        let keys = vec![(key, 1), (key, 2), (key, 3), (key, 4)];
        for i in 1..5 {
            assert_eq!(
                choose_validators(keys.clone(), Hash::zero(), i)
                    .witnesses
                    .len(),
                i
            )
        }
        for i in 5..10 {
            assert_eq!(
                choose_validators(keys.clone(), Hash::zero(), i)
                    .witnesses
                    .len(),
                4
            )
        }
    }

}

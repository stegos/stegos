//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

use serde_derive::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Copy, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyCheck {
    /// Don't check anything in macroblock. Only block multisig.
    None,
    /// Load chain by blocks, rather than fast load from snapshot.
    LoadChain,
    /// Check all incoming blocks consistency.
    Incoming,
    /// Check and validate persistence state.
    Full,
}

/// Blockchain configuration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ChainConfig {
    /// Maximal number of slots for election.
    pub max_slot_count: i64,
    /// Minimal stake amount.
    pub min_stake_amount: i64,
    /// How many epochs stake is valid.
    pub stake_epochs: u64,
    /// The number of blocks per epoch.
    pub micro_blocks_in_epoch: u32,
    /// Difficulty in bits, of service awards.
    pub awards_difficulty: usize,
    /// Block reward for creating block.
    pub block_reward: i64,
    /// Service award part of block reward.
    pub service_award_per_epoch: i64,
    /// Maximal delta between block's timestamp and local timestamp.
    pub vetted_timestamp_delta: Duration,
    /// When change is_synchronized to false.
    pub sync_timeout: Duration,
}

const STG: i64 = 1_000_000;

impl Default for ChainConfig {
    fn default() -> Self {
        let micro_blocks_in_epoch: u32 = 60;
        ChainConfig {
            max_slot_count: 1000,
            min_stake_amount: 50_000 * STG,
            micro_blocks_in_epoch,
            stake_epochs: 10,
            awards_difficulty: 10, // 10 bits = mean(2^10 epochs) ~ 5 days.
            block_reward: 24 * STG,
            service_award_per_epoch: 12 * STG * (micro_blocks_in_epoch as i64 + 1), // 12 STG per block
            // Sic: synchronize this value with NodeConfig::{micro, macro}_block_timeout.
            vetted_timestamp_delta: Duration::from_secs(30),
            sync_timeout: Duration::from_secs(5 * 60), // should >= block_timeout.
        }
    }
}

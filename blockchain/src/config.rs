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
use tempdir::TempDir;

/// Blockchain configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

impl Default for ChainConfig {
    fn default() -> Self {
        let micro_blocks_in_epoch: u32 = 60;
        ChainConfig {
            max_slot_count: 1000,
            min_stake_amount: 1_000_000_000, // 1000 STG
            micro_blocks_in_epoch,
            stake_epochs: 6,
            awards_difficulty: 3,
            block_reward: 40_000_000, // 40 STG
            service_award_per_epoch: 20_000_000i64 * (micro_blocks_in_epoch as i64 + 1), // 20 STG per block
        }
    }
}

/// Storage configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct StorageConfig {
    /// Database path
    pub database_path: String,
    /// Force strict checking of database (BP + BLS + VRF).
    pub force_check: bool,
}

impl StorageConfig {
    pub fn testing() -> (Self, TempDir) {
        let temp_dir = TempDir::new("stegostest").unwrap();
        let database_path = temp_dir.path().to_str().unwrap().to_string();
        let cfg = StorageConfig {
            database_path,
            force_check: true,
        };
        (cfg, temp_dir)
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            database_path: String::from("database"),
            force_check: cfg!(debug_assertions),
        }
    }
}

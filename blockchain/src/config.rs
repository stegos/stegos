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

/// Blockchain configuration.
#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    /// Maximal number of slots for election.
    pub max_slot_count: usize,
    /// Minimal stake amount.
    pub min_stake_amount: i64,
    /// Time to lock stakes.
    pub bonding_time: u64,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        BlockchainConfig {
            max_slot_count: 1000,
            min_stake_amount: 1000,
            bonding_time: 900,
        }
    }
}

/// Storage configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct StorageConfig {
    /// Database path
    pub database_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            database_path: "database".to_string(),
        }
    }
}

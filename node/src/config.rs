//
// MIT License
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

use serde_derive::{Deserialize, Serialize};

/// Chain configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ChainConfig {
    /// Time delta in which our messages should be delivered, or forgotten.
    pub message_timeout: u64,
    /// Estimated time of block validation
    pub block_validation_timeout: u64,
    /// How long wait for transactions before starting to create a new block.
    pub tx_wait_timeout: u64,
    /// How long wait for blocks.
    pub block_timeout: u64,
    /// How long wait for micro blocks.
    pub micro_block_timeout: u64,
    /// Max difference in timestamps of leader and validators.
    pub timestamp_delta_max: u64,
    /// Max count of sealed block in epoch.
    pub blocks_in_epoch: u64,
    /// Fixed reward per block.
    pub block_reward: i64,
    /// Fixed fee for payment transactions.
    pub payment_fee: i64,
    /// Fixed fee for the stake transactions.
    pub stake_fee: i64,
    /// Maximal number of slots for election.
    pub max_slot_count: usize,
    /// Minimal stake amount.
    pub min_stake_amount: i64,
    /// Time to lock stakes.
    pub bonding_time: u64,
    /// Limit of blocks to download starting from current known blockchain state.
    pub loader_batch_size: u64,
}

impl Default for ChainConfig {
    fn default() -> Self {
        let message_timeout = 60;
        let block_validation_timeout = 30; // tx_count * verify_tx = 1500 * 20ms.
        let tx_wait_timeout = 30;
        let block_timeout = tx_wait_timeout + // propose timeout
            message_timeout * 3 + // 3 consensus message
            block_validation_timeout * 3; // leader + validators + sealed block.
        let micro_block_timeout = tx_wait_timeout + message_timeout + block_validation_timeout;
        ChainConfig {
            message_timeout,
            block_validation_timeout,
            tx_wait_timeout,
            block_timeout,
            micro_block_timeout,
            timestamp_delta_max: 10 * 60,
            blocks_in_epoch: 5,
            block_reward: 60,
            payment_fee: 1,
            stake_fee: 1,
            max_slot_count: 1000,
            min_stake_amount: 1000,
            bonding_time: 900,
            loader_batch_size: 100,
        }
    }
}

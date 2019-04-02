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
use std::time::Duration;

/// Chain configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ChainConfig {
    /// Time delta in which our messages should be delivered, or forgotten.
    pub message_timeout: Duration,
    /// How long wait for transactions before starting to create a new block.
    pub tx_wait_timeout: Duration,
    /// Estimated time of the micro block validation.
    pub micro_block_validation_timeout: Duration,
    /// How long wait for micro blocks.
    pub micro_block_timeout: Duration,
    /// Estimated time of the key block validation.
    pub key_block_validation_timeout: Duration,
    /// How long wait for the keu blocks.
    pub key_block_timeout: Duration,
    /// Time to lock stakes.
    pub bonding_time: Duration,
    /// Max difference in timestamps of leader and validators.
    pub blocks_in_epoch: u64,
    /// Fixed reward per block.
    pub block_reward: i64,
    /// Fixed fee for payment transactions.
    pub payment_fee: i64,
    /// Fixed fee for the stake transactions.
    pub stake_fee: i64,
    /// Maximal number of slots for election.
    pub max_slot_count: i64,
    /// Minimal stake amount.
    pub min_stake_amount: i64,
    /// Limit of blocks to download starting from current known blockchain state.
    pub loader_batch_size: u64,
}

impl Default for ChainConfig {
    fn default() -> Self {
        let message_timeout = Duration::from_secs(1);
        let tx_wait_timeout = Duration::from_secs(1);
        // tx_count * verify_tx = 1500 * 20ms.
        let micro_block_validation_timeout = Duration::from_secs(30);
        let micro_block_timeout =
            tx_wait_timeout + message_timeout + micro_block_validation_timeout;
        let key_block_validation_timeout = Duration::from_millis(5);
        let key_block_timeout = message_timeout * 3 + // 3 consensus message
            key_block_validation_timeout * 3; // leader + validators + sealed block.

        ChainConfig {
            message_timeout,
            tx_wait_timeout,
            micro_block_validation_timeout,
            micro_block_timeout,
            key_block_validation_timeout,
            key_block_timeout,
            bonding_time: Duration::from_secs(15 * 60),
            blocks_in_epoch: 5,
            block_reward: 60,
            payment_fee: 1,
            stake_fee: 1,
            max_slot_count: 1000,
            min_stake_amount: 1000,
            loader_batch_size: 100,
        }
    }
}

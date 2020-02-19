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

/// Node configuration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct NodeConfig {
    /// How long wait for the micro blocks.
    pub micro_block_timeout: Duration,
    /// How long wait for the key blocks.
    pub macro_block_timeout: Duration,
    /// Timeout to check is_synchronized status.
    pub sync_change_timeout: Duration,
    /// The maximal number of outputs in a transaction.
    pub max_inputs_in_tx: usize,
    /// The maximal number of outputs in a transaction.
    pub max_outputs_in_tx: usize,
    /// The maximal number of inputs in a micro block.
    pub max_inputs_in_block: usize,
    /// The maximal number of outputs in a micro block.
    pub max_outputs_in_block: usize,
    /// The maximal number of inputs in mempool.
    pub max_inputs_in_mempool: usize,
    /// The maximal number of outputs in mempool.
    pub max_outputs_in_mempool: usize,
    /// Minimal fee for payment transactions.
    pub min_payment_fee: i64,
    /// Minimal fee for the stake transactions.
    pub min_stake_fee: i64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            // Sic: synchronize this value with ChainConfig::vetted_timeout.
            micro_block_timeout: Duration::from_secs(30),
            macro_block_timeout: Duration::from_secs(30),
            sync_change_timeout: Duration::from_secs(30), // should >= block_timeout.
            max_inputs_in_tx: 100,
            max_outputs_in_tx: 100, // snowball::MAX_UTXOS * txpool::MAX_PARTICIPANTS.
            max_inputs_in_block: 1000,
            max_outputs_in_block: 1000,
            max_inputs_in_mempool: 10000,
            max_outputs_in_mempool: 10000,
            min_payment_fee: 1_000, // 0.001 STG
            min_stake_fee: 0,       // free
        }
    }
}

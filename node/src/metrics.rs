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

use lazy_static::lazy_static;
use prometheus::*;

lazy_static! {
    //
    // Micro + Macro Blocks.
    //
    pub static ref SYNCHRONIZED: IntGauge =
        register_int_gauge!("stegos_synchronized", "Flag that the node is synchornized with the network.").unwrap();
    pub static ref BLOCK_REMOTE_TIMESTAMP: Gauge =
        register_gauge!("stegos_block_remote_timestamp", "The local time at a remote leader when the last block began to be created, i.e it equals to the value of block.header.timestamp.").unwrap();
    pub static ref BLOCK_LOCAL_TIMESTAMP: Gauge =
        register_gauge!("stegos_block_local_timestamp", "The local time at this node when the last block was registered.").unwrap();
    pub static ref BLOCK_IDLE: Gauge =
        register_gauge!("stegos_block_idle", "The elapsed time since the last block, i.e. it is the time difference between the local time at this node and the time when the last block was registered.").unwrap();
    pub static ref NODE_CURRENT_STAKE_BALANCE: IntGauge = register_int_gauge!(
        "stegos_node_current_stake_balance",
        "Total stake of this node."
    )
    .unwrap();
    pub static ref NODE_AVAILABLE_STAKE_BALANCE: IntGauge = register_int_gauge!(
        "stegos_node_available_stake_balance",
        "Inactive stake of this node."
    )
    .unwrap();

    pub static ref NODE_SLOTS_COUNT: IntGauge = register_int_gauge!(
        "stegos_node_slots_count",
        "Amount of slots node has in received macroblock."
    )
    .unwrap();
    //
    // Macro Blocks.
    //
    pub static ref MACRO_BLOCKS_AUTOCOMMITS: IntCounter = register_int_counter!(
        "stegos_macro_block_autocommits",
        "The number of auto-commits of proposed block"
    )
    .unwrap();
    pub static ref MACRO_BLOCK_VIEW_CHANGES: IntCounter = register_int_counter!(
        "stegos_macro_block_view_changes",
        "The number of forced view_changes for the macro blocks."
    )
    .unwrap();

    pub static ref MACRO_BLOCK_APPLY_TIME: Gauge = register_gauge!(
        "stegos_macro_block_apply_time",
        "Macro block applying time."
    )
    .unwrap();

    pub static ref MACRO_BLOCK_CREATE_TIME: Gauge = register_gauge!(
        "stegos_macro_block_create_time",
        "Macro block create time."
    )
    .unwrap();
    pub static ref MACRO_BLOCK_CREATE_TIME_HG: Histogram = register_histogram!(
        "stegos_macro_block_create_time_hg",
        "Histogram of macro block creation time",
         vec![0.020, 0.030, 0.040, 0.050, 0.060, 0.070, 0.080, 0.090, 0.100]
    )
    .unwrap();
    pub static ref MACRO_BLOCK_VALIDATE_TIME: Gauge = register_gauge!(
        "stegos_macro_block_validate_time",
        "Macro block validate time."
    )
    .unwrap();
    pub static ref MACRO_BLOCK_VALIDATE_TIME_HG: Histogram = register_histogram!(
        "stegos_macro_block_validate_time_hg",
        "Histogram of macro block validation time",
          vec![0.005, 0.010, 0.015, 0.020, 0.025, 0.030, 0.035, 0.040, 0.050, 0.100]
    )
    .unwrap();
    pub static ref MACRO_BLOCK_LAG: Gauge = register_gauge!(
        "stegos_macro_block_lag",
        "Macro block creation + validation + propagation time, i.e. it is the time difference between the local time at a remote leader when the last block began to be created and the local time at this node when this block was registered."
    )
    .unwrap();
    pub static ref MACRO_BLOCK_LAG_HG: Histogram = register_histogram!(
        "stegos_macro_block_lag_hg",
        "Histogram of stegos_macro_block_lag",
         vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1., 2., 3., 4., 5.]
    )
    .unwrap();

    //
    // Micro Blocks.
    //
    pub static ref MICRO_BLOCKS_FORKS: IntCounter = register_int_counter!(
        "stegos_micro_blocks_forks",
        "The number of forks detected"
    )
    .unwrap();
    pub static ref MICRO_BLOCKS_CHEATS: IntCounter = register_int_counter!(
        "stegos_micro_blocks_cheats",
        "The number of duplicate blocks for the same slot detected"
    )
    .unwrap();
    pub static ref MICRO_BLOCK_VIEW_CHANGES: IntCounter = register_int_counter!(
        "stegos_micro_block_view_changes",
        "The number of forced view_changes for the micro blocks."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_CREATE_TIME: Gauge = register_gauge!(
        "stegos_micro_block_create_time",
        "Micro block create time."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_CREATE_TIME_HG: Histogram = register_histogram!(
        "stegos_micro_block_create_time_hg",
        "Histogram of micro block creation time",
         vec![0.020, 0.030, 0.040, 0.050, 0.060, 0.070, 0.080, 0.090, 0.100]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_VALIDATE_TIME: Gauge = register_gauge!(
        "stegos_micro_block_validate_time",
        "Micro block validate time."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_VALIDATE_TIME_HG: Histogram = register_histogram!(
        "stegos_micro_block_validate_time_hg",
        "Histogram of micro block validation time",
         vec![0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2., 3., 4., 5.]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_LAG: Gauge = register_gauge!(
        "stegos_micro_block_lag",
        "Like stegos_macro_block_lag, but for micro blocks."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_LAG_HG: Histogram = register_histogram!(
        "stegos_micro_block_lag_hg",
        "Histogram of stegos_micro_block_lag.",
         vec![0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2., 3., 4., 5., 6., 7., 8., 9., 10.]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_INTERVAL: Gauge = register_gauge!(
        "stegos_micro_block_interval",
        "Interval between two micro blocks."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_INTERVAL_HG: Histogram = register_histogram!(
        "stegos_micro_block_interval_hg",
        "Histogram of micro block intervals",
         vec![1., 2., 3., 4., 5., 6., 7., 8., 9., 10., 20., 30., 40., 50., 60.]
    )
    .unwrap();

    //
    // Mempool.
    //
    pub static ref MEMPOOL_INPUTS: IntGauge =
        register_int_gauge!("stegos_mempool_inputs", "The number of inputs in mempool.").unwrap();
    pub static ref MEMPOOL_OUTPUTS: IntGauge =
        register_int_gauge!("stegos_mempool_outputs", "The number of outputs in mempool.").unwrap();
    pub static ref MEMPOOL_TRANSACTIONS: IntGauge =
        register_int_gauge!("stegos_mempool_transactions", "The number of transactions in mempool.").unwrap();
}

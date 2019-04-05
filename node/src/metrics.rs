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
use std::time::SystemTime;

/// Convert SystemTime to unix timestamp in millisecond precision.
pub fn time_to_timestamp_ms(time: SystemTime) -> i64 {
    let since_the_epoch = time
        .duration_since(std::time::UNIX_EPOCH)
        .expect("timestamp is valid");
    (since_the_epoch.as_secs() * 1000) as i64 + (since_the_epoch.subsec_millis() as i64)
}

lazy_static! {
    pub static ref MEMPOOL_LEN: IntGauge =
        register_int_gauge!("stegos_blockchain_mempool", "Size of mempool.").unwrap();
    pub static ref AUTOCOMMIT: IntCounter = register_int_counter!(
        "stegos_consensus_autocommit",
        "The number of auto-commits of proposed block"
    )
    .unwrap();
    pub static ref KEY_BLOCK_VIEW_CHANGES: IntCounter = register_int_counter!(
        "stegos_key_block_view_changes",
        "The number of forced view_changes for the key blocks."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_VIEW_CHANGES: IntCounter = register_int_counter!(
        "stegos_micro_block_view_changes",
        "The number of forced view_changes for the micro blocks."
    )
    .unwrap();
    pub static ref FORKS: IntCounter = register_int_counter!(
        "stegos_forks",
        "The number of forks detected"
    )
    .unwrap();
    pub static ref SYNCHRONIZED: IntGauge =
        register_int_gauge!("stegos_synchronized", "Flag that the node is synchornized with the network.").unwrap();
    pub static ref BLOCK_REMOTE_TIMESTAMP: IntGauge =
        register_int_gauge!("stegos_block_remote_timestamp_ms", "The local time at a remote leader when the last block began to be created, i.e it equals to the value of block.header.timestamp.").unwrap();
    pub static ref BLOCK_LOCAL_TIMESTAMP: IntGauge =
        register_int_gauge!("stegos_block_local_timestamp_ms", "The local time at this node when the last block was registered.").unwrap();
    pub static ref BLOCK_LAG: IntGauge =
        register_int_gauge!("stegos_block_lag_ms", "The last block creation + validation + propagation time, i.e. it is the time difference between the local time at a remote leader when the last block began to be created and the local time at this node when this block was registered.").unwrap();
    pub static ref BLOCK_IDLE: IntGauge =
        register_int_gauge!("stegos_block_idle_ms", "The elapsed time since the last block, i.e. it is the time difference between the local time at this node and the time when the last block was registered.").unwrap();
}

pub mod vrf {
    use super::*;
    lazy_static! {
        pub static ref IS_ACTIVE: IntGauge = register_int_gauge!(
            "stegos_vrf_state",
            "Current node vrf state (0 = disabled, 1 = active)."
        )
        .unwrap();
        pub static ref VIEW_CHANGE: IntGauge =
            register_int_gauge!("stegos_vrf_view_change", "Current node vrf state.").unwrap();
        pub static ref TICKETS_COLLECTED: IntGauge =
            register_int_gauge!("stegos_vrf_tickets_len", "Count of collected tickets.").unwrap();
        pub static ref TICKETS_HANDLED: IntGauge = register_int_gauge!(
            "stegos_vrf_tickets_handled_len",
            "Count of tickets received since last view change."
        )
        .unwrap();
        pub static ref TICKETS_QUEUED: IntGauge =
            register_int_gauge!("stegos_vrf_tickets_queue_len", "Count of tickets queued.")
                .unwrap();
    }
}

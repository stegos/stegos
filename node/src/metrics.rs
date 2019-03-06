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
    pub static ref MEMPOOL_LEN: IntGauge =
        register_int_gauge!("stegos_blockchain_mempool", "Size of mempool.").unwrap();
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

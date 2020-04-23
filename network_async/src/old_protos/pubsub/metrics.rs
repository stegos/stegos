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
    pub static ref LRU_CACHE_SIZE: IntGauge = register_int_gauge!(
        "stegos_pubsub_lru_cache_size",
        "Size of LRU cache for messages."
    )
    .unwrap();
    pub static ref INCOMING_RATES: GaugeVec = register_gauge_vec!(
        "stegos_pubsub_incoming_rate_per_peer",
        "Incoming messages per sec",
        &["peer"]
    )
    .unwrap();
    pub static ref OUTGOING_PUBSUB_TRAFFIC: IntCounterVec = register_int_counter_vec!(
        "stegos_pubsub_outgoing_traffic_per_topic",
        "Outgoing bytes per topic",
        &["topic"]
    )
    .unwrap();
    pub static ref INCOMING_PUBSUB_TRAFFIC: IntCounterVec = register_int_counter_vec!(
        "stegos_pubsub_incoming_traffic_per_topic",
        "Outgoing bytes per topic",
        &["topic"]
    )
    .unwrap();
    pub static ref CONNECTED_PEERS: IntGauge = register_int_gauge!(
        "stegos_pubsub_connected_peers",
        "Total count of connected peers"
    )
    .unwrap();
    pub static ref UNLOCKED_PEERS: IntGauge =
        register_int_gauge!("stegos_pubsub_unlocked_peers", "Count of unlocked peers").unwrap();
}

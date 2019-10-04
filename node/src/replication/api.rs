//! Replication - Public API.

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state")]
#[serde(rename_all = "snake_case")]
pub enum PeerInfo {
    Localhost {
        peer_id: String,
        epoch: u64,
        offset: u32,
    },
    Discovered {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
    },
    Connecting {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
    },
    Connected {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
    },
    Accepted {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
    },
    Receiving {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
        epoch: u64,
        offset: u32,
        bytes_received: u64,
        blocks_received: u64,
    },
    Sending {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
        epoch: u64,
        offset: u32,
        bytes_sent: u64,
        blocks_sent: u64,
    },
    Failed {
        peer_id: String,
        multiaddr: String,
        #[serde(with = "humantime_serde")]
        idle: Duration,
        error: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReplicationInfo {
    pub peers: Vec<PeerInfo>,
}

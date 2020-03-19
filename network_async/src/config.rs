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

/// Network configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct NetworkConfig {
    /// DNS server ton use to resolve seed nodes
    pub dns_servers: Vec<String>,
    /// Local Node endpoint.
    pub endpoint: String,
    /// Advertised Node endpoint.
    pub advertised_endpoint: String,
    /// DNS name of pool of seed nodes
    pub seed_pool: String,
    /// List of nodes to connect to on startup.
    pub seed_nodes: Vec<String>,
    /// Minimum active connections (try to keep at least so many established connections)
    pub min_connections: usize,
    /// Maximum active connections (Don't try to open more than max_connections connections)
    pub max_connections: usize,
    /// Connection monitoring tick interval (secs)
    pub monitoring_interval: u64,
    /// Handshake puzzle difficulty (VDF complexity)
    pub hanshake_puzzle_difficulty: u64,
    /// Network readiness threshold (number of handshake-enabled established connections)
    pub readiness_threshold: usize,
}

/// Default values for network configuration.
impl Default for NetworkConfig {
    fn default() -> NetworkConfig {
        NetworkConfig {
            dns_servers: vec![],
            seed_pool: "".to_string(),
            seed_nodes: vec![],
            advertised_endpoint: "".to_string(),
            endpoint: "".to_string(),
            min_connections: 8,
            max_connections: 32,
            monitoring_interval: 60,
            hanshake_puzzle_difficulty: 100,
            readiness_threshold: 2,
        }
    }
}

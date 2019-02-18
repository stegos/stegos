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
    /// Node ID
    /// Local IP address to bind to
    pub bind_ip: String,
    /// Local port to use for incoming connections
    pub bind_port: u16,
    /// List of advertised reachable address for this node
    pub advertised_addresses: Vec<String>,
    /// Advertise local active, non-loopback addresses
    pub advertise_local_ips: bool,
    /// Heartbeat interval secs
    pub heartbeat_interval: u64,
    /// List of nodes to connect to on startup.
    pub seed_nodes: Vec<String>,
    /// Minimum active connections (try to keep at least so many established connections)
    pub min_connections: usize,
    /// Maximum active connections (Don't try to open more than max_connections connections)
    pub max_connections: usize,
    /// Connection monitoring tick interval (secs)
    pub monitoring_interval: u64,
}

/// Default values for network configuration.
impl Default for NetworkConfig {
    fn default() -> NetworkConfig {
        NetworkConfig {
            bind_port: 10203,
            seed_nodes: vec![],
            advertised_addresses: vec![],
            advertise_local_ips: true,
            bind_ip: "0.0.0.0".to_string(),
            min_connections: 8,
            max_connections: 32,
            monitoring_interval: 5,
            heartbeat_interval: 30,
        }
    }
}

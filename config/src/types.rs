//
// Copyright (c) 2018 Stegos
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

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

///! Configuration Structures.

/// Configuration root
///
/// Every member of this structure is deserialized from corresponding section
/// of stegos.toml file.
///
/// Don't forget to update stegos.toml.example after adding new options.
///
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    /// General settings
    pub general: ConfigGeneral,
    /// Network configuration.
    pub network: ConfigNetwork,
    /// Key Chain configuration.
    pub keychain: ConfigKeyChain,
}

/// Default values for global configuration.
impl Default for Config {
    fn default() -> Config {
        Config {
            general: Default::default(),
            network: Default::default(),
            keychain: Default::default(),
        }
    }
}

/// General configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ConfigGeneral {
    /// Log4RS configuration file
    pub log4rs_config: String,
}

impl Default for ConfigGeneral {
    fn default() -> Self {
        ConfigGeneral {
            log4rs_config: "stegos-log4rs.toml".to_string(),
        }
    }
}

/// Key Chain Configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ConfigKeyChain {
    /// Path to secret key.
    pub private_key: String,
    /// Path to public key.
    pub public_key: String,
}

impl Default for ConfigKeyChain {
    fn default() -> Self {
        ConfigKeyChain {
            private_key: "stegos.skey".to_string(),
            public_key: "stegos.pkey".to_string(),
        }
    }
}

/// Network configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ConfigNetwork {
    /// Node ID
    /// TODO: Replace with correct public key, now only for testing
    pub node_id: String,
    /// Local IP address to bind to
    pub bind_ip: String,
    /// Local port to use for incoming connections
    pub bind_port: u16,
    /// List of advertised reachable address for this node
    pub advertised_addresses: Vec<String>,
    /// Advertise local active, non-loopback addresses
    pub advertise_local_ips: bool,
    /// List of nodes to connect to on startup.
    pub seed_nodes: Vec<String>,
    /// Path to Node's public key
    pub public_key: String,
    /// Path to Node's private key
    pub private_key: String,
    /// Broadcast topit for FloodSub
    pub broadcast_topic: String,
    /// Minimum active connections (try to keep at least so many established connections)
    pub min_connections: usize,
    /// Maximum active connections (Don't try to open more than max_connections connections)
    pub max_connections: usize,
    /// Connection monitoring tick interval (secs)
    pub monitoring_interval: u64,
}

/// Default values for network configuration.
impl Default for ConfigNetwork {
    fn default() -> ConfigNetwork {
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();

        ConfigNetwork {
            node_id: rand_string.clone(),
            bind_port: 10203,
            seed_nodes: vec![],
            advertised_addresses: vec![],
            advertise_local_ips: true,
            bind_ip: "0.0.0.0".to_string(),
            public_key: "public_key.der".to_string(),
            private_key: "private_key.pk8".to_string(),
            broadcast_topic: "stegos".to_string(),
            min_connections: 2,
            max_connections: 2,
            monitoring_interval: 15,
        }
    }
}

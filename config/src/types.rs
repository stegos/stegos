///! Configuration Structures.

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
    /// Network configuration.
    pub network: ConfigNetwork,
}

/// Default values for global configuration.
impl Default for Config {
    fn default() -> Config {
        Config {
            network: Default::default(),
        }
    }
}

/// Network configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ConfigNetwork {
    /// An example string configuration value.
    pub listen_address: String,
    /// List of advertised reachable address for this node
    pub advertised_addresses: Vec<String>,
    /// An example u32 configuration value.
    pub u32val: u32,
    /// List of nodes to connect to on startup.
    pub seed_nodes: Vec<String>,
    /// Path to Node's public key
    pub public_key: String,
    /// Path to Node's private key
    pub private_key: String,
    /// Broadcast topit for FloodSub
    pub broadcast_topic: String,
}

/// Default values for network configuration.
impl Default for ConfigNetwork {
    fn default() -> ConfigNetwork {
        ConfigNetwork {
            u32val: 0,
            seed_nodes: vec![],
            advertised_addresses: vec![],
            listen_address: "/ip4/0.0.0.0/tcp/10050".to_string(),
            public_key: "public_key.der".to_string(),
            private_key: "private_key.pk8".to_string(),
            broadcast_topic: "stegos".to_string(),
        }
    }
}

//! Configuration Handling.

//
// Copyright (c) 2018 Stegos AG
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

use failure::Fail;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::result::Result;
use stegos_blockchain::ConsistencyCheck;
use stegos_network::NetworkConfig;
use stegos_node::NodeConfig;
use toml;

/// Configuration root
///
/// Every member of this structure is deserialized from corresponding section
/// of stegos.toml file.
///
/// Don't forget to update stegos.toml.example after adding new options.
///
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct Config {
    /// General settings
    pub general: GeneralConfig,
    /// Node configuration.
    #[serde(skip_serializing)]
    pub node: NodeConfig,
    /// Network configuration.
    pub network: NetworkConfig,
}

/// Default values for global configuration.
impl Default for Config {
    fn default() -> Config {
        Config {
            general: Default::default(),
            node: Default::default(),
            network: Default::default(),
        }
    }
}

/// General configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct GeneralConfig {
    /// Chain name.
    pub chain: String,
    /// Data directory.
    pub data_dir: PathBuf,
    /// Force strict checking (BP + BLS + VRF) of blockchain on the disk.
    pub consistency_check: ConsistencyCheck,
    /// Log4RS configuration file
    pub log_config: PathBuf,
    /// Prometheus exporter endpoint
    pub prometheus_endpoint: String,
    /// WebSocket API endpoint,
    pub api_endpoint: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        // `~/.local/share/stegos` or just `data` in the current directory
        let data_dir = dirs::data_dir()
            .map(|p| p.join("stegos"))
            .unwrap_or(PathBuf::from(r"data"));
        GeneralConfig {
            chain: "testnet".to_string(),
            data_dir,
            consistency_check: if cfg!(debug_assertions) {
                ConsistencyCheck::Full
            } else {
                ConsistencyCheck::None
            },
            log_config: PathBuf::new(),
            prometheus_endpoint: "".to_string(),
            api_endpoint: "127.0.0.1:3145".to_string(),
        }
    }
}

/// Error type for wrapping configuration errors.
#[derive(Debug, Fail)]
pub enum ConfigError {
    /// Caused if configuration file is missing.
    #[fail(display = "Configuration file not found.")]
    NotFoundError,
    /// Caused on input/output errors.
    #[fail(display = "Failed to read configuration file: {}.", _0)]
    IOError(io::Error),
    /// Caused by parse errors.
    #[fail(display = "Failed to parse configuration file: {}.", _0)]
    ParseError(toml::de::Error),
}

///
/// Load configuration file
///
/// # Arguments
///
/// * `cfg_path` - A path to configuration file
///
/// # Errors
///
/// Returns ConfigError on error.
///
pub fn from_file<P: AsRef<Path>>(cfg_path: P) -> Result<Config, ConfigError> {
    // Open configuration file
    let mut f = match File::open(cfg_path) {
        // The file is readable
        Ok(f) => f,
        // The file doesn't exists - use defaults
        Err(ref e) if e.kind() == ErrorKind::NotFound => return Err(ConfigError::NotFoundError),
        // Propagate the error
        Err(e) => return Err(ConfigError::IOError(e)),
    };

    // Read the file content
    let mut contents = String::new();
    if let Err(e) = f.read_to_string(&mut contents) {
        return Err(ConfigError::IOError(e));
    }
    drop(f);

    // Deserialize TOML and return result
    match toml::from_str(&contents) {
        Ok(cfg) => Ok(cfg),
        Err(e) => Err(ConfigError::ParseError(e)),
    }
}

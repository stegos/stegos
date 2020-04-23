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
use log::info;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::result::Result;
use stegos_blockchain::{ChainConfig, ConsistencyCheck};
use toml;

///
/// Stegos vault configuration
///
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct VaultConfig {
    pub node_address: String,
    pub node_token_path: PathBuf,
    /// General settings
    pub general: GeneralConfig,
    pub chain_cfg: ChainConfig,
}

impl VaultConfig {
    pub fn save<P: AsRef<Path>>(&self, cfg_path: P) -> Result<(), ConfigError> {
        let result = match toml::to_string(&self) {
            Ok(cfg) => cfg,
            Err(e) => return Err(ConfigError::WriteTomlError(e)),
        };
        let cfg_path = cfg_path.as_ref();

        // Open configuration file
        let mut f = match File::create(cfg_path) {
            // The file is readable
            Ok(f) => f,
            // The file doesn't exists - use defaults
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                return Err(ConfigError::NotFoundError)
            }
            // Propagate the error
            Err(e) => return Err(ConfigError::IOError(e)),
        };

        info!("Creating new config at {:?}", cfg_path);

        if let Err(e) = f.write_all(result.as_bytes()) {
            return Err(ConfigError::IOError(e));
        }

        Ok(())
    }
}
impl Default for VaultConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .map(|p| p.join("stegos-vault"))
            .unwrap_or(PathBuf::from(r"data"));

        VaultConfig {
            node_address: String::from("127.0.0.1:3145"),
            node_token_path: data_dir.join("api.token"),
            /// General settings
            general: Default::default(),
            chain_cfg: Default::default(),
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
        // `~/.local/share/stegos-vault` or just `data` in the current directory
        let data_dir = dirs::data_dir()
            .map(|p| p.join("stegos-vault"))
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
            api_endpoint: "127.0.0.1:4145".to_string(),
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

    /// Caused by toml serialize errors.
    #[fail(display = "Failed to write configuration file: {}.", _0)]
    WriteTomlError(toml::ser::Error),
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
pub fn from_file<P: AsRef<Path>>(cfg_path: P) -> Result<VaultConfig, ConfigError> {
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

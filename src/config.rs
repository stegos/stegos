//! Configuration Handling.

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

use serde_derive::{Deserialize, Serialize};
use std::error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::result::Result;
use stegos_blockchain::StorageConfig;
use stegos_keychain::KeyChainConfig;
use stegos_network::NetworkConfig;
use toml;

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
    pub general: GeneralConfig,
    /// Network configuration.
    pub network: NetworkConfig,
    /// Key Chain configuration.
    pub keychain: KeyChainConfig,
    /// Storage configuration.
    pub storage: StorageConfig,
}

/// Default values for global configuration.
impl Default for Config {
    fn default() -> Config {
        Config {
            general: Default::default(),
            network: Default::default(),
            keychain: Default::default(),
            storage: Default::default(),
        }
    }
}

/// General configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct GeneralConfig {
    /// Log4RS configuration file
    pub log4rs_config: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        GeneralConfig {
            log4rs_config: "stegos-log4rs.toml".to_string(),
        }
    }
}

/// Error type for wrapping configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    /// Caused if configuration file is missing.
    NotFoundError,
    /// Caused on input/output errors.
    IOError(io::Error),
    /// Caused by parse errors.
    ParseError(toml::de::Error),
}

/// Display implementation for ConfigError.
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NotFoundError => write!(f, "Configuration file not found"),
            ConfigError::IOError(e) => write!(f, "Failed to read configuration file: {}", e),
            ConfigError::ParseError(e) => write!(f, "Failed to parse configuration file: {}", e),
        }
    }
}

/// Error implementation for ConfigError.
impl error::Error for ConfigError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ConfigError::IOError(ref e) => Some(e),
            ConfigError::ParseError(ref e) => Some(e),
            _ => None,
        }
    }
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

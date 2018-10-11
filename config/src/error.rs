///! Configuration Error Types.
use std::error;
use std::fmt;
use std::io;
use toml;

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigError::NotFoundError => write!(f, "Configuration file not found"),
            ConfigError::IOError(e) => write!(f, "Failed to read configuration file: {}", e),
            ConfigError::ParseError(e) => write!(f, "Failed to parse configuration file: {}", e),
        }
    }
}

/// Error implementation for ConfigError.
impl error::Error for ConfigError {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ConfigError::IOError(ref e) => Some(e),
            ConfigError::ParseError(ref e) => Some(e),
            _ => None,
        }
    }
}

///! Configuration Error Types.

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

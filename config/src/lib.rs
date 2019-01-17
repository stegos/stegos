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

#![warn(missing_docs, missing_debug_implementations)]
#![deny(warnings)]

mod error;
mod types;

pub use crate::error::*;
pub use crate::types::*;
use serde_derive;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::result::Result;
use toml;

// TODO: move fee constants to appropriate place.

/// Fixed fee for monetary transactions.
pub const MONETARY_FEE: i64 = 1;
/// Fixed fee for escrow transactions.
pub const ESCROW_FEE: i64 = 1;
/// Data unit used to calculate fee.
pub const DATA_UNIT: usize = 1024;
/// Fee for one DATA_UNIT.
pub const DATA_UNIT_FEE: i64 = 1;

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

//! WebSocket API - Configuration.

//
// MIT License
//
// Copyright (c) 2019 Stegos AG
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

use crate::KeyError;
use failure::Error;
use log::info;
use rand::{thread_rng, RngCore};
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::iter::repeat;
use std::path::Path;

/// WebSocket Configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct WebSocketConfig {
    /// Local IP address to bind to.
    pub bind_ip: String,
    /// Local IP port to bind to.
    pub bind_port: u16,
    /// File with the encryption key (32-bytes AES256 key, base64 encoded)
    pub token_file: String,
}

/// Default values for websocket configuration.
impl Default for WebSocketConfig {
    fn default() -> WebSocketConfig {
        WebSocketConfig {
            bind_ip: "0.0.0.0".to_string(),
            bind_port: 3145,
            token_file: "api_token.txt".to_string(),
        }
    }
}

// Load API Key from file, generate new key, if file is missing
pub fn load_key(cfg: &WebSocketConfig) -> Result<Vec<u8>, Error> {
    if !Path::new(&cfg.token_file).exists() {
        info!("API Key file is missing, generating new one");
        let mut gen = thread_rng();
        let mut key: Vec<u8> = repeat(0u8).take(crate::API_KEYSIZE).collect();
        gen.fill_bytes(&mut key[..]);
        fs::write(cfg.token_file.clone(), base64::encode(&key))
            .map_err(|e| KeyError::InputOutputError(cfg.token_file.clone(), e))?;
        return Ok(key);
    }
    let key_encoded = fs::read_to_string(cfg.token_file.clone())
        .map_err(|e| KeyError::InputOutputError(cfg.token_file.clone(), e))?;
    let key = base64::decode(&key_encoded)
        .map_err(|e| KeyError::ParseError(cfg.token_file.clone(), e))?;
    if key.len() != crate::API_KEYSIZE {
        return Err(KeyError::InvalidKeySize(crate::API_KEYSIZE, key.len()).into());
    }
    Ok(key)
}

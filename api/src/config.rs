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

use crate::crypto::{ApiToken, API_TOKENSIZE};
use crate::error::KeyError;
use log::info;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// WebSocket Configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ApiConfig {
    /// Local IP address to bind to.
    pub bind_ip: String,
    /// Local IP port to bind to.
    pub bind_port: u16,
    /// File with the encryption key (32-bytes AES256 key, base64 encoded)
    pub token_file: String,
}

/// Default values for websocket configuration.
impl Default for ApiConfig {
    fn default() -> ApiConfig {
        ApiConfig {
            bind_ip: "0.0.0.0".to_string(),
            bind_port: 3145,
            token_file: "api_token.txt".to_string(),
        }
    }
}

// Load API Key from file, generate new key, if file is missing
pub fn load_or_create_api_token(token_file: &str) -> Result<ApiToken, KeyError> {
    if !Path::new(token_file).exists() {
        info!("API Key file is missing, generating new one");
        let token = ApiToken::new();
        fs::write(token_file.clone(), base64::encode(&token.0))
            .map_err(|e| KeyError::InputOutputError(token_file.to_string(), e))?;
        return Ok(token);
    } else {
        return load_api_token(token_file);
    }
}

/// Load API token from a file.
pub fn load_api_token(token_file: &str) -> Result<ApiToken, KeyError> {
    let token = fs::read_to_string(token_file)
        .map_err(|e| KeyError::InputOutputError(token_file.to_string(), e))?;
    let token =
        base64::decode(&token).map_err(|e| KeyError::ParseError(token_file.to_string(), e))?;
    if token.len() != API_TOKENSIZE {
        return Err(KeyError::InvalidKeySize(API_TOKENSIZE, token.len()).into());
    }
    let mut token2 = [0u8; API_TOKENSIZE];
    token2.copy_from_slice(&token);
    Ok(ApiToken(token2))
}

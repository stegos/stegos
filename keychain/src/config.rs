//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

/// Key Chain Configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct KeyChainConfig {
    /// Path to password file.
    pub password_file: String,
    /// Path to recovery file.
    pub recovery_file: String,
    /// Path to SCC secret key.
    pub wallet_skey_file: String,
    /// Path to SCC public key.
    pub wallet_pkey_file: String,
    /// Path to PBC secret key.
    pub network_skey_file: String,
    /// Path to PBC public key.
    pub network_pkey_file: String,
}

impl Default for KeyChainConfig {
    fn default() -> Self {
        KeyChainConfig {
            password_file: "-".to_string(),
            recovery_file: "".to_string(),
            wallet_skey_file: "wallet.skey".to_string(),
            wallet_pkey_file: "wallet.pkey".to_string(),
            network_skey_file: "network.skey".to_string(),
            network_pkey_file: "network.pkey".to_string(),
        }
    }
}

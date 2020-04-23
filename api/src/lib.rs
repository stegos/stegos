//! WebSocket API.

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

#![recursion_limit = "1024"] // used for futures::select in server/mod.rs
                             // #![deny(warnings)]

mod client;
mod crypto;
mod error;
pub mod network_api;
pub mod server;

pub use crate::client::WebSocketClient;
use crate::crypto::{decrypt, encrypt};
pub use crate::crypto::{load_api_token, load_or_create_api_token, ApiToken};
pub use crate::error::KeyError;
use failure::{bail, Error};
use log::*;
pub use network_api::*;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_derive::{Deserialize, Serialize};
pub use stegos_node::{ChainNotification, NodeRequest, NodeResponse, StatusNotification};
pub use stegos_wallet::api::*;

pub type RequestId = u64;

fn is_request_id_default(id: &RequestId) -> bool {
    *id == 0
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestKind {
    NetworkRequest(NetworkRequest),
    WalletsRequest(WalletRequest),
    NodeRequest(NodeRequest),
    Raw(serde_json::Value),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InnerResponses {
    /// This notifications are imediately created after reconnected to server,
    /// and need to inform client that it should resubscribe.
    Reconnect,
    InternalError {
        error: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Request {
    #[serde(flatten)]
    pub kind: RequestKind,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_request_id_default")]
    pub id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseKind {
    NetworkResponse(NetworkResponse),
    NetworkNotification(NetworkNotification),
    WalletResponse(WalletResponse),
    WalletNotification(WalletNotification),
    NodeResponse(NodeResponse),
    StatusNotification(StatusNotification),
    ChainNotification(ChainNotification),
    Raw(serde_json::Value),
    Inner(InnerResponses),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    #[serde(flatten)]
    pub kind: ResponseKind,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_request_id_default")]
    pub id: RequestId,
}

pub fn encode<T: Serialize>(api_token: &ApiToken, msg: &T) -> String {
    let msg = serde_json::to_vec(&msg).expect("serialized");
    let msg = encrypt(api_token, &msg);
    let msg = base64::encode(&msg);
    msg
}

pub fn decode<T: DeserializeOwned>(api_token: &ApiToken, msg: &str) -> Result<T, Error> {
    let msg = match base64::decode(&msg) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to base64::decode message: error={}", e);
            bail!("Failed to base64::decode");
        }
    };
    let msg = decrypt(api_token, &msg);
    // Check for {} brackets in decoded message.
    const LEFT_BRACKET: u8 = 123;
    const RIGHT_BRACKET: u8 = 125;
    if msg.len() < 2 || msg[0] != LEFT_BRACKET || msg[msg.len() - 1] != RIGHT_BRACKET {
        error!("Failed to decrypt message");
        bail!("Failed to decrypt");
    }
    let msg: T = match serde_json::from_slice(&msg) {
        Ok(r) => r,
        Err(e) => {
            error!(
                "Failed to parse JSON: msg={}, error={}",
                String::from_utf8_lossy(&msg),
                e
            );
            bail!("Failed to parse JSON");
        }
    };
    Ok(msg)
}

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

#![deny(warnings)]

mod config;
mod crypto;
mod error;
mod server;

pub use crate::config::ApiConfig;
pub use crate::crypto::ApiToken;
pub use crate::error::KeyError;
pub use crate::server::WebSocketServer;

use crate::crypto::{decrypt, encrypt};
use log::*;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use stegos_crypto::pbc;
use stegos_node::{EpochChanged, NodeRequest, NodeResponse, SyncChanged};
use stegos_wallet::{WalletNotification, WalletRequest, WalletResponse};
use websocket::WebSocketError;

pub type RequestId = u64;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum NetworkRequest {
    SubscribeUnicast {
        topic: String,
    },
    SubscribeBroadcast {
        topic: String,
    },
    UnsubscribeUnicast {
        topic: String,
    },
    UnsubscribeBroadcast {
        topic: String,
    },
    SendUnicast {
        topic: String,
        to: pbc::PublicKey,
        data: Vec<u8>,
    },
    PublishBroadcast {
        topic: String,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum NetworkResponse {
    SubscribedUnicast,
    SubscribedBroadcast,
    UnsubscribedUnicast,
    UnsubscribedBroadcast,
    SentUnicast,
    PublishedBroadcast,
    Error { error: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum NetworkNotification {
    UnicastMessage {
        topic: String,
        from: pbc::PublicKey,
        data: Vec<u8>,
    },
    BroadcastMessage {
        topic: String,
        data: Vec<u8>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RequestKind {
    NetworkRequest(NetworkRequest),
    WalletRequest(WalletRequest),
    NodeRequest(NodeRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Request {
    #[serde(flatten)]
    kind: RequestKind,
    #[serde(default)]
    id: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum NodeNotification {
    SyncChanged(SyncChanged),
    EpochChanged(EpochChanged),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ResponseKind {
    NetworkResponse(NetworkResponse),
    NetworkNotification(NetworkNotification),
    WalletResponse(WalletResponse),
    WalletNotification(WalletNotification),
    NodeResponse(NodeResponse),
    NodeNotification(NodeNotification),
}

fn is_default(id: &RequestId) -> bool {
    *id == 0
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct Response {
    #[serde(flatten)]
    kind: ResponseKind,
    #[serde(skip_serializing_if = "is_default")]
    id: RequestId,
}

fn encode<T: Serialize>(api_token: &ApiToken, msg: &T) -> String {
    let msg = serde_json::to_vec(&msg).expect("serialized");
    let msg = encrypt(api_token, &msg);
    let msg = base64::encode(&msg);
    msg
}

fn decode<T: DeserializeOwned>(api_token: &ApiToken, msg: &str) -> Result<T, WebSocketError> {
    let msg = match base64::decode(&msg) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to base64::decode message: error={}", e);
            return Err(WebSocketError::RequestError("Invalid request"));
        }
    };
    let msg = decrypt(api_token, &msg);
    let msg: T = match serde_json::from_slice(&msg) {
        Ok(r) => r,
        Err(e) => {
            error!(
                "Failed to deserialize: msg={}, error={}",
                String::from_utf8_lossy(&msg),
                e
            );
            return Err(WebSocketError::RequestError("Invalid request"));
        }
    };
    Ok(msg)
}

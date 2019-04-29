//! Wallet - API.

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

use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use futures::sync::oneshot;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_node::OutputsChanged;

///
/// Out-of-band notifications.
///
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum WalletNotification {
    BalanceChanged { balance: i64 },
    PaymentReceived { amount: i64, comment: String },
}

///
/// RPC requests.
///
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum WalletRequest {
    Payment {
        recipient: PublicKey,
        amount: i64,
        comment: String,
    },
    SecurePayment {
        recipient: PublicKey,
        amount: i64,
        comment: String,
    },
    Stake {
        amount: i64,
    },
    Unstake {
        amount: i64,
    },
    UnstakeAll {},
    KeysInfo {},
    BalanceInfo {},
    UnspentInfo {},
    GetRecovery {},
}

///
/// RPC responses.
///
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "response")]
#[serde(rename_all = "snake_case")]
pub enum WalletResponse {
    TransactionCreated {
        tx_hash: Hash,
        fee: i64,
    },
    ValueShuffleStarted {},
    BalanceInfo {
        balance: i64,
    },
    KeysInfo {
        wallet_pkey: PublicKey,
        network_pkey: secure::PublicKey,
    },
    UnspentInfo {
        unspent: Vec<(Hash, i64)>,
        unspent_stakes: Vec<(Hash, i64)>,
    },
    Recovery {
        recovery: String,
    },
    Error {
        error: String,
    },
}

///
/// Events.
///
#[derive(Debug)]
pub(crate) enum WalletEvent {
    //
    // Public API.
    //
    Subscribe {
        tx: UnboundedSender<WalletNotification>,
    },
    Request {
        request: WalletRequest,
        tx: oneshot::Sender<WalletResponse>,
    },

    //
    // Internal events.
    //
    NodeOutputsChanged(OutputsChanged),
}

#[derive(Debug, Clone)]
pub struct Wallet {
    pub(crate) outbox: UnboundedSender<WalletEvent>,
}

impl Wallet {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> UnboundedReceiver<WalletNotification> {
        let (tx, rx) = unbounded();
        let msg = WalletEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Wallet Request.
    pub fn request(&self, request: WalletRequest) -> oneshot::Receiver<WalletResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = WalletEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

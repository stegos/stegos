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
pub use stegos_blockchain::PaymentPayloadData;
pub use stegos_blockchain::StakeInfo;
use stegos_crypto::curve1174::PublicKey;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_node::EpochChanged;
use stegos_node::OutputsChanged;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PaymentInfo {
    pub utxo: Hash,
    pub amount: i64,
    pub data: PaymentPayloadData,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPaymentInfo {
    pub utxo: Hash,
    pub amount: i64,
}

///
/// Out-of-band notifications.
///
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum WalletNotification {
    BalanceChanged { balance: i64 },
    Received(PaymentInfo),
    ReceivedPublic(PublicPaymentInfo),
    Spent(PaymentInfo),
    SpentPublic(PublicPaymentInfo),
    Staked(StakeInfo),
    Unstaked(StakeInfo),
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
    PublicPayment {
        recipient: PublicKey,
        amount: i64,
    },
    SecurePayment {
        recipient: PublicKey,
        amount: i64,
        comment: String,
    },
    WaitForCommit {
        tx_hash: Hash,
    },
    Stake {
        amount: i64,
    },
    Unstake {
        amount: i64,
    },
    UnstakeAll {},
    RestakeAll {},
    CloakAll {},
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
    ValueShuffleStarted {
        session_id: Hash,
    },
    TransactionCommitted(TransactionCommitted),
    BalanceInfo {
        balance: i64,
    },
    KeysInfo {
        wallet_pkey: PublicKey,
        network_pkey: pbc::PublicKey,
    },
    UnspentInfo {
        public_payments: Vec<PublicPaymentInfo>,
        payments: Vec<PaymentInfo>,
        stakes: Vec<StakeInfo>,
    },
    Recovery {
        recovery: String,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result")]
#[serde(rename_all = "snake_case")]
pub enum TransactionCommitted {
    // TODO: add info about rollback.
    Committed {},
    NotFoundInMempool {}, //TODO: replace, after persistent for all created transactions.
    ConflictTransactionCommitted { conflicted_output: Hash },
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
    NodeEpochChanged(EpochChanged),
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

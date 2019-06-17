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

use crate::storage::PaymentCertificate;
use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use futures::sync::oneshot;
use serde_derive::{Deserialize, Serialize};
use std::time::SystemTime;
pub use stegos_blockchain::PaymentPayloadData;
pub use stegos_blockchain::StakeInfo;
use stegos_crypto::curve1174::PublicKey;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_node::EpochChanged;
use stegos_node::OutputsChanged;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LogEntryInfo {
    Incoming {
        timestamp: SystemTime,
        output: OutputInfo,
    },
    Outgoing {
        timestamp: SystemTime,
        tx: PaymentTransactionInfo,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OutputInfo {
    Payment(PaymentInfo),
    PublicPayment(PublicPaymentInfo),
    Staked(StakeInfo),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PaymentInfo {
    pub utxo: Hash,
    pub amount: i64,
    pub data: PaymentPayloadData,
    pub locked: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPaymentInfo {
    pub utxo: Hash,
    pub amount: i64,
    pub locked: String,
}

///
/// Out-of-band notifications.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum WalletRequest {
    Payment {
        password: String,
        recipient: PublicKey,
        amount: i64,
        comment: String,
        locked_timestamp: Option<SystemTime>,
    },
    PublicPayment {
        password: String,
        recipient: PublicKey,
        amount: i64,
        locked_timestamp: Option<SystemTime>,
    },
    SecurePayment {
        password: String,
        recipient: PublicKey,
        amount: i64,
        comment: String,
        locked_timestamp: Option<SystemTime>,
    },
    WaitForCommit {
        tx_hash: Hash,
    },
    Stake {
        password: String,
        amount: i64,
    },
    Unstake {
        password: String,
        amount: i64,
    },
    UnstakeAll {
        password: String,
    },
    RestakeAll {
        password: String,
    },
    CloakAll {
        password: String,
    },
    KeysInfo {},
    BalanceInfo {},
    UnspentInfo {},
    HistoryInfo {
        starting_from: SystemTime,
        limit: u64,
    },
    GetRecovery {
        password: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionInfo {
    pub tx_hash: Hash,
    pub certificates: Vec<PaymentCertificate>,
}

///
/// RPC responses.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response")]
#[serde(rename_all = "snake_case")]
pub enum WalletResponse {
    TransactionCreatedWithCertificate {
        tx_hash: Hash,
        info: PaymentTransactionInfo,
    },
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
    HistoryInfo {
        log: Vec<LogEntryInfo>,
    },
    Recovery {
        recovery: String,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl From<PaymentInfo> for OutputInfo {
    fn from(pi: PaymentInfo) -> OutputInfo {
        OutputInfo::Payment(pi)
    }
}

impl From<PublicPaymentInfo> for OutputInfo {
    fn from(pi: PublicPaymentInfo) -> OutputInfo {
        OutputInfo::PublicPayment(pi)
    }
}

impl From<StakeInfo> for OutputInfo {
    fn from(pi: StakeInfo) -> OutputInfo {
        OutputInfo::Staked(pi)
    }
}

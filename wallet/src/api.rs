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
pub use stegos_blockchain::PaymentPayloadData;
pub use stegos_blockchain::StakeInfo;
use stegos_blockchain::Timestamp;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::PublicKey;

pub type WalletId = String;

#[derive(Eq, PartialEq, Serialize, Deserialize, Clone, Debug)]
pub enum LogEntryInfo {
    Incoming {
        timestamp: Timestamp,
        output: OutputInfo,
    },
    Outgoing {
        timestamp: Timestamp,
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
    pub locked_timestamp: Option<Timestamp>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPaymentInfo {
    pub utxo: Hash,
    pub amount: i64,
    pub locked_timestamp: Option<Timestamp>,
}

///
/// Out-of-band notifications.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
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

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WalletsNotification {
    pub wallet_id: WalletId,
    #[serde(flatten)]
    pub notification: WalletNotification,
}

///
/// RPC requests.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum WalletRequest {
    Seal,
    Unseal {
        password: String,
    },
    Payment {
        recipient: PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
        with_certificate: bool,
    },
    PublicPayment {
        recipient: PublicKey,
        amount: i64,
        payment_fee: i64,
        locked_timestamp: Option<Timestamp>,
    },
    SecurePayment {
        recipient: PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
    },
    WaitForCommit {
        tx_hash: Hash,
    },
    Stake {
        amount: i64,
        payment_fee: i64,
    },
    Unstake {
        amount: i64,
        payment_fee: i64,
    },
    UnstakeAll {
        payment_fee: i64,
    },
    RestakeAll {},
    CloakAll {
        payment_fee: i64,
    },
    KeysInfo {},
    BalanceInfo {},
    UnspentInfo {},
    HistoryInfo {
        starting_from: Timestamp,
        limit: u64,
    },
    ChangePassword {
        new_password: String,
    },
    GetRecovery {},
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "request")]
pub enum WalletManagerRequest {
    ListWallets {},
    CreateWallet { password: String },
    RecoverWallet { recovery: String, password: String },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum WalletsRequest {
    WalletManagerRequest(WalletManagerRequest),
    WalletRequest {
        wallet_id: WalletId,
        #[serde(flatten)]
        request: WalletRequest,
    },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionInfo {
    pub tx_hash: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<PaymentCertificate>,
}

///
/// RPC responses.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response")]
#[serde(rename_all = "snake_case")]
pub enum WalletResponse {
    Sealed,
    Unsealed,
    TransactionCreated(PaymentTransactionInfo),
    ValueShuffleStarted {
        session_id: Hash,
    },
    TransactionCommitted(TransactionCommitted),
    BalanceInfo {
        balance: i64,
    },
    KeysInfo {
        wallet_address: PublicKey,
        network_address: pbc::PublicKey,
    },
    UnspentInfo {
        public_payments: Vec<PublicPaymentInfo>,
        payments: Vec<PaymentInfo>,
        stakes: Vec<StakeInfo>,
    },
    HistoryInfo {
        log: Vec<LogEntryInfo>,
    },
    PasswordChanged,
    Recovery {
        recovery: String,
    },
    Error {
        error: String,
    },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "response")]
pub enum WalletManagerResponse {
    WalletsInfo { wallets: Vec<WalletId> },
    WalletCreated { wallet_id: WalletId },
    Error { error: String },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum WalletsResponse {
    WalletManagerResponse(WalletManagerResponse),
    WalletResponse {
        wallet_id: WalletId,
        #[serde(flatten)]
        response: WalletResponse,
    },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug)]
pub(crate) enum WalletsEvent {
    Subscribe {
        tx: UnboundedSender<WalletsNotification>,
    },
    Request {
        request: WalletsRequest,
        tx: oneshot::Sender<WalletsResponse>,
    },
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

#[derive(Debug, Clone)]
pub struct WalletManager {
    pub(crate) outbox: UnboundedSender<WalletsEvent>,
}

impl WalletManager {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> UnboundedReceiver<WalletsNotification> {
        let (tx, rx) = unbounded();
        let msg = WalletsEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Wallet Request.
    pub fn request(&self, request: WalletsRequest) -> oneshot::Receiver<WalletsResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = WalletsEvent::Request { request, tx };
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

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Check encoding/decoding of API structures.
    #[test]
    fn serde() {
        let request1 = WalletsRequest::WalletManagerRequest(WalletManagerRequest::CreateWallet {
            password: "password xx".to_string(),
        });
        let json1 = serde_json::to_string(&request1).unwrap();
        let request1_check: WalletsRequest = serde_json::from_str(&json1).unwrap();
        assert_eq!(&request1, &request1_check);
        println!("{:?} {}", &request1, json1);

        let request2 = WalletsRequest::WalletRequest {
            wallet_id: "my_wallet_id".to_string(),
            request: WalletRequest::Stake {
                amount: 4324,
                payment_fee: 10,
            },
        };
        let json2 = serde_json::to_string(&request2).unwrap();
        let request2_check: WalletsRequest = serde_json::from_str(&json2).unwrap();
        assert_eq!(&request2, &request2_check);
        println!("{:?} {}", &request2, json2);
    }
}

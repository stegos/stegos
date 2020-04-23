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

// pub use crate::snowball::State as SnowballStatus;
use futures::channel::mpsc;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stegos_blockchain::api::StatusInfo;
pub use stegos_blockchain::PaymentPayloadData;
pub use stegos_blockchain::StakeInfo;
use stegos_blockchain::Timestamp;
use stegos_blockchain::Transaction;
pub use stegos_blockchain::TransactionStatus;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;
use stegos_crypto::utils::deserialize_protobuf_from_hex;
use stegos_crypto::utils::serialize_protobuf_to_hex;
pub use stegos_replication::api::*;

pub type AccountId = String;

#[derive(Eq, PartialEq, Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum LogEntryInfo {
    Incoming {
        timestamp: Timestamp,
        #[serde(flatten)]
        output: OutputInfo,
    },
    Outgoing {
        timestamp: Timestamp,
        #[serde(flatten)]
        tx: TransactionInfo,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "output_type")]
pub enum OutputInfo {
    Payment(PaymentInfo),
    PublicPayment(PublicPaymentInfo),
    Staked(StakeInfo),
}

impl OutputInfo {
    pub fn output_hash(&self) -> Hash {
        match self {
            OutputInfo::Payment(p) => p.output_hash,
            OutputInfo::PublicPayment(p) => p.output_hash,
            OutputInfo::Staked(p) => p.output_hash,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PaymentInfo {
    pub output_hash: Hash,
    pub amount: i64,
    #[serde(flatten)]
    pub data: PaymentPayloadData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_timestamp: Option<Timestamp>,
    pub recipient: scc::PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rvalue: Option<scc::Fr>,
    pub is_change: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicPaymentInfo {
    pub output_hash: Hash,
    pub amount: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_timestamp: Option<Timestamp>,
    pub recipient: scc::PublicKey,
}

///
/// Information about balance.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct Balance {
    /// Available funds plus funds that are being held.
    pub current: i64,
    /// Funds can spend right now.
    pub available: i64,
}

///
/// Account balance per each UTXO type.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct AccountBalance {
    /// PaymentUTXO.
    pub payment: Balance,
    /// PublicPaymentUTXO.
    pub public_payment: Balance,
    /// StakeUTXO.
    pub stake: Balance,
    /// PaymentUTXO + PublicPaymentUTXO + StakeUTXO.
    #[serde(flatten)]
    pub total: Balance,
    /// Is account balance finalized (was updated before last macroblock).
    pub is_final: bool,
    #[serde(default)]
    pub epoch: u64,
}

/// Recovery information.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct AccountRecovery {
    /// 24-word recovery phrase.
    pub recovery: String,
}

///
/// Out-of-band notifications.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AccountNotification {
    StatusChanged(StatusInfo),
    #[serde(skip)]
    UpstreamError(String),
    Unsealed,
    Sealed,
    BalanceChanged(AccountBalance),
    // SnowballStatus(SnowballStatus),
    TransactionStatus {
        tx_hash: Hash,
        #[serde(flatten)]
        status: TransactionStatus,
    },
    Received(PaymentInfo),
    ReceivedPublic(PublicPaymentInfo),
    Spent(PaymentInfo),
    SpentPublic(PublicPaymentInfo),
    Staked(StakeInfo),
    Unstaked(StakeInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WalletNotification {
    pub account_id: AccountId,
    #[serde(flatten)]
    pub notification: AccountNotification,
}

///
/// RPC requests.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AccountRequest {
    Seal,
    /// Controll request that perform full disable of account future.
    /// Used for future account removing
    #[serde(skip)]
    Disable,
    Unseal {
        password: String,
    },
    Payment {
        recipient: scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        with_certificate: bool,
        #[serde(default)]
        raw: bool,
    },
    PublicPayment {
        recipient: scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        #[serde(default)]
        raw: bool,
    },
    SecurePayment {
        recipient: scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
    },
    StakeAll {
        payment_fee: i64,
    },
    StakeRemote {
        amount: i64,
        payment_fee: i64,
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
    CloakAll {
        payment_fee: i64,
    },
    AccountInfo {},
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
#[serde(tag = "type")]
pub enum WalletControlRequest {
    ListAccounts {}, // legacy
    AccountsInfo {},
    CreateAccount {
        password: String,
    },
    RecoverAccount {
        #[serde(flatten)]
        recovery: AccountRecovery,
        password: String,
    },
    DeleteAccount {
        account_id: AccountId,
    },
    LightReplicationInfo {},
    SubscribeWalletUpdates {},
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum WalletRequest {
    WalletControlRequest(WalletControlRequest),
    AccountRequest {
        account_id: AccountId,
        #[serde(flatten)]
        request: AccountRequest,
    },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub tx_hash: Hash,
    pub fee: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<OutputInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Hash>,
    #[serde(flatten)]
    pub status: TransactionStatus,
}

///
/// RPC responses.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AccountResponse {
    Sealed,
    Unsealed,
    #[serde(skip)]
    Disabled,
    TransactionCreated(TransactionInfo),
    RawTransactionCreated {
        #[serde(serialize_with = "serialize_protobuf_to_hex")]
        #[serde(deserialize_with = "deserialize_protobuf_from_hex")]
        data: Transaction,
    },
    BalanceInfo(AccountBalance),
    AccountInfo(AccountInfo),
    UnspentInfo {
        public_payments: Vec<PublicPaymentInfo>,
        payments: Vec<PaymentInfo>,
        stakes: Vec<StakeInfo>,
    },
    HistoryInfo {
        log: Vec<LogEntryInfo>,
    },
    PasswordChanged,
    Recovery(AccountRecovery),
    Error {
        error: String,
    },
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccountInfo {
    pub account_pkey: scc::PublicKey,
    pub network_pkey: pbc::PublicKey,
    #[serde(default)]
    #[serde(flatten)]
    pub status: StatusInfo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum WalletControlResponse {
    AccountsInfo {
        accounts: BTreeMap<AccountId, AccountInfo>,
        remote_epoch: u64,
    },
    AccountCreated {
        account_id: AccountId,
    },
    AccountDeleted {
        account_id: AccountId,
    },
    LightReplicationInfo(ReplicationInfo),
    SubscribedWalletUpdates {
        #[serde(skip)]
        rx: Option<mpsc::UnboundedReceiver<WalletNotification>>, // Option is needed for serde.
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum WalletResponse {
    WalletControlResponse(WalletControlResponse),
    AccountResponse {
        account_id: AccountId,
        #[serde(flatten)]
        response: AccountResponse,
    },
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
        let request1 = WalletRequest::WalletControlRequest(WalletControlRequest::CreateAccount {
            password: "password xx".to_string(),
        });
        let json1 = serde_json::to_string(&request1).unwrap();
        let request1_check: WalletRequest = serde_json::from_str(&json1).unwrap();
        assert_eq!(&request1, &request1_check);
        println!("{:?} {}", &request1, json1);

        let request2 = WalletRequest::AccountRequest {
            account_id: "my_account_id".to_string(),
            request: AccountRequest::Stake {
                amount: 4324,
                payment_fee: 10,
            },
        };
        let json2 = serde_json::to_string(&request2).unwrap();
        let request2_check: WalletRequest = serde_json::from_str(&json2).unwrap();
        assert_eq!(&request2, &request2_check);
        println!("{:?} {}", &request2, json2);
    }
}

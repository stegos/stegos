use crate::error::Error as VaultError;
use failure::{bail, Error};
use futures::channel::mpsc;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use stegos_api::{server::api::RawResponse, ResponseKind};
use stegos_crypto::hash::Hash;
use stegos_crypto::scc;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum VaultRequest {
    // - [ ] Set password (to create accounts and unlock them)
    // - [ ] Create the cold storage account as soon as the password is set
    // - [ ] Return the cold storage account
    // - [ ] Create account
    // - [ ] Remove account
    // - [ ] Notify of a public deposit
    // - [ ] Notify of a credit to the cold storage account
    // - [ ] Withdraw
    Unseal {
        password: String,
    },

    CreateUser {
        account_id: String,
    },

    BalanceInfo {},

    GetUser {
        account_id: String,
    },

    GetUsers {},

    RecoveryInfo {
        #[serde(default)]
        account_id: Option<String>,
    },

    RemoveUser {
        account_id: String,

        /// By default Removing only hide data inside .trash folder,
        /// you can force removing secret key by setting burn flag.
        #[serde(default)]
        burn: bool,
    },
    Subscribe {
        epoch: u64,
    },
    Withdraw {
        public_key: scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        public: bool,
    },
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub public_key: scc::PublicKey,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum VaultResponse {
    Unsealed {
        created: bool,
    },
    CreatedUser {
        account_id: String,
    },
    Recovery {
        account_id: Option<String>,
        recovery: String,
    },
    GetUser {
        account_id: String,
        public_key: scc::PublicKey,
    },
    BalanceInfo {
        main: scc::PublicKey,
        amount: i64,
        confirmed_epoch: u64,
    },
    GetUsers {
        main: scc::PublicKey,
        list: Vec<AccountInfo>,
    },
    RemovedUser {
        account_id: String,
        public_key: scc::PublicKey,
        //secret_key: scc::SecretKey,
    },
    WithdrawCreated {
        outputs_hashes: Vec<Hash>,
    },
    Subscribed {
        #[serde(skip)]
        rx: Option<mpsc::UnboundedReceiver<VaultNotification>>, // Option is needed for serde.
    },
    Error {
        code: u64,
        error: String,
    },
}

impl VaultResponse {
    pub(super) fn subscribe_to_stream(
        &mut self,
    ) -> Result<Box<dyn Stream<Item = RawResponse> + Unpin + Send>, Error> {
        match self {
            VaultResponse::Subscribed { ref mut rx } => {
                return Ok(Box::new(
                    rx.take()
                        .expect("Stream exist")
                        .map(|i| ResponseKind::Raw(serde_json::to_value(i).unwrap()))
                        .map(RawResponse),
                ))
            }
            resp => bail!("Response didn't support notifications: resp={:?}", resp),
        }
    }
}

impl<'a> From<&'a VaultError> for VaultResponse {
    fn from(err: &VaultError) -> VaultResponse {
        let code = err.code();
        let error = err.to_string();
        VaultResponse::Error { error, code }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation")]
#[serde(rename_all = "snake_case")]
pub enum UtxoInfo {
    Spent { output_hash: Hash, amount: i64 },
    Received { output_hash: Hash, amount: i64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserBalanceUpdated {
    pub public_key: scc::PublicKey,
    pub id: String,
    pub amount: i64,
    // utxos: Vec<UtxoInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "update_type")]
#[serde(rename_all = "snake_case")]
pub enum VaultNotificationEntry {
    UserDepositReceived(UserBalanceUpdated),
    UserDepositConfirmed(UserBalanceUpdated),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationBlock {
    pub list: Vec<VaultNotificationEntry>,
    // if balance updated
    pub amount: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum VaultNotification {
    BlockProcessed {
        epoch: u64,
        #[serde(flatten)]
        notification: NotificationBlock,
    },
    Disconnected {
        error: String,
        code: u64,
    },
}

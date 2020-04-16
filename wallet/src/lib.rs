//! Account.

//
// Copyright (c) 2018 Stegos AG
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
#![recursion_limit = "1024"]
// #![deny(warnings)]

pub mod api;
mod change;
mod error;
mod metrics;
mod protos;
pub mod recovery;
// mod snowball;
mod storage;
//#[cfg(test)]
//mod test;
pub mod accounts;
mod transaction;
use self::accounts::*;

use self::error::WalletError;
use self::recovery::recovery_to_account_skey;
// use self::snowball::{Snowball, SnowballOutput, State as SnowballState};
use self::storage::*;
use self::transaction::*;
use api::*;
use bit_vec::BitVec;
use failure::{format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::select;
use log::*;
use std::collections::HashMap;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use stegos_blockchain::api::StatusInfo;
use stegos_blockchain::TransactionStatus;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::keyfile::{
    load_account_pkey, load_network_keypair, write_account_pkey, write_account_skey,
};
use stegos_keychain::KeyError;
use stegos_network::{Network, PeerId, ReplicationEvent};
use stegos_replication::api::PeerInfo;
use stegos_replication::{Replication, ReplicationRow};
use stegos_serialization::traits::ProtoConvert;
use tokio::time::{Duration, Interval};

use futures::stream::SelectAll;

const STAKE_FEE: i64 = 0;
const RESEND_TX_INTERVAL: Duration = Duration::from_secs(2 * 60);
const PENDING_UTXO_TIME: Duration = Duration::from_secs(5 * 60);
const CHECK_LOCKED_INPUTS: Duration = Duration::from_secs(10);

/// Topic used for sending transactions.
pub const TX_TOPIC: &'static str = "tx";

///
/// Events.
///
#[derive(Debug)]
pub enum AccountEvent {
    //
    // Public API.
    //
    Subscribe {
        tx: mpsc::UnboundedSender<AccountNotification>,
    },
    Request {
        request: AccountRequest,
        tx: oneshot::Sender<AccountResponse>,
    },
}

/// This could be used for non PaymentTx.
impl From<Result<TransactionInfo, Error>> for AccountResponse {
    fn from(r: Result<TransactionInfo, Error>) -> Self {
        match r {
            Ok(info) => AccountResponse::TransactionCreated(info),
            Err(e) => AccountResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

impl From<Vec<LogEntryInfo>> for AccountResponse {
    fn from(log: Vec<LogEntryInfo>) -> Self {
        AccountResponse::HistoryInfo { log }
    }
}

#[derive(Debug, Clone)]
pub struct Account {
    pub outbox: mpsc::UnboundedSender<AccountEvent>,
}

impl Account {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<AccountNotification> {
        let (tx, rx) = mpsc::unbounded();
        let msg = AccountEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a request.
    pub fn request(&self, request: AccountRequest) -> oneshot::Receiver<AccountResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = AccountEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

#[derive(Debug)]
enum WalletEvent {
    Subscribe {
        tx: mpsc::UnboundedSender<WalletNotification>,
    },
    Request {
        request: WalletRequest,
        tx: oneshot::Sender<WalletResponse>,
    },
}

pub struct AccountHandle {
    /// Account public key.
    pub account_pkey: scc::PublicKey,
    /// Account API.
    pub account: Account,
    /// Current status,
    pub status: StatusInfo,
    /// True if unsealed.
    pub unsealed: bool,
    /// A channel to send blocks,
    pub chain_tx: mpsc::Sender<LightBlock>,
}

pub struct WalletService {
    accounts_dir: PathBuf,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    network: Network,
    genesis_hash: Hash,
    chain_cfg: ChainConfig,
    max_inputs_in_tx: usize,
    accounts: HashMap<AccountId, AccountHandle>,

    account_notifications:
        SelectAll<Box<dyn Stream<Item = (AccountId, AccountNotification)> + Unpin + Send>>,
    subscribers: Vec<mpsc::UnboundedSender<WalletNotification>>,

    events: mpsc::UnboundedReceiver<WalletEvent>,
    replication: Replication,
}

impl WalletService {
    pub fn new(
        accounts_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        peer_id: PeerId,
        replication_rx: mpsc::UnboundedReceiver<ReplicationEvent>,
        genesis_hash: Hash,
        chain_cfg: ChainConfig,
        max_inputs_in_tx: usize,
    ) -> Result<(Self, Wallet), Error> {
        let (outbox, events) = mpsc::unbounded::<WalletEvent>();
        let subscribers = Vec::new();
        let account_notifications = SelectAll::new();
        let light = true;
        let replication = Replication::new(peer_id, network.clone(), light, replication_rx);
        let mut service = WalletService {
            accounts_dir: accounts_dir.to_path_buf(),
            network_skey,
            network_pkey,
            network,
            genesis_hash,
            chain_cfg,
            max_inputs_in_tx,
            accounts: HashMap::new(),
            subscribers,
            account_notifications,
            events,
            replication,
        };

        info!("Scanning directory {:?} for accounts", accounts_dir);

        // Scan directory for accounts.
        for entry in fs::read_dir(accounts_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string();
            // Skip non-UTF-8 filenames
            if name.is_err() {
                continue;
            }
            if name.unwrap().starts_with(".") || !entry.file_type()?.is_dir() {
                continue;
            }

            // Find a secret key.
            let account_skey_file = entry.path().join("account.skey");
            let account_pkey_file = entry.path().join("account.pkey");
            if !account_skey_file.exists() || !account_pkey_file.exists() {
                continue;
            }

            // Extract account name.
            let account_id: String = match entry.file_name().into_string() {
                Ok(id) => id,
                Err(os_string) => {
                    warn!("Invalid folder name: folder={:?}", os_string);
                    continue;
                }
            };

            service.open_account(&account_id, false)?;
        }

        info!("Recovered {} account(s)", service.accounts.len());
        let api = Wallet { outbox };
        Ok((service, api))
    }

    ///
    /// Open existing account.
    ///
    fn open_account(&mut self, account_id: &str, is_new: bool) -> Result<(), Error> {
        let account_dir = self.accounts_dir.join(account_id);
        let account_database_dir = account_dir.join("lightdb");
        let account_pkey_file = account_dir.join("account.pkey");
        let account_pkey = load_account_pkey(&account_pkey_file)?;
        debug!("Found account id={}, pkey={}", account_id, account_pkey);

        // Check for duplicates.
        for handle in self.accounts.values() {
            if handle.account_pkey == account_pkey {
                return Err(WalletError::DuplicateAccount(account_pkey).into());
            }
        }

        // TODO: implement the fast recovery for freshly created accounts.
        drop(is_new);

        // TODO: determine optimal block size.
        let (chain_tx, chain_rx) = mpsc::channel(2);
        let (account_service, account) = SealedAccountService::from_file(
            &account_database_dir,
            &account_dir,
            self.network_skey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.genesis_hash.clone(),
            self.chain_cfg.clone(),
            self.max_inputs_in_tx,
            chain_rx,
        )?;
        let account_id_clone = account_id.to_string();
        let account_notifications = account
            .subscribe()
            .map(move |i| (account_id_clone.clone(), i));

        self.account_notifications
            .push(Box::new(account_notifications));

        let handle = AccountHandle {
            account_pkey,
            account,
            status: StatusInfo {
                is_synchronized: false,
                epoch: 0,
                offset: 0,
                view_change: 0,
                last_block_hash: Hash::zero(),
                last_macro_block_hash: Hash::zero(),
                last_macro_block_timestamp: Timestamp::now(),
                local_timestamp: Timestamp::now(),
            },
            unsealed: false,
            chain_tx,
        };
        let prev = self.accounts.insert(account_id.to_string(), handle);
        assert!(prev.is_none(), "account_id is unique");
        tokio::spawn(account_service.entry());
        Ok(())
    }

    /// Find the next available account id.
    fn find_account_id(&self) -> AccountId {
        for i in 1..std::u64::MAX {
            let account_id = i.to_string();
            let account_dir = self.accounts_dir.join(&account_id);
            if !self.accounts.contains_key(&account_id) && !account_dir.exists() {
                return account_id;
            }
        }
        unreachable!("Failed to find the next account id");
    }

    ///
    /// Create a new account for provided keys.
    ///
    fn create_account(
        &mut self,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        password: &str,
    ) -> Result<AccountId, Error> {
        let account_id = self.find_account_id();
        let account_dir = self.accounts_dir.join(format!("{}", account_id));
        fs::create_dir_all(&account_dir)?;
        let account_skey_file = account_dir.join("account.skey");
        let account_pkey_file = account_dir.join("account.pkey");
        write_account_pkey(&account_pkey_file, &account_pkey)?;
        write_account_skey(&account_skey_file, &account_skey, password)?;
        Ok(account_id)
    }

    fn handle_control_request(
        &mut self,
        request: WalletControlRequest,
    ) -> Result<WalletControlResponse, Error> {
        match request {
            WalletControlRequest::ListAccounts {} | WalletControlRequest::AccountsInfo {} => {
                let accounts = self
                    .accounts
                    .iter()
                    .map(|(account_id, handle)| {
                        (
                            account_id.clone(),
                            AccountInfo {
                                account_pkey: handle.account_pkey.clone(),
                                network_pkey: self.network_pkey.clone(),
                                status: handle.status.clone(),
                            },
                        )
                    })
                    .collect();
                let replication_info = self.replication.info();
                let remote_epoch = replication_info
                    .peers
                    .into_iter()
                    .filter_map(|r| match r {
                        PeerInfo::Receiving { epoch, .. } => Some(epoch),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                Ok(WalletControlResponse::AccountsInfo {
                    accounts,
                    remote_epoch,
                })
            }
            WalletControlRequest::CreateAccount { password } => {
                let (account_skey, account_pkey) = scc::make_random_keys();
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                info!("Created a new account {}", account_pkey);
                self.open_account(&account_id, true)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::RecoverAccount {
                recovery: AccountRecovery { recovery },
                password,
            } => {
                let account_skey = recovery_to_account_skey(&recovery)?;
                let account_pkey: scc::PublicKey = account_skey.clone().into();
                // Check for duplicates.
                for handle in self.accounts.values() {
                    if handle.account_pkey == account_pkey {
                        return Err(WalletError::DuplicateAccount(account_pkey).into());
                    }
                }
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                info!("Restored account from 24-word phrase {}", account_pkey);
                self.open_account(&account_id, false)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::DeleteAccount { .. } => {
                unreachable!("Delete account should be already processed in different routine")
            }
            WalletControlRequest::LightReplicationInfo {} => Ok(
                WalletControlResponse::LightReplicationInfo(self.replication.info()),
            ),
        }
    }

    fn handle_account_request(
        &mut self,
        account_id: String,
        request: AccountRequest,
        tx: oneshot::Sender<WalletResponse>,
    ) {
        match self.accounts.get(&account_id) {
            Some(handle) => {
                let fut = handle.account.request(request);
                tokio::spawn(async move {
                    let response = fut.await.expect("No error in request.");
                    let r = WalletResponse::AccountResponse {
                        account_id,
                        response,
                    };
                    tx.send(r).ok(); // ignore error;
                });
            }
            None => {
                let r = WalletControlResponse::Error {
                    error: format!("Unknown account: {}", account_id),
                };
                let r = WalletResponse::WalletControlResponse(r);
                tx.send(r).ok(); // ignore error;
            }
        }
    }

    fn handle_account_delete(
        &mut self,
        account_id: AccountId,
        tx: oneshot::Sender<WalletResponse>,
    ) {
        let accounts_dir = self.accounts_dir.clone();
        match self.accounts.remove(&account_id) {
            Some(handle) => {
                warn!("Removing account {}", account_id);
                // Try to seal account, and then perform removing.
                let fut = handle.account.request(AccountRequest::Disable);
                tokio::spawn(async move {
                    let res = match fut.await {
                        // oneshot can be closed before we process event.
                        Ok(AccountResponse::Disabled) => {
                            Self::delete_account(account_id, accounts_dir)
                        }

                        Err(e) => Err(format_err!("Error processing disable: {}", e)),
                        Ok(response) => Err(format_err!(
                            "Wrong reponse to disable account: {:?}",
                            response
                        )),
                    };

                    let r = match res {
                        Ok(account_id) => WalletControlResponse::AccountDeleted { account_id },
                        Err(e) => WalletControlResponse::Error {
                            error: e.to_string(),
                        },
                    };
                    let response = WalletResponse::WalletControlResponse(r);
                    futures::future::ok::<(), ()>(drop(tx.send(response)))
                });
            }
            None => {
                let r = WalletControlResponse::Error {
                    error: format!("Unknown account: {}", account_id),
                };
                let response = WalletResponse::WalletControlResponse(r);
                tx.send(response).ok();
            }
        }
    }

    fn delete_account(account_id: AccountId, accounts_dir: PathBuf) -> Result<AccountId, Error> {
        let account_dir = accounts_dir.join(&account_id);
        if account_dir.exists() {
            let suffix = Timestamp::now()
                .duration_since(Timestamp::UNIX_EPOCH)
                .as_secs();
            let trash_dir = accounts_dir.join(".trash");
            if !trash_dir.exists() {
                fs::create_dir_all(&trash_dir)?;
            }
            let account_dir_bkp = trash_dir.join(format!("{}-{}", &account_id, suffix));
            warn!("Renaming {:?} to {:?}", account_dir, account_dir_bkp);
            fs::rename(account_dir, account_dir_bkp)?;
            return Ok(account_id);
        }
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Account dir was not found").into(),
        );
    }

    /// Handle incoming blocks received from network.
    fn handle_block(&mut self, block: LightBlock) -> Result<(), Error> {
        for (account_id, handle) in &mut self.accounts {
            if !handle.unsealed {
                continue;
            }
            if let Err(e) = handle.chain_tx.try_send(block.clone()) {
                warn!("{}: account_id={}", e, account_id);
            }
        }
        Ok(())
    }

    pub async fn start(mut self) {
        // Process events.
        loop {
            select! {
                    event = self.events.next() => match event.unwrap() {
                        WalletEvent::Subscribe { tx } => {
                            self.subscribers.push(tx);
                        }
                        WalletEvent::Request { request, tx } => {
                            match request {
                                // process DeleteAccount seperately, because we need to end account future before.
                                WalletRequest::WalletControlRequest(
                                    WalletControlRequest::DeleteAccount { account_id },
                                ) => self.handle_account_delete(account_id, tx),
                                WalletRequest::WalletControlRequest(request) => {
                                    let response = match self.handle_control_request(request) {
                                        Ok(r) => r,
                                        Err(e) => WalletControlResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    };
                                    let response = WalletResponse::WalletControlResponse(response);
                                    tx.send(response).ok(); // ignore errors.
                                }
                                WalletRequest::AccountRequest {
                                    account_id,
                                    request,
                                } => self.handle_account_request(account_id, request, tx),
                            }
                        }
                    },
                // Forward notifications.
                notification = self.account_notifications.next() => {
                    if let Some((account_id, notification)) = notification {
                        if let Some(handle) = self.accounts.get_mut(&account_id) {
                            match &notification {
                                AccountNotification::StatusChanged(status_info) => {
                                    handle.status = status_info.clone();
                                    debug!(
                                        "Account changed: account_id={}, epoch={}, offset={}",
                                        account_id, status_info.epoch, status_info.offset
                                    );
                                }
                                AccountNotification::Unsealed => {
                                    debug!("Account unsealed: account_id={}", account_id);
                                    handle.unsealed = true;
                                    self.replication.change_upstream(false);
                                }

                                AccountNotification::Sealed => {
                                    debug!("Account sealed: account_id={}", account_id);
                                    handle.unsealed = false;
                                }
                                AccountNotification::UpstreamError(e) => {
                                    debug!("Upstream error: {}", e);
                                    self.replication.change_upstream(false);
                                }
                                _ => {}
                            }

                            let notification = WalletNotification {
                                account_id: account_id.clone(),
                                notification,
                            };
                            self.subscribers
                                .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                        } else {
                            warn!("Received notification from account without handle: account_id={}", account_id);
                        }
                    }
                }

            }

            // Replication
            // 'outer: while self.accounts.len() > 0 {
            //     // Sic: check that all accounts are ready before polling the replication.
            //     let mut current_epoch = std::u64::MAX;
            //     let mut current_offset = std::u32::MAX;
            //     let mut unsealed = false;
            //     for (_account_id, handle) in &mut self.accounts {
            //         if !handle.unsealed {
            //             continue;
            //         }
            //         unsealed = true;
            //         match handle.chain_tx.poll_ready() {
            //             Ok(Async::Ready(_)) => true,
            //             _ => break 'outer,
            //         };
            //         if handle.status.epoch <= current_epoch {
            //             current_epoch = handle.status.epoch;
            //             if handle.status.offset <= current_offset {
            //                 current_offset = handle.status.offset;
            //             }
            //         }
            //     }

            //     if !unsealed {
            //         break;
            //     }

            //     let micro_blocks_in_epoch = self.chain_cfg.micro_blocks_in_epoch;
            //     let block_reader = DummyBlockReady {};
            //     trace!(
            //         "Poll replication: current_epoch={}, current_offset={}",
            //         current_epoch,
            //         current_offset
            //     );
            //     match self.replication.poll(
            //         current_epoch,
            //         current_offset,
            //         micro_blocks_in_epoch,
            //         &block_reader,
            //     ) {
            //         Async::Ready(Some(ReplicationRow::LightBlock(block))) => {
            //             if let Err(e) = self.handle_block(block) {
            //                 error!("Invalid block received from replication: {}", e);
            //             }
            //         }
            //         Async::Ready(Some(ReplicationRow::Block(_block))) => {
            //             panic!("The full block received from replication");
            //         }
            //         Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
            //         Async::NotReady => break,
            //     }
            // }
        }
    }
}

struct DummyBlockReady {}

impl BlockReader for DummyBlockReady {
    fn iter_starting<'a>(
        &'a self,
        _epoch: u64,
        _offset: u32,
    ) -> Result<Box<dyn Iterator<Item = Block> + 'a>, Error> {
        return Err(format_err!("The light node can't be used a an upstream"));
    }
    fn light_iter_starting<'a>(
        &'a self,
        _epoch: u64,
        _offset: u32,
    ) -> Result<Box<dyn Iterator<Item = LightBlock> + 'a>, Error> {
        return Err(format_err!("The light node can't be used a an upstream"));
    }
}

#[derive(Debug, Clone)]
pub struct Wallet {
    outbox: mpsc::UnboundedSender<WalletEvent>,
}

impl Wallet {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<WalletNotification> {
        let (tx, rx) = mpsc::unbounded();
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

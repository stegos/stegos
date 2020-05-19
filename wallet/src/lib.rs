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
#![recursion_limit = "2048"]

pub mod accounts;
pub mod api;
mod change;
mod error;
mod metrics;
mod protos;
pub mod recovery;
mod storage;
mod transaction;
use self::accounts::*;

use self::error::WalletError;
use self::recovery::recovery_to_account_skey;
use api::*;
use failure::{format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::future::FutureExt;
use futures::prelude::*;
use futures::select;
use futures::stream;
use log::*;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use stegos_blockchain::api::StatusInfo;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain::keyfile::{load_account_pkey, write_account_pkey, write_account_skey};
use stegos_network::{Network, PeerId, ReplicationEvent};
use stegos_replication::api::PeerInfo;
use stegos_replication::{OutputsInfo, Replication, ReplicationRow};
use tokio::time::{Duration, Instant};

use futures::stream::SelectAll;

const STAKE_FEE: i64 = 0;
const REPLICATION_RETRY_REQUEST: Duration = Duration::from_secs(30);
const REPLICATION_RETRY_ON_NO_CONNECTION: Duration = Duration::from_secs(3);
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
    pub chain_tx: mpsc::Sender<ReplicationOutEvent>,
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

    events: mpsc::UnboundedReceiver<(WalletRequest, oneshot::Sender<WalletResponse>)>,
    replication: ReplicationBlockCollector,
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
        let (outbox, events) = mpsc::unbounded();
        let subscribers = Vec::new();
        let account_notifications = SelectAll::new();
        let light = true;
        let replication = ReplicationBlockCollector::new(
            chain_cfg.clone(),
            Replication::new(peer_id, network.clone(), light, replication_rx),
        );
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
                let replication_info = self.replication.replication.info();
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
                WalletControlResponse::LightReplicationInfo(self.replication.replication.info()),
            ),
            WalletControlRequest::SubscribeWalletUpdates {} => {
                let (sender, rx) = mpsc::unbounded();
                self.subscribers.push(sender);
                Ok(WalletControlResponse::SubscribedWalletUpdates { rx: rx.into() })
            }
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

    pub async fn start(mut self) {
        // Timer to prevent network death.
        // let dead_timer = tokio::time::interval_at(Duration::from_secs(3));
        // Process events.
        loop {
            select! {
                // _ = dead_timer.tick().fuse() => {},
                event = self.events.next() => {
                    let (request, tx) = match event {
                        Some((request, tx)) => (request, tx),
                        None => return,
                    };
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
                event = self.replication.select(&mut self.accounts).fuse() => {
                    trace!("Return replication event = {:?}", event);

                    if let Some(event) = self.replication.process_event(&mut self.accounts, event).await {
                        error!("Replication shutdown.");
                        return;
                    }
                }
            }
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

    fn get_block<'a>(
        &'a self,
        _epoch: u64,
        _offset: u32,
    ) -> Result<std::borrow::Cow<'a, Block>, Error> {
        return Err(format_err!("The light node can't be used as an upstream"));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryProcessed {
    needed_outputs: Vec<(u32, Hash)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockEvent {
    CanaryProcessed {
        epoch: u64,
        offset: Option<u32>,
        account_id: AccountId,
        response: CanaryProcessed,
    },
    OutputsReceived {
        epoch: u64,
        offset: Option<u32>,
        found_outputs: Vec<Output>,
    },
}

impl BlockEvent {
    fn epoch(&self) -> u64 {
        match self {
            BlockEvent::CanaryProcessed { epoch, .. } => *epoch,
            BlockEvent::OutputsReceived { epoch, .. } => *epoch,
        }
    }

    fn offset(&self) -> Option<u32> {
        match self {
            BlockEvent::CanaryProcessed { offset, .. } => *offset,
            BlockEvent::OutputsReceived { offset, .. } => *offset,
        }
    }
}

#[derive(Debug)]
pub enum ReplicationOutEvent {
    FullBlock {
        block: LightBlock,
        outputs: Vec<Output>,
    },
    CanaryList {
        canaries: Vec<Canary>,
        outputs: Vec<Hash>,
        tx: oneshot::Sender<CanaryProcessed>,
    },
}

#[derive(Debug)]
pub enum AccountBlockState {
    Pending,
    Resolved { outputs: Vec<(u32, Hash)> },
}

/// Pipeline of block processing,
#[derive(Debug)]
pub enum BlockState<B> {
    BugState,
    WaitCanaryValidate {
        block: B,
        accounts: HashMap<AccountId, AccountBlockState>,
    },
    BlockPending {
        block: B,
        outputs: Vec<Output>,
        pending_outputs: HashMap<Hash, u32>,
        deadline: Instant,
    },
    BlockReady {
        block: B,
        outputs: Vec<Output>,
    },
}

impl<B> BlockState<B> {
    fn init(block: B, accounts: Vec<AccountId>) -> BlockState<B> {
        BlockState::WaitCanaryValidate {
            block,
            accounts: accounts
                .into_iter()
                .map(|k| (k, AccountBlockState::Pending))
                .collect(),
        }
    }

    fn block(&self) -> &B {
        match self {
            BlockState::BlockPending { ref block, .. } => block,
            BlockState::BlockReady { ref block, .. } => block,
            BlockState::WaitCanaryValidate { ref block, .. } => block,
            BlockState::BugState => unreachable!(),
        }
    }
}

pub struct ReplicationBlockCollector {
    replication: Replication,
    pending_blocks: VecDeque<BlockState<LightMacroBlock>>,
    micro_blocks: VecDeque<BlockState<LightMicroBlock>>,
    chain_cfg: ChainConfig,

    replication_responses: stream::FuturesUnordered<
        Box<dyn Future<Output = Result<BlockEvent, oneshot::Canceled>> + Unpin + Send>,
    >,

    timer: tokio::time::Interval,
}

impl ReplicationBlockCollector {
    fn new(chain_cfg: ChainConfig, replication: Replication) -> Self {
        Self {
            replication,
            pending_blocks: VecDeque::new(),
            micro_blocks: VecDeque::new(),
            chain_cfg,
            replication_responses: stream::FuturesUnordered::new(),
            timer: tokio::time::interval(Duration::from_secs(2)),
        }
    }

    fn change_upstream(&mut self, error: bool) {
        self.replication.change_upstream(error)
    }

    fn first_epoch(&self) -> Option<u64> {
        self.pending_blocks.front().map(|b| b.block().header.epoch)
    }

    fn last_full_epoch(&self) -> Option<u64> {
        self.pending_blocks.back().map(|b| b.block().header.epoch)
    }

    fn first_offset(&self) -> Option<u32> {
        self.micro_blocks.front().map(|b| b.block().header.offset)
    }

    fn block_process_event<B: BlockInfo>(
        replication: &mut Replication,
        original_block: &mut BlockState<B>,
        event: BlockEvent,
    ) {
        let state = std::mem::replace(original_block, BlockState::BugState);
        match (event, state) {
            (_, BlockState::BugState) => {
                unreachable!("Bug state should not persist between transfer")
            }
            // Process canary
            (
                BlockEvent::CanaryProcessed {
                    epoch,
                    offset,
                    account_id,
                    response,
                },
                BlockState::WaitCanaryValidate {
                    block,
                    mut accounts,
                },
            ) => {
                //
                // Contract
                //
                trace!(
                    "Block({}:{:?}) BlockEvent::CanaryProcessed event",
                    epoch,
                    offset
                );
                assert_eq!(epoch, block.epoch());
                assert_eq!(offset, block.offset());

                //
                // Buisness logic
                //
                *accounts
                    .get_mut(&account_id)
                    .expect("Account already known") = AccountBlockState::Resolved {
                    outputs: response.needed_outputs,
                };

                let mut pending_outputs = HashMap::new();
                let mut collected_outputs = Vec::new();
                let mut ready = true;
                for (_account_id, account) in &accounts {
                    match account {
                        AccountBlockState::Pending => ready = false,

                        AccountBlockState::Resolved { outputs } => {
                            for (id, hash) in outputs.clone() {
                                collected_outputs.push(id);
                                pending_outputs.insert(hash, id);
                            }
                        }
                    }
                }

                //
                // Transfer
                //
                debug!("Block({}:{:?}) ready = {}", epoch, offset, ready);
                if ready {
                    if pending_outputs.is_empty() {
                        debug!(
                            "Block({}:{:?}) WaitCanaryValidate -> BlockReady",
                            epoch, offset
                        );
                        *original_block = BlockState::BlockReady {
                            block,
                            outputs: Vec::new(),
                        };
                        return;
                    } else {
                        let deadline = if replication.try_request_outputs(
                            epoch,
                            offset.unwrap_or(std::u32::MAX),
                            collected_outputs,
                        ) {
                            Instant::now() + REPLICATION_RETRY_REQUEST
                        } else {
                            Instant::now() + REPLICATION_RETRY_ON_NO_CONNECTION
                        };
                        debug!(
                            "Block({}:{:?}) WaitCanaryValidate -> BlockPending",
                            epoch, offset
                        );
                        *original_block = BlockState::BlockPending {
                            block,
                            outputs: Vec::new(),
                            pending_outputs,
                            deadline,
                        };
                        return;
                    }
                }
                *original_block = BlockState::WaitCanaryValidate { block, accounts };
            }
            // Process outputs
            (
                BlockEvent::OutputsReceived {
                    epoch,
                    offset,
                    found_outputs,
                },
                BlockState::BlockPending {
                    block,
                    mut outputs,
                    mut pending_outputs,
                    deadline,
                },
            ) => {
                //
                // Contract
                //
                trace!(
                    "Block({}:{:?}) BlockEvent::OutputsReceived event",
                    epoch,
                    offset
                );
                assert_eq!(epoch, block.epoch());
                assert_eq!(offset, block.offset());

                //
                // Logic
                //
                for output in found_outputs {
                    let output_hash = Hash::digest(&output);
                    if pending_outputs.remove(&output_hash).is_some() {
                        trace!(
                            "BlockState::BlockPending Processing output: output_hash={}",
                            output_hash
                        );
                        outputs.push(output);
                    } else {
                        warn!(
                            "OutputsReceived with output that was not pending: output_hash={}",
                            output_hash
                        );
                    }
                }

                //
                // Transfer
                //
                let state;
                if pending_outputs.is_empty() {
                    info!("Block({}:{:?}) BlockPending -> BlockReady", epoch, offset);
                    state = BlockState::BlockReady { block, outputs };
                } else {
                    state = BlockState::BlockPending {
                        block,
                        outputs,
                        deadline,
                        pending_outputs,
                    };
                }
                *original_block = state;
            }
            (BlockEvent::OutputsReceived { .. }, state) => {
                warn!(
                    "Outdated OutputsReceived from replication, state = {:?}",
                    state
                );
                *original_block = state;
            }
            (BlockEvent::CanaryProcessed { .. }, s) => {
                // if we receive oudated CanaryProcessed event, then some account was skipped
                panic!("Outdated CanaryProcessed from replication, state = {:?}", s)
            }
        }
    }

    async fn broadcast_block(
        &mut self,
        accounts: &mut HashMap<AccountId, AccountHandle>,
        block: LightBlock,
        outputs: Vec<Output>,
    ) -> Result<(), Error> {
        for (account_id, handle) in accounts {
            if !handle.unsealed {
                continue;
            }
            trace!("Sending block to account={}", account_id);
            let event = ReplicationOutEvent::FullBlock {
                block: block.clone(),
                outputs: outputs.clone(),
            };
            if let Err(e) = handle.chain_tx.send(event).await {
                warn!("{}: account_id={}", e, account_id);
            }
        }
        Ok(())
    }

    async fn broadcast_canary(
        &mut self,
        accounts: &mut HashMap<AccountId, AccountHandle>,
        canaries: Vec<Canary>,
        outputs: Vec<Hash>,
        epoch: u64,
        offset: Option<u32>,
    ) -> Result<(), Error> {
        for (account_id, handle) in accounts {
            if !handle.unsealed {
                continue;
            }

            trace!("Sending canary to account={}", account_id);
            let (tx, rx) = oneshot::channel::<CanaryProcessed>();
            let event = ReplicationOutEvent::CanaryList {
                canaries: canaries.clone(),
                outputs: outputs.clone(),
                tx,
            };
            if let Err(e) = handle.chain_tx.send(event).await {
                warn!("{}: account_id={}", e, account_id);
            }
            let epoch = epoch.clone();
            let offset = offset.clone();
            let account_id = account_id.clone();
            self.replication_responses
                .push(Box::new(rx.map_ok(move |r| BlockEvent::CanaryProcessed {
                    response: r,
                    epoch,
                    offset,
                    account_id,
                })));
        }
        Ok(())
    }

    pub fn process_block_event(&mut self, event: BlockEvent) {
        let epoch = event.epoch();
        let offset = event.offset();
        // microblock
        if let Some(offset) = offset {
            if let Some(first_offset) = self.first_offset() {
                if first_offset > offset {
                    warn!(
                        "Received event with offset from past, our_offset = {}, event = {:?}",
                        first_offset, event
                    );
                    return;
                }
                let id = offset - first_offset;
                if let Some(block) = self.micro_blocks.get_mut(id as usize) {
                    Self::block_process_event(&mut self.replication, block, event)
                } else {
                    warn!("Not found block for event = {:?}", event);
                }
            }
        }
        // macroblock
        else if let Some(first_epoch) = self.first_epoch() {
            if first_epoch > epoch {
                warn!(
                    "Received event with epoch from past, our_epoch = {}, event = {:?}",
                    first_epoch, event
                );
                return;
            }
            let id = epoch - first_epoch;
            if let Some(block) = self.pending_blocks.get_mut(id as usize) {
                Self::block_process_event(&mut self.replication, block, event)
            } else {
                warn!("Not found block for event = {:?}", event);
            }
        }
    }

    pub fn process_timer(&mut self, now: Instant) {
        Self::process_timer_inner(&mut self.replication, self.pending_blocks.iter_mut(), now);
        Self::process_timer_inner(&mut self.replication, self.micro_blocks.iter_mut(), now);
    }

    fn process_timer_inner<'a, B: BlockInfo + 'static, I>(
        replication: &mut Replication,
        blocks: I,
        now: Instant,
    ) where
        I: Iterator<Item = &'a mut BlockState<B>>,
    {
        for block in blocks {
            match block {
                BlockState::BlockPending {
                    block,
                    pending_outputs,
                    deadline,
                    ..
                } => {
                    let epoch = block.epoch();
                    let offset = block.offset();
                    if *deadline > now {
                        continue;
                    }
                    debug!("Block({}:{:?}) process timer event event", epoch, offset);
                    let mut collected_outputs = Vec::new();

                    for (_h, id) in pending_outputs {
                        collected_outputs.push(*id);
                    }

                    // Update timers
                    let new_deadline = if replication.try_request_outputs(
                        epoch,
                        offset.unwrap_or(std::u32::MAX),
                        collected_outputs,
                    ) {
                        Instant::now() + REPLICATION_RETRY_REQUEST
                    } else {
                        Instant::now() + REPLICATION_RETRY_ON_NO_CONNECTION
                    };
                    *deadline = new_deadline;
                }
                _ => {} // ignore rest states
            }
        }
    }

    async fn process_event(
        &mut self,
        accounts: &mut HashMap<AccountId, AccountHandle>,
        event: ReplicationInEvent,
    ) -> Option<()> {
        match event {
            ReplicationInEvent::ReplicationBlock { block } => {
                debug!("Received block");
                let mut active_accounts = Vec::new();
                for (account_id, handle) in accounts.iter() {
                    if !handle.unsealed {
                        continue;
                    }
                    active_accounts.push(account_id.clone());
                }
                match block {
                    LightBlock::LightMacroBlock(b) => {
                        let epoch = b.header.epoch;
                        let canaries = b.canaries.clone();
                        let output_hashes = b.output_hashes.clone();
                        if let Some(our_epoch) = self.last_full_epoch() {
                            assert_eq!(our_epoch + 1, epoch);
                        }
                        let block = BlockState::init(b, active_accounts.clone());
                        if let Err(e) = self
                            .broadcast_canary(accounts, canaries, output_hashes, epoch, None)
                            .await
                        {
                            error!("Failed to broadcast canary = {}", e);
                        }
                        self.pending_blocks.push_back(block);
                        self.micro_blocks.clear();
                    }
                    LightBlock::LightMicroBlock(b) => {
                        let epoch = b.header.epoch;
                        let offset = b.header.offset;
                        let canaries = b.canaries.clone();
                        let output_hashes = b.output_hashes.clone();
                        if let Some(micro_block) = self.micro_blocks.back() {
                            assert_eq!(micro_block.block().header.epoch, epoch);
                            assert_eq!(micro_block.block().header.offset + 1, offset);
                        } else {
                            if let Some(our_epoch) = self.last_full_epoch() {
                                if our_epoch + 1 != epoch {
                                    warn!("First micro_block in epoch should continue our history, our_epoch={}, micro_block_epoch={}", our_epoch, epoch);
                                    return None;
                                }
                            }
                        }
                        if let Err(e) = self
                            .broadcast_canary(
                                accounts,
                                canaries,
                                output_hashes,
                                epoch,
                                Some(offset),
                            )
                            .await
                        {
                            error!("Failed to broadcast canary = {}", e);
                        }
                        debug!("Add micro block epoch = {}, offset = {}", epoch, offset);
                        let block = BlockState::init(b, active_accounts.clone());
                        self.micro_blocks.push_back(block);
                    }
                }
            }
            ReplicationInEvent::ReplicationOutputs { outputs_info } => {
                debug!("Received OutputsInfo");
                let epoch = outputs_info.block_epoch;
                let offset = if outputs_info.block_offset == std::u32::MAX {
                    None
                } else {
                    Some(outputs_info.block_offset)
                };
                let event = BlockEvent::OutputsReceived {
                    epoch,
                    offset,
                    found_outputs: outputs_info.found_outputs,
                };
                self.process_block_event(event);
            }
            ReplicationInEvent::Timer { now } => self.process_timer(now),

            ReplicationInEvent::BlockEvent { block_event } => self.process_block_event(block_event),
            ReplicationInEvent::Shutdown => return Some(()),
        }

        while let Some(BlockState::BlockReady { .. }) = self.pending_blocks.front() {
            match self.pending_blocks.pop_front() {
                Some(BlockState::BlockReady { block, outputs }) => {
                    if let Err(e) = self.broadcast_block(accounts, block.into(), outputs).await {
                        error!("Failed to broadcast block = {}", e);
                    }
                }
                s => unreachable!("Wrong state {:?}", s),
            }
        }

        if self.pending_blocks.is_empty() {
            while let Some(BlockState::BlockReady { .. }) = self.micro_blocks.front() {
                match self.micro_blocks.pop_front() {
                    Some(BlockState::BlockReady { block, outputs }) => {
                        if let Err(e) = self.broadcast_block(accounts, block.into(), outputs).await
                        {
                            error!("Failed to broadcast block = {}", e);
                        }
                    }
                    s => unreachable!("Wrong state {:?}", s),
                }
            }
        }

        None
    }

    async fn select(
        &mut self,
        accounts: &mut HashMap<AccountId, AccountHandle>,
    ) -> ReplicationInEvent {
        // Replication
        loop {
            // Sic: check that all accounts are ready before polling the replication.
            let mut current_epoch = std::u64::MAX;
            let mut current_offset = std::u32::MAX;
            let mut unsealed = false;
            for (_account_id, handle) in accounts.iter() {
                if !handle.unsealed {
                    continue;
                }
                unsealed = true;
                if handle.status.epoch <= current_epoch {
                    current_epoch = handle.status.epoch;
                    if handle.status.offset <= current_offset {
                        current_offset = handle.status.offset;
                    }
                }
            }
            if !unsealed {
                // If no unsealed accounts, wait for external events.
                let future = future::pending();
                let () = future.await;
            }

            let micro_blocks_in_epoch = self.chain_cfg.micro_blocks_in_epoch;
            let block_reader = DummyBlockReady {};
            if let Some(epoch) = self.last_full_epoch() {
                let mut epoch = epoch;
                // We processing epoch that is not full.
                if self.micro_blocks.len() > 0 {
                    epoch += 1;
                    current_offset = 0;
                }

                if epoch < current_epoch {
                    debug!("Removing all history, because wallet request history from future: current_epoch = {}, epoch_requested = {}", epoch, current_epoch);
                    self.micro_blocks.clear();
                    self.pending_blocks.clear();
                }
            }

            if let Some(epoch) = self.first_epoch() {
                if epoch < current_epoch {
                    debug!(
                        "Removed one block from queue, because it is outdated: epoch = {}",
                        epoch
                    );
                    let _block = self.pending_blocks.pop_front();
                }
            }

            // TODO: move this logic into replication.
            if let Some(b) = self.micro_blocks.back() {
                current_epoch = b.block().header.epoch;
                current_offset = b.block().header.offset + 1;
            } else if let Some(epoch) = self.last_full_epoch() {
                current_epoch = epoch + 1;
            }

            trace!(
                "Poll replication: current_epoch={}, current_offset={}",
                current_epoch,
                current_offset
            );

            let replication = &mut self.replication;
            let replication_fut = future::poll_fn(|cx| {
                replication.poll(
                    cx,
                    current_epoch,
                    current_offset,
                    micro_blocks_in_epoch,
                    &block_reader,
                )
            });
            select! {
                event = replication_fut.fuse() => match event {
                    Some(ReplicationRow::LightBlock(block)) => {
                        return ReplicationInEvent::ReplicationBlock { block, };
                    }
                    Some(ReplicationRow::OutputsInfo(outputs_info)) => {
                        return ReplicationInEvent::ReplicationOutputs { outputs_info, };
                    }
                    Some(ReplicationRow::Block(_block)) => {
                        panic!("The full block received from replication");
                    }
                    None => return ReplicationInEvent::Shutdown, // Shutdown.
                },
                notifications = self.replication_responses.next() => {
                    if let Some(event) = notifications {
                        match event {
                            Ok(block_event) => return ReplicationInEvent::BlockEvent {block_event},
                            Err(e) => panic!("{}", e)// TODO handle eeror
                        }
                    }
                }
                now = self.timer.tick().fuse() => {
                    return ReplicationInEvent::Timer { now, };
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ReplicationInEvent {
    BlockEvent { block_event: BlockEvent },
    Timer { now: Instant },
    ReplicationBlock { block: LightBlock },
    ReplicationOutputs { outputs_info: OutputsInfo },
    Shutdown,
}

trait BlockInfo: std::fmt::Debug {
    fn epoch(&self) -> u64;
    fn offset(&self) -> Option<u32>;
}

impl BlockInfo for LightMacroBlock {
    fn epoch(&self) -> u64 {
        self.header.epoch
    }
    fn offset(&self) -> Option<u32> {
        None
    }
}
impl BlockInfo for LightMicroBlock {
    fn epoch(&self) -> u64 {
        self.header.epoch
    }

    fn offset(&self) -> Option<u32> {
        Some(self.header.offset)
    }
}

#[derive(Debug, Clone)]
pub struct Wallet {
    outbox: mpsc::UnboundedSender<(WalletRequest, oneshot::Sender<WalletResponse>)>,
}

impl Wallet {
    /// Execute a Wallet Request.
    pub fn request(&self, request: WalletRequest) -> oneshot::Receiver<WalletResponse> {
        let (tx, rx) = oneshot::channel();
        self.outbox
            .unbounded_send((request, tx))
            .expect("connected");
        rx
    }
}

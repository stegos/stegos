use crate::api::*;
use crate::config::VaultConfig;

use async_trait::async_trait;
use failure::{bail, format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;

use log::*;
use rocksdb::{self, Options, DB};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use futures::select;
use futures::stream::SelectAll;
use stegos_api::load_api_token;
use stegos_api::WebSocketClient;
use stegos_api::{InnerResponses, Request, RequestKind, Response, ResponseKind};
use stegos_blockchain::api::StatusInfo;
use stegos_blockchain::Timestamp;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain::keyfile::{
    load_account_pkey, load_account_skey, write_account_pkey, write_account_skey,
};
use stegos_node::api::ChainNotification;
use stegos_node::{NodeRequest, NodeResponse};
use stegos_wallet::{
    accounts::UnsealedAccountService,
    api::{AccountNotification, AccountRequest, AccountResponse},
    Account, AccountEvent,
};

use stegos_blockchain::{
    Output, PaymentOutput, PaymentPayloadData, PaymentTransaction, PublicPaymentOutput, Transaction,
};
use stegos_crypto::scc::Fr;
use tokio::time::{Duration, Instant};

const PENDING_OUTPUTS: &'static str = "pending_outputs";

const COLON_FAMILIES: &[&'static str] = &[PENDING_OUTPUTS];

const RESUBSCRIBE_INTERVAL: Duration = Duration::from_secs(10);

// TODO: Add pending list of created outputs, in order to confirm processing.
// TODO:

type AsyncRequest = (oneshot::Sender<VaultResponse>, VaultRequest);
use crate::error::Error as VaultError;

#[derive(Clone, Debug)]
pub struct Vault {
    sender: mpsc::UnboundedSender<AsyncRequest>,
}

impl Vault {
    pub fn spawn(cfg: VaultConfig, genesis_hash: Hash) -> Vault {
        let (sender, receiver) = mpsc::unbounded();

        tokio::spawn(async move {
            let service = VaultService::new(cfg, genesis_hash, receiver)
                .await
                .unwrap();
            service.run().await
        });
        Vault { sender }
    }

    pub fn request(&self, request: VaultRequest) -> oneshot::Receiver<VaultResponse> {
        let (tx, rx) = oneshot::channel();
        self.sender.unbounded_send((tx, request)).ok();
        rx
    }
}

use std::convert::{TryFrom, TryInto};
use stegos_api::server::api::*;

impl TryFrom<RawRequest> for VaultRequest {
    type Error = Error;
    fn try_from(request: RawRequest) -> Result<VaultRequest, Self::Error> {
        match request.0.kind {
            RequestKind::Raw(req) => Ok(serde_json::from_value(req)?),
            _ => bail!("Cannot parse request as node request."),
        }
    }
}

impl TryFrom<VaultResponse> for RawResponse {
    type Error = Error;
    fn try_from(response: VaultResponse) -> Result<RawResponse, Self::Error> {
        let value = serde_json::to_value(response)?;
        Ok(RawResponse(ResponseKind::Raw(value)))
    }
}

type Subscribtion = Box<dyn Stream<Item = RawResponse> + Unpin + Send>;

#[async_trait]
impl ApiHandler for Vault {
    fn register_notification(&self) -> Vec<String> {
        vec!["subscribe".to_string()]
    }

    async fn process_request(&self, req: RawRequest) -> Result<RawResponse, Error> {
        let request: VaultRequest = req.try_into()?;
        let response = self.request(request).await?;
        Ok(response.try_into()?)
    }

    async fn try_process(
        &self,
        req: RawRequest,
        notifications: &mut SelectAll<Subscribtion>,
        is_notification: bool,
    ) -> Result<RawResponse, Error> {
        debug!(
            "calling try_process in vault api_handler, notification={}",
            is_notification
        );
        let request: VaultRequest = req.try_into()?;
        let mut response = self.request(request).await?;
        if is_notification {
            let notification = response.subscribe_to_stream()?;
            notifications.push(notification);
        }
        Ok(response.try_into()?)
    }

    fn cloned(&self) -> Box<dyn ApiHandler> {
        Box::new(self.clone())
    }
}

pub(crate) type AccountId = String;

struct AccountHandle {
    public_key: scc::PublicKey,
    secret_key: scc::SecretKey,
    account: Account,
    status: StatusInfo,
    chain_tx: mpsc::Sender<stegos_wallet::ReplicationOutEvent>,
}

struct VaultService {
    // Websocket server pipe.
    server: mpsc::UnboundedReceiver<AsyncRequest>,

    // Websocket client to online node.
    client: WebSocketClient,

    cfg: VaultConfig,
    password: String,

    handle: AccountHandle,
    account_subscribtion: mpsc::UnboundedReceiver<AccountNotification>,

    created_accounts: HashMap<AccountId, scc::PublicKey>,
    users_list: HashMap<scc::PublicKey, (AccountId, scc::SecretKey)>,

    sender: Option<(u64, mpsc::UnboundedSender<VaultNotification>)>,

    pending_updates: HashMap<Hash, UserBalanceUpdated>, // in database
    notifications_block: BTreeMap<u64, NotificationBlock>, // in database

    // RocksDB database object.
    database: rocksdb::DB,
}

impl VaultService {
    async fn new(
        cfg: VaultConfig,
        genesis_hash: Hash,
        mut server: mpsc::UnboundedReceiver<AsyncRequest>,
    ) -> Result<Self, Error> {
        let users_list = HashMap::new();
        let created_accounts = HashMap::new();
        let uri = format!("ws://{}", cfg.node_address);
        let api_token = load_api_token(&cfg.node_token_path).map_err(Error::from)?;
        let client = match WebSocketClient::new(uri, api_token).await {
            Ok(client) => client,
            Err(e) => {
                error!(
                    "Cannot connect to online node, check if {} address is available.",
                    cfg.node_address
                );
                return Err(e);
            }
        };

        let (resp, password, handle, account_subscribtion, created) = loop {
            match server
                .next()
                .await
                .expect("First request should be unseal.")
            {
                (resp, VaultRequest::Unseal { password }) => {
                    match Self::open_main_account(
                        &cfg.general.data_dir,
                        genesis_hash,
                        &cfg,
                        100,
                        password.clone(),
                    )
                    .await
                    {
                        Ok((handle, account_subscribtion, created)) => {
                            break (resp, password, handle, account_subscribtion, created)
                        }
                        Err(e) => {
                            error!("Cannot open main account = {}", e);
                            resp.send(From::from(&VaultError::Basic(e))).ok();
                        }
                    }
                }
                (resp, req) => {
                    let error =
                        VaultError::UnexpectedRequest(req, format!("expected Unseal request"));
                    resp.send(From::from(&error)).ok();
                }
            }
        };
        resp.send(VaultResponse::Unsealed { created }).ok();
        trace!("Main account oppened");

        let path = cfg.general.data_dir.join("vault_db");
        debug!("Database path = {}", path.to_string_lossy());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let database = DB::open_cf(&opts, path, COLON_FAMILIES).expect("couldn't open database");
        debug!("Loading database");

        let mut vault_service = VaultService {
            server,
            cfg,
            client,
            password,
            handle,
            users_list,
            created_accounts,
            account_subscribtion,
            sender: None,
            database,
            pending_updates: HashMap::new(),
            notifications_block: BTreeMap::new(),
        };
        vault_service.load_users()?;
        Ok(vault_service)
    }

    async fn subscribe_to_online_node(client: &mut WebSocketClient, epoch: u64) {
        info!(
            "Requesting history from online node since epoch = {}",
            epoch
        );
        let request_kind =
            RequestKind::NodeRequest(NodeRequest::SubscribeChain { epoch, offset: 0 });
        let request = Request {
            kind: request_kind,
            id: 0,
        };
        let response = client.request(request).await.unwrap();
        match response.kind {
            ResponseKind::NodeResponse(NodeResponse::SubscribedChain { .. }) => {
                info!("Successfully subscribed to online node chain notifications");
            }
            _ => {
                error!(
                    "Received wrong response for notification request = {:?}",
                    response
                );
            }
        }
    }

    async fn run(mut self) {
        Self::subscribe_to_online_node(&mut self.client, self.handle.status.epoch).await;
        let mut interval =
            tokio::time::interval_at(Instant::now() + RESUBSCRIBE_INTERVAL, RESUBSCRIBE_INTERVAL);
        loop {
            let notifications = self.client.notification();
            select! {
                res = self.server.next() => {
                    let (sender, request) = res.unwrap();
                    let response = self.handle_server(request).await;
                    let response = match response {
                        Ok(resp) => resp,
                        Err(err) => From::from(&err),
                    };
                    sender.send(response).unwrap();
                },
                node_notification = notifications.fuse() => {
                    self.handle_client(node_notification.expect("Online node should never gone.")).await;
                },
                account_notification = self.account_subscribtion.next() => {
                    let account_notification = account_notification.expect("Inner account node should never gone.");
                    self.handle_account_notification(account_notification).await;
                    interval = tokio::time::interval_at(Instant::now() + RESUBSCRIBE_INTERVAL, RESUBSCRIBE_INTERVAL);
                },
                tick = interval.tick().fuse() => {
                    debug!("Timeout while receiving for notification from node, resubscribing.");
                    Self::subscribe_to_online_node(&mut self.client, self.handle.status.epoch).await;
                }
            }

            self.broadcast_notifications().await
        }
    }

    async fn handle_account_notification(&mut self, account_notification: AccountNotification) {
        debug!("Received account notification = {:?}", account_notification);

        match account_notification {
            AccountNotification::BalanceChanged(b) => {
                let amount = b.total.available;
                self.push_balance_update(b.epoch, amount);
            }
            AccountNotification::StatusChanged(status_info) => {
                self.handle.status = status_info.clone();
                info!(
                    "Main account changed: epoch={}, offset={}",
                    status_info.epoch, status_info.offset
                );
            }
            _ => {} // ignore rest notifications
        }
    }

    async fn handle_server(&mut self, request: VaultRequest) -> Result<VaultResponse, VaultError> {
        match request {
            VaultRequest::Unseal { .. } => {
                let req = VaultRequest::Unseal {
                    password: "****".to_string(),
                };
                Err(VaultError::UnexpectedRequest(
                    req,
                    format!("account already unsealed"),
                ))
            }
            VaultRequest::CreateUser { account_id } => self.create_account(account_id),
            VaultRequest::GetUser { account_id } => self.get_user(account_id),
            VaultRequest::GetUsers { .. } => self.get_users().await,
            VaultRequest::RemoveUser { account_id, burn } => self.remove_user(account_id, burn),
            VaultRequest::Withdraw {
                public_key,
                amount,
                payment_fee,
                public,
            } => {
                self.request_withdraw(public_key, amount, payment_fee, public)
                    .await
            }
            VaultRequest::BalanceInfo {} => self.request_balance().await,
            VaultRequest::Subscribe { epoch } => self.subscribe(epoch).await,
            VaultRequest::RecoveryInfo { account_id } => self.request_recovery(account_id).await,
        }
    }

    async fn process_deposit(&mut self, epoch: u64, outputs: Vec<Output>) -> Result<(), Error> {
        const MIN_PAYMENT_FEE: i64 = 1000;

        for output in &outputs {
            let input = Hash::digest(output);
            if let Some(balance) = self.pending_update_take_by_output(&input) {
                info!(
                    "Confirmed balance update: user = {}, amount = {}",
                    balance.id, balance.amount
                );
                let notification = VaultNotificationEntry::UserDepositConfirmed(balance);
                self.push_user_updates(epoch, notification);
            }
        }

        let mut txins: HashMap<scc::PublicKey, Vec<PublicPaymentOutput>> = HashMap::new();
        for output in outputs {
            match output {
                Output::PublicPaymentOutput(p) => {
                    trace!("Found public payment output = {:?}", p);
                    if self.users_list.get(&p.recipient).is_some() {
                        info!(
                            "Found output that belong to user: public_key={}, amount={}",
                            p.recipient, p.amount
                        );
                        txins.entry(p.recipient).or_default().push(p)
                    }
                }
                _ => {}
            }
        }
        for (public_key, txins) in txins {
            let (id, secret_key) = self.users_list.get(&public_key).unwrap().clone();
            let (amount, data) = match handle_create_raw_tx(
                &self.database,
                txins,
                self.handle.public_key,
                secret_key,
                MIN_PAYMENT_FEE,
            ) {
                Ok(data) => data,
                Err(e) => {
                    error!("{}", e);
                    continue;
                }
            };

            let request = NodeRequest::BroadcastTransaction { data: data.clone() };
            let raw_request = Request {
                id: 0,
                kind: RequestKind::NodeRequest(request),
            };

            debug!("Broadcasting transaction trough online node.");
            let response = self.client.request(raw_request).await.unwrap();
            match response.kind {
                ResponseKind::NodeResponse(NodeResponse::BroadcastTransaction { .. }) => {
                    debug!("Successfully broadcasted transaction. Added to pending list.");
                    let update = UserBalanceUpdated {
                        public_key,
                        id,
                        amount,
                    };
                    for output in data.txouts() {
                        let output_hash = Hash::digest(&output);
                        debug!(
                            "Received balance update: hash = {}, update= {:?}",
                            output_hash, update
                        );
                        self.push_pending_update(output_hash, update.clone());
                        let notification =
                            VaultNotificationEntry::UserDepositReceived(update.clone());
                        self.push_user_updates(epoch, notification);
                    }
                }
                _ => {
                    trace!(
                        "Received wrong response for broadcast request = {:?}",
                        response
                    );
                }
            }
        }
        Ok(())
    }

    async fn handle_client(&mut self, response: Response) {
        trace!("Received new notification = {:?}", response);
        match response.kind {
            ResponseKind::ChainNotification(node_chain) => {
                if let ChainNotification::MacroBlockCommitted(block) = node_chain {
                    info!(
                        "Received new macro_block epoch={}, processing",
                        block.block.header.epoch
                    );
                    let validators = block.epoch_info.into_stakers_group();
                    if let Err(e) = self
                        .process_deposit(block.block.header.epoch, block.block.outputs.clone())
                        .await
                    {
                        error!("Failed to process deposit = {}", e)
                    }
                    let outputs = block.block.outputs.clone();
                    let light_block = block.block.into_light_macro_block(validators);
                    let event = stegos_wallet::ReplicationOutEvent::FullBlock {
                        block: light_block.into(),
                        outputs,
                    };

                    self.handle
                        .chain_tx
                        .send(event)
                        .await
                        .expect("Account should read blocks.");
                }
            }

            ResponseKind::Inner(InnerResponses::Reconnect) => {
                info!("Connection to node was recovered, trying to resubscribe.");
                Self::subscribe_to_online_node(&mut self.client, self.handle.status.epoch).await;
            }
            _ => {}
        }
    }

    async fn request_recovery(
        &mut self,
        account_id: Option<String>,
    ) -> Result<VaultResponse, VaultError> {
        let skey = match &account_id {
            None => &self.handle.secret_key,
            Some(id) => {
                let pk = if let Some(pk) = self.created_accounts.get(id) {
                    pk
                } else {
                    return Err(VaultError::AccountNotFound(id.clone()));
                };
                let (get_id, secret_key) = self.users_list.get(pk).unwrap();
                assert_eq!(id, get_id);
                secret_key
            }
        };
        let recovery = stegos_wallet::recovery::account_skey_to_recovery(skey);
        Ok(VaultResponse::Recovery {
            account_id,
            recovery,
        })
    }

    async fn request_withdraw(
        &mut self,
        recipient: scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        public: bool,
    ) -> Result<VaultResponse, VaultError> {
        let account_request = if public {
            AccountRequest::PublicPayment {
                recipient,
                amount,
                payment_fee,
                raw: true,
            }
        } else {
            AccountRequest::Payment {
                recipient,
                amount,
                payment_fee,
                comment: "Withdraw".to_string(),
                with_certificate: true,
                raw: true,
            }
        };
        let response = self.handle.account.request(account_request);
        let response = if let Ok(response) = response.await {
            response
        } else {
            return Err(VaultError::WithdrawRequestCanceled);
        };
        match response {
            AccountResponse::RawTransactionCreated { data: tx } => {
                let outputs_hashes: Vec<_> = tx.txouts().iter().map(Hash::digest).collect();

                let request = NodeRequest::BroadcastTransaction { data: tx };
                let raw_request = Request {
                    id: 0,
                    kind: RequestKind::NodeRequest(request),
                };

                debug!("Broadcasting transaction trough online node.");
                let response = self.client.request(raw_request).await.unwrap();
                match response.kind {
                    ResponseKind::NodeResponse(NodeResponse::BroadcastTransaction {
                        hash, ..
                    }) => {
                        debug!(
                            "Successfully broadcasted withdraw transaction, tx_hash = {}",
                            hash
                        );
                        Ok(VaultResponse::WithdrawCreated { outputs_hashes })
                    }
                    _ => Err(format_err!(
                        "Received wrong response for broadcast request = {:?}",
                        response
                    )
                    .into()),
                }
            }
            response => return Err(VaultError::UnexpectedResponse(format!("{:?}", response))),
        }
    }

    // Get pending update by output_hash
    fn pending_update_take_by_output(&mut self, output_hash: &Hash) -> Option<UserBalanceUpdated> {
        self.pending_updates.remove(output_hash)
    }

    // Get pending update by output_hash
    fn push_pending_update(&mut self, output_hash: Hash, balance: UserBalanceUpdated) {
        self.pending_updates.insert(output_hash, balance);
    }

    async fn broadcast_notifications(&mut self) {
        let current_epoch = self.handle.status.epoch;
        if let Some((sender_epoch, sender)) = &mut self.sender {
            let last_epoch = *sender_epoch + 1;
            if last_epoch >= current_epoch {
                return;
            }
            for (epoch, block) in self.notifications_block.range(last_epoch..=current_epoch) {
                *sender_epoch = *epoch;
                debug!(
                    "Sending notification: epoch={}, notification={:?}",
                    epoch, block
                );
                let notification = VaultNotification::BlockProcessed {
                    epoch: *epoch,
                    notification: block.clone(),
                };
                if let Err(e) = sender.send(notification).await {
                    error!(
                        "Cannot send notification to client, removing sender: error = {}",
                        e
                    );
                    self.sender = None;
                    break;
                }
            }
        } else {
            debug!("Ignoring notification processing, client was not found.");
        }
    }

    // Set balance changed in specific epoch.
    fn push_balance_update(&mut self, epoch: u64, amount: i64) {
        self.notifications_block
            .entry(epoch)
            .or_insert(NotificationBlock {
                list: Vec::new(),
                amount: None,
            })
            .amount = Some(amount);
    }

    // Push new update for specific block
    fn push_user_updates(&mut self, epoch: u64, notification: VaultNotificationEntry) {
        self.notifications_block
            .entry(epoch)
            .or_insert(NotificationBlock {
                list: Vec::new(),
                amount: None,
            })
            .list
            .push(notification)
    }

    async fn subscribe(&mut self, epoch: u64) -> Result<VaultResponse, VaultError> {
        let (tx, rx) = mpsc::unbounded();
        if let Some(sender) = &mut self.sender {
            debug!("Found old notification, disconnecting");
            let error = VaultError::OnlySingleNotificationAllowed;
            let _ok_or_ignore = sender
                .1
                .send(VaultNotification::Disconnected {
                    code: error.code(),
                    error: error.to_string(),
                })
                .await;
        }
        self.sender = Some((epoch, tx));
        Ok(VaultResponse::Subscribed { rx: rx.into() })
    }

    fn remove_user(
        &mut self,
        account_id: AccountId,
        _burn: bool,
    ) -> Result<VaultResponse, VaultError> {
        let account_dir = self.accounts_dir().join(&account_id);

        if !account_dir.exists() {
            return Err(VaultError::AccountNotFound(account_id));
        }
        if let Some(public_key) = self.created_accounts.remove(&account_id) {
            self.users_list.remove(&public_key);
            let suffix = Timestamp::now()
                .duration_since(Timestamp::UNIX_EPOCH)
                .as_secs();

            let trash_dir = self.cfg.general.data_dir.join(".trash");

            if !trash_dir.exists() {
                fs::create_dir_all(&trash_dir).map_err(Error::from)?;
            }
            let account_dir_bkp = trash_dir.join(format!("{}-{}", &account_id, suffix));
            warn!("Renaming {:?} to {:?}", account_dir, account_dir_bkp);
            fs::rename(account_dir, account_dir_bkp).map_err(Error::from)?;
            return Ok(VaultResponse::RemovedUser {
                account_id,
                public_key,
            });
        } else {
            return Err(VaultError::AccountNotFound(account_id));
        }
    }

    fn create_account(&mut self, account_id: String) -> Result<VaultResponse, VaultError> {
        if account_exist(&self.accounts_dir(), &account_id) {
            return Err(VaultError::AlreadyExist(account_id));
        }

        let (account_skey, account_pkey) = generate_keypair(&self.handle.secret_key, &account_id);
        create_keypair(
            &self.accounts_dir(),
            account_skey,
            account_pkey,
            account_id.clone(),
            &self.password,
        )?;
        self.register_account(account_id.clone(), account_pkey, account_skey)?;
        Ok(VaultResponse::CreatedUser { account_id })
    }

    fn get_user(&mut self, account_id: String) -> Result<VaultResponse, VaultError> {
        match self.created_accounts.get(&account_id).take() {
            None => Err(VaultError::AccountNotFound(account_id)),
            Some(&public_key) => Ok(VaultResponse::GetUser {
                account_id,
                public_key,
            }),
        }
    }

    async fn request_balance(&mut self) -> Result<VaultResponse, VaultError> {
        let account_request = AccountRequest::BalanceInfo {};
        let response = self.handle.account.request(account_request);
        let response = if let Ok(response) = response.await {
            response
        } else {
            return Err(VaultError::WithdrawRequestCanceled);
        };

        match response {
            AccountResponse::BalanceInfo(balance) => Ok(VaultResponse::BalanceInfo {
                main: self.handle.public_key,
                amount: balance.total.available,
                confirmed_epoch: self.handle.status.epoch,
            }),
            response => return Err(VaultError::UnexpectedResponse(format!("{:?}", response))),
        }
    }

    async fn get_users(&mut self) -> Result<VaultResponse, VaultError> {
        let main = self.handle.public_key;
        let list = self
            .created_accounts
            .iter()
            .map(|(id, pkey)| AccountInfo {
                account_id: id.clone(),
                public_key: pkey.clone(),
            })
            .collect();
        Ok(VaultResponse::GetUsers { main, list })
    }

    fn accounts_dir(&self) -> PathBuf {
        self.cfg.general.data_dir.join("users")
    }

    fn load_users(&mut self) -> Result<(), Error> {
        let accounts_dir = self.accounts_dir();
        if !accounts_dir.exists() {
            fs::create_dir_all(&accounts_dir)?;
        }
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
            let account_pkey = match load_account_pkey(&account_pkey_file) {
                Ok(account_pkey) => account_pkey,
                Err(e) => {
                    warn!("Cannot open file {:?} = {}", account_pkey_file, e);
                    continue;
                }
            };

            let account_skey = match load_account_skey(&account_skey_file, &self.password) {
                Ok(account_pkey) => account_pkey,
                Err(e) => {
                    warn!("Cannot open file {:?} = {}", account_skey_file, e);
                    continue;
                }
            };

            // Extract account name.
            let account_id: String = match entry.file_name().into_string() {
                Ok(id) => id,
                Err(os_string) => {
                    warn!("Invalid folder name: folder={:?}", os_string);
                    continue;
                }
            };

            if self.created_accounts.get(&account_id).is_some() {
                error!(
                    "Dublicate account_id found: account_id={}, folder={:?}",
                    account_id, entry
                );
                continue;
            }

            if self.users_list.get(&account_pkey).is_some() {
                error!(
                    "Dublicate found: account_id={}, account_pkey={}, folder={:?}",
                    account_id, account_pkey, entry
                );
                continue;
            }

            self.register_account(account_id, account_pkey, account_skey)?;
        }
        Ok(())
    }

    fn register_account(
        &mut self,
        account_id: String,
        account_pkey: scc::PublicKey,
        account_skey: scc::SecretKey,
    ) -> Result<(), VaultError> {
        if self.created_accounts.get(&account_id).is_some() {
            return Err(
                format_err!("Dublicate account_id found: account_id={}", account_id).into(),
            );
        }

        if self.users_list.get(&account_pkey).is_some() {
            return Err(format_err!(
                "Dublicate found: account_id={}, account_pkey={}",
                account_id,
                account_pkey
            )
            .into());
        }
        info!(
            "Loaded user account: account_id={}, account_pkey={}",
            account_id, account_pkey
        );

        assert!(self
            .created_accounts
            .insert(account_id.clone(), account_pkey)
            .is_none());
        assert!(self
            .users_list
            .insert(account_pkey, (account_id, account_skey))
            .is_none());
        Ok(())
    }

    ///
    /// Open existing account.
    ///
    async fn open_main_account(
        data_dir: &Path,
        genesis_hash: Hash,
        cfg: &VaultConfig,
        max_inputs_in_tx: usize,
        password: String,
    ) -> Result<
        (
            AccountHandle,
            mpsc::UnboundedReceiver<AccountNotification>,
            bool,
        ),
        Error,
    > {
        let account_dir = data_dir.join("master");

        let account_database_dir = account_dir.join("lightdb");
        let account_pkey_file = account_dir.join("account.pkey");
        let account_skey_file = account_dir.join("account.skey");
        let mut new = false;
        if !account_pkey_file.exists() {
            fs::create_dir_all(&account_dir)?;
            let (skey, pkey) = scc::make_random_keys();
            write_account_pkey(&account_pkey_file, &pkey)?;
            write_account_skey(&account_skey_file, &skey, &password)?;
            new = true;
        }

        let account_pkey = load_account_pkey(&account_pkey_file)?;
        let account_skey = load_account_skey(&account_skey_file, &password)?;
        debug!("Found master account  pkey={}", account_pkey);

        // Initialize fake network
        let (network_skey, network_pkey) = pbc::make_random_keys();
        let mut network_config = stegos_network::NetworkConfig::default();
        network_config.min_connections = 0;
        network_config.max_connections = 0;
        network_config.readiness_threshold = 0;

        let (network, network_service, _peer_id, _replication_rx) =
            stegos_network::Libp2pNetwork::new(
                network_config,
                stegos_network::NetworkName::from_str("dev").unwrap(),
                network_skey.clone(),
                network_pkey.clone(),
            )
            .await?;

        tokio::spawn(network_service);

        // TODO: determine optimal block size.
        let (chain_tx, chain_notifications) = mpsc::channel(2);
        let subscribers: Vec<mpsc::UnboundedSender<AccountNotification>> = Vec::new();
        let (outbox, events) = mpsc::unbounded::<AccountEvent>();

        let mut unsealed = UnsealedAccountService::new(
            account_database_dir,
            account_dir,
            account_skey.clone(),
            account_pkey,
            network_skey,
            network_pkey,
            network,
            genesis_hash,
            cfg.chain_cfg.clone(),
            max_inputs_in_tx,
            subscribers,
            events,
            chain_notifications,
        );
        let epoch = unsealed.last_epoch();

        let account = Account { outbox };
        let account_notifications = account.subscribe();

        let handle = AccountHandle {
            public_key: account_pkey,
            secret_key: account_skey,
            account,
            status: StatusInfo {
                is_synchronized: false,
                epoch,
                offset: 0,
                view_change: 0,
                last_block_hash: Hash::zero(),
                last_macro_block_hash: Hash::zero(),
                last_macro_block_timestamp: Timestamp::now(),
                local_timestamp: Timestamp::now(),
            },
            chain_tx,
        };
        tokio::spawn(async move {
            unsealed.process().await;
            error!("Account closed.");
            std::process::abort();
        });
        Ok((handle, account_notifications, new))
    }
}

fn generate_keypair(
    master_skey: &scc::SecretKey,
    account_id: &str,
) -> (scc::SecretKey, scc::PublicKey) {
    let seed = Hash::digest_chain(&[&master_skey, &account_id]).bits();
    scc::make_deterministic_keys(&seed)
}

fn account_exist(accounts_dir: &Path, account_id: &str) -> bool {
    let account_dir = accounts_dir.join(account_id);
    let account_skey_file = account_dir.join("account.skey");
    let account_pkey_file = account_dir.join("account.pkey");
    account_skey_file.exists() || account_pkey_file.exists()
}
///
/// Create a new account for provided keys.
///
fn create_keypair(
    accounts_dir: &Path,
    account_skey: scc::SecretKey,
    account_pkey: scc::PublicKey,
    account_id: String,
    password: &str,
) -> Result<(), Error> {
    let account_dir = accounts_dir.join(account_id);
    debug!("Creating keypair at: {:?}", account_dir);

    fs::create_dir_all(&account_dir)?;

    let account_skey_file = account_dir.join("account.skey");
    let account_pkey_file = account_dir.join("account.pkey");

    write_account_pkey(&account_pkey_file, &account_pkey)?;
    write_account_skey(&account_skey_file, &account_skey, password)?;
    Ok(())
}

fn handle_create_raw_tx(
    _database: &rocksdb::DB,
    txins: Vec<PublicPaymentOutput>,
    recipient: scc::PublicKey,
    account_secret_key: scc::SecretKey,
    fee: i64,
) -> Result<(i64, Transaction), Error> {
    let mut amount = 0;
    let mut inputs = Vec::new();
    for input in txins {
        amount += input.amount;
        inputs.push(input.into());
    }
    if amount < fee {
        bail!("Failed to create tx, amount is too small {}.", amount)
    }
    let value = amount - fee;

    let mut outputs_gamma = Fr::zero();
    let mut outputs = Vec::new();
    let (output, gamma, _) = PaymentOutput::with_payload(
        None,
        &recipient,
        value,
        PaymentPayloadData::Comment("Transfer to cold storage".to_string()),
    )?;
    outputs_gamma = outputs_gamma + gamma;
    outputs.push(output.into());

    let tx = PaymentTransaction::new(&account_secret_key, &inputs, &outputs, &outputs_gamma, fee)?;
    Ok((amount, tx.into()))
}

use crate::api::*;
use crate::config::VaultConfig;

use async_trait::async_trait;
use failure::{bail, format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;

use log::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use stegos_api::load_api_token;
use stegos_api::WebSocketClient;
use stegos_blockchain::Timestamp;
use stegos_blockchain::{api::StatusInfo, LightBlock};
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain::keyfile::{
    load_account_pkey, load_account_skey, load_network_keypair, write_account_pkey,
    write_account_skey,
};
use stegos_wallet::{
    accounts::UnsealedAccountService, api::AccountNotification, Account, AccountEvent,
};

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
use stegos_api::{RequestKind, ResponseKind};

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

#[async_trait]
impl ApiHandler for Vault {
    async fn try_process(&self, req: RawRequest) -> Result<RawResponse, Error> {
        let request: VaultRequest = req.try_into()?;
        let response = self.request(request).await?;
        Ok(response.try_into()?)
    }

    fn cloned(&self) -> Box<dyn ApiHandler> {
        Box::new(self.clone())
    }
}

pub(crate) type AccountId = String;

struct AccountHandle {
    account_pkey: scc::PublicKey,
    account: Account,
    status: StatusInfo,
    chain_tx: mpsc::Sender<LightBlock>,
}

struct VaultService {
    // Websocket server pipe.
    server: mpsc::UnboundedReceiver<AsyncRequest>,

    // Websocket client to online node.
    client: WebSocketClient,

    cfg: VaultConfig,
    genesis_hash: Hash,
    password: String,
    public_key: scc::PublicKey,
    secret_key: scc::SecretKey,

    handle: AccountHandle,
    account_subscribtion: mpsc::UnboundedReceiver<AccountNotification>,

    created_accounts: HashMap<AccountId, scc::PublicKey>,
    users_list: HashMap<scc::PublicKey, scc::SecretKey>,
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
        let client = WebSocketClient::new(uri, api_token).await?;

        let (resp, password) = match server
            .next()
            .await
            .expect("First request should be unseal.")
        {
            (resp, VaultRequest::Unseal { password }) => (resp, password),
            (resp, req) => {
                let error = VaultError::UnexpectedRequest(req, format!("expected Unseal request"));
                resp.send(From::from(&error)).ok();
                return Err(error.into());
            }
        };

        let (public_key, secret_key, handle, account_subscribtion, created) =
            Self::open_main_account(
                &cfg.general.data_dir,
                genesis_hash,
                &cfg,
                100,
                password.clone(),
            )
            .await?;
        trace!("Opened main account");
        let mut vault_service = VaultService {
            server,
            cfg,
            genesis_hash,
            client,
            password,
            public_key,
            secret_key,
            handle,
            users_list,
            created_accounts,
            account_subscribtion,
        };
        vault_service.load_users()?;
        resp.send(VaultResponse::Unsealed { created }).ok();
        Ok(vault_service)
    }

    async fn run(mut self) {
        loop {
            let (sender, request) = self.server.next().await.expect("Server stream closed.");
            let response = match request {
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

                VaultRequest::GetUsers { .. } => self.get_users(),

                VaultRequest::RemoveUser { account_id, burn } => {
                    Err(VaultError::Basic(format_err!("unimplemented")))
                }

                VaultRequest::Withdraw { public_key, amount } => {
                    Err(VaultError::Basic(format_err!("unimplemented")))
                }
            };
            let response = match response {
                Ok(resp) => resp,
                Err(err) => From::from(&err),
            };

            sender.send(response).unwrap();
        }
    }

    fn create_account(&mut self, account_id: String) -> Result<VaultResponse, VaultError> {
        if account_exist(&self.accounts_dir(), &account_id) {
            return Err(VaultError::AlreadyExist(account_id));
        }

        let (account_skey, account_pkey) = generate_keypair(&self.secret_key, &account_id);
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

    fn get_users(&mut self) -> Result<VaultResponse, VaultError> {
        let main = self.public_key;
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

            self.register_account(account_id, account_pkey, account_skey);
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
            .insert(account_id, account_pkey)
            .is_none());
        assert!(self.users_list.insert(account_pkey, account_skey).is_none());
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
            scc::PublicKey,
            scc::SecretKey,
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

        let (network, network_service, _peer_id, replication_rx) =
            stegos_network::Libp2pNetwork::new(
                network_config,
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

        let account = Account { outbox };
        let account_notifications = account.subscribe();

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
            chain_tx,
        };
        tokio::spawn(async move {
            unsealed.process().await;
            error!("Account closed.");
            std::process::abort();
        });
        Ok((
            account_pkey,
            account_skey,
            handle,
            account_notifications,
            new,
        ))
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

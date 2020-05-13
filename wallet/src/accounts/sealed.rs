//! Sealed Account.

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

use super::unsealed::{UnsealedAccountResult, UnsealedAccountService};
use crate::api::*;
use crate::ReplicationOutEvent;
use crate::{Account, AccountEvent};
use futures::channel::mpsc;
use futures::prelude::*;
use log::*;
use std::path::{Path, PathBuf};
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::keyfile::load_account_pkey;
use stegos_keychain::KeyError;
use stegos_network::Network;

pub struct SealedAccountService {
    /// Path to database dir.
    database_dir: PathBuf,
    /// Path to account directory.
    account_dir: PathBuf,
    /// Account Public Key.
    account_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Genesis header.
    genesis_hash: Hash,
    /// Chain configuration.
    chain_cfg: ChainConfig,
    /// Maximum allowed count of input UTXOs
    max_inputs_in_tx: usize,

    /// Network API (shared).
    network: Network,

    //
    // Api subscribers
    //
    subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
    /// Incoming events.
    events: mpsc::UnboundedReceiver<AccountEvent>,
    /// Incoming blocks.
    chain_notifications: mpsc::Receiver<ReplicationOutEvent>,
}

impl SealedAccountService {
    pub(crate) fn from_file(
        database_dir: &Path,
        account_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        genesis_hash: Hash,
        chain_cfg: ChainConfig,
        max_inputs_in_tx: usize,
        chain_notifications: mpsc::Receiver<ReplicationOutEvent>,
    ) -> Result<(Self, Account), KeyError> {
        let account_pkey_file = account_dir.join("account.pkey");
        let account_pkey = load_account_pkey(&account_pkey_file)?;
        let subscribers: Vec<mpsc::UnboundedSender<AccountNotification>> = Vec::new();
        let (outbox, events) = mpsc::unbounded::<AccountEvent>();
        let service = Self::new(
            database_dir.to_path_buf(),
            account_dir.to_path_buf(),
            account_pkey,
            network_skey,
            network_pkey,
            network,
            genesis_hash,
            chain_cfg,
            max_inputs_in_tx,
            subscribers,
            events,
            chain_notifications,
        );
        let api = Account { outbox };
        Ok((service, api))
    }

    fn new(
        database_dir: PathBuf,
        account_dir: PathBuf,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        genesis_hash: Hash,
        chain_cfg: ChainConfig,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
        chain_notifications: mpsc::Receiver<ReplicationOutEvent>,
    ) -> Self {
        let mut service = SealedAccountService {
            database_dir,
            account_dir,
            account_pkey,
            network_skey,
            network_pkey,
            genesis_hash,
            chain_cfg,
            max_inputs_in_tx,
            network,
            subscribers,
            events,
            chain_notifications,
        };
        service.notify(AccountNotification::Sealed);
        service
    }

    fn load_secret_key(&self, password: &str) -> Result<scc::SecretKey, KeyError> {
        let account_skey_file = self.account_dir.join("account.skey");
        let account_skey = keychain::keyfile::load_account_skey(&account_skey_file, password)?;

        if let Err(e) = scc::check_keying(&account_skey, &self.account_pkey) {
            return Err(KeyError::InvalidKey(
                account_skey_file.to_string_lossy().to_string(),
                e,
            ));
        }
        Ok(account_skey)
    }

    fn notify(&mut self, notification: AccountNotification) {
        trace!("Created notification = {:?}", notification);
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }

    async fn process(&mut self) -> Option<scc::SecretKey> {
        loop {
            let event = self.events.next().await?;
            match event {
                AccountEvent::Request { request, tx } => {
                    let response = match request {
                        AccountRequest::Unseal { password } => {
                            match self.load_secret_key(&password) {
                                Ok(account_skey) => {
                                    tx.send(AccountResponse::Unsealed).ok(); // ignore errors.
                                                                             // Finish this future.
                                    return Some(account_skey);
                                }
                                Err(e) => AccountResponse::Error {
                                    error: format!("{}", e),
                                },
                            }
                        }
                        AccountRequest::AccountInfo {} => {
                            let account_info = AccountInfo {
                                account_pkey: self.account_pkey,
                                network_pkey: self.network_pkey,
                                status: Default::default(),
                            };
                            AccountResponse::AccountInfo(account_info)
                        }
                        AccountRequest::Disable {} => {
                            info!("Stopping account for future removing.");
                            return None;
                        }
                        _ => AccountResponse::Error {
                            error: "Account is sealed".to_string(),
                        },
                    };
                    tx.send(response).ok(); // ignore errors.
                }
                AccountEvent::Subscribe { tx } => {
                    self.subscribers.push(tx);
                }
            }
        }
    }

    /// Entry point for accounts.
    pub async fn entry(self) {
        let mut sealed = self;
        loop {
            // run sealed account that can unseal internally
            let account_skey = match sealed.process().await {
                Some(skey) => skey,
                None => {
                    debug!("Terminated");
                    return;
                }
            };

            info!("Unsealed account: address={}", &sealed.account_pkey);
            let mut unsealed = UnsealedAccountService::new(
                sealed.database_dir,
                sealed.account_dir,
                account_skey,
                sealed.account_pkey,
                sealed.network_skey,
                sealed.network_pkey,
                sealed.network,
                sealed.genesis_hash,
                sealed.chain_cfg,
                sealed.max_inputs_in_tx,
                sealed.subscribers,
                sealed.events,
                sealed.chain_notifications,
            );

            match unsealed.process().await {
                UnsealedAccountResult::Terminated => {
                    debug!("Terminated");
                    return;
                }
                UnsealedAccountResult::Disabled(tx) => {
                    debug!("Account disabled, feel free to remove");
                    tx.send(AccountResponse::Disabled).ok();
                    return;
                }
                UnsealedAccountResult::Sealed => {
                    info!("Sealed account: address={}", &unsealed.account_pkey);
                    sealed = SealedAccountService::new(
                        unsealed.database_dir,
                        unsealed.account_dir,
                        unsealed.account_pkey,
                        unsealed.network_skey,
                        unsealed.network_pkey,
                        unsealed.network,
                        unsealed.database.genesis_hash().clone(),
                        unsealed.database.cfg().clone(),
                        unsealed.max_inputs_in_tx,
                        unsealed.subscribers,
                        unsealed.events,
                        unsealed.chain_notifications,
                    );
                }
            }
        }
    }
}

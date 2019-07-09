//! Wallet.

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

use crate::api::{
    Account, AccountId, AccountNotification, AccountRequest, Wallet, WalletControlRequest,
    WalletControlResponse, WalletEvent, WalletRequest, WalletResponse,
};
use crate::recovery::recovery_to_account_skey;
use crate::{AccountService, WalletNotification};
use failure::Error;
use futures::future::IntoFuture;
use futures::stream::Stream;
use futures::sync::{mpsc, oneshot};
use futures::{Async, Future, Poll};
use log::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use stegos_crypto::{pbc, scc};
use stegos_keychain::keyfile::{write_account_pkey, write_account_skey};
use stegos_network::Network;
use stegos_node::Node;
use tokio::runtime::TaskExecutor;

struct AccountHandle {
    /// Wallet API.
    account: Account,
    /// Wallet Notifications.
    account_notifications: mpsc::UnboundedReceiver<AccountNotification>,
}

pub struct WalletService {
    accounts_dir: PathBuf,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    network: Network,
    node: Node,
    executor: TaskExecutor,
    stake_epochs: u64,
    accounts: HashMap<AccountId, AccountHandle>,
    subscribers: Vec<mpsc::UnboundedSender<WalletNotification>>,
    events: mpsc::UnboundedReceiver<WalletEvent>,
}

impl WalletService {
    pub fn new(
        accounts_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        executor: TaskExecutor,
        stake_epochs: u64,
    ) -> Result<(Self, Wallet), Error> {
        let (outbox, events) = mpsc::unbounded::<WalletEvent>();
        let subscribers: Vec<mpsc::UnboundedSender<WalletNotification>> = Vec::new();
        let mut service = WalletService {
            accounts_dir: accounts_dir.to_path_buf(),
            network_skey,
            network_pkey,
            network,
            node,
            executor,
            stake_epochs,
            accounts: HashMap::new(),
            subscribers,
            events,
        };

        info!("Scanning directory {:?} for account keys", accounts_dir);

        // Scan directory for accounts.
        for entry in fs::read_dir(accounts_dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            // Find a secret key.
            let account_skey_file = entry.path();
            match account_skey_file.extension() {
                Some(ext) => {
                    if ext != "skey" {
                        continue;
                    }
                }
                None => continue,
            }

            debug!("Found a potential secret key: {:?}", account_skey_file);

            // Extract account name.
            let account_id: String = match account_skey_file.file_stem() {
                Some(stem) => match stem.to_str() {
                    Some(name) => name.to_string(),
                    None => {
                        warn!("Invalid file name: file={:?}", account_skey_file);
                        continue;
                    }
                },
                None => {
                    warn!("Invalid file name: file={:?}", account_skey_file);
                    continue;
                }
            };

            debug!("Recovering account {}", account_id);
            service.open_account(&account_id)?;
            info!("Recovered account {}", account_id);
        }

        info!("Found {} account(s)", service.accounts.len());
        let api = Wallet { outbox };
        Ok((service, api))
    }

    ///
    /// Open existing account.
    ///
    fn open_account(&mut self, account_id: &str) -> Result<(), Error> {
        let account_database_dir = self.accounts_dir.join(account_id);
        let account_skey_file = self.accounts_dir.join(format!("{}.skey", account_id));
        let account_pkey_file = self.accounts_dir.join(format!("{}.pkey", account_id));
        let (account_service, account) = AccountService::new(
            &account_database_dir,
            &account_skey_file,
            &account_pkey_file,
            self.network_skey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.stake_epochs,
        )?;
        let account_notifications = account.subscribe();
        let handle = AccountHandle {
            account,
            account_notifications,
        };
        self.accounts.insert(account_id.to_string(), handle);
        self.executor.spawn(account_service);
        Ok(())
    }

    /// Find the next available account id.
    fn find_account_id(&self) -> AccountId {
        for i in 1..std::u64::MAX {
            let account_id = i.to_string();
            if !self.accounts.contains_key(&account_id) {
                return account_id;
            }
        }
        unreachable!();
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
        let account_skey_file = self.accounts_dir.join(format!("{}.skey", account_id));
        let account_pkey_file = self.accounts_dir.join(format!("{}.pkey", account_id));
        write_account_pkey(&account_pkey_file, &account_pkey)?;
        write_account_skey(&account_skey_file, &account_skey, password)?;
        self.open_account(&account_id)?;
        Ok(account_id)
    }

    fn handle_control_request(
        &mut self,
        request: WalletControlRequest,
    ) -> Result<WalletControlResponse, Error> {
        match request {
            WalletControlRequest::ListWallets {} => {
                let accounts = self.accounts.keys().cloned().collect();
                Ok(WalletControlResponse::AccountsInfo { accounts })
            }
            WalletControlRequest::CreateWallet { password } => {
                let (account_skey, account_pkey) = scc::make_random_keys();
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::RecoverWallet { recovery, password } => {
                info!("Recovering keys...");
                let account_skey = recovery_to_account_skey(&recovery)?;
                let account_pkey: scc::PublicKey = account_skey.clone().into();
                info!(
                    "Recovered a account key: pkey={}",
                    String::from(&account_pkey)
                );
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
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
                let fut = handle
                    .account
                    .request(request)
                    .into_future()
                    .map_err(|_| ())
                    .map(move |response| {
                        let r = WalletResponse::AccountResponse {
                            account_id,
                            response,
                        };
                        tx.send(r).ok(); // ignore error;
                    });
                self.executor.spawn(fut);
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
}

impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Process events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                    WalletEvent::Request { request, tx } => {
                        match request {
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
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        // Forward notifications.
        for (account_id, handle) in self.accounts.iter_mut() {
            loop {
                match handle.account_notifications.poll() {
                    Ok(Async::Ready(Some(notification))) => {
                        let notification = WalletNotification {
                            account_id: account_id.clone(),
                            notification,
                        };
                        self.subscribers
                            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                    }
                    Ok(Async::Ready(None)) => panic!("AccountService has died"),
                    Ok(Async::NotReady) => break,
                    Err(()) => unreachable!(),
                }
            }
        }

        Ok(Async::NotReady)
    }
}

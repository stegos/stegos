//! Wallet Manager.

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
    Wallet, WalletId, WalletManager, WalletManagerRequest, WalletManagerResponse,
    WalletNotification, WalletRequest, WalletsEvent, WalletsRequest, WalletsResponse,
};
use crate::recovery::recovery_to_wallet_skey;
use crate::{WalletService, WalletsNotification};
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
use stegos_keychain::keyfile::{write_wallet_pkey, write_wallet_skey};
use stegos_network::Network;
use stegos_node::Node;
use tokio::runtime::TaskExecutor;

struct WalletHandle {
    /// Wallet API.
    wallet: Wallet,
    /// Wallet Notifications.
    wallet_notifications: mpsc::UnboundedReceiver<WalletNotification>,
}

pub struct WalletManagerService {
    wallets_dir: PathBuf,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    network: Network,
    node: Node,
    executor: TaskExecutor,
    stake_epochs: u64,
    wallets: HashMap<WalletId, WalletHandle>,
    subscribers: Vec<mpsc::UnboundedSender<WalletsNotification>>,
    events: mpsc::UnboundedReceiver<WalletsEvent>,
}

impl WalletManagerService {
    pub fn new(
        wallets_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        executor: TaskExecutor,
        stake_epochs: u64,
    ) -> Result<(Self, WalletManager), Error> {
        let (outbox, events) = mpsc::unbounded::<WalletsEvent>();
        let subscribers: Vec<mpsc::UnboundedSender<WalletsNotification>> = Vec::new();
        let mut service = WalletManagerService {
            wallets_dir: wallets_dir.to_path_buf(),
            network_skey,
            network_pkey,
            network,
            node,
            executor,
            stake_epochs,
            wallets: HashMap::new(),
            subscribers,
            events,
        };

        info!("Scanning directory {:?} for wallet keys", wallets_dir);

        // Scan directory for wallets.
        for entry in fs::read_dir(wallets_dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            // Find a secret key.
            let wallet_skey_file = entry.path();
            match wallet_skey_file.extension() {
                Some(ext) => {
                    if ext != "skey" {
                        continue;
                    }
                }
                None => continue,
            }

            debug!("Found a potential secret key: {:?}", wallet_skey_file);

            // Extract wallet name.
            let wallet_id: String = match wallet_skey_file.file_stem() {
                Some(stem) => match stem.to_str() {
                    Some(name) => name.to_string(),
                    None => {
                        warn!("Invalid file name: file={:?}", wallet_skey_file);
                        continue;
                    }
                },
                None => {
                    warn!("Invalid file name: file={:?}", wallet_skey_file);
                    continue;
                }
            };

            debug!("Recovering wallet {}", wallet_id);
            service.open_wallet(&wallet_id)?;
            info!("Recovered wallet {}", wallet_id);
        }

        info!("Found {} wallet(s)", service.wallets.len());
        let api = WalletManager { outbox };
        Ok((service, api))
    }

    ///
    /// Open existing wallet.
    ///
    fn open_wallet(&mut self, wallet_id: &str) -> Result<(), Error> {
        let wallet_database_dir = self.wallets_dir.join(wallet_id);
        let wallet_skey_file = self.wallets_dir.join(format!("{}.skey", wallet_id));
        let wallet_pkey_file = self.wallets_dir.join(format!("{}.pkey", wallet_id));
        let (wallet_service, wallet) = WalletService::new(
            &wallet_database_dir,
            &wallet_skey_file,
            &wallet_pkey_file,
            self.network_skey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.stake_epochs,
        )?;
        let wallet_notifications = wallet.subscribe();
        let handle = WalletHandle {
            wallet,
            wallet_notifications,
        };
        self.wallets.insert(wallet_id.to_string(), handle);
        self.executor.spawn(wallet_service);
        Ok(())
    }

    /// Find the next available wallet id.
    fn find_wallet_id(&self) -> WalletId {
        for i in 1..std::u64::MAX {
            let wallet_id = i.to_string();
            if !self.wallets.contains_key(&wallet_id) {
                return wallet_id;
            }
        }
        unreachable!();
    }

    ///
    /// Create a new wallet for provided keys.
    ///
    fn create_wallet(
        &mut self,
        wallet_skey: scc::SecretKey,
        wallet_pkey: scc::PublicKey,
        password: &str,
    ) -> Result<WalletId, Error> {
        let wallet_id = self.find_wallet_id();
        let wallet_skey_file = self.wallets_dir.join(format!("{}.skey", wallet_id));
        let wallet_pkey_file = self.wallets_dir.join(format!("{}.pkey", wallet_id));
        write_wallet_pkey(&wallet_pkey_file, &wallet_pkey)?;
        write_wallet_skey(&wallet_skey_file, &wallet_skey, password)?;
        self.open_wallet(&wallet_id)?;
        Ok(wallet_id)
    }

    fn handle_manager_request(
        &mut self,
        request: WalletManagerRequest,
    ) -> Result<WalletManagerResponse, Error> {
        match request {
            WalletManagerRequest::ListWallets {} => {
                let wallets = self.wallets.keys().cloned().collect();
                Ok(WalletManagerResponse::WalletsInfo { wallets })
            }
            WalletManagerRequest::CreateWallet { password } => {
                let (wallet_skey, wallet_pkey) = scc::make_random_keys();
                let wallet_id = self.create_wallet(wallet_skey, wallet_pkey, &password)?;
                Ok(WalletManagerResponse::WalletCreated { wallet_id })
            }
            WalletManagerRequest::RecoverWallet { recovery, password } => {
                info!("Recovering keys...");
                let wallet_skey = recovery_to_wallet_skey(&recovery)?;
                let wallet_pkey: scc::PublicKey = wallet_skey.clone().into();
                info!(
                    "Recovered a wallet key: pkey={}",
                    String::from(&wallet_pkey)
                );
                let wallet_id = self.create_wallet(wallet_skey, wallet_pkey, &password)?;
                Ok(WalletManagerResponse::WalletCreated { wallet_id })
            }
        }
    }

    fn handle_wallet_request(
        &mut self,
        wallet_id: String,
        request: WalletRequest,
        tx: oneshot::Sender<WalletsResponse>,
    ) {
        match self.wallets.get(&wallet_id) {
            Some(handle) => {
                let fut = handle
                    .wallet
                    .request(request)
                    .into_future()
                    .map_err(|_| ())
                    .map(move |response| {
                        let r = WalletsResponse::WalletResponse {
                            wallet_id,
                            response,
                        };
                        tx.send(r).ok(); // ignore error;
                    });
                self.executor.spawn(fut);
            }
            None => {
                let r = WalletManagerResponse::Error {
                    error: format!("Unknown wallet: {}", wallet_id),
                };
                let r = WalletsResponse::WalletManagerResponse(r);
                tx.send(r).ok(); // ignore error;
            }
        }
    }
}

impl Future for WalletManagerService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Process events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletsEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                    WalletsEvent::Request { request, tx } => {
                        match request {
                            WalletsRequest::WalletManagerRequest(request) => {
                                let response = match self.handle_manager_request(request) {
                                    Ok(r) => r,
                                    Err(e) => WalletManagerResponse::Error {
                                        error: format!("{}", e),
                                    },
                                };
                                let response = WalletsResponse::WalletManagerResponse(response);
                                tx.send(response).ok(); // ignore errors.
                            }
                            WalletsRequest::WalletRequest { wallet_id, request } => {
                                self.handle_wallet_request(wallet_id, request, tx)
                            }
                        }
                    }
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        // Forward notifications.
        for (wallet_id, handle) in self.wallets.iter_mut() {
            loop {
                match handle.wallet_notifications.poll() {
                    Ok(Async::Ready(Some(notification))) => {
                        let notification = WalletsNotification {
                            wallet_id: wallet_id.clone(),
                            notification,
                        };
                        self.subscribers
                            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                    }
                    Ok(Async::Ready(None)) => panic!("Wallet has died"),
                    Ok(Async::NotReady) => break,
                    Err(()) => unreachable!(),
                }
            }
        }

        Ok(Async::NotReady)
    }
}

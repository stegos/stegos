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

#![allow(unused)]

pub use stegos_node::test::*;
mod account_transaction;
use super::Account;
use crate::{
    AccountEvent, AccountNotification, AccountResponse, AccountService, UnsealedAccountService,
};
use stegos_blockchain::{Blockchain, ChainConfig};
use stegos_crypto::scc;
use stegos_network::Network;
use tempdir::TempDir;

use crate::api::TransactionInfo;
use futures::sync::{mpsc, oneshot};
use futures::{Async, Future, Stream};
use log::info;
use stegos_node::Node;

const PASSWORD: &str = "1234";

fn genesis_accounts(s: &mut Sandbox) -> Vec<AccountSandbox> {
    let mut accounts = Vec::new();
    for i in 0..s.nodes.len() {
        let mut account = AccountSandbox::new_genesis(s, i, None);
        accounts.push(account);
    }
    accounts
}

struct AccountSandbox {
    //TODO: moove tempdir out of account sandbox
    _tmp_dir: TempDir,
    #[allow(dead_code)]
    network: Loopback,
    account: Account,
    account_service: UnsealedAccountService,
}

impl AccountSandbox {
    pub fn new(
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        keys: KeyChain,
        node: &mut NodeSandbox,
        network_service: Loopback,
        network: Network,
        path: Option<TempDir>,
    ) -> AccountSandbox {
        let temp_dir = path.unwrap_or(TempDir::new("account").unwrap());
        let temp_path = temp_dir.path();
        let network_pkey = keys.network_pkey;
        let network_skey = keys.network_skey.clone();
        let account_pkey = keys.account_pkey;
        let account_skey = keys.account_skey.clone();

        let database_dir = temp_path.join("database_path");
        let account_skey_file = temp_path.join("account.skey");
        let account_pkey_file = temp_path.join("account.pkey");

        stegos_keychain::keyfile::write_account_skey(&account_skey_file, &account_skey, PASSWORD)
            .unwrap();
        stegos_keychain::keyfile::write_account_pkey(&account_pkey_file, &account_pkey).unwrap();

        info!(
            "Wrote account key pair: skey_file={:?}, pkey_file={:?}",
            account_skey_file, account_pkey_file
        );

        let (outbox, events) = mpsc::unbounded::<AccountEvent>();
        let subscribers: Vec<mpsc::UnboundedSender<AccountNotification>> = Vec::new();
        let account_service = UnsealedAccountService::new(
            database_dir,
            account_skey_file,
            account_pkey_file,
            account_skey,
            account_pkey,
            network_skey,
            network_pkey,
            network,
            node.node.clone(),
            stake_epochs,
            max_inputs_in_tx,
            subscribers,
            events,
        );
        let account = Account { outbox };

        let mut account = AccountSandbox {
            account,
            account_service,
            network: network_service,
            _tmp_dir: temp_dir,
        };

        account.poll();
        // give node a time to process wallet recovery.
        for _ in 0..node.chain().epoch() {
            node.poll();
            account.poll();
        }

        account
    }

    pub fn new_genesis(s: &mut Sandbox, node_id: usize, path: Option<TempDir>) -> AccountSandbox {
        let stake_epochs = s.config.chain.stake_epochs;
        let max_inputs_in_tx = s.config.node.max_inputs_in_tx;
        let keys = s.keychains[node_id].clone();
        // genesis accounts should reuse the same network.

        let (network_service, network) = s.nodes[node_id].clone_network();

        let node = &mut s.nodes[node_id];
        Self::new(
            stake_epochs,
            max_inputs_in_tx,
            keys,
            node,
            network_service,
            network,
            path,
        )
    }

    pub fn poll(&mut self) {
        futures_testing::execute(
            format!("node:{}", self.account_service.network_pkey),
            |_| self.account_service.poll(),
        );
    }
}

fn get_request(mut rx: oneshot::Receiver<AccountResponse>) -> AccountResponse {
    match rx.poll() {
        Ok(Async::Ready(msg)) => return msg,
        _ => panic!("No message received in time, or error when receiving message"),
    }
}

fn get_notification(rx: &mut mpsc::UnboundedReceiver<AccountNotification>) -> AccountNotification {
    match rx.poll() {
        Ok(Async::Ready(Some(msg))) => return msg,
        _ => panic!("No message received in time, or error when receiving message"),
    }
}

fn clear_notification(rx: &mut mpsc::UnboundedReceiver<AccountNotification>) {
    loop {
        match rx.poll() {
            Ok(Async::NotReady) => break,
            Ok(Async::Ready(Some(_))) => {}
            _ => panic!("No message received in time, or error when receiving message"),
        }
    }
}

// test::
// Create regular transaction.
// check that it was not committed.
// skip_micro_block().
// check that tx was committed.

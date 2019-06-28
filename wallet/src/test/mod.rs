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

pub use stegos_node::test::*;
mod wallet_transaction;
use super::Wallet;
use crate::{WalletResponse, WalletService};
use stegos_blockchain::{Blockchain, ChainConfig};
use stegos_crypto::scc;
use stegos_network::Network;
use tempdir::TempDir;

use futures::sync::oneshot;
use futures::{Async, Future};
use log::info;
use stegos_node::Node;

const PASSWORD: &str = "1234";

fn genesis_wallets(s: &mut Sandbox) -> Vec<WalletSandbox> {
    let mut wallets = Vec::new();
    for i in 0..s.nodes.len() {
        let wallet = WalletSandbox::new_genesis(s, i);
        wallets.push(wallet);
    }
    wallets
}

struct WalletSandbox {
    //TODO: moove tempdir out of wallet sandbox
    _tmp_dir: TempDir,
    #[allow(dead_code)]
    network: Loopback,
    wallet: Wallet,
    wallet_service: WalletService,
}

impl WalletSandbox {
    pub fn new(
        stake_epochs: u64,
        keys: KeyChain,
        node: Node,
        chain: &Blockchain,
        network_service: Loopback,
        network: Network,
    ) -> WalletSandbox {
        let temp_dir = TempDir::new("wallet").unwrap();
        let network_pkey = keys.network_pkey;
        let network_skey = keys.network_skey.clone();
        let wallet_pkey = keys.wallet_pkey;
        let wallet_skey = keys.wallet_skey.clone();
        // init network
        let mut database_path = temp_dir.path().to_path_buf();

        database_path.push("database_path");
        let mut wallet_skey_path = temp_dir.path().to_path_buf();
        wallet_skey_path.push("wallet.skey");
        stegos_keychain::keyfile::write_wallet_skey(&wallet_skey_path, &wallet_skey, PASSWORD)
            .unwrap();

        info!("Wrote wallet key pair: skey_file={:?}", wallet_skey_path);

        let persistent_state = chain
            .recover_wallets(&[(&wallet_skey, &wallet_pkey)])
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let (wallet_service, wallet) = WalletService::new(
            &database_path,
            wallet_skey_path.to_str().unwrap().to_string(),
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
            network,
            node,
            stake_epochs,
            persistent_state,
        );

        WalletSandbox {
            wallet,
            wallet_service,
            network: network_service,
            _tmp_dir: temp_dir,
        }
    }

    pub fn new_genesis(s: &mut Sandbox, node_id: usize) -> WalletSandbox {
        let stake_epochs = s.config.chain.stake_epochs;
        let node = s.nodes[node_id].node.clone();
        let keys = s.keychains[node_id].clone();
        // genesis wallets should reuse the same network.
        let (network_service, network) = s.nodes[node_id].clone_network();
        Self::new(
            stake_epochs,
            keys,
            node,
            &s.nodes[node_id].chain(),
            network_service,
            network,
        )
    }

    #[allow(dead_code)]
    pub fn new_custom(s: &mut Sandbox, node_id: usize) -> WalletSandbox {
        let stake_epochs = s.config.chain.stake_epochs;
        let node = s.nodes[node_id].node.clone();
        let mut keys = s.keychains[node_id].clone();
        // change wallet keys to custom
        let (skey, pkey) = scc::make_random_keys();
        keys.wallet_pkey = pkey;
        keys.wallet_skey = skey;

        let (network_service, network) = Loopback::new();
        Self::new(
            stake_epochs,
            keys,
            node,
            &s.nodes[node_id].chain(),
            network_service,
            network,
        )
    }

    pub fn poll(&mut self) {
        futures_testing::execute(&mut self.wallet_service);
    }
}

fn get_request(mut rx: oneshot::Receiver<WalletResponse>) -> WalletResponse {
    match rx.poll() {
        Ok(Async::Ready(msg)) => return msg,
        _ => panic!("No message received in time, or error when receiving message"),
    }
}

// test::
// Create regular transaction.
// check that it was not committed.
// skip_micro_block().
// check that tx was committed.

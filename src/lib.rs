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

use failure::{format_err, Error};
use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use log::*;
use std::fs;
use std::path::PathBuf;
use stegos_api::{ApiToken, WebSocketServer};
use stegos_blockchain::{
    chain_to_prefix, initialize_chain, Blockchain, ConsistencyCheck, Timestamp,
};
use stegos_crypto::hash::Hash;
use stegos_keychain::keyfile::load_network_keys;
use stegos_network::Libp2pNetwork;
use stegos_node::{NodeConfig, NodeService};
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

fn init(
    chain_name: String,
    data_dir: String,
    api_token: String,
    api_endpoint: String,
) -> Result<(), Error> {
    let version = format!(
        "{}.{}.{} ({} {})",
        env!("VERSION_MAJOR"),
        env!("VERSION_MINOR"),
        env!("VERSION_PATCH"),
        env!("VERSION_COMMIT"),
        env!("VERSION_DATE")
    );

    let data_dir = PathBuf::from(data_dir);
    debug!(
        "Initialize stegos with data directory = {}",
        data_dir.to_string_lossy()
    );
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", data_dir, e))?
    }
    let chain_dir = data_dir.join("chain");
    if !chain_dir.exists() {
        fs::create_dir(&chain_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", chain_dir, e))?
    }
    let accounts_dir = data_dir.join("accounts");
    if !accounts_dir.exists() {
        fs::create_dir(&accounts_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", accounts_dir, e))?
    }

    stegos_crypto::set_network_prefix(chain_to_prefix(&chain_name))
        .expect("Network prefix not initialised.");

    // Initialize keychain
    let network_skey_file = data_dir.join("network.skey");
    let network_pkey_file = data_dir.join("network.pkey");
    let (network_skey, network_pkey) = load_network_keys(&network_skey_file, &network_pkey_file)?;

    let mut network_cfg: stegos_network::NetworkConfig = Default::default();

    // set pool that used for specific network
    network_cfg.seed_pool = format!("_stegos._tcp.{}.stegos.com", chain_name).to_string();
    // set dns server to cloudflare and google
    network_cfg.dns_servers.push("1.1.1.1:53".to_string());
    network_cfg.dns_servers.push("8.8.8.8:53".to_string());

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service, peer_id, replication_rx) =
        Libp2pNetwork::new(network_cfg, network_skey.clone(), network_pkey.clone())?;

    // Initialize blockchain
    let (genesis, chain_cfg) = initialize_chain(&chain_name)?;
    info!(
        "Using '{}' chain, genesis={}",
        chain_name,
        Hash::digest(&genesis)
    );
    let timestamp = Timestamp::now();
    let chain = Blockchain::new(
        chain_cfg.clone(),
        &chain_dir,
        ConsistencyCheck::None,
        genesis,
        timestamp,
    )?;

    let epoch = chain.epoch() - 1;
    // Initialize node
    let node_cfg: NodeConfig = Default::default();
    let (mut node_service, node) = NodeService::new(
        node_cfg.clone(),
        chain,
        network_skey.clone(),
        network_pkey.clone(),
        network.clone(),
        chain_name,
        peer_id,
        replication_rx,
    )?;

    // Initialize Wallet.
    let (wallet_service, wallet) = WalletService::new(
        &accounts_dir,
        network_skey,
        network_pkey,
        network.clone(),
        node.clone(),
        rt.executor(),
        chain_cfg.stake_epochs,
        node_cfg.max_inputs_in_tx,
        epoch,
    )?;
    rt.spawn(wallet_service);

    // Start WebSocket API server.
    let api_token = ApiToken::from_base64(&api_token)?;
    WebSocketServer::spawn(
        api_endpoint,
        api_token,
        rt.executor(),
        network.clone(),
        wallet.clone(),
        node.clone(),
        version,
    )?;

    node_service.init().expect("shit happens");
    rt.spawn(node_service);

    // Start main event loop
    rt.block_on(network_service)
        .expect("errors are handled earlier");

    Ok(())
}

#[cfg(target_os = "android")]
#[no_mangle]
//#![allow(non_snake_case)]
pub extern "system" fn Java_com_stegos_stegos_1wallet_Stegos_init(
    env: JNIEnv,
    _class: JClass,
    chain: JString,
    data_dir: JString,
    api_token: JString,
    api_endpoint: JString,
) -> jint {
    android_logger::init_once(android_logger::Config::default().with_min_level(Level::Trace));
    let chain: String = env.get_string(chain).unwrap().into();
    let data_dir: String = env.get_string(data_dir).unwrap().into();
    let api_token: String = env.get_string(api_token).unwrap().into();
    let api_endpoint: String = env.get_string(api_endpoint).unwrap().into();

    if let Err(e) = init(chain, data_dir, api_token, api_endpoint) {
        error!("{}", e);
        return 1;
    }

    return 0;
}

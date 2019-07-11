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

use stegos::*;

use clap;
use clap::{App, Arg, ArgMatches};
use dirs;
use failure::{format_err, Error};
use futures::stream::Stream;
use futures::Future;
use hyper::server::Server;
use hyper::service::service_fn_ok;
use log::*;
use std::path::Path;
use std::path::PathBuf;
use std::{fs, process};
use stegos_api::{load_or_create_api_token, WebSocketServer};
use stegos_blockchain::{Blockchain, Timestamp};
use stegos_crypto::pbc;
use stegos_keychain::{self as keychain, KeyError};
use stegos_network::{Libp2pNetwork, NETWORK_STATUS_TOPIC};
use stegos_node::NodeService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

use crate::report_metrics;

fn load_configuration_file(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
    // Use --config argument for configuration.
    if let Some(cfg_path) = args.value_of_os("config") {
        let cfg = config::from_file(cfg_path)?;
        return Ok(cfg);
    }

    // Use $PWD/stegos.toml for configuration.
    match config::from_file(consts::CONFIG_FILE_NAME) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    // Use ~/.config/stegos.toml for configuration.
    let cfg_path = dirs::config_dir()
        .unwrap_or(PathBuf::from(r"."))
        .join(PathBuf::from(consts::CONFIG_FILE_NAME));
    match config::from_file(cfg_path) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    Ok(Default::default())
}

pub fn load_configuration(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
    let mut cfg = load_configuration_file(args)?;
    // Override global.chain via ENV.
    if let Ok(chain) = std::env::var("STEGOS_CHAIN") {
        cfg.general.chain = chain;
    }

    // Override global.chain via command-line.
    if let Some(chain) = args.value_of("chain") {
        cfg.general.chain = chain.to_string();
    }
    // Use default SRV record for the chain
    if cfg.general.chain != "dev" && cfg.network.seed_pool == "" {
        cfg.network.seed_pool =
            format!("_stegos._tcp.{}.aws.stegos.com", cfg.general.chain).to_string();
    }

    // Disable [chain] and [node] sections for mainnet and testnet.
    let is_prod = cfg.general.chain == "mainnet" || cfg.general.chain == "testnet";
    if is_prod && cfg.chain != Default::default() {
        return Err(format_err!(
            "Can't override [chain] options for {}",
            cfg.general.chain
        ));
    }
    if is_prod && cfg.node != Default::default() {
        return Err(format_err!(
            "Can't override [node] options for {}",
            cfg.general.chain
        ));
    }

    Ok(cfg)
}

/// Load or create network keys.
fn load_network_keys(
    network_skey_file: &Path,
    network_pkey_file: &Path,
) -> Result<(pbc::SecretKey, pbc::PublicKey), KeyError> {
    if !network_skey_file.exists() && !network_pkey_file.exists() {
        debug!(
            "Can't find network keys on the disk: skey_file={}, pkey_file={}",
            network_skey_file.to_string_lossy(),
            network_pkey_file.to_string_lossy()
        );

        debug!("Generating a new network key pair...");
        let (network_skey, network_pkey) = pbc::make_random_keys();
        info!(
            "Generated a new network key pair: pkey={}",
            network_pkey.to_hex()
        );

        keychain::keyfile::write_network_pkey(&network_pkey_file, &network_pkey)?;
        keychain::keyfile::write_network_skey(&network_skey_file, &network_skey)?;
        info!(
            "Wrote network key pair to the disk: skey_file={}, pkey_file={}",
            network_skey_file.to_string_lossy(),
            network_pkey_file.to_string_lossy(),
        );

        Ok((network_skey, network_pkey))
    } else {
        debug!("Loading network keys from the disk...");
        let (network_skey, network_pkey) =
            keychain::keyfile::load_network_keypair(&network_skey_file, &network_pkey_file)?;

        Ok((network_skey, network_pkey))
    }
}

fn run() -> Result<(), Error> {
    let name = "Stegos Node";
    let version = format!(
        "{}.{}.{} ({} {})",
        env!("VERSION_MAJOR"),
        env!("VERSION_MINOR"),
        env!("VERSION_PATCH"),
        env!("VERSION_COMMIT"),
        env!("VERSION_DATE")
    );

    let args = App::new(name)
        .version(&version[..])
        .author("Stegos AG <info@stegos.com>")
        .about("Stegos is a completely anonymous and confidential cryptocurrency.")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to stegos.toml configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("chain")
                .short("n")
                .long("chain")
                .value_name("NAME")
                .help("Specify chain to use: testnet or dev")
                .takes_value(true),
        )
        .get_matches();

    // Parse configuration
    let mut cfg = load_configuration(&args)?;

    // Initialize logger
    initialize_logger(&cfg)?;

    // Print welcome message
    info!("{} {}", name, version);

    let data_dir = cfg.general.data_dir.clone();
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }
    let chain_dir = data_dir.join("chain");
    if !chain_dir.exists() {
        fs::create_dir(&chain_dir)?;
    }
    let accounts_dir = data_dir.join("accounts");
    if !accounts_dir.exists() {
        fs::create_dir(&accounts_dir)?;
    }

    // Initialize keychain
    let network_skey_file = data_dir.join("network.skey");
    let network_pkey_file = data_dir.join("network.pkey");
    let (network_skey, network_pkey) = load_network_keys(&network_skey_file, &network_pkey_file)?;

    // Resolve seed pool (works, if chain=='testent', does nothing otherwise)
    resolve_pool(&mut cfg)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service) =
        Libp2pNetwork::new(&cfg.network, network_skey.clone(), network_pkey.clone())?;

    // Start metrics exporter
    if cfg.general.prometheus_endpoint != "" {
        // Prepare HTTP service to export Prometheus metrics
        let prom_serv = || service_fn_ok(report_metrics);
        let addr = cfg.general.prometheus_endpoint.as_str().parse()?;

        let hyper_service = Server::bind(&addr)
            .serve(prom_serv)
            .map_err(|e| error!("failed to bind prometheus exporter: {}", e));

        // Run hyper server to export Prometheus metrics
        rt.spawn(hyper_service);
    }

    // Initialize blockchain
    let genesis = initialize_genesis(&cfg)?;
    let timestamp = Timestamp::now();
    let chain = Blockchain::new(
        cfg.chain.clone(),
        &chain_dir,
        cfg.general.force_check,
        genesis,
        timestamp,
    )?;

    // Initialize node
    let (mut node_service, node) = NodeService::new(
        cfg.node.clone(),
        chain,
        network_skey.clone(),
        network_pkey.clone(),
        network.clone(),
    )?;

    // Initialize Wallet.
    let (wallet_service, wallet) = WalletService::new(
        &accounts_dir,
        network_skey,
        network_pkey,
        network.clone(),
        node.clone(),
        rt.executor(),
        cfg.chain.stake_epochs,
    )?;
    rt.spawn(wallet_service);

    // Start WebSocket API server.
    if cfg.general.api_endpoint != "" {
        let token_file = data_dir.join("api.token");
        let api_token = load_or_create_api_token(&token_file)?;
        WebSocketServer::spawn(
            cfg.general.api_endpoint,
            api_token,
            rt.executor(),
            network.clone(),
            wallet.clone(),
            node.clone(),
        )?;
    }

    // Start all services when network is ready.
    let executor = rt.executor();
    let network_ready_future = network
        .subscribe(&NETWORK_STATUS_TOPIC)?
        .into_future()
        .map_err(drop)
        .and_then(move |_s| {
            info!("Network is ready");
            // TODO: how to handle errors here?
            node_service.init().expect("shit happens");
            executor.spawn(node_service);
            Ok(())
        });
    rt.spawn(network_ready_future);

    // Start main event loop
    rt.block_on(network_service)
        .expect("errors are handled earlier");

    Ok(())
}

// 2
fn main() {
    if let Err(e) = run() {
        println!("Failed with error: {}", e); // Logger can be not yet initialized.
        error!("{}", e);
        process::exit(1)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_logger;
    use tempdir::TempDir;

    #[test]
    // #[ignore]
    fn is_testnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "testnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("testnet looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            Default::default(),
            chain_dir.path(),
            true,
            genesis,
            timestamp,
        )
        .expect("testnet looks like unloadable.");
    }

    #[test]
    // #[ignore]
    fn is_devnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "devnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("devnet looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            Default::default(),
            chain_dir.path(),
            true,
            genesis,
            timestamp,
        )
        .expect("devnet looks like unloadable.");
    }

    #[test]
    fn is_dev_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "dev";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("dev looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            Default::default(),
            chain_dir.path(),
            true,
            genesis,
            timestamp,
        )
        .expect("dev looks like unloadable.");
    }

    #[test]
    fn log_test() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        trace!("This is trace output");
        debug!("This is debug output");
        info!("This is info output");
        warn!("This is warn output");
        error!("This is error output");
        assert_eq!(2 + 2, 4);
    }
}

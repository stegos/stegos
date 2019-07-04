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
use failure::Error;
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
use stegos_crypto::scc;
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

    Ok(cfg)
}

/// Load or create wallet keys.
fn load_wallet_keys(
    wallet_skey_file: &Path,
    wallet_pkey_file: &Path,
    password_file: &Path,
    recovery_file: &Path,
) -> Result<(scc::SecretKey, scc::PublicKey), KeyError> {
    if !wallet_skey_file.exists() && !wallet_pkey_file.exists() {
        debug!(
            "Can't find keys on the disk: skey_file={}, pkey_file={}",
            wallet_skey_file.to_string_lossy(),
            wallet_pkey_file.to_string_lossy()
        );

        let (wallet_skey, wallet_pkey) = if recovery_file.is_file() {
            info!("Recovering keys...");
            let wallet_skey = keychain::input::read_recovery_from_file(recovery_file)?;
            let wallet_pkey: scc::PublicKey = wallet_skey.clone().into();
            info!(
                "Recovered a wallet key: pkey={}",
                String::from(&wallet_pkey)
            );
            (wallet_skey, wallet_pkey)
        } else {
            debug!("Generating a new wallet key pair...");
            let (wallet_skey, wallet_pkey) = scc::make_random_keys();
            info!(
                "Generated a new wallet key pair: pkey={}",
                String::from(&wallet_pkey)
            );
            (wallet_skey, wallet_pkey)
        };

        let password = String::new();
        keychain::keyfile::write_wallet_pkey(&wallet_pkey_file, &wallet_pkey)?;
        keychain::keyfile::write_wallet_skey(&wallet_skey_file, &wallet_skey, &password)?;
        info!(
            "Wrote wallet key pair: skey_file={}, pkey_file={}",
            wallet_skey_file.to_string_lossy(),
            wallet_pkey_file.to_string_lossy()
        );

        Ok((wallet_skey, wallet_pkey))
    } else {
        debug!("Loading wallet keys from the disk...");
        let password = if password_file.is_file() {
            keychain::input::read_password_from_file(&password_file)?
        } else {
            String::new()
        };

        let (wallet_skey, wallet_pkey) = keychain::keyfile::load_wallet_keypair(
            &wallet_skey_file,
            &wallet_pkey_file,
            &password,
        )?;

        Ok((wallet_skey, wallet_pkey))
    }
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
            Arg::with_name("recovery-file")
                .short("r")
                .long("recovery-file")
                .help("Recover wallet from 24-word recovery phrase")
                .long_help(
                    "Recover wallet from 24-word recovery phrase. \
                     Provide a path to file which contains 24-word recovery phrase.\
                     Use '--recovery-file -' to read recovery phrase from terminal.",
                )
                .takes_value(true)
                .value_name("FILE"),
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
    let wallets_dir = data_dir.join("wallets");
    if !wallets_dir.exists() {
        fs::create_dir(&wallets_dir)?;
    }

    // Initialize keychain
    let network_skey_file = data_dir.join("network.skey");
    let network_pkey_file = data_dir.join("network.pkey");
    let (network_skey, network_pkey) = load_network_keys(&network_skey_file, &network_pkey_file)?;
    let wallet_id = 1;
    let wallet_database_dir = wallets_dir.join(format!("{}", wallet_id));
    let wallet_skey_file = wallets_dir.join(format!("{}.skey", wallet_id));
    let wallet_pkey_file = wallets_dir.join(format!("{}.pkey", wallet_id));
    let password_file = wallets_dir.join(format!("{}.pass", wallet_id));
    let recovery_file = if let Some(recovery_file) = args.value_of("recovery-file") {
        PathBuf::from(recovery_file)
    } else {
        PathBuf::new()
    };
    let (wallet_skey, wallet_pkey) = load_wallet_keys(
        &wallet_skey_file,
        &wallet_pkey_file,
        &password_file,
        &recovery_file,
    )?;

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
        &wallet_database_dir,
        &wallet_skey_file,
        wallet_skey,
        wallet_pkey,
        network_skey,
        network_pkey,
        network.clone(),
        node.clone(),
        cfg.chain.stake_epochs,
    );
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

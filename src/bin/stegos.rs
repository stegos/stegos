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

use atty;
use clap;
use clap::{App, Arg, ArgMatches};
use dirs;
use failure::Error;
use futures::stream::Stream;
use futures::Future;
use hyper::server::Server;
use hyper::service::service_fn_ok;
use hyper::{Body, Request, Response};
use log::*;
use prometheus::{self, Encoder};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use stegos_api::WebSocketAPI;
use stegos_blockchain::Blockchain;
use stegos_keychain::*;
use stegos_network::{Libp2pNetwork, NETWORK_STATUS_TOPIC};
use stegos_node::NodeService;
use stegos_txpool::TransactionPoolService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

use crate::console::*;

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

    // Password options.
    if let Some(password_file) = args.value_of("password-file") {
        cfg.keychain.password_file = password_file.to_string();
    }

    // Recovery options.
    if let Some(recovery_file) = args.value_of("recovery-file") {
        cfg.keychain.recovery_file = recovery_file.to_string();
    }

    Ok(cfg)
}

fn report_metrics(_req: Request<Body>) -> Response<Body> {
    let mut response = Response::builder();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    //
    // Calculate actual value of BLOCK_IDLE metric.
    //
    let block_local_timestamp = stegos_node::metrics::BLOCK_LOCAL_TIMESTAMP.get();
    if block_local_timestamp > 0 {
        let timestamp = stegos_node::metrics::time_to_timestamp_ms(SystemTime::now());
        stegos_node::metrics::BLOCK_IDLE.set(timestamp - block_local_timestamp);
    }
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let res = response
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    res
}

fn run() -> Result<(), Error> {
    let name = "Stegos";
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
            Arg::with_name("password-file")
                .short("p")
                .long("password-file")
                .help("Read wallet's password from a file")
                .long_help(
                    "Read wallet's password from a file. \
                     Provide a path to file which contains wallet password.\
                     Use '--password-file -' to read password from terminal.",
                )
                .takes_value(true)
                .value_name("FILE"),
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

    // Initialize keychain
    let keychain = KeyChain::new(cfg.keychain.clone())?;

    // Resolve seed pool (works, if chain=='testent', does nothing otherwise)
    resolve_pool(&mut cfg)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service) = Libp2pNetwork::new(&cfg.network, &keychain)?;

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
    let timestamp = SystemTime::now();
    let chain = Blockchain::new(cfg.chain.clone().into(), cfg.storage, genesis, timestamp)?;
    let wallet_persistent_state =
        chain.recover_wallet(&keychain.wallet_skey, &keychain.wallet_pkey)?;

    // Initialize node
    let (mut node_service, node) =
        NodeService::new(cfg.chain.clone(), chain, keychain.clone(), network.clone())?;

    // Initialize TransactionPool.
    let txpool_service = TransactionPoolService::new(&keychain, network.clone(), node.clone());

    // Initialize Wallet.
    let (wallet_service, wallet) = WalletService::new(
        keychain.clone(),
        network.clone(),
        node.clone(),
        cfg.chain.payment_fee,
        cfg.chain.stake_fee,
        cfg.chain.stake_epochs,
        wallet_persistent_state,
    );

    // Don't initialize REPL if stdin is not a TTY device
    let console_service = if atty::is(atty::Stream::Stdin) {
        // Initialize console
        Some(ConsoleService::new(
            &cfg.general,
            network.clone(),
            wallet.clone(),
            node.clone(),
        )?)
    } else {
        None
    };

    // Start WebSocket API server.
    WebSocketAPI::spawn(cfg.api, rt.executor(), wallet.clone(), node.clone())?;

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
            executor.spawn(txpool_service);
            executor.spawn(wallet_service);
            if let Some(console_service) = console_service {
                executor.spawn(console_service);
            }

            Ok(())
        });
    rt.spawn(network_ready_future);

    // Start main event loop
    rt.block_on(network_service)
        .expect("errors are handled earlier");

    Ok(())
}

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

    #[test]
    #[ignore]
    fn is_testnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "testnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("testnet looks like unloadable.");
        let timestamp = SystemTime::now();
        Blockchain::testing(Default::default(), genesis, timestamp)
            .expect("testnet looks like unloadable.");
    }

    #[test]
    #[ignore]
    fn is_devnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "devnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("devnet looks like unloadable.");
        let timestamp = SystemTime::now();
        Blockchain::testing(Default::default(), genesis, timestamp)
            .expect("devnet looks like unloadable.");
    }

    #[test]
    fn is_dev_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let mut config = config::Config::default();
        let chain = "dev";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("dev looks like unloadable.");
        let timestamp = SystemTime::now();
        Blockchain::testing(Default::default(), genesis, timestamp)
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

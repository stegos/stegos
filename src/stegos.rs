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

mod config;
mod console;
mod consts;
mod generator;
mod money;

use atty;
use clap;
use clap::{App, Arg, ArgMatches};
use dirs;
use failure::format_err;
use failure::Error;
use futures::Future;
use hyper::server::Server;
use hyper::service::service_fn_ok;
use hyper::{Body, Request, Response};
use log::*;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::{Error as LogError, Handle as LogHandle};
use prometheus::{self, Encoder};
use resolve::{config::DnsConfig, record::Srv, resolver};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use stegos_api::WebSocketAPI;
use stegos_blockchain::Block;
use stegos_crypto::hash::Hash;
use stegos_keychain::*;
use stegos_network::Libp2pNetwork;
use stegos_node::NodeService;
use stegos_serialization::traits::*;
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

fn load_configuration(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
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

fn initialize_logger(cfg: &config::Config) -> Result<LogHandle, LogError> {
    // Try to load log4rs config file
    let path = Path::new(&cfg.general.log4rs_config);
    if !cfg.general.log4rs_config.is_empty() && path.is_file() {
        match log4rs::load_config_file(path, Default::default()) {
            Ok(config) => return Ok(log4rs::init_config(config)?),
            Err(e) => {
                error!("Failed to read log4rs config file: {}", e);
                println!("Failed to read log4rs config file: {}", e);
            }
        }
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)(local)} {h({l})} [{M}] {m}{n}",
        )))
        .build();
    let config = LogConfig::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .logger(Logger::builder().build("stegos", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_blockchain", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_crypto", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_consensus", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_keychain", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_node", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_network", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_txpool", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_wallet", LevelFilter::Info))
        .build(Root::builder().appender("stdout").build(LevelFilter::Warn))
        .expect("console logger should never fail");

    Ok(log4rs::init_config(config)?)
}

fn initialize_genesis(cfg: &config::Config) -> Result<Vec<Block>, Error> {
    let (block1, block2): (&[u8], &[u8]) = match cfg.general.chain.as_ref() {
        "dev" => (
            include_bytes!("../chains/dev/genesis0.bin"),
            include_bytes!("../chains/dev/genesis1.bin"),
        ),
        "testnet" => (
            include_bytes!("../chains/testnet/genesis0.bin"),
            include_bytes!("../chains/testnet/genesis1.bin"),
        ),
        "devnet" => (
            include_bytes!("../chains/devnet/genesis0.bin"),
            include_bytes!("../chains/devnet/genesis1.bin"),
        ),
        chain @ _ => {
            return Err(format_err!("Unknown chain: {}", chain));
        }
    };
    info!("Using genesis for '{}' chain", cfg.general.chain);
    let mut blocks = Vec::<Block>::new();
    for (i, block) in [block1.as_ref(), block2.as_ref()].iter().enumerate() {
        let block = Block::from_buffer(&block)?;
        let header = block.base_header();
        info!(
            "Block #{}: hash={}, version={}",
            i,
            Hash::digest(&block),
            header.version,
        );
        blocks.push(block);
    }
    Ok(blocks)
}

fn resolve_pool(cfg: &mut config::Config) -> Result<(), Error> {
    if cfg.network.seed_pool == "" {
        return Ok(());
    }

    let config = DnsConfig::load_default()?;
    let resolver = resolver::DnsResolver::new(config)?;

    let rrs: Vec<Srv> = resolver.resolve_record(&cfg.network.seed_pool)?;

    for r in rrs.iter() {
        if let Ok(addrs) = resolver.resolve_host(&r.target) {
            for a in addrs {
                let maddr = format!("/ip4/{}/tcp/{}", a.to_string(), r.port);
                // don't try to connect to ourselves or already configured seed nodes
                if cfg.network.advertised_addresses.iter().all(|a| *a != maddr)
                    && cfg.network.seed_nodes.iter().all(|a| *a != maddr)
                {
                    info!(target: "stegos_network::ncp", "Adding node from seed pool: {}", maddr);
                    cfg.network.seed_nodes.push(maddr);
                }
            }
        }
    }
    Ok(())
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

    // Initialize genesis
    let genesis = initialize_genesis(&cfg)?;

    // Resolve seed pool (works, if chain=='testent', does nothing otherwise)
    resolve_pool(&mut cfg)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service) = Libp2pNetwork::new(&cfg.network, &keychain)?;
    rt.spawn(network_service);

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

    // Initialize node
    let (node_service, node) = NodeService::new(
        cfg.chain.clone(),
        cfg.storage,
        keychain.clone(),
        genesis,
        network.clone(),
    )?;

    // Initialize TransactionPool.
    let txpool_service = TransactionPoolService::new(&keychain, network.clone(), node.clone());
    rt.spawn(txpool_service);

    // Initialize Wallet.
    let (wallet_service, wallet) = WalletService::new(
        keychain.clone(),
        network.clone(),
        node.clone(),
        cfg.chain.payment_fee,
        cfg.chain.stake_fee,
    );
    rt.spawn(wallet_service);

    // Don't initialize REPL if stdin is not a TTY device
    if atty::is(atty::Stream::Stdin) {
        // Initialize console
        let console_service =
            ConsoleService::new(&cfg.general, network.clone(), wallet.clone(), node.clone())?;
        rt.spawn(console_service);
    }

    // Start WebSocket API server.
    WebSocketAPI::spawn(cfg.api, rt.executor(), wallet.clone(), node.clone())?;

    // Start main event loop
    rt.block_on(node_service)
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
    use futures::sync::mpsc::unbounded;
    use simple_logger;
    use stegos_network::loopback::Loopback;
    use stegos_node::{ChainConfig, NodeService};

    #[test]
    #[ignore]
    fn is_testnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let keys = KeyChain::new_mem();
        let mut config = config::Config::default();
        let chain = "testnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("testnet looks like unloadable.");
        let cfg: ChainConfig = Default::default();
        let (_loopback, network) = Loopback::new();
        let (_outbox, inbox) = unbounded();
        NodeService::testing(cfg, keys.clone(), network, genesis, inbox).unwrap();
    }

    #[test]
    #[ignore]
    fn is_devnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let keys = KeyChain::new_mem();
        let mut config = config::Config::default();
        let chain = "devnet";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("devnet looks like unloadable.");
        let cfg: ChainConfig = Default::default();
        let (_loopback, network) = Loopback::new();
        let (_outbox, inbox) = unbounded();
        NodeService::testing(cfg, keys.clone(), network, genesis, inbox).unwrap();
    }

    #[test]
    fn is_dev_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let keys = KeyChain::new_mem();
        let mut config = config::Config::default();
        let chain = "dev";
        config.general.chain = chain.to_string();
        let genesis = initialize_genesis(&config).expect("dev looks like unloadable.");
        let cfg: ChainConfig = Default::default();
        let (_loopback, network) = Loopback::new();
        let (_outbox, inbox) = unbounded();
        NodeService::testing(cfg, keys.clone(), network, genesis, inbox).unwrap();
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

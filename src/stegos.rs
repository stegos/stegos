//
// Copyright (c) 2018 Stegos
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

use atty;
use chrono::NaiveDateTime;
use clap;
use clap::{App, Arg, ArgMatches};
use dirs;
use failure::format_err;
use failure::Error;
use log::*;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::{Error as LogError, Handle as LogHandle};
use std::path::PathBuf;
use std::process;
use stegos_blockchain::Block;
use stegos_crypto::hash::Hash;
use stegos_keychain::*;
use stegos_network::Libp2pNetwork;
use stegos_node::Node;
use stegos_serialization::traits::*;
use stegos_txpool::TransactionPoolService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

use crate::console::*;

fn load_configuration(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
    let mut cfg = if let Some(cfg_path) = args.value_of_os("config") {
        // Use --config argument for configuration.
        config::from_file(cfg_path)?
    } else {
        // Use ~/.config/stegos.toml for configuration.
        let cfg_path = dirs::config_dir()
            .unwrap_or(PathBuf::from(r"."))
            .join(PathBuf::from(consts::CONFIG_FILE_NAME));
        match config::from_file(cfg_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                match e {
                    // Don't raise an error on missing configuration file.
                    config::ConfigError::NotFoundError => Default::default(),
                    _ => return Err(e.into()),
                }
            }
        }
    };

    // Override global.chain via ENV.
    if let Ok(chain) = std::env::var("STEGOS_CHAIN") {
        cfg.general.chain = chain;
    }

    // Override global.chain via command-line.
    if let Some(chain) = args.value_of("chain") {
        cfg.general.chain = chain.to_string();
    }

    Ok(cfg)
}

fn initialize_logger(cfg: &config::Config) -> Result<LogHandle, LogError> {
    // Try to load log4rs config file
    let handle = match log4rs::load_config_file(
        PathBuf::from(&cfg.general.log4rs_config),
        Default::default(),
    ) {
        Ok(config) => log4rs::init_config(config)?,
        Err(e) => {
            error!("Failed to read log4rs config file: {}", e);
            println!("Failed to read log4rs config file: {}", e);
            let stdout = ConsoleAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "{d(%Y-%m-%d %H:%M:%S)(local)} [{t}] {h({l})} {M}: {m}{n}",
                )))
                .build();
            let config = LogConfig::builder()
                .appender(Appender::builder().build("stdout", Box::new(stdout)))
                .logger(Logger::builder().build("stegos_network", LevelFilter::Debug))
                .build(Root::builder().appender("stdout").build(LevelFilter::Info))
                .expect("console logger should never fail");
            log4rs::init_config(config)?
        }
    };
    Ok(handle)
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
        chain @ _ => {
            return Err(format_err!("Unknown chain: {}", chain));
        }
    };
    info!("Using genesis for '{}' chain", cfg.general.chain);
    let mut blocks = Vec::<Block>::new();
    for (i, block) in [block1.as_ref(), block2.as_ref()].iter().enumerate() {
        let block = Block::from_buffer(&block)?;
        let header = block.base_header();
        let timestamp = NaiveDateTime::from_timestamp(header.timestamp as i64, 0);
        info!(
            "Block #{}: hash={}, version={}, timestamp={}",
            i,
            Hash::digest(&block),
            header.version,
            timestamp
        );
        blocks.push(block);
    }
    Ok(blocks)
}

fn run() -> Result<(), Error> {
    let name = "Stegos";
    let version = format!(
        "{} ({} {})",
        env!("VERGEN_SEMVER"),
        env!("VERGEN_SHA_SHORT"),
        env!("VERGEN_BUILD_DATE")
    );

    let args = App::new(name)
        .version(&version[..])
        .author("Stegos AG <info@stegos.cc>")
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
    let cfg = load_configuration(&args)?;

    // Initialize logger
    initialize_logger(&cfg)?;

    // Print welcome message
    info!("{} {}", name, version);

    // Initialize genesis
    let genesis = initialize_genesis(&cfg)?;

    // Initialize keychain
    let keychain = KeyChain::new(&cfg.keychain)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service) = Libp2pNetwork::new(&cfg.network, &keychain)?;

    // Initialize node
    let (node_service, node) = Node::new(&cfg.storage, keychain.clone(), network.clone())?;
    rt.spawn(node_service);

    // Initialize TransactionPool.
    let txpool_service = TransactionPoolService::new(&keychain, network.clone(), node.clone());
    rt.spawn(txpool_service);

    // Don't initialize REPL if stdin is not a TTY device
    if atty::is(atty::Stream::Stdin) {
        // Initialize Wallet.
        let (wallet_service, wallet) = WalletService::new(
            keychain.wallet_skey.clone(),
            keychain.wallet_pkey.clone(),
            keychain.cosi_pkey.clone(),
            network.clone(),
            node.clone(),
        );
        rt.spawn(wallet_service);

        // Initialize console
        let console_service = ConsoleService::new(network.clone(), wallet.clone())?;
        rt.spawn(console_service);
    }

    // Register genesis block.
    node.init(genesis).unwrap();

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

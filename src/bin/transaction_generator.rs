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

use crate::report_metrics;
use clap;
use clap::{App, Arg};
use failure::{format_err, Error};
use futures::Future;
use hyper::server::Server;
use hyper::service::service_fn_ok;
use log::*;
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use stegos::config::Config;
use stegos::generator::{Generator, GeneratorMode};
use stegos_blockchain::{Blockchain, Output};
use stegos_crypto::curve1174;
use stegos_crypto::pbc;
use stegos_keychain as keychain;
use stegos_network::Libp2pNetwork;
use stegos_node::NodeService;
use stegos_txpool::TransactionPoolService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

const CONFIG_NAME: &'static str = "stegos.toml";
const LOG_CONFIG_NAME: &'static str = "stegos-log4rs.toml";

pub fn load_configuration(folder: &str) -> Result<config::Config, Error> {
    let mut path = PathBuf::from(folder);
    path.push(CONFIG_NAME);
    let mut cfg = config::from_file(path)?;

    // Override global.chain via ENV.
    if let Ok(chain) = std::env::var("STEGOS_CHAIN") {
        cfg.general.chain = chain;
    }

    // Use default SRV record for the chain
    if cfg.general.chain != "dev" && cfg.network.seed_pool == "" {
        cfg.network.seed_pool =
            format!("_stegos._tcp.{}.aws.stegos.com", cfg.general.chain).to_string();
    }

    // Check password_file.
    if keychain::input::is_input_interactive(&cfg.keychain.password_file) {
        return Err(format_err!("Please set password_file"));
    }

    Ok(cfg)
}

fn load_nodes_configs<'a>(
    folders: impl Iterator<Item = &'a str>,
) -> Result<Vec<GeneratorInstance>, Error> {
    let mut instances = Vec::new();
    for folder in folders {
        // Parse configuration
        let cfg = load_configuration(&folder)?;
        let password = keychain::input::read_password_from_file(&cfg.keychain.password_file)?;
        let (wallet_skey, wallet_pkey) = keychain::keyfile::load_wallet_keypair(
            &cfg.keychain.wallet_skey_file,
            &cfg.keychain.wallet_pkey_file,
            &password,
        )?;
        let (network_skey, network_pkey) = keychain::keyfile::load_network_keypair(
            &cfg.keychain.network_skey_file,
            &cfg.keychain.network_pkey_file,
            &password,
        )?;
        let instance = GeneratorInstance {
            cfg,
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
            wallet_recover: Vec::new(),
        };
        instances.push(instance);
    }
    Ok(instances)
}

struct GeneratorInstance {
    cfg: Config,
    wallet_skey: curve1174::SecretKey,
    wallet_pkey: curve1174::PublicKey,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    wallet_recover: Vec<(Output, u64)>,
}

//TODO: run single node and network.
fn run() -> Result<(), Error> {
    let name = "stegos-generator";
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
            Arg::with_name("folders")
                .short("f")
                .long("folders")
                .value_name("FOLDERS")
                .help("Path to folders with bot config")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .value_name("MODE")
                .help("Generator mode could be one of (VS, REGULAR).")
                .default_value("REGULAR")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-config")
                .short("L")
                .long("log-config")
                .value_name("LOG_CONFIG")
                .help("Path to log config.")
                .takes_value(true),
        )
        .get_matches();

    let path = match args.value_of("log-config") {
        Some(config) => config,
        _ => LOG_CONFIG_NAME,
    };

    let mode = match args.value_of("mode").unwrap() {
        "VS" | "VALUESHUFFLE" | "VALUE_SHUFFLE" => GeneratorMode::ValueShuffle,
        _ => GeneratorMode::Regular,
    };

    let folders = args.values_of("folders").unwrap();

    // Print welcome message
    info!("{} {}", name, version);

    let mut instances = load_nodes_configs(folders)?;
    let base_instance = instances.first().expect("Expected atleast one generator.");
    let (mut base_config, network_skey, network_pkey, recipient_pkey) = (
        base_instance.cfg.clone(),
        base_instance.network_skey.clone(),
        base_instance.network_pkey.clone(),
        base_instance.wallet_pkey.clone(),
    );

    base_config.general.log4rs_config = path.to_string();

    // Initialize logger
    initialize_logger(&base_config)?;

    let mut rt = Runtime::new()?;

    // Resolve seed pool (works, if chain=='testent', does nothing otherwise)
    resolve_pool(&mut base_config)?;
    // Initialize network
    let (network, network_service) = Libp2pNetwork::new(
        &base_config.network,
        network_skey.clone(),
        network_pkey.clone(),
    )?;
    rt.spawn(network_service);

    // Start metrics exporter
    if base_config.general.prometheus_endpoint != "" {
        // Prepare HTTP service to export Prometheus metrics
        let prom_serv = || service_fn_ok(report_metrics);
        let addr = base_config.general.prometheus_endpoint.as_str().parse()?;

        let hyper_service = Server::bind(&addr)
            .serve(prom_serv)
            .map_err(|e| error!("failed to bind prometheus exporter: {}", e));

        // Run hyper server to export Prometheus metrics
        rt.spawn(hyper_service);
    }

    // Initialize blockchain
    info!("Loading blockchain.");
    let genesis = initialize_genesis(&base_config)?;
    let timestamp = SystemTime::now();
    let chain = Blockchain::new(
        base_config.chain.clone(),
        base_config.blockchain_db,
        genesis,
        timestamp,
    )?;

    info!("Recover wallets.");
    let keys: Vec<curve1174::PublicKey> = instances
        .iter()
        .map(|instance| instance.wallet_pkey)
        .collect();
    for instance in instances.iter_mut() {
        instance.wallet_recover =
            chain.recover_wallet(&instance.wallet_skey, &instance.wallet_pkey)?;
        // use single node keys.
        instance.network_skey = network_skey.clone();
        instance.network_pkey = network_pkey.clone();
        instance.cfg.general.generate_txs.extend_from_slice(&keys);
    }

    info!("Starting node service.");
    // Initialize node
    let (node_service, node) = NodeService::new(
        base_config.node.clone(),
        chain,
        recipient_pkey.clone(),
        network_skey.clone(),
        network_pkey.clone(),
        network.clone(),
    )?;

    // Initialize TransactionPool.
    let txpool_service =
        TransactionPoolService::new(network_pkey.clone(), network.clone(), node.clone());
    rt.spawn(txpool_service);

    for instance in instances {
        let cfg = instance.cfg;
        let wallet_persistent_state = instance.wallet_recover;

        info!("Starting wallet with generator.");
        // Initialize Wallet.
        let (wallet_service, wallet) = WalletService::new(
            cfg.wallet_db.database_path.as_ref(),
            cfg.keychain.wallet_skey_file,
            instance.wallet_skey,
            instance.wallet_pkey,
            instance.network_skey,
            instance.network_pkey,
            network.clone(),
            node.clone(),
            cfg.chain.stake_epochs,
            wallet_persistent_state,
        );
        rt.spawn(wallet_service);

        let bot = Generator::new(
            wallet,
            cfg.keychain.password_file.clone(),
            cfg.general.generate_txs,
            mode,
            true,
        );
        rt.spawn(bot);
    }
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

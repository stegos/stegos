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
use clap::{App, Arg};
use failure::Error;
use futures::future::select_all;
use log::*;
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use stegos::generator::Generator;
use stegos_blockchain::Blockchain;
use stegos_keychain::*;
use stegos_network::Libp2pNetwork;
use stegos_node::NodeService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;

const CONFIG_NAME: &'static str = "stegos.toml";

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

    Ok(cfg)
}

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
        .get_matches();
    // Initialize logger
    initialize_logger(&config::Config::default())?;
    let values = args.values_of("folders").unwrap();
    // Initialize network
    let mut rt = Runtime::new()?;
    let mut nodes = Vec::new();
    for folder in values {
        // Parse configuration
        let mut cfg = load_configuration(&folder)?;

        // Print welcome message
        info!("{} {}", name, version);

        // Initialize keychain
        let keychain = KeyChain::new(cfg.keychain.clone())?;

        // Resolve seed pool (works, if chain=='testent', does nothing otherwise)
        resolve_pool(&mut cfg)?;

        // Initialize blockchain
        let genesis = initialize_genesis(&cfg)?;
        let timestamp = SystemTime::now();
        let chain = Blockchain::new(cfg.chain.clone().into(), cfg.storage, genesis, timestamp)?;
        let wallet_persistent_state =
            chain.recover_wallet(&keychain.wallet_skey, &keychain.wallet_pkey)?;
        let (network, network_service) = Libp2pNetwork::new(&cfg.network, &keychain)?;
        rt.spawn(network_service);

        // Initialize node
        let (node_service, node) =
            NodeService::new(cfg.chain.clone(), chain, keychain.clone(), network.clone())?;
        nodes.push(node_service);

        // Initialize Wallet.
        let (wallet_service, wallet) = WalletService::new(
            keychain.clone(),
            network.clone(),
            node,
            cfg.chain.payment_fee,
            cfg.chain.stake_fee,
            cfg.chain.stake_epochs,
            wallet_persistent_state,
        );
        rt.spawn(wallet_service);

        let bot = Generator::new(wallet, cfg.general.generate_txs, true);
        rt.spawn(bot);
    }
    // Start main event loop
    rt.block_on(select_all(nodes))
        .map_err(drop)
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

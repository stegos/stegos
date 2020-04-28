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
#![recursion_limit = "256"]

mod config;

use clap;
use clap::ArgMatches;
use clap::{App, Arg};
use failure::Error;
use log::*;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use stegos_api::load_or_create_api_token;
use stegos_api::server::spawn_server;
use stegos_blockchain::{chain_to_prefix, initialize_chain};
use stegos_crypto::hash::Hash;
pub mod api;
pub mod error;
pub mod vault;
use vault::Vault;

const STEGOS_VAULT_TOML: &'static str = "stegos-vault.toml";

fn load_or_create_configuration_file(args: &ArgMatches<'_>) -> Result<config::VaultConfig, Error> {
    // Use --config argument for configuration.
    if let Some(cfg_path) = args.value_of_os("config") {
        let cfg = config::from_file(cfg_path)?;
        return Ok(cfg);
    }

    // Use $PWD/stegosd.toml for configuration.
    match config::from_file(STEGOS_VAULT_TOML) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    // Use ~/.config/stegos/stegosd.toml for configuration.
    let cfg_path = dirs::config_dir()
        .map(|p| p.join(r"stegos-vault"))
        .unwrap_or(PathBuf::from(r"."))
        .join(PathBuf::from(STEGOS_VAULT_TOML));

    match config::from_file(cfg_path) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    let config = config::VaultConfig::default();
    config.save(STEGOS_VAULT_TOML).unwrap();

    // Use default configuration.
    Ok(config)
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}
async fn run() -> Result<(), Error> {
    let name = "Stegos CLI".to_string();
    let version = format!(
        "{}.{}.{} ({} {})",
        env!("VERSION_MAJOR"),
        env!("VERSION_MINOR"),
        env!("VERSION_PATCH"),
        env!("VERSION_COMMIT"),
        env!("VERSION_DATE")
    );

    let default_data_dir = dirs::data_dir()
        .map(|p| p.join("stegos"))
        .unwrap_or(PathBuf::from(r"data"))
        .to_string_lossy()
        .to_string();

    let args = App::new(&name)
        .version(&version[..])
        .author("Stegos AG <info@stegos.com>")
        .about("Stegos is a completely anonymous and confidential cryptocurrency.")
        .arg(
            Arg::with_name("api-endpoint")
                .index(1)
                .short("a")
                .long("api-endpoint")
                .env("STEGOS_API_ENDPOINT")
                .value_name("ENDPOINT")
                .help("API ENDPOINT, e.g. 127.0.0.1:3145")
                .takes_value(true)
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                }),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .env("STEGOS_CONFIG")
                .value_name("FILE")
                .help("Path to stegos.toml configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api-token-file")
                .short("t")
                .long("api-token-file")
                .env("STEGOS_API_TOKEN_FILE")
                .help("A path to file, contains 16-byte API TOKEN")
                .takes_value(true)
                .value_name("FILE"),
        )
        .arg(
            Arg::with_name("remote-api-token-file")
                .short("rt")
                .long("remote-api-token-file")
                .env("STEGOS_REMOTE_API_TOKEN_FILE")
                .help(
                    "A path to file, contains 16-byte API TOKEN used for connecting to remote node",
                )
                .takes_value(true)
                .value_name("FILE"),
        )
        .arg(
            Arg::with_name("chain")
                .short("n")
                .long("chain")
                .env("STEGOS_CHAIN")
                .value_name("NAME")
                .help("Specify chain to use: testnet or dev")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("data-dir")
                .short("d")
                .long("data-dir")
                .env("STEGOS_DATA_DIR")
                .value_name("DIR")
                .help("Path to data directory, contains api.token file")
                .default_value(&default_data_dir)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .help("Change verbosity level")
                .short("v")
                .long("verbose")
                .multiple(true),
        )
        .get_matches();

    let verbosity = args.occurrences_of("verbose");
    let level = match verbosity {
        0 => log::Level::Info,
        1 => log::Level::Debug,
        2 | _ => log::Level::Trace,
    };
    simple_logger::init_with_level(level).unwrap_or_default();

    let chain = args.value_of("chain").map(ToString::to_string);

    let data_dir = PathBuf::from(args.value_of("data-dir").unwrap());
    if !data_dir.exists() {
        if let Err(e) = fs::create_dir_all(&data_dir) {
            eprintln!(
                "Failed to create data directory {:?} for \"stegos.history\": {}",
                data_dir, e
            );
            // Ignore this error.
        }
    }

    let api_token_file = if let Some(api_token_file) = args.value_of("api-token-file") {
        PathBuf::from(api_token_file)
    } else {
        data_dir.join("api.token")
    };

    let mut cfg = load_or_create_configuration_file(&args)?;
    if let Some(chain) = chain {
        info!("Overriding chain from cli chain={}", chain);
        cfg.general.chain = chain;
    }
    stegos_crypto::set_network_prefix(chain_to_prefix(&cfg.general.chain))
        .expect("Network prefix not initialised.");

    let remote_api_token_file = if let Some(api_token_file) = args.value_of("remote-api-token-file")
    {
        info!(
            "Overriding remote api token path from cli remote-api-token-file={}",
            api_token_file
        );
        PathBuf::from(api_token_file)
    } else if cfg.node_token_path != std::ffi::OsStr::new("") {
        cfg.node_token_path
    } else {
        info!(
            "Setting remote api token path to our server token file={:?}",
            api_token_file
        );
        api_token_file.clone()
    };

    if let Some(api_endpoint) = args.value_of("api-endpoint") {
        info!(
            "Overriding remote node endpoint from cli api-endpoint={}",
            api_endpoint
        );
        cfg.node_address = api_endpoint.to_string();
    }
    cfg.node_token_path = remote_api_token_file;

    let (genesis, chain_cfg) = initialize_chain(&cfg.general.chain)?;
    cfg.chain_cfg = chain_cfg;
    // Start WebSocket API server.
    if cfg.general.api_endpoint == "" {
        warn!("No endpoint provided using default 127.0.0.1:4145");
        cfg.general.api_endpoint = "127.0.0.1:4145".to_owned();
    }

    let api = Vault::spawn(cfg.clone(), Hash::digest(&genesis));
    let api_token = load_or_create_api_token(&api_token_file)?;
    let join = spawn_server(
        cfg.general.api_endpoint,
        api_token,
        vec![Box::new(api)],
        None,
        version,
        cfg.general.chain,
    )
    .await?;
    join.await?;

    Ok(())
}

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

mod console;
mod consts;

use atty;
use clap;
use clap::{App, Arg, ArgMatches};
use dirs;
use log::*;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::{Error as LogError, Handle as LogHandle};
use rustyline;
use std::error::Error;
use std::path::PathBuf;
use std::process;
use stegos_config;
use stegos_config::{Config, ConfigError};
use stegos_keychain::*;
use stegos_network::Network;
use stegos_node::{genesis_dev, Node};
use tokio::runtime::Runtime;

use crate::console::*;

fn load_configuration(args: &ArgMatches<'_>) -> Result<Config, Box<dyn Error>> {
    if let Some(cfg_path) = args.value_of_os("config") {
        // Use --config argument for configuration.
        return Ok(stegos_config::from_file(cfg_path)?);
    }

    // Use ~/.config/stegos.toml for configuration.
    let cfg_path = dirs::config_dir()
        .unwrap_or(PathBuf::from(r"."))
        .join(PathBuf::from(consts::CONFIG_FILE_NAME));
    match stegos_config::from_file(cfg_path) {
        Ok(cfg) => return Ok(cfg),
        Err(e) => {
            match e {
                // Don't raise an error on missing configuration file.
                ConfigError::NotFoundError => Ok(Default::default()),
                _ => return Err(Box::new(e)),
            }
        }
    }
}

fn initialize_logger(cfg: &Config) -> Result<LogHandle, LogError> {
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

fn run() -> Result<(), Box<dyn Error>> {
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
        .get_matches();

    // Parse configuration
    let cfg = load_configuration(&args)?;

    // Initialize logger
    initialize_logger(&cfg)?;

    // Print welcome message
    info!("{} {}", name, version);

    // Initialize keychain
    let keychain = KeyChain::new(&cfg.keychain)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service, broker) = Network::new(&cfg.network, &keychain)?;

    // Initialize node
    let genesis = genesis_dev().expect("failed to load genesis block");
    let (node_service, node) = Node::new(keychain.clone(), broker.clone())?;
    rt.spawn(node_service);

    // Don't initialize REPL if stdin is not a TTY device
    if atty::is(atty::Stream::Stdin) {
        // Initialize console
        let console_service =
            Console::new(&keychain, network.clone(), broker.clone(), node.clone())?;
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

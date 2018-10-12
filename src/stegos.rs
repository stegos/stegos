#![deny(warnings)]

mod consts;

#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
#[macro_use]
extern crate clap;
extern crate dirs;
extern crate stegos_config;
extern crate stegos_network;

use clap::{App, Arg, ArgMatches};
use slog::{Drain, Logger};
use std::error::Error;
use std::path::PathBuf;
use std::process;
use stegos_config::{Config, ConfigError};

fn load_configuration(args: &ArgMatches) -> Result<Config, Box<Error>> {
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

fn initialize_logger(_: &ArgMatches) -> Result<Logger, Box<Error>> {
    // TODO: allow to configure logger by configuration file
    // Initialize logger
    let decorator = slog_term::TermDecorator::new().build();
    // let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Ok(slog::Logger::root(drain, o!()))
}

fn run() -> Result<(), Box<Error>> {
    let args = App::new("Stegos")
        .version(crate_version!())
        .author("Stegos AG <info@stegos.cc>")
        .about("Stegos is a completely anonymous and confidential cryptocurrency.")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to stegos.toml configuration file")
                .takes_value(true),
        ).get_matches();

    // Parse configuration
    let cfg = load_configuration(&args)?;

    // Initialize logger
    let log = initialize_logger(&args)?;

    // Initialize network
    stegos_network::init(cfg.network, log.new(o!()))?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1)
    };
}

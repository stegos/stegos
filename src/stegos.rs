mod consts;

#[macro_use]
extern crate clap;
extern crate dirs;
extern crate stegos_config;

use clap::{App, Arg, ArgMatches};
use std::error::Error;
use std::path::PathBuf;
use std::process;

use stegos_config::{Config, ConfigError};

fn load_configuration(args: ArgMatches) -> Result<Config, Box<Error>> {
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
        )
        .get_matches();

    // Parse configuration
    let cfg = load_configuration(args)?;

    // Print some configuration values
    println!("config.network.strval: {}", cfg.network.strval);
    println!("config.network.u32val: {}", cfg.network.u32val);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1)
    };
}

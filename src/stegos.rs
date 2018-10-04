#[macro_use]
extern crate clap;

use clap::{App, Arg};

fn main() {
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

    let config = args.value_of("config").unwrap_or("stegos.toml");
    println!("Configuration file: {}", config);
}
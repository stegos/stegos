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

mod console;

use crate::console::Formatter;
use clap;
use clap::{App, Arg};
use console::ConsoleService;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[tokio::main]
async fn main() {
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
    let default_endpoint = "127.0.0.1:3145";

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
                .default_value(&default_endpoint)
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                }),
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
            Arg::with_name("chain")
                .short("n")
                .long("chain")
                .env("STEGOS_CHAIN")
                .value_name("NAME")
                .help("Specify chain to use: testnet or dev")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("raw")
                .short("R")
                .long("raw")
                .help("Use stegos CLI to send prevalidated raw requests.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("keep-console")
                .short("N")
                .long("keep-console")
                .help("Use stegos CLI to subscribe on notifications.")
                .takes_value(false),
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
            Arg::with_name("formatter")
                .short("f")
                .long("formatter")
                .env("FORMATTER")
                .value_name("FORMATTER")
                .help("Formatter to use: yaml or json")
                .default_value("yaml")
                .possible_values(&["json", "yaml"])
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
    let raw = args.is_present("raw");
    let subscribed = args.is_present("keep-console");
    let history_file = data_dir.join("stegos.history");
    let api_token_file = if let Some(api_token_file) = args.value_of("api-token-file") {
        PathBuf::from(api_token_file)
    } else {
        data_dir.join("api.token")
    };
    let uri = format!("ws://{}", args.value_of("api-endpoint").unwrap());
    let api_token = match stegos_api::load_api_token(&api_token_file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load API Token from {:?}: {}", api_token_file, e);
            std::process::exit(1);
        }
    };
    let formatter = Formatter::from_str(args.value_of("formatter").unwrap()).unwrap();
    ConsoleService::spawn(
        chain,
        name,
        version,
        uri,
        api_token,
        history_file,
        formatter,
        raw,
        subscribed,
    )
    .await
    .unwrap();
}

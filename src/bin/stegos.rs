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

use clap;
use clap::{App, Arg};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use stegos::config::GeneralConfig;
use stegos::console::ConsoleService;
use tokio::runtime::Runtime;

fn main() {
    let name = "Stegos CLI";
    let version = format!(
        "{}.{}.{} ({} {})",
        env!("VERSION_MAJOR"),
        env!("VERSION_MINOR"),
        env!("VERSION_PATCH"),
        env!("VERSION_COMMIT"),
        env!("VERSION_DATE")
    );

    let gcfg: GeneralConfig = Default::default();
    let default_token_file = gcfg
        .data_dir
        .join("api.token")
        .to_string_lossy()
        .to_string();
    let default_endpoint = gcfg.api_endpoint;

    let args = App::new(name)
        .version(&version[..])
        .author("Stegos AG <info@stegos.com>")
        .about("Stegos is a completely anonymous and confidential cryptocurrency.")
        .arg(
            Arg::with_name("api-endpoint")
                .index(1)
                .short("a")
                .long("api-endpoint")
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
            Arg::with_name("token-file")
                .short("t")
                .long("token-file")
                .help("A path to file, contains 16-byte API TOKEN")
                .default_value(&default_token_file)
                .takes_value(true)
                .validator(|token_file| {
                    stegos_api::load_api_token(Path::new(&token_file))
                        .map(|_| ())
                        .map_err(|e| format!("{:?}", e))
                })
                .value_name("FILE"),
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

    let token_file = args.value_of("token-file").unwrap();
    let uri = format!("ws://{}", args.value_of("api-endpoint").unwrap());
    let api_token = stegos_api::load_api_token(Path::new(token_file)).unwrap();

    println!("{} {}", name, version);
    println!("Type 'help' to get help");
    println!();

    let mut rt = Runtime::new().expect("Failed to initialize tokio");
    let console_service = ConsoleService::new(uri, api_token);
    rt.block_on(console_service)
        .expect("errors are handled earlier");
}

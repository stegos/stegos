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

mod config;

use crate::config::GeneralConfig;
use clap::{self, App, Arg, ArgMatches};
use dirs;
use failure::{format_err, Error};
use futures::{Future, Stream};
use hyper::server::Server;
use hyper::service::service_fn_ok;
use hyper::{Body, Request, Response};
use log::*;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::{Error as LogError, Handle as LogHandle};
use prometheus::{self, Encoder};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, process};
use stegos_api::{load_or_create_api_token, WebSocketServer};
use stegos_blockchain::{
    chain_to_prefix, initialize_chain, Blockchain, ConsistencyCheck, Timestamp,
};
use stegos_crypto::hash::Hash;
use stegos_keychain::keyfile::load_network_keys;
use stegos_network::{Libp2pNetwork, NETWORK_STATUS_TOPIC};
use stegos_node::NodeService;
use stegos_wallet::WalletService;
use tokio::runtime::Runtime;
use tokio_timer::clock;

/// The default file name for configuration
const STEGOSD_TOML: &'static str = "stegosd.toml";
/// The default file name for logger configuration.
const STEGOSD_LOG4RS_TOML: &'static str = "stegosd-log4rs.toml";
/// The default file name for the log file.
const STEGOSD_LOG: &'static str = "stegosd.log";

/// The size of single stegosd.log file, untill rotate.
const STEGOSD_LOG_SIZE_LIMIT: u64 = 5 * 1024 * 1024; // 5 MBytes
/// The count of logs file in archive.
const STEGOSD_LOG_COUNT_LIMIT: u32 = 10; // 10 log files

fn load_logger_configuration_file(path: &Path) -> Result<LogHandle, LogError> {
    match log4rs::load_config_file(path, Default::default()) {
        Ok(config) => return Ok(log4rs::init_config(config)?),
        Err(e) => {
            return Err(LogError::Log4rs(
                format_err!("Failed to read logger configuration {:?}: {}", path, e).into(),
            ));
        }
    }
}

fn load_logger_configuration(
    args: &ArgMatches<'_>,
    data_dir: &PathBuf,
    cfg_log_config: &PathBuf,
) -> Result<LogHandle, Error> {
    // Override log_config via command-line or environment.
    if let Some(log_config) = args.value_of_os("log-config") {
        return Ok(load_logger_configuration_file(Path::new(log_config))?);
    }

    // Use log_config from stegosd.toml for configuration.
    if !cfg_log_config.as_os_str().is_empty() {
        return Ok(load_logger_configuration_file(&cfg_log_config)?);
    }

    // Use $PWD/stegosd-log4rs.toml for configuration.
    let cfg_path = PathBuf::from(STEGOSD_LOG4RS_TOML);
    if cfg_path.exists() {
        return Ok(load_logger_configuration_file(&cfg_path)?);
    }

    // Use ~/.config/stegos/stegosd-log4rs.toml for configuration.
    let cfg_path = dirs::config_dir()
        .map(|p| p.join(r"stegos"))
        .unwrap_or(PathBuf::from(r"."))
        .join(PathBuf::from(STEGOSD_LOG4RS_TOML));
    if cfg_path.exists() {
        return Ok(load_logger_configuration_file(&cfg_path)?);
    }

    // Use default configuration.
    let verbosity = args.occurrences_of("verbose");
    let (console_level, level) = match verbosity {
        0 => (log::LevelFilter::Info, log::LevelFilter::Debug),
        1 => (log::LevelFilter::Debug, log::LevelFilter::Debug),
        2 | _ => (log::LevelFilter::Trace, log::LevelFilter::Trace),
    };
    let pattern = "{d(%Y-%m-%d %H:%M:%S)(local)} {h({l})} [{t}] {m}{n}";
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();
    let trigger = Box::new(SizeTrigger::new(STEGOSD_LOG_SIZE_LIMIT));
    let roller = Box::new(
        FixedWindowRoller::builder()
            .build(
                &format!("{}/logs/stegosd.{{}}.log.gz", data_dir.to_string_lossy()),
                STEGOSD_LOG_COUNT_LIMIT,
            )
            .map_err(|e| format_err!("Error during setting log: {}", e))?,
    );
    let policy = Box::new(CompoundPolicy::new(trigger, roller));
    let file = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(data_dir.join(STEGOSD_LOG), policy)
        .map_err(|e| {
            format_err!(
                "Failed to create the log file {:?}: {}",
                data_dir.join(STEGOSD_LOG),
                e
            )
        })?;
    let config = LogConfig::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(console_level)))
                .build("console", Box::new(console)),
        )
        .appender(Appender::builder().build("rolling_file", Box::new(file)))
        .logger(Logger::builder().build("stegos", level))
        .logger(Logger::builder().build("stegosd", level))
        .logger(Logger::builder().build("stegos_api", level))
        .logger(Logger::builder().build("stegos_blockchain", level))
        .logger(Logger::builder().build("stegos_crypto", level))
        .logger(Logger::builder().build("stegos_consensus", level))
        .logger(Logger::builder().build("stegos_keychain", level))
        .logger(Logger::builder().build("stegos_node", level))
        .logger(Logger::builder().build("stegos_network", level))
        .logger(Logger::builder().build("stegos_wallet", level))
        .logger(Logger::builder().build("trust-dns-resolver", log::LevelFilter::Trace))
        .build(
            Root::builder()
                .appender("rolling_file")
                .appender("console")
                .build(LevelFilter::Info),
        )
        .expect("Failed to initialize logger");

    Ok(log4rs::init_config(config)?)
}

fn report_metrics(_req: Request<Body>) -> Response<Body> {
    let mut response = Response::builder();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    //
    // Calculate actual value of BLOCK_IDLE metric.
    //
    let block_local_timestamp: f64 = stegos_node::metrics::BLOCK_LOCAL_TIMESTAMP.get();
    if block_local_timestamp > 0.0 {
        let timestamp: f64 = Timestamp::now().into();
        stegos_node::metrics::BLOCK_IDLE.set(timestamp - block_local_timestamp);
    }
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let res = response
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    res
}

/// Enable backtraces and coredumps.
fn enable_debug() {
    // Enable backtraces.
    let backtrace = std::env::var("RUST_BACKTRACE").unwrap_or("full".to_string());
    std::env::set_var("RUST_BACKTRACE", &backtrace);
    // Enable coredumps for macos and linux.
    #[cfg(not(target_os = "windows"))]
    {
        if backtrace == "full" {
            unsafe {
                let mut rlim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) == 0 {
                    rlim.rlim_cur = rlim.rlim_max;
                    let _ = libc::setrlimit(libc::RLIMIT_CORE, &rlim); // ignore errors.
                }
                #[cfg(target_os = "linux")]
                {
                    let _ = libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0); // ignore errors.
                }
            }
        }
    }
}

fn load_configuration_file(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
    // Use --config argument for configuration.
    if let Some(cfg_path) = args.value_of_os("config") {
        let cfg = config::from_file(cfg_path)?;
        return Ok(cfg);
    }

    // Use $PWD/stegosd.toml for configuration.
    match config::from_file(STEGOSD_TOML) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    // Use ~/.config/stegos/stegosd.toml for configuration.
    let cfg_path = dirs::config_dir()
        .map(|p| p.join(r"stegos"))
        .unwrap_or(PathBuf::from(r"."))
        .join(PathBuf::from(STEGOSD_TOML));
    match config::from_file(cfg_path) {
        Ok(cfg) => return Ok(cfg),
        Err(config::ConfigError::NotFoundError) => {} // fall through.
        Err(e) => return Err(e.into()),
    }

    // Use default configuration.
    Ok(Default::default())
}

fn load_configuration(args: &ArgMatches<'_>) -> Result<config::Config, Error> {
    let mut cfg = load_configuration_file(args)?;
    // Override global.chain via command-line or environment.
    if let Some(chain) = args.value_of("chain") {
        cfg.general.chain = chain.to_string();
    }

    // Override global.data_dir via command-line or environment.
    if let Some(data_dir) = args.value_of_os("data-dir") {
        cfg.general.data_dir = PathBuf::from(data_dir);
    }

    // Override global.consistency_check via command-line.
    if args.is_present("recover") {
        cfg.general.consistency_check = ConsistencyCheck::LoadChain;
    }
    // Override global.consistency_check via command-line.
    if args.is_present("force-check") {
        if args.is_present("recover") {
            error!("--force-check is set, ignoring --recover")
        }
        cfg.general.consistency_check = ConsistencyCheck::Full;
    }

    // Override network.endpoint via command-line or environment.
    if let Some(endpoint) = args.value_of("node-endpoint") {
        cfg.network.endpoint = endpoint.to_string();
    }
    if cfg.network.endpoint != "" {
        SocketAddr::from_str(&cfg.network.endpoint).map_err(|e| {
            format_err!("Invalid network.endpoint '{}': {}", cfg.network.endpoint, e)
        })?;
    }

    // Override network.advertised_endpoint via command-line or environment.
    if let Some(network_endpoint) = args.value_of("advertised-endpoint") {
        cfg.network.advertised_endpoint = network_endpoint.to_string();
    }
    if cfg.network.advertised_endpoint != "" {
        SocketAddr::from_str(&cfg.network.advertised_endpoint).map_err(|e| {
            format_err!(
                "Invalid network.advertised_endpoint '{}': {}",
                cfg.network.advertised_endpoint,
                e
            )
        })?;
    }

    // Use default SRV record for the chain
    if cfg.general.chain != "dev" && cfg.network.seed_pool == "" {
        cfg.network.seed_pool =
            format!("_stegos._tcp.{}.stegos.com", cfg.general.chain).to_string();
    }

    // Override global.prometheus_endpoint via command-line or environment.
    if let Some(prometheus_endpoint) = args.value_of("prometheus-endpoint") {
        cfg.general.prometheus_endpoint = prometheus_endpoint.to_string();
    }
    if cfg.general.prometheus_endpoint != "" {
        SocketAddr::from_str(&cfg.general.prometheus_endpoint).map_err(|e| {
            format_err!(
                "Invalid prometheus_endpoint '{}': {}",
                cfg.general.prometheus_endpoint,
                e
            )
        })?;
    }

    // Override global.api_endpoint via command-line or environment.
    if let Some(api_endpoint) = args.value_of("api-endpoint") {
        cfg.general.api_endpoint = api_endpoint.to_string();
    } else if cfg.general.api_endpoint != "" {
        SocketAddr::from_str(&cfg.general.api_endpoint).map_err(|e| {
            format_err!(
                "Invalid api_endpoint '{}': {}",
                &cfg.general.api_endpoint,
                e
            )
        })?;
    }

    // Disable [node] sections.
    if cfg.general.chain == "mainnet" && cfg.node != Default::default() {
        return Err(format_err!(
            "Can't override [node] options for {}",
            cfg.general.chain
        ));
    }

    if cfg.general.chain != "mainnet" {
        enable_debug();
    }

    Ok(cfg)
}

fn run() -> Result<(), Error> {
    let name = "Stegos Node";
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
            Arg::with_name("config")
                .short("c")
                .long("config")
                .env("STEGOS_CONFIG")
                .value_name("FILE")
                .help("Path to stegos.toml configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-config")
                .short("l")
                .long("log-config")
                .env("STEGOS_LOG_CONFIG")
                .value_name("FILE")
                .help("Path to stegos-log4rs.toml configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("data-dir")
                .short("d")
                .long("data-dir")
                .env("STEGOS_DATA_DIR")
                .value_name("DIR")
                .help("Path to data directory")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("node-endpoint")
                .long("node-endpoint")
                .env("STEGOS_NODE_ENDPOINT")
                .value_name("ENDPOINT")
                .help("Node endpoint (ip:port), e.g. 0.0.0.0:3145")
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("advertised-endpoint")
                .long("advertised-endpoint")
                .env("STEGOS_ADVERTISED_ENDPOINT")
                .value_name("ENDPOINT")
                .help("Node advertised endpoint (ip:port), e.g. 1.1.1.1:3145")
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api-endpoint")
                .short("a")
                .long("api-endpoint")
                .env("STEGOS_API_ENDPOINT")
                .value_name("ENDPOINT")
                .help("WebSocket API endpoint (ip:port), e.g. 127.0.0.1:3145")
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("prometheus-endpoint")
                .short("p")
                .long("prometheus-endpoint")
                .env("STEGOS_PROMETHEUS_ENDPOINT")
                .value_name("ENDPOINT")
                .help("Prometheus Exporter endpoint (ip:port), e.g. 127.0.0.1:9090")
                .takes_value(true)
                .validator(|uri| {
                    SocketAddr::from_str(&uri)
                        .map(|_| ())
                        .map_err(|e| format!("{}", e))
                }),
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
            Arg::with_name("verbose")
                .help("Change verbosity level")
                .short("v")
                .long("verbose")
                .multiple(true),
        )
        .arg(
            Arg::with_name("force-check")
                .help("Force BP, BLS, VRF validation during recovery")
                .long("force-check"),
        )
        .arg(
            Arg::with_name("recover")
                .help("Force recovery using blocks saved on disk, rather than Snapshot.")
                .long("recover"),
        )
        .get_matches();

    // Parse configuration
    let cfg = load_configuration(&args)?;

    // Initialize logger
    let _log = load_logger_configuration(&args, &cfg.general.data_dir, &cfg.general.log_config)?;
    // Print welcome message
    info!("{} {}", name, version);
    debug!("Configuration:\n{}", serde_yaml::to_string(&cfg).unwrap());

    // Append chain name if dir default.
    // But keep root_dir for api.token unchanged.
    let root_dir = cfg.general.data_dir.clone();
    let mut data_dir = root_dir.clone();
    if data_dir == GeneralConfig::default().data_dir {
        data_dir.push(cfg.general.chain.as_str());
    }

    debug!(
        "Initialize stegos with data directory = {}",
        data_dir.to_string_lossy()
    );
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", data_dir, e))?
    }
    let chain_dir = data_dir.join("chain");
    if !chain_dir.exists() {
        fs::create_dir(&chain_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", chain_dir, e))?
    }
    let accounts_dir = data_dir.join("accounts");
    if !accounts_dir.exists() {
        fs::create_dir(&accounts_dir)
            .map_err(|e| format_err!("Failed to create {:?}: {}", accounts_dir, e))?
    }

    stegos_crypto::set_network_prefix(chain_to_prefix(&cfg.general.chain))
        .expect("Network prefix not initialised.");

    // Initialize keychain
    let network_skey_file = data_dir.join("network.skey");
    let network_pkey_file = data_dir.join("network.pkey");
    let (network_skey, network_pkey) = load_network_keys(&network_skey_file, &network_pkey_file)?;

    // Initialize network
    let mut rt = Runtime::new()?;
    let (network, network_service, peer_id, replication_rx) = Libp2pNetwork::new(
        cfg.network.clone(),
        network_skey.clone(),
        network_pkey.clone(),
    )?;

    // Start metrics exporter
    if cfg.general.prometheus_endpoint != "" {
        let addr: SocketAddr = cfg.general.prometheus_endpoint.parse()?;
        info!("Starting Prometheus Exporter on {}", &addr);

        let prom_serv = || service_fn_ok(report_metrics);
        let hyper_service = Server::bind(&addr)
            .serve(prom_serv)
            .map_err(|e| error!("failed to bind prometheus exporter: {}", e));

        // Run hyper server to export Prometheus metrics
        rt.spawn(hyper_service);
    }

    // Initialize blockchain
    let (genesis, chain_cfg) = initialize_chain(&cfg.general.chain)?;
    info!(
        "Using '{}' chain, genesis={}",
        cfg.general.chain,
        Hash::digest(&genesis)
    );
    let timestamp = Timestamp::now();
    let chain = Blockchain::new(
        chain_cfg.clone(),
        &chain_dir,
        cfg.general.consistency_check,
        genesis,
        timestamp,
    )?;

    let epoch = chain.epoch();
    // Initialize node
    let (mut node_service, node) = NodeService::new(
        cfg.node.clone(),
        chain,
        network_skey.clone(),
        network_pkey.clone(),
        network.clone(),
        cfg.general.chain.clone(),
        peer_id,
        replication_rx,
    )?;

    // Initialize Wallet.
    let (wallet_service, wallet) = WalletService::new(
        &accounts_dir,
        network_skey,
        network_pkey,
        network.clone(),
        node.clone(),
        rt.executor(),
        chain_cfg.stake_epochs,
        cfg.node.max_inputs_in_tx,
        epoch,
    )?;
    rt.spawn(wallet_service);

    // Start WebSocket API server.
    if cfg.general.api_endpoint != "" {
        let token_file = root_dir.join("api.token");
        let api_token = load_or_create_api_token(&token_file)?;
        WebSocketServer::spawn(
            cfg.general.api_endpoint,
            api_token,
            rt.executor(),
            network.clone(),
            wallet.clone(),
            node.clone(),
            version,
        )?;
    }

    // Start all services when network is ready.
    let executor = rt.executor();
    let network_ready_future = network
        .subscribe(&NETWORK_STATUS_TOPIC)?
        .into_future()
        .map_err(drop)
        .and_then(|_s| {
            // Sic: NetworkReady doesn't wait until unicast networking is initialized.
            // https://github.com/stegos/stegos/issues/1192
            // Fire a timer here to wait until unicast networking is fully initialized.
            // This duration (30 secs) was experimentally found on the real network.
            let network_grace_period = std::time::Duration::from_secs(0);
            tokio_timer::Delay::new(clock::now() + network_grace_period).map_err(drop)
        })
        .and_then(move |()| {
            info!("Network is ready");
            // TODO: how to handle errors here?
            node_service.init().expect("shit happens");
            executor.spawn(node_service);
            Ok(())
        });
    rt.spawn(network_ready_future);

    // Start main event loop
    rt.block_on(network_service)
        .expect("errors are handled earlier");

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e); // Logger can be not yet initialized.
        error!("{:?}", e);
        process::exit(1)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_logger;
    use tempdir::TempDir;

    #[test]
    #[ignore]
    fn is_testnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let chain = "testnet";
        let (genesis, chain_cfg) = initialize_chain(chain).expect("testnet looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            chain_cfg,
            chain_dir.path(),
            ConsistencyCheck::Full,
            genesis,
            timestamp,
        )
        .expect("testnet looks like unloadable.");
    }

    #[test]
    // #[ignore]
    fn is_mainnet_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let chain = "mainnet";
        let (genesis, chain_cfg) = initialize_chain(chain).expect("mainnet looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            chain_cfg,
            chain_dir.path(),
            ConsistencyCheck::Full,
            genesis,
            timestamp,
        )
        .expect("mainnet looks like unloadable.");
    }

    #[test]
    fn is_dev_loadable() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let chain = "dev";
        let (genesis, chain_cfg) = initialize_chain(chain).expect("dev looks like unloadable.");
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        Blockchain::new(
            chain_cfg,
            chain_dir.path(),
            ConsistencyCheck::Full,
            genesis,
            timestamp,
        )
        .expect("dev looks like unloadable.");
    }

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

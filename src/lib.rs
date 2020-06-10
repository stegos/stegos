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

#[cfg(target_os = "android")]
use android_logger;
use failure::{format_err, Error};
use futures::channel::oneshot::Sender;
use futures::future::Either;
use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use log::*;
#[cfg(not(target_os = "android"))]
use log4rs::append::console::ConsoleAppender;
#[cfg(not(target_os = "android"))]
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
#[cfg(not(target_os = "android"))]
use log4rs::encode::pattern::PatternEncoder;
#[cfg(not(target_os = "android"))]
use log4rs::Handle as LogHandle;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use stegos_api::{server::spawn_server, ApiToken};
use stegos_blockchain::{chain_to_prefix, initialize_chain};
use stegos_crypto::hash::Hash;
use stegos_keychain::keyfile::load_network_keys;
use stegos_network::{Libp2pNetwork, NetworkConfig, NetworkName};
use stegos_node::NodeConfig;
use stegos_wallet::WalletService;

#[cfg(target_os = "android")]
fn load_logger_configuration() -> () {
    android_logger::init_once(android_logger::Config::default().with_min_level(Level::Trace));
}

#[cfg(not(target_os = "android"))]
fn load_logger_configuration() -> LogHandle {
    let pattern = "{d(%Y-%m-%d %H:%M:%S)(local)} {h({l})} [{t}] {m}{n}";
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();
    let config = LogConfig::builder()
        .appender(Appender::builder().build("console", Box::new(console)))
        .logger(Logger::builder().build("stegos", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegosd", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_api", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_blockchain", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_crypto", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_consensus", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_keychain", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_node", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_node::replication", log::LevelFilter::Debug))
        .logger(Logger::builder().build("stegos_network", log::LevelFilter::Info))
        .logger(Logger::builder().build("stegos_wallet", log::LevelFilter::Debug))
        .logger(Logger::builder().build("trust-dns-resolver", log::LevelFilter::Trace))
        .build(Root::builder().appender("console").build(LevelFilter::Warn))
        .expect("Failed to initialize logger");

    log4rs::init_config(config).expect("Failed to initialize logger")
}

use lazy_static::lazy_static;
lazy_static! {
    // Mutex is used to allow access from different threads
    static ref SENDER: Mutex<Option<Sender<ExternalSignals>>> =  Mutex::new(None) ;
}
#[derive(Debug)]
pub enum ExternalSignals {
    Shutdown,
    Restart,
}

#[cfg(not(target_os = "android"))]
fn set_panic_hooks() {
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            error!("panic occurred: {:?}", s);
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            error!("panic occurred: {:?}", s);
        } else {
            error!("panic occurred without payload");
        }
        if let Some(location) = panic_info.location() {
            error!(
                "panic occurred in file '{}' at line {} bt={:?}",
                location.file(),
                location.line(),
                backtrace::Backtrace::new()
            );
        } else {
            error!(
                "panic occurred but can't get location information... bt={:?}",
                backtrace::Backtrace::new()
            );
        }
    }));
}

#[cfg(target_os = "android")]
fn set_panic_hooks() {}

async fn init(
    chain_name: String,
    data_dir: String,
    api_token: String,
    api_endpoint: String,
) -> Result<(), Error> {
    set_panic_hooks();
    loop {
        let version = format!(
            "{}.{}.{} ({} {})",
            env!("VERSION_MAJOR"),
            env!("VERSION_MINOR"),
            env!("VERSION_PATCH"),
            env!("VERSION_COMMIT"),
            env!("VERSION_DATE")
        );

        let data_dir = PathBuf::from(&data_dir);
        debug!(
            "Initialize stegos with data directory = {}",
            data_dir.to_string_lossy()
        );
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)
                .map_err(|e| format_err!("Failed to create {:?}: {}", data_dir, e))?
        }

        let accounts_dir = data_dir.join("accounts");
        if !accounts_dir.exists() {
            fs::create_dir(&accounts_dir)
                .map_err(|e| format_err!("Failed to create {:?}: {}", accounts_dir, e))?
        }

        if let Err(e) = stegos_crypto::set_network_prefix(chain_to_prefix(&chain_name)) {
            match e {
                stegos_crypto::CryptoError::NetworkPrefixAlreadySet(..) => {}
                e => panic!("Network prefix not initialised {}", e),
            }
        };

        // Initialize keychain
        let network_skey_file = data_dir.join("network.skey");
        let network_pkey_file = data_dir.join("network.pkey");
        let (network_skey, network_pkey) =
            load_network_keys(&network_skey_file, &network_pkey_file)?;

        let mut network_config: NetworkConfig = Default::default();

        // set dns server to cloudflare and google
        network_config.dns_servers.push("1.1.1.1:53".to_string());
        network_config.dns_servers.push("8.8.8.8:53".to_string());

        // Initialize network
        if chain_name != "dev" {
            network_config.seed_pool =
                format!("_stegos._tcp.{}.stegos.com", &chain_name).to_string();
        }
        let (network, network_service, peer_id, replication_rx) = Libp2pNetwork::new(
            network_config,
            NetworkName::from_str(&chain_name).unwrap(),
            network_skey.clone(),
            network_pkey.clone(),
        )
        .await?;

        // Initialize Wallet.
        let (genesis, chain_cfg) = initialize_chain(&chain_name)?;
        info!(
            "Using '{}' chain, genesis={}",
            chain_name,
            Hash::digest(&genesis)
        );
        let node_cfg = NodeConfig::default();
        let (wallet_service, wallet) = WalletService::new(
            &accounts_dir,
            network_skey,
            network_pkey,
            network.clone(),
            peer_id,
            replication_rx,
            Hash::digest(&genesis),
            chain_cfg,
            node_cfg.max_inputs_in_tx,
        )?;
        tokio::spawn(wallet_service.start());

        // Start WebSocket API server.
        let api_token = ApiToken::from_base64(&api_token)?;
        spawn_server(
            api_endpoint.clone(),
            api_token,
            vec![Box::new(wallet.clone())],
            network.clone().into(),
            version,
            chain_name.clone(),
        )
        .await?;

        let (tx, rx) = futures::channel::oneshot::channel();
        *SENDER.lock().unwrap() = Some(tx);
        let main_future = futures::future::select(network_service, rx);
        // Start main event loop
        let result = main_future.await;

        let event = match result {
            // Network future ends.
            Either::Left((_, _channel_future)) => {
                info!("Network is shutting down, stopping stegos lib.");
                ExternalSignals::Shutdown
            }
            // Channel received item.
            Either::Right((Ok(item), _a)) => item,

            Either::Right((Err(_), _a)) => panic!("Error processing main future"),
        };

        if let ExternalSignals::Shutdown = event {
            info!("Shutdowning stegos lib.");
            break;
        }
        info!("Restarting stegos lib.");
    }
    Ok(())
}

fn init_sync(
    chain_name: String,
    data_dir: String,
    api_token: String,
    api_endpoint: String,
) -> Result<(), Error> {
    let mut runtime = tokio::runtime::Builder::new();
    let mut runtime = runtime.basic_scheduler();
    runtime = runtime.threaded_scheduler();
    runtime
        .enable_all()
        .build()?
        .block_on(async move { init(chain_name, data_dir, api_token, api_endpoint).await })?;
    Ok(())
}

#[no_mangle]
pub extern "system" fn init_rust() -> u32 {
    let _log = load_logger_configuration();
    let chain: String = "testnet".into();
    let data_dir: String = "../data".into();
    let api_token: String = "iUNtuwIDfPheI6BBqOin6A==".into();
    let api_endpoint: String = "127.0.0.1:3145".into();

    if let Err(e) = init_sync(chain, data_dir, api_token, api_endpoint) {
        error!("{}", e);
        return 1;
    }

    return 0;
}

#[no_mangle]
pub extern "system" fn Java_com_stegos_stegos_1wallet_Stegos_init(
    env: JNIEnv,
    _class: JClass,
    chain: JString,
    data_dir: JString,
    api_token: JString,
    api_endpoint: JString,
) -> jint {
    let _log = load_logger_configuration();
    let chain: String = env.get_string(chain).unwrap().into();
    let data_dir: String = env.get_string(data_dir).unwrap().into();
    let api_token: String = env.get_string(api_token).unwrap().into();
    let api_endpoint: String = env.get_string(api_endpoint).unwrap().into();

    if let Err(e) = init_sync(chain, data_dir, api_token, api_endpoint) {
        error!("{}", e);
        return 1;
    }

    return 0;
}

#[no_mangle]
pub extern "system" fn Java_com_stegos_stegos_1wallet_Stegos_shutdown(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let sender = SENDER.lock().unwrap().take().unwrap();
    if let Err(e) = sender.send(ExternalSignals::Shutdown) {
        error!("{:?}", e);
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "system" fn Java_com_stegos_stegos_1wallet_Stegos_restart(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    let sender = SENDER.lock().unwrap().take().unwrap();
    if let Err(e) = sender.send(ExternalSignals::Restart) {
        error!("{:?}", e);
        return 1;
    }
    return 0;
}

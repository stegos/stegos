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

pub mod config;
pub mod console;
pub mod consts;
pub mod generator;
pub mod money;

use failure::format_err;
use failure::Error;
use hyper::{Body, Request, Response};
use log::*;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config as LogConfig, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::{Error as LogError, Handle as LogHandle};
use prometheus::{self, Encoder};
use resolve::{config::DnsConfig, record::Srv, resolver};
use std::path::Path;
use std::time::SystemTime;
use stegos_blockchain::{Block, MacroBlock};
use stegos_crypto::hash::Hash;
use stegos_serialization::traits::*;

pub fn initialize_logger(cfg: &config::Config) -> Result<LogHandle, LogError> {
    // Try to load log4rs config file
    let path = Path::new(&cfg.general.log4rs_config);
    if !cfg.general.log4rs_config.is_empty() && path.is_file() {
        match log4rs::load_config_file(path, Default::default()) {
            Ok(config) => return Ok(log4rs::init_config(config)?),
            Err(e) => {
                error!("Failed to read log4rs config file: {}", e);
                println!("Failed to read log4rs config file: {}", e);
            }
        }
    };

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)(local)} {h({l})} [{M}] {m}{n}",
        )))
        .build();
    let config = LogConfig::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .logger(Logger::builder().build("stegos", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_blockchain", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_crypto", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_consensus", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_keychain", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_node", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_network", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_txpool", LevelFilter::Info))
        .logger(Logger::builder().build("stegos_wallet", LevelFilter::Info))
        .build(Root::builder().appender("stdout").build(LevelFilter::Warn))
        .expect("console logger should never fail");

    Ok(log4rs::init_config(config)?)
}

pub fn initialize_genesis(cfg: &config::Config) -> Result<MacroBlock, Error> {
    let genesis: &[u8] = match cfg.general.chain.as_ref() {
        "dev" => include_bytes!("../chains/dev/genesis.bin"),
        "testnet" => include_bytes!("../chains/testnet/genesis.bin"),
        "devnet" => include_bytes!("../chains/devnet/genesis.bin"),
        chain @ _ => {
            return Err(format_err!("Unknown chain: {}", chain));
        }
    };
    let genesis = Block::from_buffer(genesis).expect("Invalid genesis");
    let genesis = genesis.unwrap_macro();
    let hash = Hash::digest(&genesis);
    info!("Using genesis={} for '{}' chain", hash, cfg.general.chain);
    Ok(genesis)
}

pub fn resolve_pool(cfg: &mut config::Config) -> Result<(), Error> {
    if cfg.network.seed_pool == "" {
        return Ok(());
    }

    let config = DnsConfig::load_default()?;
    let resolver = resolver::DnsResolver::new(config)?;

    let rrs: Vec<Srv> = resolver.resolve_record(&cfg.network.seed_pool)?;

    for r in rrs.iter() {
        if let Ok(addrs) = resolver.resolve_host(&r.target) {
            for a in addrs {
                let maddr = format!("/ip4/{}/tcp/{}", a.to_string(), r.port);
                // don't try to connect to ourselves or already configured seed nodes
                if cfg.network.advertised_addresses.iter().all(|a| *a != maddr)
                    && cfg.network.seed_nodes.iter().all(|a| *a != maddr)
                {
                    info!(target: "stegos_network::ncp", "Adding node from seed pool: {}", maddr);
                    cfg.network.seed_nodes.push(maddr);
                }
            }
        }
    }
    Ok(())
}

pub fn report_metrics(_req: Request<Body>) -> Response<Body> {
    let mut response = Response::builder();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    //
    // Calculate actual value of BLOCK_IDLE metric.
    //
    let block_local_timestamp = stegos_node::metrics::BLOCK_LOCAL_TIMESTAMP.get();
    if block_local_timestamp > 0 {
        let timestamp = stegos_node::metrics::time_to_timestamp_ms(SystemTime::now());
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

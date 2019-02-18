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

use chrono::Utc;
use clap::{crate_version, App, Arg};
use log::*;
use protobuf::Message;
use simple_logger;
use std::fs;
use std::process;
use stegos_blockchain::genesis;
use stegos_keychain::KeyChain;
use stegos_keychain::KeyChainConfig;
use stegos_serialization::traits::ProtoConvert;

fn main() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    let args = App::new("Stegos Bootstrap Utility")
        .version(crate_version!())
        .author("Stegos AG <info@stegos.cc>")
        .about("A tool to generate initial keys and genesis block.")
        .arg(
            Arg::with_name("keys")
                .short("k")
                .long("keys")
                .value_name("NUMBER")
                .help("Number of initial keys to generate.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("coins")
                .short("c")
                .long("coins")
                .value_name("NUMBER")
                .help("Total number of coins to create.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("stake")
                .short("s")
                .long("stake")
                .value_name("NUMBER")
                .help("Stake per each validator.")
                .takes_value(true),
        )
        .get_matches();

    let keys = if let Some(keys) = args.value_of("keys") {
        match keys.parse::<i32>() {
            Ok(keys) => {
                if keys < 1 {
                    eprintln!("Invalid number of keys: must be greater than 1");
                    process::exit(1);
                };
                keys
            }
            Err(e) => {
                eprintln!("Invalid number of keys: {}", e);
                process::exit(1);
            }
        }
    } else {
        5
    };

    let coins = if let Some(coins) = args.value_of("coins") {
        match coins.parse::<i64>() {
            Ok(coins) => {
                if coins < 100 {
                    eprintln!("Invalid number of coins: must be greater than 100");
                    process::exit(1);
                };
                coins
            }
            Err(e) => {
                eprintln!("Invalid number of coins: {}", e);
                process::exit(1);
            }
        }
    } else {
        1_000_000_000i64
    };

    let stake = if let Some(stake) = args.value_of("stake") {
        match stake.parse::<i64>() {
            Ok(stake) => {
                if stake < 1 {
                    eprintln!("Invalid stake: must be greater than 1");
                    process::exit(1);
                };
                stake
            }
            Err(e) => {
                eprintln!("Invalid stake: {}", e);
                process::exit(1);
            }
        }
    } else {
        100i64
    };

    info!("Generating genesis keys...");
    let mut keychains = Vec::<KeyChain>::new();
    for i in 0..keys {
        let config = KeyChainConfig {
            private_key: format!("stegos{:02}.skey", i + 1),
            public_key: format!("stegos{:02}.pkey", i + 1),
        };

        let keychain = match KeyChain::new(&config) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Failed to generate keys: {}", e);
                process::exit(2);
            }
        };

        keychains.push(keychain);
    }

    info!("Generating genesis blocks...");
    let timestamp = Utc::now().timestamp() as u64;
    let blocks = genesis(&keychains, stake, coins, timestamp);
    for (i, block) in blocks.iter().enumerate() {
        let block_data = block.into_proto();
        let block_data = block_data.write_to_bytes().unwrap();
        fs::write(format!("genesis{}.bin", i), &block_data).expect("failed to write genesis block");
    }

    info!("Done");
}

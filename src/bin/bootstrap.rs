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

use clap::{crate_version, App, Arg};
use log::*;
use simple_logger;
use std::fs;
use std::path::Path;
use std::process;
use std::time::SystemTime;
use stegos_blockchain::{genesis, Block, ChainConfig, StakeDef};
use stegos_crypto::{curve1174, pbc};
use stegos_keychain as keychain;
use stegos_serialization::traits::ProtoConvert;

fn main() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    let cfg: ChainConfig = Default::default();
    let args = App::new("Stegos Bootstrap Utility")
        .version(crate_version!())
        .author("Stegos AG <info@stegos.com>")
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
        1_000_000_000_000_000i64
    };

    let stake = if let Some(stake) = args.value_of("stake") {
        match stake.parse::<i64>() {
            Ok(stake) => {
                if stake < cfg.min_stake_amount {
                    eprintln!(
                        "Invalid stake: must be greater than MIN_STAKE_AMOUNT = {}",
                        cfg.min_stake_amount
                    );
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
        cfg.min_stake_amount
    };

    info!("Generating genesis keys...");
    let mut keychains = Vec::<(
        curve1174::SecretKey,
        curve1174::PublicKey,
        pbc::SecretKey,
        pbc::PublicKey,
    )>::new();
    for i in 0..keys {
        let password_file = format!("password{:02}.txt", i + 1);
        let wallet_skey_file = format!("wallet{:02}.skey", i + 1);
        let wallet_pkey_file = format!("wallet{:02}.pkey", i + 1);
        let network_skey_file = format!("network{:02}.skey", i + 1);
        let network_pkey_file = format!("network{:02}.pkey", i + 1);

        let password = keychain::input::read_password_from_file(&password_file)
            .expect("failed to read password");

        let (wallet_skey, wallet_pkey) = curve1174::make_random_keys();
        let (network_skey, network_pkey) = pbc::make_random_keys();

        keychain::keyfile::write_wallet_pkey(Path::new(&wallet_pkey_file), &wallet_pkey)
            .expect("failed to write wallet pkey");
        keychain::keyfile::write_wallet_skey(Path::new(&wallet_skey_file), &wallet_skey, &password)
            .expect("failed to write wallet skey");
        keychain::keyfile::write_network_pkey(Path::new(&network_pkey_file), &network_pkey)
            .expect("failed to write network pkey");
        keychain::keyfile::write_network_skey(
            Path::new(&network_skey_file),
            &network_skey,
            &password,
        )
        .expect("failed to write wallet skey");

        keychains.push((wallet_skey, wallet_pkey, network_skey, network_pkey));
    }

    info!("Generating genesis blocks...");
    let timestamp = SystemTime::now();
    let mut stakes = Vec::with_capacity(keychains.len());
    for i in 0..keychains.len() {
        let stake_def = StakeDef {
            beneficiary_pkey: &keychains[i].1,
            network_skey: &keychains[i].2,
            network_pkey: &keychains[i].3,
            amount: stake,
        };
        stakes.push(stake_def);
    }
    let genesis_block = genesis(&stakes, coins, timestamp);
    let block_data = Block::MacroBlock(genesis_block).into_buffer().unwrap();
    fs::write("genesis.bin", &block_data).expect("failed to write genesis block");

    info!("Done");
}

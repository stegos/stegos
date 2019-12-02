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

use bit_vec::BitVec;
use clap::{crate_version, App, Arg};
use log::*;
use simple_logger;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
use stegos_blockchain::{
    chain_to_prefix, create_multi_signature, election, mix, Block, ChainConfig, MacroBlock, Output,
    PaymentOutput, PaymentPayloadData, StakeOutput, StakersGroup, Timestamp,
};
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::KeyError;
use stegos_serialization::traits::ProtoConvert;

fn fix_newline(password: &mut String) {
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
}

fn read_password_from_file(password_file: &Path) -> Result<String, KeyError> {
    info!("Reading password from file {:?}...", password_file);
    let mut password = fs::read_to_string(password_file)
        .map_err(|e| KeyError::InputOutputError(password_file.to_string_lossy().to_string(), e))?;
    fix_newline(&mut password);
    Ok(password)
}

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
        .arg(
            Arg::with_name("chain")
                .short("n")
                .long("chain")
                .env("STEGOS_CHAIN")
                .value_name("NAME")
                .help("Specify chain to use: mainnet, testnet or dev")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("owner")
                .short("o")
                .long("owner")
                .value_name("ADDRESS")
                .help("Public key of account, used to make all stake transactions")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("difficulty")
                .short("d")
                .long("difficulty")
                .value_name("DIFFICULTY")
                .default_value("500000")
                .validator(|s| s.parse::<u64>().map(|_| ()).map_err(|e| format!("{}", e)))
                .help("Difficulty of VDF")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("reuse")
                .long("reuse")
                .help("Re-use existing keys"),
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
                        "WARNING: stake is less than MIN_STAKE_AMOUNT = {}",
                        cfg.min_stake_amount
                    );
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

    let difficulty = args.value_of("difficulty").unwrap().parse::<u64>().unwrap();

    let chain = args.value_of("chain").unwrap_or("dev");
    let reuse = args.is_present("reuse");

    info!("Generating genesis for chain: {} ...", chain);

    stegos_crypto::set_network_prefix(chain_to_prefix(chain))
        .expect("Network prefix not initialised.");

    let mut stakers: StakersGroup = Vec::with_capacity(keys as usize);
    let mut outputs: Vec<Output> = Vec::with_capacity(1 + keys as usize);
    let mut keychains = Vec::<(
        scc::SecretKey,
        scc::PublicKey,
        pbc::SecretKey,
        pbc::PublicKey,
    )>::new();
    let mut payout: i64 = coins;
    for i in 0..keys {
        let data_dir = PathBuf::from(chain).join(format!("node{:02}", i + 1));
        let network_skey_file = data_dir.join("network.skey");
        let network_pkey_file = data_dir.join("network.pkey");
        let account_dir1 = data_dir.join("accounts").join("1");
        let password_file = account_dir1.join("password.txt");
        let account_skey_file = account_dir1.join("account.skey");
        let account_pkey_file = account_dir1.join("account.pkey");

        let password = read_password_from_file(&password_file).expect("failed to read password");

        let (account_skey, account_pkey) =
            if reuse && account_skey_file.exists() && account_pkey_file.exists() {
                // Load existing keys.
                info!("Reusing account.skey/account.skey for node{:02}", i);
                keychain::keyfile::load_account_keypair(
                    &account_skey_file,
                    &account_pkey_file,
                    &password,
                )
                .expect("failed to read account keys")
            } else {
                // Generate new keys.
                info!("Generating new account.skey/account.skey for node{:02}", i);
                let (account_skey, account_pkey) = scc::make_random_keys();

                // Write keys.
                info!("New account key: {}", String::from(&account_pkey));
                keychain::keyfile::write_account_pkey(&account_pkey_file, &account_pkey)
                    .expect("failed to write account pkey");
                keychain::keyfile::write_account_skey(&account_skey_file, &account_skey, &password)
                    .expect("failed to write account skey");
                (account_skey, account_pkey)
            };

        let (network_skey, network_pkey) =
            if reuse && network_skey_file.exists() && network_pkey_file.exists() {
                // Load existing keys.
                info!("Reusing network.skey/network.skey for node{:02}", i);
                keychain::keyfile::load_network_keypair(&network_skey_file, &network_pkey_file)
                    .expect("failed to read network keys")
            } else {
                // Generate new keys.
                info!("Generating new network.skey/network.skey for node{:02}", i);
                let (network_skey, network_pkey) = pbc::make_random_keys();

                // Write keys.
                info!("New network key: {}", &network_pkey);
                keychain::keyfile::write_network_pkey(&network_pkey_file, &network_pkey)
                    .expect("failed to write network pkey");
                keychain::keyfile::write_network_skey(&network_skey_file, &network_skey)
                    .expect("failed to write network skey");
                (network_skey, network_pkey)
            };

        keychains.push((
            account_skey,
            account_pkey,
            network_skey.clone(),
            network_pkey.clone(),
        ));

        // Create a stake.
        let output = StakeOutput::new(&account_pkey, &network_skey, &network_pkey, stake)
            .expect("invalid keys");

        assert!(payout >= stake);
        payout -= stake;
        outputs.push(output.into());
        stakers.push((network_pkey, stake));
    }

    // Create an initial payment.
    let beneficiary_pkey = match args.value_of("owner") {
        Some(address) => {
            scc::PublicKey::from_str(address).expect("Incorrect beneficiary public key")
        }
        None => keychains[0].1.clone(),
    };
    let output_data = PaymentPayloadData::Comment("Genesis".to_string());
    let (output, outputs_gamma, _rvalue) =
        PaymentOutput::with_payload(None, &beneficiary_pkey, payout, output_data)
            .expect("invalid keys");
    outputs.push(output.into());

    // Calculate initial values.
    let epoch: u64 = 0;
    let view_change: u32 = 0;
    let previous = Hash::digest("genesis");
    let last_macro_block_random = Hash::digest("genesis");
    let seed = mix(last_macro_block_random, view_change);
    let random = pbc::make_VRF(&keychains[0].2, &seed);
    let activity_map = BitVec::from_elem(keychains.len(), true);
    let timestamp = Timestamp::now();
    let validators =
        election::select_validators_slots(stakers, random, cfg.max_slot_count).validators;

    // Create a block.
    let mut block = MacroBlock::new(
        previous,
        epoch,
        view_change,
        keychains[0].3.clone(),
        random,
        difficulty,
        timestamp,
        coins,
        -outputs_gamma,
        activity_map,
        validators,
        Vec::new(),
        outputs,
    );

    //
    // Sign the block.
    // NOTE: this signature is not really used.
    // Sign the genesis block just to prove ownership of secret keys.
    //
    let block_hash = Hash::digest(&block);
    let (multisig, multisigmap) = {
        let mut signatures: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let mut validators: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
        for (_, _, network_skey, network_pkey) in keychains {
            let sig = pbc::sign_hash(&block_hash, &network_skey);
            signatures.insert(network_pkey.clone(), sig);
            validators.insert(network_pkey.clone(), stake);
        }
        let validators = validators.into_iter().collect();
        create_multi_signature(&validators, &signatures)
    };
    block.multisig = multisig;
    block.multisigmap = multisigmap;

    // Write the block to the disk.
    let block_data = Block::MacroBlock(block).into_buffer().unwrap();
    let genesis_path = PathBuf::from("chains").join(chain).join("genesis.bin");
    fs::write(&genesis_path, &block_data).expect("failed to write genesis block");
    info!("Wrote {:?}", &genesis_path);

    info!("Done");
}

#![feature(test)]
use simple_logger;
use std::time::Duration;
use stegos_blockchain::test::fake_genesis;
use stegos_blockchain::{Blockchain, ChainConfig, Timestamp};
use stegos_crypto::hash::Hash;

#[macro_use]
extern crate criterion;

use criterion::{Bencher, Criterion};
use stegos_blockchain::test::create_fake_micro_block;
use stegos_crypto::pbc::{check_hash, make_random_keys, sign_hash};

fn create_blocks(b: &mut Bencher) {
    const NUM_NODES: usize = 1;

    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    let timestamp_at_start = Timestamp::now();
    let mut timestamp = timestamp_at_start;
    let cfg: ChainConfig = ChainConfig {
        micro_blocks_in_epoch: 100,
        ..Default::default()
    };

    let (keychains, genesis) = fake_genesis(
        cfg.min_stake_amount,
        cfg.min_stake_amount * (NUM_NODES as i64) + 100,
        NUM_NODES,
        timestamp,
    );

    let mut chain = Blockchain::testing(cfg.clone(), genesis.clone(), timestamp).unwrap();

    let mut blocks = Vec::new();
    // create valid blocks.
    for _ in 0..10 {
        timestamp += Duration::from_millis(1);
        // Non-empty block.
        let (block, _input_hashes, _output_hashes) =
            create_fake_micro_block(&chain, &keychains, timestamp);

        chain
            .push_micro_block(block.clone(), timestamp.clone())
            .unwrap();

        blocks.push((block, timestamp));
    }

    println!("start tracking");
    b.iter_with_setup(
        || {
            // start bench to other blockchain
            Blockchain::testing(cfg.clone(), genesis.clone(), timestamp).unwrap()
        },
        |mut chain| {
            for (b, t) in &blocks {
                chain.push_micro_block(b.clone(), t.clone()).unwrap();
            }
        },
    );
}

fn block_benchmark(c: &mut Criterion) {
    c.bench_function("block 10", create_blocks);
}

fn validate_bls_signature(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, pkey) = make_random_keys();
            let hash = Hash::digest("test");
            let signature = sign_hash(&hash, &skey);
            (hash, signature, pkey)
        },
        |(hash, signature, pkey)| {
            check_hash(&hash, &signature, &pkey).unwrap();
        },
    );
}

fn sign_bls_signature(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, _pkey) = make_random_keys();
            let hash = Hash::digest("test");
            (hash, skey)
        },
        |(hash, skey)| {
            sign_hash(&hash, &skey);
        },
    );
}

fn bls_benchmark(c: &mut Criterion) {
    c.bench_function("validate_bls_signature", validate_bls_signature);
    c.bench_function("sign_bls_signature", sign_bls_signature);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(1)).sample_size(2);
     targets = block_benchmark, bls_benchmark
}

criterion_main!(benches);

#![feature(test)]

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use log::*;
use simple_logger;
use std::time::Duration;
use stegos_blockchain::{test, Blockchain, ChainConfig, MacroBlock, StorageConfig, Timestamp};

fn push_macro_block(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    const NUM_NODES: usize = 32;
    const STAKE_EPOCHS: u64 = 100; // disable re-staking
    const EPOCHS: u64 = 10;

    //
    // Initialize blockchain.
    //
    let mut timestamp = Timestamp::now();
    let mut cfg: ChainConfig = Default::default();
    cfg.stake_epochs = STAKE_EPOCHS;
    cfg.micro_blocks_in_epoch = 2;
    let (keychains, genesis) = test::fake_genesis(
        cfg.min_stake_amount,
        (NUM_NODES as i64) * cfg.min_stake_amount + 100,
        NUM_NODES,
        timestamp,
    );
    let mut chain = Blockchain::testing(cfg.clone(), genesis.clone(), timestamp)
        .expect("Failed to create blockchain");

    //
    // Generate epochs.
    //
    let mut blocks: Vec<MacroBlock> = Vec::new();
    for epoch in 1..=EPOCHS {
        assert_eq!(chain.epoch(), epoch);
        info!("Generating epoch={}", epoch);
        timestamp += Duration::from_millis(1);
        let (block, _input_hashes, _output_hashes) =
            test::create_fake_micro_block(&mut chain, &keychains, timestamp);
        chain
            .push_micro_block(block, timestamp)
            .expect("block is valid");

        // Add empty micro blocks to finish the epoch.
        for _offset in 1..cfg.micro_blocks_in_epoch {
            timestamp += Duration::from_millis(1);
            let block = test::create_micro_block_with_coinbase(&mut chain, &keychains, timestamp);
            chain
                .push_micro_block(block, timestamp)
                .expect("block is valid");
        }
        assert_eq!(chain.offset(), cfg.micro_blocks_in_epoch);

        // Create a macro block.
        timestamp += Duration::from_millis(1);
        let (block, _extra_transactions) =
            test::create_fake_macro_block(&chain, &keychains, timestamp);

        // Remove all micro blocks.
        while chain.offset() > 0 {
            chain.pop_micro_block().expect("Should be ok");
        }

        // Push macro block.
        chain.push_macro_block(block.clone(), timestamp).unwrap();
        blocks.push(block);
    }
    assert_eq!(chain.epoch(), 1 + EPOCHS);
    drop(chain);

    info!("Starting benchmark");
    b.iter_with_setup(
        || {
            info!("");
            // start bench to other blockchain
            let chain = Blockchain::testing(cfg.clone(), genesis.clone(), timestamp).unwrap();
            let blocks = blocks.clone();
            (chain, blocks)
        },
        |(mut chain, blocks)| {
            for block in blocks {
                chain.push_macro_block(block, timestamp).unwrap();
            }
        },
    );
}

fn push_macro_block_benchmark(c: &mut Criterion) {
    c.bench_function("blockchain::push_macro_block(10)", push_macro_block);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(1)).sample_size(2);
     targets = push_macro_block_benchmark
}

criterion_main!(benches);

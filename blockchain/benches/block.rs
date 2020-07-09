#![feature(test)]

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use log::*;
use simple_logger;
use std::path::Path;
use std::time::Duration;
use stegos_blockchain::{test, Blockchain, ChainConfig, ConsistencyCheck, Macroblock, Timestamp};
use tempdir::TempDir;

fn generate_chain(
    cfg: ChainConfig,
    chain_dir: &Path,
    num_nodes: usize,
    epochs: u64,
) -> Vec<Macroblock> {
    //
    // Initialize blockchain.
    //
    let mut ts = Timestamp::now();
    let (keychains, genesis) = test::fake_genesis(
        cfg.min_stake_amount,
        (num_nodes as i64) * cfg.min_stake_amount + 100,
        cfg.max_slot_count,
        num_nodes,
        ts,
        cfg.awards_difficulty,
        None,
    );
    let mut chain = Blockchain::new(
        cfg.clone(),
        chain_dir,
        ConsistencyCheck::None,
        genesis.clone(),
        ts,
    )
    .expect("Failed to create blockchain");

    //
    // Generate epochs.
    //
    let mut blocks: Vec<Macroblock> = Vec::new();
    blocks.push(genesis);
    for epoch in 1..=epochs {
        assert_eq!(chain.epoch(), epoch);
        info!("Generating epoch={}", epoch);
        for _offset in 0..cfg.blocks_in_epoch {
            ts += Duration::from_millis(1);
            let (block, _input_hashes, _output_hashes) =
                test::create_fake_ublock(&mut chain, &keychains, ts);
            chain.push_ublock(block, ts).expect("no I/O errors");
        }
        assert_eq!(chain.offset(), cfg.blocks_in_epoch);

        // Create a macro block.
        ts += Duration::from_millis(1);
        let (block, _extra_transactions) = test::create_fake_mblock(&chain, &keychains, ts);

        // Remove all micro blocks.
        while chain.offset() > 0 {
            chain.pop_ublock().expect("no I/O errors");
        }

        // Push macro block.
        chain.push_mblock(block.clone(), ts).unwrap();
        blocks.push(block);
    }
    assert_eq!(chain.epoch(), 1 + epochs);
    drop(chain);
    blocks
}

fn push_mblock(b: &mut Bencher) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        blocks_in_epoch: 1,
        ..Default::default()
    };
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    // Try to apply blocks to a new blockchain.
    info!("Starting benchmark");
    let ts = Timestamp::now();
    b.iter_with_setup(
        || {
            let chain_dir = TempDir::new("bench").unwrap();
            let chain = Blockchain::new(
                cfg.clone(),
                chain_dir.path(),
                ConsistencyCheck::None,
                blocks[0].clone(),
                ts,
            )
            .unwrap();
            (chain, chain_dir, blocks.clone())
        },
        |(mut chain, _temp_dir, blocks)| {
            for block in blocks.into_iter().skip(1) {
                chain.push_mblock(block, ts).unwrap();
            }
        },
    );
}

fn recover_mblock(b: &mut Bencher) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        blocks_in_epoch: 1,
        ..Default::default()
    };
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    // Try to recovery from the disk.
    info!("Starting benchmark");
    let ts = Timestamp::now();
    b.iter(|| {
        let _chain = Blockchain::new(
            cfg.clone(),
            chain_dir.path(),
            ConsistencyCheck::None,
            blocks[0].clone(),
            ts,
        )
        .unwrap();
    });
}

fn blocks_benchmark(c: &mut Criterion) {
    simple_logger::init_with_level(log::Level::Info).unwrap_or_default();
    c.bench_function("blockchain::push_mblock(10)", push_mblock);
    c.bench_function("blockchain::recover_mblock(10)", recover_mblock);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(1)).sample_size(2);
     targets = blocks_benchmark
}

criterion_main!(benches);

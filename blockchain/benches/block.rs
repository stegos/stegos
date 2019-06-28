#![feature(test)]

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use log::*;
use simple_logger;
use std::time::Duration;
use stegos_blockchain::{test, Blockchain, ChainConfig, MacroBlock, StorageConfig, Timestamp};

fn generate_chain(
    cfg: ChainConfig,
    storage_cfg: StorageConfig,
    num_nodes: usize,
    epochs: u64,
) -> Vec<MacroBlock> {
    //
    // Initialize blockchain.
    //
    let mut timestamp = Timestamp::now();
    let (keychains, genesis) = test::fake_genesis(
        cfg.min_stake_amount,
        (num_nodes as i64) * cfg.min_stake_amount + 100,
        num_nodes,
        timestamp,
    );
    let mut chain = Blockchain::new(cfg.clone(), storage_cfg.clone(), genesis.clone(), timestamp)
        .expect("Failed to create blockchain");

    //
    // Generate epochs.
    //
    let mut blocks: Vec<MacroBlock> = Vec::new();
    blocks.push(genesis);
    for epoch in 1..=epochs {
        assert_eq!(chain.epoch(), epoch);
        info!("Generating epoch={}", epoch);
        for _offset in 0..cfg.micro_blocks_in_epoch {
            timestamp += Duration::from_millis(1);
            let (block, _input_hashes, _output_hashes) =
                test::create_fake_micro_block(&mut chain, &keychains, timestamp);
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
    assert_eq!(chain.epoch(), 1 + epochs);
    drop(chain);
    blocks
}

fn push_macro_block(b: &mut Bencher) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        micro_blocks_in_epoch: 1,
        ..Default::default()
    };
    let (storage_cfg, _temp_dir) = StorageConfig::testing();
    let blocks = generate_chain(cfg.clone(), storage_cfg.clone(), NUM_NODES, EPOCHS);

    // Try to apply blocks to a new blockchain.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();
    b.iter_with_setup(
        || {
            let (storage_cfg, temp_dir) = StorageConfig::testing();
            let chain =
                Blockchain::new(cfg.clone(), storage_cfg, blocks[0].clone(), timestamp).unwrap();
            (chain, temp_dir, blocks.clone())
        },
        |(mut chain, _temp_dir, blocks)| {
            for block in blocks.into_iter().skip(1) {
                chain.push_macro_block(block, timestamp).unwrap();
            }
        },
    );
}

fn recover_macro_block(b: &mut Bencher) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        micro_blocks_in_epoch: 1,
        ..Default::default()
    };
    let (storage_cfg, _temp_dir) = StorageConfig::testing();
    let blocks = generate_chain(cfg.clone(), storage_cfg.clone(), NUM_NODES, EPOCHS);

    // Try to recovery from the disk.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();
    b.iter(|| {
        let _chain = Blockchain::new(
            cfg.clone(),
            storage_cfg.clone(),
            blocks[0].clone(),
            timestamp,
        )
        .unwrap();
    });
}

fn blocks_benchmark(c: &mut Criterion) {
    simple_logger::init_with_level(log::Level::Info).unwrap_or_default();
    c.bench_function("blockchain::push_macro_block(10)", push_macro_block);
    c.bench_function("blockchain::recover_macro_block(10)", recover_macro_block);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(1)).sample_size(2);
     targets = blocks_benchmark
}

criterion_main!(benches);

#![feature(test)]

use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};
use log::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use simple_logger;
use std::path::Path;
use std::time::Duration;
use stegos_blockchain::{
    test, Blockchain, ChainConfig, MacroBlock, PaymentOutput, PaymentPayload, Timestamp,
};
use stegos_crypto::scc::make_random_keys;
use stegos_serialization::traits::ProtoConvert;
use tempdir::TempDir;

fn generate_chain(
    cfg: ChainConfig,
    chain_dir: &Path,
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
        None,
    );
    let mut chain = Blockchain::new(cfg.clone(), chain_dir, false, genesis.clone(), timestamp)
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
                .expect("no I/O errors");
        }
        assert_eq!(chain.offset(), cfg.micro_blocks_in_epoch);

        // Create a macro block.
        timestamp += Duration::from_millis(1);
        let (block, _extra_transactions) =
            test::create_fake_macro_block(&chain, &keychains, timestamp);

        // Remove all micro blocks.
        while chain.offset() > 0 {
            chain.pop_micro_block().expect("no I/O errors");
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
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    // Try to apply blocks to a new blockchain.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();
    b.iter_with_setup(
        || {
            let chain_dir = TempDir::new("bench").unwrap();
            let chain = Blockchain::new(
                cfg.clone(),
                chain_dir.path(),
                false,
                blocks[0].clone(),
                timestamp,
            )
            .unwrap();
            (chain, blocks.clone())
        },
        |(mut chain, blocks)| {
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
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    // Try to recovery from the disk.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();
    b.iter(|| {
        let _chain = Blockchain::new(
            cfg.clone(),
            chain_dir.path(),
            false,
            blocks[0].clone(),
            timestamp,
        )
        .unwrap();
    });
}

enum Serialization {
    CBOR,
    ProtoBuf,
    Bincode,
    MsgPack,
}

impl Serialization {
    fn serialize<T: Serialize + ProtoConvert>(&self, val: &T) -> Vec<u8> {
        match self {
            Self::CBOR => serde_cbor::to_vec(val).unwrap(),
            Self::Bincode => bincode::serialize(val).unwrap(),
            Self::MsgPack => rmp_serde::to_vec(val).unwrap(),
            Self::ProtoBuf => val.into_buffer().unwrap(),
        }
    }
    fn deserialize<T: DeserializeOwned + ProtoConvert>(&self, val: &[u8]) -> T {
        match self {
            Self::CBOR => serde_cbor::from_slice(val).unwrap(),
            Self::Bincode => bincode::deserialize_from(val).unwrap(),
            Self::MsgPack => rmp_serde::from_read(val).unwrap(),
            Self::ProtoBuf => T::from_buffer(val).unwrap(),
        }
    }
}

fn serialize_macro_block(b: &mut Bencher, s: Serialization) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        micro_blocks_in_epoch: 1,
        ..Default::default()
    };
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    let block = blocks[0].clone();
    // Try to recovery from the disk.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();

    b.iter(|| black_box(s.serialize(&block)));
}

fn deserialize_macro_block(b: &mut Bencher, s: Serialization) {
    const NUM_NODES: usize = 32;
    const EPOCHS: u64 = 10;
    let cfg = ChainConfig {
        stake_epochs: 100,
        micro_blocks_in_epoch: 1,
        ..Default::default()
    };
    let chain_dir = TempDir::new("bench").unwrap();
    let blocks = generate_chain(cfg.clone(), chain_dir.path(), NUM_NODES, EPOCHS);

    let block = blocks[0].clone();
    // Try to recovery from the disk.
    info!("Starting benchmark");
    let timestamp = Timestamp::now();

    let buffer = s.serialize(&block);

    b.iter(|| black_box(s.deserialize::<MacroBlock>(&buffer)));
}

fn serialize_payment(b: &mut Bencher, s: Serialization) {
    let (_, pk) = make_random_keys();
    let payment = PaymentOutput::new(&pk, 100).unwrap();
    info!("Starting benchmark");
    b.iter(|| black_box(s.serialize(&payment.0)));
}

fn deserialize_payment(b: &mut Bencher, s: Serialization) {
    let (_, pk) = make_random_keys();
    let payment = PaymentOutput::new(&pk, 100).unwrap();

    let buffer = s.serialize(&payment.0);
    info!("Starting benchmark");

    b.iter(|| black_box(s.deserialize::<PaymentOutput>(&buffer)));
}

fn blocks_benchmark(c: &mut Criterion) {
    //simple_logger::init_with_level(log::Level::Info).unwrap_or_default();
    c.bench_function("blockchain::push_macro_block(10)", push_macro_block);
    c.bench_function("blockchain::recover_macro_block(10)", recover_macro_block);
    c.bench_function("blockchain::serialize_macro(cbor)", |b| {
        serialize_macro_block(b, Serialization::CBOR)
    });
    c.bench_function("blockchain::serialize_macro(proto)", |b| {
        serialize_macro_block(b, Serialization::ProtoBuf)
    });

    c.bench_function("blockchain::deserialize_macro(cbor)", |b| {
        deserialize_macro_block(b, Serialization::CBOR)
    });
    c.bench_function("blockchain::deserialize_macro(proto)", |b| {
        deserialize_macro_block(b, Serialization::ProtoBuf)
    });

    c.bench_function("blockchain::serialize_payment(cbor)", |b| {
        serialize_payment(b, Serialization::CBOR)
    });
    c.bench_function("blockchain::serialize_payment(bincode)", |b| {
        serialize_payment(b, Serialization::Bincode)
    });
    c.bench_function("blockchain::serialize_payment(msgpack)", |b| {
        serialize_payment(b, Serialization::MsgPack)
    });
    c.bench_function("blockchain::serialize_payment(proto)", |b| {
        serialize_payment(b, Serialization::ProtoBuf)
    });

    c.bench_function("blockchain::deserialize_payment(cbor)", |b| {
        deserialize_payment(b, Serialization::CBOR)
    });
    //    c.bench_function("blockchain::deserialize_payment(bincode)", |b| {
    //        deserialize_payment(b, Serialization::Bincode)
    //    });
    c.bench_function("blockchain::deserialize_payment(MsgPack)", |b| {
        deserialize_payment(b, Serialization::MsgPack)
    });
    c.bench_function("blockchain::deserialize_payment(proto)", |b| {
        deserialize_payment(b, Serialization::ProtoBuf)
    });
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(1)).sample_size(10);
     targets = blocks_benchmark
}

criterion_main!(benches);

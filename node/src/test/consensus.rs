//
// MIT License
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

use super::wait;
use super::*;
use assert_matches::assert_matches;
use tokio;

use stegos_blockchain::Block;
use stegos_consensus::{ConsensusInfo, ConsensusMessageBody, ConsensusState};
use stegos_crypto::pbc;
use stegos_crypto::pbc::{make_random_keys, SecretKey, Signature};

#[tokio::test]
async fn smoke_test() {
    const NUM_RESTAKES: u64 = 3;
    let cfg = ChainConfig {
        micro_blocks_in_epoch: 1,
        stake_epochs: 2,
        awards_difficulty: 0,
        ..Default::default()
    };
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    trace!(">>> Iterating through {} macroblocks, with {} microblocks each", 
        1 + NUM_RESTAKES * config.chain.stake_epochs + 1,
        config.chain.micro_blocks_in_epoch
    );
    for _epoch in 1..=(1 + NUM_RESTAKES * config.chain.stake_epochs + 1) {
        for _offset in 0..config.chain.micro_blocks_in_epoch {
            p.skip_micro_block().await;
        }
        p.skip_macro_block().await;
    }
}

#[tokio::test]
async fn autocommit() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.skip_micro_block().await;
        let first = p.first();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = first.state().chain.epoch();

        let last_block_hash = first.state().chain.last_block_hash();

        let leader_pk = first.state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
            node.poll().await;
        }

        for i in 0..p.len() {
            let prevote: ConsensusMessage = p[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            for j in 0..p.len() {
                p[j].network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        p.poll().await;

        for i in 0..p.len() {
            let precommit: ConsensusMessage = p[i].network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            for j in 0..p.len() {
                p[j].network_service
                    .receive_broadcast(topic, precommit.clone());
            }
        }
        p.poll().await;

        // Receive sealed block.
        let block: Block = p
            .find_mut(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);

        info!("Starting checking of autocommit.");
        // dont send this block to any node, wait for autocommits.
        let mut nodes_pk: Vec<_> = p.iter().map(|n| n.state().network_pkey).collect();
        nodes_pk.sort();

        for pk in nodes_pk {
            p.poll().await;
            // Wait for macro block timeout.
            wait(config.node.macro_block_timeout).await;

            info!("Checking autocommit of node {}.", pk);
            if pk == leader_pk {
                continue;
            }

            let node = p.find_mut(&pk).unwrap();

            // The last node hasn't received sealed block.
            assert_eq!(node.state().chain.epoch(), epoch);
            assert_eq!(node.state().chain.last_block_hash(), last_block_hash);

            // poll to update node after macroblock_timeout waits
            node.poll().await;
            // Check that the last node has auto-committed the block.
            assert_eq!(node.state().chain.epoch(), epoch + 1);
            assert_eq!(node.state().chain.last_block_hash(), block_hash);

            // Check that the auto-committed block has been sent to the network.
            let block2: Block = node
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);
            let block_hash2 = Hash::digest(&block2);
            assert_eq!(block_hash, block_hash2);
        }
        // wait more time, to check if counter will not overflow.
        wait(config.node.macro_block_timeout).await;

        p.poll().await;
        p.filter_broadcast(&[SEALED_BLOCK_TOPIC, VIEW_CHANGE_TOPIC]);
    }
    .await;
}

#[tokio::test]
async fn round() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = CONSENSUS_TOPIC;

        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let epoch = p.first().state().chain.epoch();
        let round = p.first().state().chain.view_change() + 1;
        wait(config.node.macro_block_timeout).await;

        info!("====== Waiting for keyblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_pk = p.first_mut().state().chain.select_leader(round);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        p.poll().await;

        for i in 0..p.len() {
            let prevote: ConsensusMessage = p[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            for j in 0..p.len() {
                p[j].network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        p.poll().await;

        for i in 0..p.len() {
            let precommit: ConsensusMessage = p[i].network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            assert_eq!(precommit.epoch, epoch);
            assert_eq!(precommit.round, round);
            assert_eq!(precommit.block_hash, proposal.block_hash);
            for j in 0..p.len() {
                p[j].network_service
                    .receive_broadcast(topic, precommit.clone());
            }
        }
        p.poll().await;

        // Receive sealed block.
        let block: Block = p
            .find_mut(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);

        let macro_block = block.clone().unwrap_macro();
        assert_eq!(macro_block.header.view_change, round);
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        p.poll().await;

        for node in p.iter_except(&[leader_pk]) {
            assert_eq!(node.state().chain.epoch(), epoch + 1);
            assert_eq!(node.state().chain.last_block_hash(), block_hash);
        }
    }
    .await
}

// check if rounds started at correct timeout
// first immediatly after micro block
// second at macro_block_timeout
// third at macro_block_timeout * 2
#[tokio::test]
async fn multiple_rounds() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let view_change = p.first_mut().state().chain.view_change();
        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        wait(config.node.macro_block_timeout - Duration::from_millis(1)).await;

        p.poll().await;
        for i in 1..p.len() {
            p[i].network_service.assert_empty_queue()
        }

        wait(Duration::from_millis(1)).await;

        info!("====== Waiting for keyblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_pk = p.first_mut().state().chain.select_leader(view_change + 1);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        wait(config.node.macro_block_timeout * 2 - Duration::from_millis(1)).await;

        p.poll().await;
        for i in 1..p.len() {
            p[i].network_service.assert_empty_queue()
        }

        wait(Duration::from_millis(1)).await;

        info!("====== Waiting for keyblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_pk = p.first_mut().state().chain.select_leader(view_change + 2);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
    }
    .await
}

// check if locked node will rebroadcast propose.
//
#[tokio::test]
async fn lock() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();

        let mut round = p.first_mut().state().chain.view_change();

        let mut ready = false;
        for i in 0..1000 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = p.first_mut().state().chain.select_leader(round);
            let new_leader_pk = p.first_mut().state().chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            p.poll().await;
            let leader_node = p.find_mut(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[CHAIN_LOADER_TOPIC]);
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            wait(
                config.node.macro_block_timeout
                    * (round - p.first_mut().state().chain.view_change()),
            )
            .await;
        }
        assert!(ready);
        info!("Starting test.");
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let leader_pk = p.first_mut().state().chain.select_leader(round);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        p.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        // for now, every node is locked at leader_propose
        for i in 0..p.len() {
            let prevote: ConsensusMessage = p[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);
            for j in 0..p.len() {
                p[j].network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        p.poll().await;
        for i in 0..p.len() {
            let _precommit: ConsensusMessage = p[i].network_service.get_broadcast(topic);
        }
        p.poll().await;
        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 1),
        )
        .await;

        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let second_leader_pk = p.first_mut().state().chain.select_leader(round + 1);
        let leader_node = p.find_mut(&second_leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        assert_eq!(proposal.round, leader_proposal.round + 1);
        assert_eq!(proposal.block_hash, leader_proposal.block_hash);
        p.poll().await;
    }
    .await
}

#[tokio::test]
async fn lock_with_second_propose() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();

        let mut round = p.first_mut().state().chain.view_change();

        let mut ready = false;
        for i in 0..1000u32 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = p.first_mut().state().chain.select_leader(round);
            let new_leader_pk = p.first_mut().state().chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            p.poll().await;
            let leader_node = p.find_mut(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[CHAIN_LOADER_TOPIC]);
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            wait(
                config.node.macro_block_timeout
                    * (round - p.first_mut().state().chain.view_change()),
            )
            .await;
        }
        assert!(ready);
        info!("Starting test.");
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let leader_pk = p.first_mut().state().chain.select_leader(round);

        let second_leader_pk = p.first_mut().state().chain.select_leader(round + 1);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk, second_leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        p.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let mut prevotes = Vec::new();
        // for now, every node EXCEPT second_leader is locked at leader_propose
        for node in p.iter_except(&[second_leader_pk]) {
            let prevote: ConsensusMessage = node.network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);
            prevotes.push(prevote);
        }

        for node in p.iter_except(&[second_leader_pk]) {
            for prevote in &prevotes {
                node.network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }

        p.poll().await;
        for node in p.iter_except(&[second_leader_pk]) {
            let _precommit: ConsensusMessage = node.network_service.get_broadcast(topic);
        }
        p.poll().await;
        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 1),
        )
        .await;

        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_node = p.find_mut(&second_leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        assert_eq!(proposal.round, leader_proposal.round + 1);
        assert_ne!(proposal.block_hash, leader_proposal.block_hash);

        for node in p.iter_except(&[second_leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }

        // assert that no unprocessed prevotes are received for this block
        p.poll().await;
    }
    .await
}

/// Send pack of prevotes in hope that node will ignore messages.
///
#[tokio::test]
async fn pack_of_prevotes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();

        let mut round = p.first_mut().state().chain.view_change();

        let mut ready = false;
        for i in 0..1000 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = p.first_mut().state().chain.select_leader(round);
            let new_leader_pk = p.first_mut().state().chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            p.poll().await;
            let leader_node = p.find_mut(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[CHAIN_LOADER_TOPIC]);
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            wait(
                config.node.macro_block_timeout
                    * (round - p.first_mut().state().chain.view_change()),
            )
            .await;
        }

        assert!(ready);
        info!("Starting test.");
        let leader_pk = p.first_mut().state().chain.select_leader(round);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node.poll().await;
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        let leaders = &[leader_pk];
        let first_node = p.iter_except(leaders).next().unwrap();
        let first_node_pk = first_node.state().network_pkey;
        let mut split = p.split(&[first_node_pk]);

        for node in split.parts.1.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        let mut prevotes = Vec::new();
        for node in split.parts.1.iter_mut() {
            node.poll().await;
            let prevote: ConsensusMessage = node.network_service.get_broadcast(topic);

            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);

            prevotes.push(prevote)
        }

        for node in split.parts.1.iter_mut() {
            for prevote in prevotes.iter() {
                node.network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }

        split.parts.1.poll().await;
        for node in split.parts.1.iter_mut() {
            let _precommit: ConsensusMessage = node.network_service.get_broadcast(topic);
        }

        split.parts.1.poll().await;

        let first_node = split.parts.0.iter_mut().next().unwrap();

        for prevote in prevotes.iter() {
            first_node
                .network_service
                .receive_broadcast(topic, prevote.clone());
        }

        first_node
            .network_service
            .receive_broadcast(topic, leader_proposal.clone());

        first_node.poll().await;

        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 1),
        )
        .await;

        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        p.filter_broadcast(&[topic]);
    }
    .await
}

#[tokio::test]
async fn lock_with_second_propose_and_pack_of_prevotes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();

        let mut round = p.first_mut().state().chain.view_change();

        let mut ready = false;
        for i in 0..1000 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = p.first_mut().state().chain.select_leader(round);
            let new_leader_pk = p.first_mut().state().chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            p.poll().await;
            let leader_node = p.find_mut(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[CHAIN_LOADER_TOPIC]);
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            wait(
                config.node.macro_block_timeout
                    * (round - p.first_mut().state().chain.view_change()),
            )
            .await;
        }
        assert!(ready);
        info!("Starting test.");
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let leader_pk = p.first_mut().state().chain.select_leader(round);

        let second_leader_pk = p.first_mut().state().chain.select_leader(round + 1);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk, second_leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        p.poll().await;

        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let mut prevotes = Vec::new();
        // for now, every node EXCEPT second_leader is locked at leader_propose
        for node in p.iter_except(&[second_leader_pk]) {
            let prevote: ConsensusMessage = node.network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);
            prevotes.push(prevote);
        }

        let leader_node = p.find_mut(&leader_pk).unwrap();
        for prevote in &prevotes {
            leader_node
                .network_service
                .receive_broadcast(topic, prevote.clone());
        }

        p.poll().await;
        let leader_node = p.find_mut(&leader_pk).unwrap();
        let _precommit: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 1),
        )
        .await;

        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        // filter messages from chain loader.
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let leader_node = p.find_mut(&second_leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        assert_eq!(proposal.round, leader_proposal.round + 1);
        assert_ne!(proposal.block_hash, leader_proposal.block_hash);

        for node in p.iter_except(&[second_leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        p.poll().await;

        // any node except of locked first leader, should vote for second propose
        let mut prevotes = Vec::new();
        for node in p.iter_except(&[leader_pk]) {
            let prevote: ConsensusMessage = node.network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.round, proposal.round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            prevotes.push(prevote);
        }

        for node in p.iter_except(&[leader_pk]) {
            for prevote in &prevotes {
                node.network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }

        p.poll().await;

        // any node except of locked first leader, should confirm vote for second propose
        let mut precommits = Vec::new();
        for node in p.iter_except(&[leader_pk]) {
            let precommit: ConsensusMessage = node.network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            precommits.push(precommit);
        }
        p.poll().await;

        let old_leader_node = p.find_mut(&leader_pk).unwrap();

        for prevote in prevotes.iter() {
            old_leader_node
                .network_service
                .receive_broadcast(topic, prevote.clone());
        }
        for node in p.iter_mut() {
            for precommit in precommits.iter() {
                node.network_service
                    .receive_broadcast(topic, precommit.clone());
            }
        }

        p.poll().await;
        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 2),
        )
        .await;

        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        p.filter_broadcast(&[VIEW_CHANGE_TOPIC, SEALED_BLOCK_TOPIC]);
    }
    .await
}

/// Send pack of prevotes in hope that node will ignore messages.
/// This test the same as `pack_of_prevotes` but also send precommits pack to handle autocommit.
#[tokio::test]
async fn pack_of_prevotes_and_precommits() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();

        let mut round = p.first_mut().state().chain.view_change();

        let mut ready = false;
        for i in 0..1000 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = p.first_mut().state().chain.select_leader(round);
            let new_leader_pk = p.first_mut().state().chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            p.poll().await;
            let leader_node = p.find_mut(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[CHAIN_LOADER_TOPIC]);
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            wait(
                config.node.macro_block_timeout
                    * (round - p.first_mut().state().chain.view_change()),
            )
            .await;
        }

        assert!(ready);
        info!("Starting test.");
        let leader_pk = p.first_mut().state().chain.select_leader(round);
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node.poll().await;
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        let leaders = &[leader_pk];
        let first_node = p.iter_except(leaders).next().unwrap();
        let first_node_pk = first_node.state().network_pkey;
        let mut split = p.split(&[first_node_pk]);

        for node in split.parts.1.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        let mut prevotes = Vec::new();
        for node in split.parts.1.iter_mut() {
            node.poll().await;
            let prevote: ConsensusMessage = node.network_service.get_broadcast(topic);

            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);

            prevotes.push(prevote)
        }

        for node in split.parts.1.iter_mut() {
            for prevote in prevotes.iter() {
                node.network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }

        split.parts.1.poll().await;
        let mut precommits = Vec::new();
        for node in split.parts.1.iter_mut() {
            let precommit: ConsensusMessage = node.network_service.get_broadcast(topic);
            precommits.push(precommit);
        }

        split.parts.1.poll().await;

        let first_node = split.parts.0.iter_mut().next().unwrap();

        for prevote in prevotes.iter() {
            first_node
                .network_service
                .receive_broadcast(topic, prevote.clone());
        }
        for precommit in precommits.iter() {
            first_node
                .network_service
                .receive_broadcast(topic, precommit.clone());
        }

        first_node
            .network_service
            .receive_broadcast(topic, leader_proposal.clone());

        first_node.poll().await;

        wait(
            config.node.macro_block_timeout
                * (round - p.first_mut().state().chain.view_change() + 1),
        )
        .await;

        info!("====== Waiting for macroblock timeout. =====");
        p.poll().await;

        p.filter_broadcast(&[topic, SEALED_BLOCK_TOPIC]);
    }
    .await
}

#[tokio::test]
async fn out_of_order_micro_block() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 0;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        let topic = crate::CONSENSUS_TOPIC;
        p.poll().await;
        p.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        let epoch = p.first_mut().state().chain.epoch();
        let offset = p.first_mut().state().chain.offset();
        let leader_pk = p.first_mut().state().chain.leader();

        //create valid but out of order fake micro block.
        let timestamp = Timestamp::now();

        let view_change = p.first_mut().state().chain.view_change();
        let last_block_hash = p.first_mut().state().chain.last_block_hash();

        let leader = p.find(&leader_pk).unwrap();
        let seed = mix(
            leader.state().chain.last_random(),
            leader.state().chain.view_change(),
        );
        let random = pbc::make_VRF(&leader.state().network_skey, &seed);
        let solution = leader.state().chain.vdf_solver()();

        let mut block = MicroBlock::empty(
            last_block_hash,
            epoch,
            offset,
            view_change + 1,
            None,
            leader.state().network_pkey,
            random,
            solution,
            timestamp,
        );
        let leader_node = p.find_mut(&leader_pk).unwrap();
        block.sign(
            &leader_node.state().network_skey,
            &leader_node.state().network_pkey,
        );
        let block: Block = Block::MicroBlock(block);

        // Discard proposal from leader for a proposal from the leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        // broadcast block to other nodes.
        for node in &mut p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }
        p.poll().await;

        for node in p.iter() {
            assert_eq!(node.state().chain.epoch(), epoch);
            assert_eq!(node.state().chain.offset(), offset);
        }

        let leader_pk = p.first().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        leader_node
            .network_service
            .filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

fn resign_msg(msg: ConsensusMessage, key: &SecretKey) -> ConsensusMessage {
    ConsensusMessage::new(
        msg.epoch,
        msg.round,
        msg.block_hash,
        key,
        &msg.pkey,
        msg.body,
    )
}

fn create_invalid_consensus_messages(
    msg: &ConsensusMessage,
    key: &SecretKey,
) -> Vec<ConsensusMessage> {
    let mut msgs = Vec::new();

    // 1. Change round
    let mut new_msg = msg.clone();
    new_msg.round += 1;
    msgs.push(resign_msg(new_msg, key));

    let mut new_msg = msg.clone();
    new_msg.round -= 1;
    msgs.push(resign_msg(new_msg, key));

    // 2. Change epoch
    let mut new_msg = msg.clone();
    new_msg.epoch += 1;
    msgs.push(resign_msg(new_msg, key));

    let mut new_msg = msg.clone();
    new_msg.epoch -= 1;
    msgs.push(resign_msg(new_msg, key));

    // 3. Change block_hash
    let mut new_msg = msg.clone();
    new_msg.block_hash = Hash::digest("test");
    msgs.push(resign_msg(new_msg, key));

    // 4. Change signature
    let mut new_msg = msg.clone();
    new_msg.sig = Signature::zero();
    msgs.push(new_msg);

    // 4. Change pkey (to invalid peer)
    let (skey_new, pkey_new) = make_random_keys();
    let mut new_msg = msg.clone();
    new_msg.pkey = pkey_new;
    msgs.push(resign_msg(new_msg, &skey_new));

    msgs
}

fn create_invalid_header(header: &MacroBlockHeader) -> Vec<MacroBlockHeader> {
    let mut headers = Vec::new();

    // Change version
    let mut new_header = header.clone();
    new_header.version += 1;
    headers.push(new_header);

    let mut new_header = header.clone();
    new_header.version -= 1;
    headers.push(new_header);

    // Wrong epoch
    let mut new_header = header.clone();
    new_header.epoch += 1;
    headers.push(new_header);

    let mut new_header = header.clone();
    new_header.epoch -= 1;
    headers.push(new_header);

    // last block hash
    let mut new_header = header.clone();
    new_header.previous = Hash::digest("1");
    headers.push(new_header);

    // change view_change
    let mut new_header = header.clone();
    new_header.view_change += 1;
    headers.push(new_header);

    let mut new_header = header.clone();
    new_header.view_change -= 1;
    headers.push(new_header);

    //TODO: Change block_reward
    //TODO: Change random
    //TODO: Change pkey
    //TODO: Change activity_map
    //TODO: Change gamma
    //TODO: Change previous
    //TODO: Change timestamp
    //TODO: Chainge inputs_range_hash

    headers
}

fn create_invalid_proposes(msg: &ConsensusMessage, key: &SecretKey) -> Vec<ConsensusMessage> {
    let mut msgs = create_invalid_consensus_messages(&msg, key);

    let bodys: Vec<_> = match msg.body {
        ConsensusMessageBody::Proposal(ref proposal) => {
            create_invalid_header(&proposal.header)
                .into_iter()
                .map(|h| {
                    let mut proposal_new = proposal.clone();
                    proposal_new.header = h;
                    ConsensusMessageBody::Proposal(proposal_new)
                })
                .collect()
            //TODO: Change txs
        }
        _ => panic!("Wrong message, expected propose"),
    };

    msgs.extend(bodys.into_iter().map(|b| {
        let mut new_msg = msg.clone();
        new_msg.body = b;
        resign_msg(new_msg, key)
    }));
    msgs
}

fn create_invalid_prevotes(msg: &ConsensusMessage, key: &SecretKey) -> Vec<ConsensusMessage> {
    create_invalid_consensus_messages(&msg, key)
}

fn save_consensus_state(node: &NodeService) -> ConsensusInfo {
    let consensus = match node.state().validation {
        Validation::MacroBlockValidator { ref consensus, .. } => consensus,
        _ => panic!("Wrong state."),
    };
    consensus.to_info()
}

fn assert_consensus_state(info: &ConsensusInfo, node: &NodeService) {
    let consensus = match node.state().validation {
        Validation::MacroBlockValidator { ref consensus, .. } => consensus,
        _ => panic!("Wrong state."),
    };
    let new_info = consensus.to_info();
    assert_eq!(*info, new_info)
}

async fn invalid_proposes_inner<'a>(p: &mut Partition<'a>, round: u32) {
    let topic = crate::CONSENSUS_TOPIC;
    let epoch = p.first_mut().state().chain.epoch();

    let leader_pk = p.first_mut().state().chain.select_leader(round);
    trace!("SELECTING LEADER of round {} = {}", round, leader_pk);
    let leader_node = p.find_mut(&leader_pk).unwrap();

    let skey = leader_node.state().network_skey.clone();

    // Check for a proposal from the leader.
    let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
    debug!("Proposal: {:?}", proposal);
    assert_eq!(proposal.epoch, epoch);
    assert_eq!(proposal.round, round);
    assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
    let mut r = p.split(&[leader_pk]);
    let mut info = save_consensus_state(&r.parts.1.first().node_service);

    r.parts.1.for_each(|node| {
        assert_consensus_state(&info, node);
    });

    let invalid_messages = create_invalid_proposes(&proposal, &skey);
    for (id, msg) in invalid_messages.iter().enumerate() {
        for node in r.parts.1.iter_mut() {
            node.network_service.receive_broadcast(topic, msg.clone());
        }

        r.parts.1.poll().await;
        debug!("Checking state after {} message", id);
        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });
    }

    // Send the original proposal to other nodes.
    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(topic, proposal.clone());
    }
    r.parts.1.poll().await;
    // node should produce prevote.
    info.prevotes_len += 1;
    info.state = ConsensusState::Prevote;
    r.parts.1.for_each(|node| {
        assert_consensus_state(&info, node);
    });
}

// Test [multiple Invalid messages on proposes]
// Test [Proposes from invalid peer]
// Test [ Invalid header in propose]
//
// assert: that all this messages should not be accepted

#[tokio::test]
async fn invalid_proposes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.

        p.poll().await;
        p.skip_micro_block().await;

        let round = p.first_mut().state().chain.view_change();
        invalid_proposes_inner(&mut p, round).await;
        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

#[tokio::test]
async fn invalid_proposes_on_2nd_round() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.

        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;

        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        wait(config.node.macro_block_timeout).await;

        info!("====== Waiting for keyblock timeout. =====");
        p.poll().await;

        let round = p.first_mut().state().chain.view_change() + 1;
        invalid_proposes_inner(&mut p, round).await;
        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

// Test [multiple leaders on proposes]
// Test [multiple proposes from single leader]
//
// assert: that all this messages should not change state after first propose.

#[tokio::test]
async fn multiple_proposes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.

        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();
        let round = p.first_mut().state().chain.view_change();

        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();

        let skey = leader_node.state().network_skey.clone();

        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        let mut r = p.split(&[leader_pk]);
        let mut info = save_consensus_state(&r.parts.1.first().node_service);

        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        r.parts.1.poll().await;
        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        // Send the original proposal to other nodes.
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        r.parts.1.poll().await;
        // node should produce prevote.
        info.prevotes_len += 1;
        info.state = ConsensusState::Prevote;

        let mut invalid_messages = Vec::new();

        // change author
        let node = r.parts.1.first();
        let mut new_msg = proposal.clone();
        new_msg.pkey = node.state().network_pkey;
        invalid_messages.push(resign_msg(new_msg, &node.state().network_skey));

        // Send other valid propose
        let mut new_msg = proposal.clone();

        match new_msg.body {
            ConsensusMessageBody::Proposal(ref mut p) => {
                p.header.timestamp += Duration::from_millis(1);
            }
            _ => unreachable!(),
        }
        invalid_messages.push(resign_msg(new_msg, &skey));

        for node in r.parts.1.iter_mut() {
            for msg in invalid_messages.iter() {
                node.network_service.receive_broadcast(topic, msg.clone());
            }
        }
        r.parts.1.poll().await;

        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

// Test [multiple message on prevote]
#[tokio::test]
async fn invalid_prevotes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();
        let round = p.first_mut().state().chain.view_change();

        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        p.poll().await;

        let mut r = p.split(&[leader_pk]);
        let node_skey = r.parts.1.first().state().network_skey.clone();
        let node_prevote: ConsensusMessage =
            r.parts.1.first_mut().network_service.get_broadcast(topic);
        assert_matches!(node_prevote.body, ConsensusMessageBody::Prevote);

        let mut info = save_consensus_state(&r.parts.1.first().node_service);

        // Send these pre-votes to nodes.
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(topic, node_prevote.clone());
        }
        info.prevotes_len += 1;

        r.parts.1.poll().await;
        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut().skip(1) {
            assert_consensus_state(&info, &mut node.node_service);
        }

        let invalid_messages = create_invalid_prevotes(&node_prevote, &node_skey);

        for node in r.parts.1.iter_mut() {
            for msg in &invalid_messages {
                node.network_service.receive_broadcast(topic, msg.clone());
            }
        }
        r.parts.1.poll().await;

        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut().skip(1) {
            assert_consensus_state(&info, &mut node.node_service);
        }

        p.poll().await;
        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

// Test [multiple message on prevote (from leader)]
#[tokio::test]
async fn invalid_prevotes_leader() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    async {
        // Create one micro block.
        p.poll().await;
        p.skip_micro_block().await;

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = p.first_mut().state().chain.epoch();
        let round = p.first_mut().state().chain.view_change();

        let leader_pk = p.first_mut().state().chain.leader();
        let leader_node = p.find_mut(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in p.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        p.poll().await;

        let mut r = p.split(&[leader_pk]);
        let leader_skey = r.parts.0.first().state().network_skey.clone();
        let leader_prevote: ConsensusMessage =
            r.parts.0.first_mut().network_service.get_broadcast(topic);
        assert_matches!(leader_prevote.body, ConsensusMessageBody::Prevote);

        let mut info = save_consensus_state(&r.parts.1.first().node_service);

        // Send these pre-votes to nodes.
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(topic, leader_prevote.clone());
        }
        info.prevotes_len += 1;

        r.parts.1.poll().await;
        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut().skip(1) {
            assert_consensus_state(&info, &mut node.node_service);
        }

        let invalid_messages = create_invalid_prevotes(&leader_prevote, &leader_skey);

        for node in r.parts.1.iter_mut() {
            for msg in &invalid_messages {
                node.network_service.receive_broadcast(topic, msg.clone());
            }
        }
        r.parts.1.poll().await;

        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut() {
            assert_consensus_state(&info, &mut node.node_service);
        }

        p.poll().await;
        p.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    }
    .await
}

// Test [multiple message on precomit]
// Test [multiple message on precomit (from leader)]

// TODO:
// Test Keep some validator locked on round
// Test multiple count of precommits for locked round (should save precommit from previuous round?).

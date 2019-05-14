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

use super::*;
use crate::*;
use stegos_blockchain::Block;
use stegos_consensus::ConsensusMessageBody;
use stegos_crypto::pbc;

#[test]
fn smoke_test() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let height = s.nodes[0].node_service.chain.height();
        let round = s.nodes[0].node_service.chain.view_change();
        let epoch = s.nodes[0].node_service.chain.epoch();
        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.height, height);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        // Check for pre-votes.
        let mut prevotes: Vec<BlockConsensusMessage> = Vec::with_capacity(s.num_nodes());
        for node in s.nodes.iter_mut() {
            let prevote: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(prevote.height, height);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.request_hash, proposal.request_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            prevotes.push(prevote);
        }

        // Send these pre-votes to nodes.
        for i in 0..s.num_nodes() {
            for j in 0..s.num_nodes() {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, prevotes[j].clone());
                }
            }
        }
        s.poll();

        // Check for pre-commits.
        let mut precommits: Vec<BlockConsensusMessage> = Vec::with_capacity(s.num_nodes());
        for node in s.nodes.iter_mut() {
            let precommit: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(precommit.height, height);
            assert_eq!(precommit.round, round);
            assert_eq!(precommit.request_hash, proposal.request_hash);
            if let ConsensusMessageBody::Precommit {
                request_hash_sig, ..
            } = precommit.body
            {
                pbc::check_hash(
                    &proposal.request_hash,
                    &request_hash_sig,
                    &node.node_service.keys.network_pkey,
                )
                .unwrap();
            } else {
                panic!("Invalid packet");
            }
            precommits.push(precommit);
        }

        // Send these pre-commits to nodes.
        for i in 0..s.num_nodes() {
            for j in 0..s.num_nodes() {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, precommits[j].clone());
                }
            }
        }
        s.poll();

        // Receive sealed block.
        let block: Block = s
            .node(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);
        assert_eq!(block_hash, proposal.request_hash);
        assert_eq!(block.base_header().height, height);
        assert_eq!(block.base_header().previous, last_block_hash);

        // Send this sealed block to all other nodes expect the first not leader.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        // Check state of (0..NUM_NODES - 1) nodes.
        for node in s.iter_except(&[leader_pk]) {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch(), epoch + 1);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }
    });
}

#[test]
fn autocomit() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let height = s.nodes[0].node_service.chain.height();
        let epoch = s.nodes[0].node_service.chain.epoch();

        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let prevote: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let precommit: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, precommit.clone());
            }
        }
        s.poll();

        // Receive sealed block.
        let block: Block = s
            .node(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);

        // Send this sealed block to all other nodes expect the first not leader.
        for node in s.iter_except(&[leader_pk]).skip(1) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        // Check state of (0..NUM_NODES - 1) nodes.
        for node in s.iter_except(&[leader_pk]).skip(1) {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch(), epoch + 1);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }

        let skip_leader = [leader_pk];
        let last_node = s.iter_except(&skip_leader).next().unwrap();
        // The last node hasn't received sealed block.
        assert_eq!(last_node.node_service.chain.height(), height);
        assert_eq!(last_node.node_service.chain.epoch(), epoch);
        assert_eq!(
            last_node.node_service.chain.last_block_hash(),
            last_block_hash
        );

        // Wait for TX_WAIT_TIMEOUT.
        s.wait(s.cfg().macro_block_timeout);
        let last_node = s.iter_except(&skip_leader).next().unwrap();
        last_node.poll();

        // Check that the last node has auto-committed the block.
        assert_eq!(last_node.node_service.chain.height(), height + 1);
        assert_eq!(last_node.node_service.chain.epoch(), epoch + 1);
        assert_eq!(last_node.node_service.chain.last_block_hash(), block_hash);

        // Check that the auto-committed block has been sent to the network.
        let block2: Block = last_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash2 = Hash::digest(&block2);
        assert_eq!(block_hash, block_hash2);
        s.filter_unicast(&["chain-loader"])
    });
}

#[test]
fn round() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let height = s.nodes[0].node_service.chain.height();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let round = s.nodes[0].node_service.chain.view_change() + 1;
        let epoch = s.nodes[0].node_service.chain.epoch();
        s.wait(s.cfg().macro_block_timeout);

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
        let leader_node = s.node(&leader_pk).unwrap();
        let proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let prevote: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.height, height);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.request_hash, proposal.request_hash);
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let precommit: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            assert_eq!(precommit.height, height);
            assert_eq!(precommit.round, round);
            assert_eq!(precommit.request_hash, proposal.request_hash);
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, precommit.clone());
            }
        }
        s.poll();

        // Receive sealed block.
        let block: Block = s
            .node(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);

        assert_eq!(block.base_header().view_change, round);
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        for node in s.iter_except(&[leader_pk]) {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch(), epoch + 1);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }
    });
}

// check if rounds started at correct timeout
// first immediatly after micro block
// second at macro_block_timeout
// third at macro_block_timeout * 2
#[test]
fn multiple_rounds() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let view_change = s.nodes[0].node_service.chain.view_change();
        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);

        s.wait(s.cfg().macro_block_timeout - Duration::from_millis(1));

        s.poll();
        for i in 1..s.num_nodes() {
            s.nodes[i].network_service.assert_empty_queue()
        }

        s.wait(Duration::from_millis(1));

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.select_leader(view_change + 1);
        let leader_node = s.node(&leader_pk).unwrap();
        let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);

        s.wait(s.cfg().macro_block_timeout * 2 - Duration::from_millis(1));

        s.poll();
        for i in 1..s.num_nodes() {
            s.nodes[i].network_service.assert_empty_queue()
        }

        s.wait(Duration::from_millis(1));

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.select_leader(view_change + 2);
        let leader_node = s.node(&leader_pk).unwrap();
        let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
    });
}

// check if locked node will rebroadcast propose.
//
#[test]
fn lock() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let height = s.nodes[0].node_service.chain.height();

        let mut round = s.nodes[0].node_service.chain.view_change();

        let mut ready = false;
        for i in 0..1000 {
            info!(
                "Checking if leader of round {}, and {} is different",
                i,
                i + 1
            );
            let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
            let new_leader_pk = s.nodes[0].node_service.chain.select_leader(round + 1);

            if leader_pk != new_leader_pk {
                ready = true;
                break;
            }

            info!("skipping round {}, leader = {}", i, leader_pk);
            s.poll();
            let leader_node = s.node(&leader_pk).unwrap();

            leader_node
                .network_service
                .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
            let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            s.wait(
                s.cfg().macro_block_timeout * (round - s.nodes[0].node_service.chain.view_change()),
            );
        }
        assert!(ready);
        info!("Starting test.");
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
        let leader_node = s.node(&leader_pk).unwrap();

        leader_node.poll();
        // skip proposal and prevote of last leader.
        let leader_proposal: BlockConsensusMessage =
            leader_node.network_service.get_broadcast(topic);

        assert_matches!(leader_proposal.body, ConsensusMessageBody::Proposal { .. });
        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, leader_proposal.clone());
        }
        s.poll();

        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        // for now, every node is locked at leader_propose
        for i in 0..s.num_nodes() {
            let prevote: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.height, height);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.request_hash, leader_proposal.request_hash);
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();
        for i in 0..s.num_nodes() {
            let _precommit: BlockConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
        }
        s.wait(
            s.cfg().macro_block_timeout * (round - s.nodes[0].node_service.chain.view_change() + 1),
        );

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.select_leader(round + 1);
        let leader_node = s.node(&leader_pk).unwrap();
        let proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let _prevote: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        assert_eq!(proposal.round, leader_proposal.round + 1);
        assert_eq!(proposal.request_hash, leader_proposal.request_hash);
        s.poll();
    });
}

#[test]
fn out_of_order_micro_block() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();

        let height = s.nodes[0].node_service.chain.height();
        let leader_pk = s.nodes[0].node_service.chain.leader();

        //create valid but out of order fake micro block.
        let version: u64 = 1;
        let timestamp = SystemTime::now();

        let round = s.nodes[0].node_service.chain.view_change();
        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        let leader = s.node(&leader_pk).unwrap();
        let seed = mix(
            leader.node_service.chain.last_random(),
            leader.node_service.chain.view_change(),
        );
        let random = pbc::make_VRF(&leader.node_service.keys.network_skey, &seed);

        let base = BaseBlockHeader::new(
            version,
            last_block_hash,
            height,
            round + 1,
            timestamp,
            random,
        );
        let mut block = MicroBlock::empty(base, None, leader.node_service.keys.network_pkey);

        let block_hash = Hash::digest(&block);
        let leader_node = s.node(&leader_pk).unwrap();
        block.sig = pbc::sign_hash(&block_hash, &leader_node.node_service.keys.network_skey);
        let block: Block = Block::MicroBlock(block);

        // Discard proposal from leader for a proposal from the leader.
        let _proposal: BlockConsensusMessage = leader_node.network_service.get_broadcast(topic);
        // broadcast block to other nodes.
        for node in &mut s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }
        s.poll();

        s.for_each(|node| assert_eq!(node.chain.height(), height));

        let leader_pk = s.first().node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        leader_node
            .network_service
            .filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}

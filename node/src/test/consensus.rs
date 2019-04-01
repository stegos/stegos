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

use super::time::{start_test, wait};
use super::*;
use crate::*;
use stegos_blockchain::Block;
use stegos_consensus::ConsensusMessageBody;
use stegos_crypto::pbc::secure;

// TODO: re-enable this test after removing VRF
//#[test]
#[allow(dead_code)]
fn basic() {
    const NUM_NODES: usize = 3;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let topic = crate::CONSENSUS_TOPIC;
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 2;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }
        let epoch = s.nodes[0].node_service.chain.epoch();
        let leader_id = 0;

        // Process N monetary blocks.
        let mut height = s.nodes[0].node_service.chain.height();
        for _ in 1..cfg.blocks_in_epoch {
            wait(timer, Duration::from_secs(cfg.tx_wait_timeout));
            s.poll();
            let block: Block = s.nodes[leader_id]
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);
            assert_eq!(block.base_header().height, height);
            for (i, node) in s.nodes.iter_mut().enumerate() {
                if i != leader_id {
                    node.network_service
                        .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
                }
            }
            s.poll();

            height += 1;
            for node in s.nodes.iter() {
                assert_eq!(node.node_service.chain.height(), height);
            }
        }
        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        // TODO: determine who is a leader.

        // Check for a proposal from the leader.
        let proposal: BlockConsensusMessage = s.nodes[0].network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.height, height);
        assert_eq!(proposal.epoch, epoch);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.nodes.iter_mut().skip(1) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        // Check for pre-votes.
        let mut prevotes: Vec<BlockConsensusMessage> = Vec::with_capacity(NUM_NODES);
        for node in s.nodes.iter_mut() {
            let prevote: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(proposal.height, height);
            assert_eq!(proposal.epoch, epoch);
            assert_eq!(proposal.request_hash, proposal.request_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            prevotes.push(prevote);
        }

        // Send these pre-votes to nodes.
        for i in 0..NUM_NODES {
            for j in 0..NUM_NODES {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, prevotes[j].clone());
                }
            }
        }
        s.poll();

        // Check for pre-commits.
        let mut precommits: Vec<BlockConsensusMessage> = Vec::with_capacity(NUM_NODES);
        for node in s.nodes.iter_mut() {
            let precommit: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(proposal.height, height);
            assert_eq!(proposal.epoch, epoch);
            assert_eq!(proposal.request_hash, proposal.request_hash);
            if let ConsensusMessageBody::Precommit {
                request_hash_sig, ..
            } = precommit.body
            {
                assert!(secure::check_hash(
                    &proposal.request_hash,
                    &request_hash_sig,
                    &node.node_service.keys.network_pkey
                ));
            } else {
                panic!("Invalid packet");
            }
            precommits.push(precommit);
        }

        // Send these pre-commits to nodes.
        for i in 0..NUM_NODES {
            for j in 0..NUM_NODES {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, precommits[j].clone());
                }
            }
        }
        s.poll();

        // Receive sealed block.
        let block: Block = s.nodes[0]
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);
        assert_eq!(block_hash, proposal.request_hash);
        assert_eq!(block.base_header().height, height);
        assert_eq!(block.base_header().previous, last_block_hash);

        // Send this sealed block to all other nodes expect the last one.
        for node in s.nodes.iter_mut().take(NUM_NODES - 1).skip(1) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        // Check state of (0..NUM_NODES - 1) nodes.
        for node in s.nodes.iter().take(NUM_NODES - 1) {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch(), epoch);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }

        // The last node hasn't received sealed block.
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.height(), height);
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.epoch(), epoch);
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.last_block_hash(),
            last_block_hash
        );

        // Wait for TX_WAIT_TIMEOUT.
        wait(timer, Duration::from_secs(cfg.block_timeout));
        s.nodes[NUM_NODES - 1].poll();

        // Check that the last node has auto-committed the block.
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.height(),
            height + 1
        );
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.epoch(), epoch);
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.last_block_hash(),
            block_hash
        );

        // Check that the auto-committed block has been sent to the network.
        let block2: Block = s.nodes[NUM_NODES - 1]
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash2 = Hash::digest(&block2);
        assert_eq!(block_hash, block_hash2);
    });
}

#[test]
fn request_on_timeout() {
    const NUM_NODES: usize = 3;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 2;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }
        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_id = s
            .nodes_keychains
            .iter()
            .enumerate()
            .find(|(_id, keys)| leader_pk == keys.network_pkey)
            .map(|(id, _)| id)
            .unwrap();

        // emulate timeout on other nodes, and wait for request
        wait(timer, Duration::from_secs(cfg.micro_block_timeout));
        info!("BEFORE POLL");
        s.poll();
        for (_, node) in s
            .nodes
            .iter_mut()
            .enumerate()
            .filter(|(id, _)| *id != leader_id)
        {
            let _: ChainLoaderMessage = node
                .network_service
                .get_unicast(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
        }
    });
}

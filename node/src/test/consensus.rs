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

#[test]
fn basic() {
    const NUM_NODES: usize = 3;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let topic = crate::CONSENSUS_TOPIC;
        // Create NUM_NODES.
        let mut s: Sandbox = Sandbox::new(NUM_NODES);
        let height = s.nodes[0].node_service.chain.height();
        let epoch = s.nodes[0].node_service.chain.epoch;

        // Wait for TX_WAIT_TIMEOUT.
        wait(timer, crate::TX_WAIT_TIMEOUT);
        s.poll();

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
        assert_eq!(block.base_header().epoch, epoch);

        // Send this sealed block to other nodes.
        for node in s.nodes.iter_mut().skip(1) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        // Check state.
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch, epoch);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }
    });
}

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
use std::collections::HashSet;
use stegos_blockchain::Block;
use stegos_consensus::MacroBlockProposal;
use stegos_consensus::{optimistic::SealedViewChangeProof, ConsensusMessage, ConsensusMessageBody};

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] receive 2/3rd of view_change messages.
//
// Asserts that Nodes [B, D, E] go to the next view_change.
#[test]
fn dead_leader() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        // let leader shoot his block
        s.wait(s.cfg().tx_wait_timeout);
        s.poll();
        // emulate timeout on other nodes, and wait for request
        s.wait(s.cfg().micro_block_timeout);
        info!("PARTITION BEGIN");
        s.poll();
        let mut r = s.split(&[leader_pk]);
        // emulate dead leader for other nodes
        r.parts
            .1
            .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        info!("BROADCAST VIEW_CHANGES");
        for node in r.parts.1.iter_mut() {
            for msg in &msgs {
                node.network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
        }

        let next_leader = r.parts.1.next_view_change_leader();
        r.parts.1.poll();
        for node in r.parts.1.iter_mut() {
            info!("processing validator = {:?}", node.validator_id());
            if next_leader == node.node_service.keys.network_pkey {
                let _: Block = node.network_service.get_broadcast(SEALED_BLOCK_TOPIC);
                // If node was leader, they have produced micro block,
                assert_eq!(node.node_service.chain.view_change(), 0);
            } else {
                assert_eq!(node.node_service.chain.view_change(), 1);
            }
        }

        let first_leader = r.parts.0.first_mut();

        assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);
        first_leader
            .network_service
            .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC, crate::SEALED_BLOCK_TOPIC]);
        first_leader
            .network_service
            .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Nodes [C,D] Receive block (B2)
//
// Asserts that Nodes [B, D, E] has last block B2, and same height().

#[test]
fn silent_view_change() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        precondition_2_different_leaderers(&mut s);

        let starting_view_changes = s.nodes[0].node_service.chain.view_change();
        let leader_pk = s.leader();
        let new_leader = s.next_view_change_leader();

        s.wait(s.cfg().tx_wait_timeout);
        s.poll();
        s.wait(s.cfg().micro_block_timeout);
        info!("======= PARTITION BEGIN =======");
        s.poll();
        // emulate dead leader for other nodes
        {
            // filter messages from chain loader.
            s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

            let mut r = s.split(&[leader_pk]);

            let mut msgs = Vec::new();
            for node in &mut r.parts.1.nodes {
                let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
                msgs.push(msg);
            }
            assert_eq!(msgs.len(), 3);

            let new_leader_node = r.parts.1.node(&new_leader).unwrap();
            // new leader receive all view change messages and produce new block.
            // each node should accept new block.

            info!("======= BROADCAST VIEW_CHANGES =======");
            for msg in &msgs {
                new_leader_node
                    .network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
            new_leader_node.poll();

            info!("======= BROADCAST BLOCK =======");
            let block: Block = new_leader_node
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);

            assert_eq!(block.base_header().view_change, starting_view_changes + 1);
            // broadcast block to other nodes.
            for node in &mut r.parts.1.nodes {
                node.network_service
                    .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
            }
            r.parts.1.poll();
            // after this each node should go to the current block

            let last_block_hash = Hash::digest(&block);
            // skip next leader, because it can immediately produce next block,
            // and go to the next view_change.
            for node in &mut r.parts.1.nodes {
                info!("processing validator = {:?}", node.validator_id());
                assert_eq!(node.node_service.chain.view_change(), 0);
                assert_eq!(node.node_service.chain.last_block_hash(), last_block_hash);
            }
            let first_leader = r.parts.0.first_mut();

            assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);
            first_leader
                .network_service
                .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC, crate::SEALED_BLOCK_TOPIC]);
        }
    });
}

// Regression test for double view_change.
// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader and go offline.
// 3. Nodes [D] Receive single view_change message from node [C].
//
// Asserts that Nodes [D] has view_change 2, and don't go to view_change 3.

#[test]
fn double_view_change() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        let mut blocks = 0;

        for _ in 0..s.cfg().blocks_in_epoch {
            let view_change = s.first_mut().node_service.chain.view_change();
            let leader1 = s.first_mut().node_service.chain.leader();
            let leader2 = s
                .first_mut()
                .node_service
                .chain
                .select_leader(view_change + 1);
            let leader3 = s
                .first_mut()
                .node_service
                .chain
                .select_leader(view_change + 2);

            if leader1 != leader2 && leader2 != leader3 && leader3 != leader1 {
                break;
            }

            s.wait(s.cfg().tx_wait_timeout);
            s.skip_micro_block();
            blocks += 1;
        }
        assert!(blocks < s.cfg().blocks_in_epoch as u32 - 2);
        let starting_view_changes = 0;
        let leader_pk = s.nodes[0].node_service.chain.leader();
        s.for_each(|node| assert_eq!(starting_view_changes, node.chain.view_change()));

        s.wait(s.cfg().tx_wait_timeout);
        s.poll();
        s.wait(s.cfg().micro_block_timeout);
        info!("======= PARTITION BEGIN =======");
        s.poll();
        // emulate dead leader for other nodes
        {
            // filter messages from chain loader.
            s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

            let mut r = s.split(&[leader_pk]);

            let first_leader = r.parts.0.first_mut();

            assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);
            first_leader
                .network_service
                .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC, crate::SEALED_BLOCK_TOPIC]);

            let mut msgs = Vec::new();
            for node in &mut r.parts.1.nodes {
                let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
                msgs.push(msg);
            }
            assert_eq!(msgs.len(), 3);

            let new_leader = r.parts.1.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 1);

            info!("======= BROADCAST VIEW_CHANGES =======");
            for node in &mut r.parts.1.nodes {
                for msg in &msgs {
                    node.network_service
                        .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
                }
            }

            r.parts.1.poll();
            let new_leader_node = r.parts.1.node(&new_leader).unwrap();
            // new leader receive all view change messages and produce new block.

            let _: Block = new_leader_node
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);

            // firstly check that all except leader increased view_change by one
            for node in &mut r.parts.1.iter_except(&[new_leader]) {
                info!("processing validator = {:?}", node.validator_id());
                assert_eq!(
                    node.node_service.chain.view_change(),
                    starting_view_changes + 1
                );
            }

            s.wait(s.cfg().micro_block_timeout);
            let mut r = s.split(&[leader_pk, new_leader]);
            r.parts.1.poll();

            r.parts
                .1
                .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
            let mut msgs = Vec::new();
            for node in &mut r.parts.1.nodes {
                let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
                msgs.push(msg);
            }
            assert_eq!(msgs.len(), 2);

            info!("======= BROADCAST VIEW_CHANGES2 =======");
            for node in &mut r.parts.1.nodes {
                for msg in &msgs {
                    node.network_service
                        .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
                }
            }
            // secondly check that after receiving 2/4 messages we didn't change view_counter
            for node in &mut r.parts.1.nodes {
                info!("processing validator = {:?}", node.validator_id());
                assert_eq!(
                    node.node_service.chain.view_change(),
                    starting_view_changes + 1
                );
            }
            r.parts.1.assert_synchronized();
        }
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Nodes [A] Receive block (B2)
//
// Asserts that Nodes [A] has last block B2, and same height().

#[test]
fn resolve_fork_for_view_change() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        precondition_2_different_leaderers(&mut s);

        let starting_view_changes = s.nodes[0].node_service.chain.view_change();
        let starting_height = s.nodes[0].node_service.chain.height();

        let leader_pk = s.nodes[0].node_service.chain.leader();

        s.wait(s.cfg().tx_wait_timeout);

        s.poll();

        let leader = s.node(&leader_pk).unwrap();
        // forget block
        let _b: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        s.wait(s.cfg().micro_block_timeout);
        s.poll();
        // emulate dead leader for other nodes

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        info!("======= PARTITION BEGIN =======");
        let mut r = s.split(&[leader_pk]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        let new_leader = r.parts.1.next_view_change_leader();
        let new_leader_node = r.parts.1.node(&new_leader).unwrap();
        // new leader receive all view change messages and produce new block.
        // each node should accept new block.

        info!("======= BROADCAST VIEW_CHANGES =======");
        for msg in &msgs {
            new_leader_node
                .network_service
                .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
        }
        new_leader_node.poll();

        info!("======= BROADCAST BLOCK =======");
        let block: Block = new_leader_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        assert_eq!(block.base_header().view_change, starting_view_changes + 1);

        let last_block_hash = Hash::digest(&block);

        let first_leader = r.parts.0.first_mut();
        assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);
        first_leader
            .network_service
            .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC]);
        // leader can send second block, if tx_wait_time << view_change timeout, and he is lucky
        first_leader
            .network_service
            .filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);
        // broadcast block to old leader.
        first_leader
            .network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        first_leader.poll();

        info!("processing validator = {:?}", first_leader.validator_id());
        assert_eq!(first_leader.node_service.chain.view_change(), 0);
        assert_eq!(
            first_leader.node_service.chain.last_block_hash(),
            last_block_hash
        );
        assert_eq!(
            first_leader.node_service.chain.height(),
            starting_height + 1
        );
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Node [B] receive B1, and broadcasts view_change proof.
// 3. Node [A] Receive view_change_proof, and apply it.
//
// Asserts that Nodes [A] rollback his block, and has view_change 2;

#[test]
fn resolve_fork_without_block() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 1);
        }

        precondition_2_different_leaderers(&mut s);

        let starting_view_changes = s.nodes[0].node_service.chain.view_change();
        let starting_height = s.nodes[0].node_service.chain.height();

        let leader_pk = s.nodes[0].node_service.chain.leader();

        s.wait(s.cfg().tx_wait_timeout);

        s.poll();

        let leader = s.node(&leader_pk).unwrap();
        // forget block
        let first_block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        s.wait(s.cfg().micro_block_timeout);
        s.poll();
        // emulate dead leader for other nodes

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        info!("======= PARTITION BEGIN =======");
        let mut r = s.split(&[leader_pk]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        let new_leader = r.parts.1.next_view_change_leader();

        info!("======= BROADCAST VIEW_CHANGES =======");
        for node in r.parts.1.iter_mut() {
            for msg in &msgs {
                node.network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
        }

        r.parts.1.poll();

        let new_leader_node = r.parts.1.node(&new_leader).unwrap();

        info!("======= BROADCAST BLOCK =======");
        let _block: Block = new_leader_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        // assert that each node increment his view_change
        for node in r.parts.1.iter_except(&[new_leader]) {
            assert_eq!(
                node.node_service.chain.view_change(),
                starting_view_changes + 1
            );
        }

        let not_include = &[new_leader];
        // any node that receive block from past view change, should produce view_change proof.
        let node = r.parts.1.iter_except(not_include).next().unwrap();
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, first_block);
        node.poll();
        let proof: SealedViewChangeProof = node
            .network_service
            .get_unicast(crate::VIEW_CHANGE_DIRECT, &leader_pk);

        let first_leader = r.parts.0.first_mut();
        assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);
        first_leader
            .network_service
            .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC]);
        // leader can send second block, if tx_wait_time << view_change timeout, and he is lucky
        first_leader
            .network_service
            .filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);

        first_leader.poll();
        // unicast view_change proof to old leader.
        first_leader
            .network_service
            .receive_unicast(new_leader, crate::VIEW_CHANGE_DIRECT, proof);

        assert_eq!(first_leader.node_service.chain.view_change(), 0);
        // sometimes leader can produce more than one block.
        assert!(first_leader.node_service.chain.height() > starting_height);

        first_leader.poll();
        // assert leader state
        info!("processing validator = {:?}", first_leader.validator_id());
        assert_eq!(
            first_leader.node_service.chain.view_change(),
            starting_view_changes + 1
        );
        assert_eq!(first_leader.node_service.chain.height(), starting_height);
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Node [B] receive B1, and broadcasts view_change proof.
// 3. Node [A] Receive view_change_proof, and apply it.
//
// Asserts that Nodes [A] rollback his block, and has view_change 2;
// Asserts that after view_change time node will rebroadcast message rather then panic.

#[test]
fn issue_896_resolve_fork() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 1);
        }

        precondition_2_different_leaderers(&mut s);

        let starting_view_changes = s.nodes[0].node_service.chain.view_change();
        let starting_height = s.nodes[0].node_service.chain.height();

        let leader_pk = s.nodes[0].node_service.chain.leader();

        s.wait(s.cfg().tx_wait_timeout);

        s.poll();

        let leader = s.node(&leader_pk).unwrap();
        // forget block
        let first_block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        s.wait(s.cfg().micro_block_timeout);
        s.poll();
        // emulate dead leader for other nodes

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        info!("======= PARTITION BEGIN =======");
        let mut r = s.split(&[leader_pk]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        let new_leader = r.parts.1.next_view_change_leader();

        info!("======= BROADCAST VIEW_CHANGES =======");
        for node in r.parts.1.iter_mut() {
            for msg in &msgs {
                node.network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
        }

        r.parts.1.poll();

        let new_leader_node = r.parts.1.node(&new_leader).unwrap();

        info!("======= BROADCAST BLOCK =======");
        let _block: Block = new_leader_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        // assert that each node increment his view_change
        for node in r.parts.1.iter_except(&[new_leader]) {
            assert_eq!(
                node.node_service.chain.view_change(),
                starting_view_changes + 1
            );
        }
        let not_include = &[new_leader];
        // any node that receive block from past view change, should produce view_change proof.
        let node = r.parts.1.iter_except(not_include).next().unwrap();
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, first_block);
        node.poll();
        let proof: SealedViewChangeProof = node
            .network_service
            .get_unicast(crate::VIEW_CHANGE_DIRECT, &leader_pk);

        // wait half of view_change timer
        r.wait(r.config.micro_block_timeout / 2);

        let first_leader = r.parts.0.first_mut();
        assert_eq!(leader_pk, first_leader.node_service.keys.network_pkey);

        first_leader
            .network_service
            .filter_broadcast(&[crate::VIEW_CHANGE_TOPIC]);
        first_leader.poll();
        // unicast view_change proof to old leader.
        first_leader
            .network_service
            .receive_unicast(new_leader, crate::VIEW_CHANGE_DIRECT, proof);

        assert_eq!(first_leader.node_service.chain.view_change(), 0);
        // sometimes leader can produce more than one block.
        assert!(first_leader.node_service.chain.height() > starting_height);

        first_leader.poll();
        // assert leader state
        info!("processing validator = {:?}", first_leader.validator_id());
        assert_eq!(
            first_leader.node_service.chain.view_change(),
            starting_view_changes + 1
        );
        assert_eq!(first_leader.node_service.chain.height(), starting_height);

        // wait for panic.
        r.wait(r.config.micro_block_timeout - r.config.micro_block_timeout / 2);
        r.parts.0.poll();

        // if panic was fixed, check for message.
        r.wait(r.config.micro_block_timeout / 2);
        r.parts.0.poll();

        let first_leader = r.parts.0.first_mut();
        first_leader
            .network_service
            .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        // leader can send second block, if tx_wait_time << view_change timeout, and he is lucky
        first_leader
            .network_service
            .filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);

        let msg: ViewChangeMessage = first_leader
            .network_service
            .get_broadcast(crate::VIEW_CHANGE_TOPIC);
        assert_eq!(msg.chain.view_change, starting_view_changes + 1);
    });
}

#[test]
fn out_of_order_keyblock_proposal() {
    let config = SandboxConfig {
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        s.wait(s.cfg().tx_wait_timeout);
        // Process N micro blocks.
        let height = s.nodes[0].node_service.chain.height();

        let round = s.nodes[0].node_service.chain.view_change();

        let leader_pk = s.nodes[0].node_service.chain.leader();

        let proposal = {
            let previous = s.nodes[0].node_service.chain.last_block_hash();
            let last_random = s.nodes[0].node_service.chain.last_random();
            let leader_node = s.node(&leader_pk).unwrap();

            let version = 1;
            let timestamp = SystemTime::now();
            let seed = mix(last_random, round);
            let random = pbc::make_VRF(&leader_node.node_service.keys.network_skey, &seed);
            let base = BaseBlockHeader::new(version, previous, height, round, timestamp, random);
            let leader = leader_node.node_service.keys.network_pkey;
            let block = MacroBlock::empty(base, leader);
            let block_hash = Hash::digest(&block);
            let body = ConsensusMessageBody::Proposal(MacroBlockProposal {
                header: block.header.clone(),
                transactions: vec![],
            });
            ConsensusMessage::new(
                height,
                round + 1,
                block_hash,
                &leader_node.node_service.keys.network_skey,
                &leader_node.node_service.keys.network_pkey,
                body,
            )
        };

        // broadcast block to other nodes.
        for node in &mut s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::CONSENSUS_TOPIC, proposal.clone())
        }
        s.poll();

        let mut p = s.split(&[leader_pk]);

        p.parts.1.for_each(|node| {
            assert_eq!(node.chain.height(), height);
            assert_eq!(node.chain.view_change(), round);
        });

        let leader = p.parts.0.first_mut();

        assert_eq!(leader_pk, leader.node_service.keys.network_pkey);
        leader
            .network_service
            .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        leader
            .network_service
            .filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);
    });
}

#[test]
fn micro_block_without_signature() {
    let config = SandboxConfig {
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        let height = s.nodes[0].node_service.chain.height();

        s.for_each(|node| assert_eq!(node.chain.height(), height));

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
        let block = MicroBlock::empty(base, None, leader.node_service.keys.network_pkey);

        let block: Block = Block::MicroBlock(block);

        let mut r = s.split(&[leader_pk]);
        // broadcast block to other nodes.
        for node in &mut r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }
        r.parts.1.poll();

        r.parts
            .1
            .for_each(|node| assert_eq!(node.chain.height(), height));
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader cheater and create multiple blocks (B1, B2).
// 2. Nodes [B, C, D] receive B1 and B2, and punish node A.
//
// Asserts that in [A] no more validator.

#[test]
fn slash_cheater() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 1);
        }

        // next leader should be from different partition.
        for _ in 0..(s.cfg().blocks_in_epoch - 2) {
            let first_leader_pk = s.nodes[0].node_service.chain.leader();
            let new_leader_pk = s.next_leader().unwrap();
            info!(
                "Checking that leader {} and {} are different.",
                first_leader_pk, new_leader_pk
            );
            if first_leader_pk != new_leader_pk {
                break;
            }

            info!("Skipping microlock.");
            s.wait(s.cfg().tx_wait_timeout);
            s.skip_micro_block();
        }
        let leader_pk = s.nodes[0].node_service.chain.leader();

        info!("CREATE BLOCK. LEADER = {}", leader_pk);
        s.wait(s.cfg().tx_wait_timeout);

        s.poll();

        let mut r = s.split(&[leader_pk]);
        let leader = &mut r.parts.0.nodes[0];
        let b1: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let mut b2 = b1.clone();
        // modify timestamp for block
        match &mut b2 {
            Block::MicroBlock(ref mut b) => {
                b.base.timestamp += Duration::from_millis(1);
                let block_hash = Hash::digest(&*b);
                b.sig = pbc::sign_hash(&block_hash, &leader.node_service.keys.network_skey);
            }
            Block::MacroBlock(_) => unreachable!(),
        }

        info!("BROADCAST BLOCK, WITH COPY.");
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
        }
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));

        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
        }

        r.parts.1.poll();
        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
        r.wait(r.cfg().tx_wait_timeout);
        r.parts.1.skip_micro_block();

        // assert that nodes in partition 1 exclude node from partition 0.
        for node in r.parts.1.iter() {
            let validators: HashSet<_> = node
                .node_service
                .chain
                .validators()
                .iter()
                .map(|(p, _)| *p)
                .collect();
            assert!(!validators.contains(&leader_pk))
        }
    });
}

fn precondition_2_different_leaderers(s: &mut Sandbox) {
    let mut ready = false;
    for _ in 0..(s.cfg().blocks_in_epoch - 2) {
        let first_leader_pk = s.nodes[0].node_service.chain.leader();
        let new_leader_pk = s.next_view_change_leader();
        info!(
            "Checking that leader {} and {} are different.",
            first_leader_pk, new_leader_pk
        );
        if first_leader_pk != new_leader_pk {
            ready = true;
            break;
        }
        info!("Skipping microlock.");
        s.wait(s.cfg().tx_wait_timeout);
        s.skip_micro_block()
    }
    assert!(ready, "Not enought micriblocks found");
}

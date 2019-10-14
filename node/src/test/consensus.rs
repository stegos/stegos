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
use assert_matches::assert_matches;
use std::time::Duration;
use stegos_blockchain::Block;
use stegos_consensus::{ConsensusInfo, ConsensusMessageBody, ConsensusState};
use stegos_crypto::pbc;
use stegos_crypto::pbc::{make_random_keys, SecretKey, Signature};

#[test]
fn smoke_test() {
    const NUM_RESTAKES: u64 = 3;
    let cfg = ChainConfig {
        micro_blocks_in_epoch: 1,
        stake_epochs: 2,
        ..Default::default()
    };
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    Sandbox::start(config, |mut s| {
        for _epoch in 1..=(1 + NUM_RESTAKES * s.config.chain.stake_epochs + 1) {
            for _offset in 0..s.config.chain.micro_blocks_in_epoch {
                s.poll();
                s.skip_micro_block();
            }
            s.skip_macro_block();
        }
    });
}

#[test]
fn autocommit() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = s.nodes[0].node_service.chain.epoch();

        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
            node.poll();
        }

        for i in 0..s.num_nodes() {
            let prevote: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let precommit: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
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
            node.poll();
        }

        // Check state of (0..NUM_NODES - 1) nodes.
        for node in s.iter_except(&[leader_pk]).skip(1) {
            assert_eq!(node.node_service.chain.epoch(), epoch + 1);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }

        let skip_leader = [leader_pk];
        let last_node = s.iter_except(&skip_leader).next().unwrap();
        // The last node hasn't received sealed block.
        assert_eq!(last_node.node_service.chain.epoch(), epoch);
        assert_eq!(
            last_node.node_service.chain.last_block_hash(),
            last_block_hash
        );

        // Wait for macro block timeout.
        s.wait(s.config.node.macro_block_timeout);
        let last_node = s.iter_except(&skip_leader).next().unwrap();
        last_node.poll();

        // Check that the last node has auto-committed the block.
        assert_eq!(last_node.node_service.chain.epoch(), epoch + 1);
        assert_eq!(last_node.node_service.chain.last_block_hash(), block_hash);

        // Check that the auto-committed block has been sent to the network.
        let block2: Block = last_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash2 = Hash::digest(&block2);
        assert_eq!(block_hash, block_hash2);
    });
}

#[test]
fn round() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let epoch = s.nodes[0].node_service.chain.epoch();
        let round = s.nodes[0].node_service.chain.view_change() + 1;
        s.wait(s.config.node.macro_block_timeout);

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
        let leader_node = s.node(&leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let prevote: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();

        for i in 0..s.num_nodes() {
            let precommit: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(precommit.body, ConsensusMessageBody::Precommit { .. });
            assert_eq!(precommit.epoch, epoch);
            assert_eq!(precommit.round, round);
            assert_eq!(precommit.block_hash, proposal.block_hash);
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

        let macro_block = block.clone().unwrap_macro();
        assert_eq!(macro_block.header.view_change, round);
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        for node in s.iter_except(&[leader_pk]) {
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
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let view_change = s.nodes[0].node_service.chain.view_change();
        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        s.wait(s.config.node.macro_block_timeout - Duration::from_millis(1));

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
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        s.wait(s.config.node.macro_block_timeout * 2 - Duration::from_millis(1));

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
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
    });
}

// check if locked node will rebroadcast propose.
//
#[test]
fn lock() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.poll();;
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = s.nodes[0].node_service.chain.epoch();

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
            let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
            round += 1;
            // wait for current round end
            s.wait(
                s.config.node.macro_block_timeout
                    * (round - s.nodes[0].node_service.chain.view_change()),
            );
        }
        assert!(ready);
        info!("Starting test.");
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
        let leader_node = s.node(&leader_pk).unwrap();
        leader_node.poll();

        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let leader_proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

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
            let prevote: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, leader_proposal.block_hash);
            for j in 0..s.num_nodes() {
                s.nodes[j]
                    .network_service
                    .receive_broadcast(topic, prevote.clone());
            }
        }
        s.poll();
        for i in 0..s.num_nodes() {
            let _precommit: ConsensusMessage = s.nodes[i].network_service.get_broadcast(topic);
        }
        s.poll();
        s.wait(
            s.config.node.macro_block_timeout
                * (round - s.nodes[0].node_service.chain.view_change() + 1),
        );

        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
        info!("====== Waiting for macroblock timeout. =====");
        s.poll();

        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let second_leader_pk = s.nodes[0].node_service.chain.select_leader(round + 1);
        let leader_node = s.node(&second_leader_pk).unwrap();
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);

        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        assert_eq!(proposal.round, leader_proposal.round + 1);
        assert_eq!(proposal.block_hash, leader_proposal.block_hash);
        s.poll();
    });
}

#[test]
fn out_of_order_micro_block() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 0;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        let topic = crate::CONSENSUS_TOPIC;
        s.poll();
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let epoch = s.nodes[0].node_service.chain.epoch();
        let offset = s.nodes[0].node_service.chain.offset();
        let leader_pk = s.nodes[0].node_service.chain.leader();

        //create valid but out of order fake micro block.
        let timestamp = Timestamp::now();

        let view_change = s.nodes[0].node_service.chain.view_change();
        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        let leader = s.node(&leader_pk).unwrap();
        let seed = mix(
            leader.node_service.chain.last_random(),
            leader.node_service.chain.view_change(),
        );
        let random = pbc::make_VRF(&leader.node_service.network_skey, &seed);
        let solution = leader.node_service.chain.vdf_solver()();

        let mut block = MicroBlock::empty(
            last_block_hash,
            epoch,
            offset,
            view_change + 1,
            None,
            leader.node_service.network_pkey,
            random,
            solution,
            timestamp,
        );
        let leader_node = s.node(&leader_pk).unwrap();
        block.sign(
            &leader_node.node_service.network_skey,
            &leader_node.node_service.network_pkey,
        );
        let block: Block = Block::MicroBlock(block);

        // Discard proposal from leader for a proposal from the leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        // broadcast block to other nodes.
        for node in &mut s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }
        s.poll();

        for node in &s.nodes {
            assert_eq!(node.node_service.chain.epoch(), epoch);
            assert_eq!(node.node_service.chain.offset(), offset);
        }

        let leader_pk = s.first().node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        leader_node
            .network_service
            .filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
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
    let consensus = match node.validation {
        Validation::MacroBlockValidator { ref consensus, .. } => consensus,
        _ => panic!("Wrong state."),
    };
    consensus.to_info()
}

fn assert_consensus_state(info: &ConsensusInfo, node: &NodeService) {
    let consensus = match node.validation {
        Validation::MacroBlockValidator { ref consensus, .. } => consensus,
        _ => panic!("Wrong state."),
    };
    let new_info = consensus.to_info();
    assert_eq!(*info, new_info)
}

fn invalid_proposes_inner(s: &mut Sandbox, round: u32) {
    let topic = crate::CONSENSUS_TOPIC;
    let epoch = s.nodes[0].node_service.chain.epoch();

    let leader_pk = s.nodes[0].node_service.chain.select_leader(round);
    trace!("SELECTING LEADER of round {} = {}", round, leader_pk);
    let leader_node = s.node(&leader_pk).unwrap();

    let skey = leader_node.node_service.network_skey.clone();

    // Check for a proposal from the leader.
    let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
    debug!("Proposal: {:?}", proposal);
    assert_eq!(proposal.epoch, epoch);
    assert_eq!(proposal.round, round);
    assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
    let mut r = s.split(&[leader_pk]);
    let mut info = save_consensus_state(&r.parts.1.first().node_service);

    r.parts.1.for_each(|node| {
        assert_consensus_state(&info, node);
    });

    let invalid_messages = create_invalid_proposes(&proposal, &skey);
    for (id, msg) in invalid_messages.iter().enumerate() {
        for node in r.parts.1.iter_mut() {
            node.network_service.receive_broadcast(topic, msg.clone());
        }

        r.parts.1.poll();
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
    r.parts.1.poll();
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

#[test]
fn invalid_proposes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.

        s.poll();
        s.skip_micro_block();

        let round = s.nodes[0].node_service.chain.view_change();
        invalid_proposes_inner(&mut s, round);
        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}

#[test]
fn invalid_proposes_on_2nd_round() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.

        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // skip proposal and prevote of last leader.
        let _proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        let _prevote: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        s.wait(s.config.node.macro_block_timeout);

        info!("====== Waiting for keyblock timeout. =====");
        s.poll();

        let round = s.nodes[0].node_service.chain.view_change() + 1;;
        invalid_proposes_inner(&mut s, round);
        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}

// Test [multiple leaders on proposes]
// Test [multiple proposes from single leader]
//
// assert: that all this messages should not change state after first propose.

#[test]
fn multiple_proposes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.

        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = s.nodes[0].node_service.chain.epoch();
        let round = s.nodes[0].node_service.chain.view_change();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();

        let skey = leader_node.node_service.network_skey.clone();

        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });
        let mut r = s.split(&[leader_pk]);
        let mut info = save_consensus_state(&r.parts.1.first().node_service);

        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        r.parts.1.poll();
        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        // Send the original proposal to other nodes.
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        r.parts.1.poll();
        // node should produce prevote.
        info.prevotes_len += 1;
        info.state = ConsensusState::Prevote;

        let mut invalid_messages = Vec::new();

        // change author
        let node = r.parts.1.first();
        let mut new_msg = proposal.clone();
        new_msg.pkey = node.node_service.network_pkey;
        invalid_messages.push(resign_msg(new_msg, &node.node_service.network_skey));

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
        r.parts.1.poll();

        r.parts.1.for_each(|node| {
            assert_consensus_state(&info, node);
        });

        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}

// Test [multiple message on prevote]
#[test]
fn invalid_prevotes() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = s.nodes[0].node_service.chain.epoch();
        let round = s.nodes[0].node_service.chain.view_change();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        let mut r = s.split(&[leader_pk]);
        let node_skey = r.parts.1.first().node_service.network_skey.clone();
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

        r.parts.1.poll();
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
        r.parts.1.poll();

        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut().skip(1) {
            assert_consensus_state(&info, &mut node.node_service);
        }

        s.poll();
        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}
// Test [multiple message on prevote (from leader)]
#[test]
fn invalid_prevotes_leader() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 1;
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 4,
        ..Default::default()
    };
    assert!(config.chain.stake_epochs > 1);

    Sandbox::start(config, |mut s| {
        // Create one micro block.
        s.poll();
        s.skip_micro_block();

        let topic = crate::CONSENSUS_TOPIC;
        let epoch = s.nodes[0].node_service.chain.epoch();
        let round = s.nodes[0].node_service.chain.view_change();

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_node = s.node(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node.network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        let mut r = s.split(&[leader_pk]);
        let leader_skey = r.parts.0.first().node_service.network_skey.clone();
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

        r.parts.1.poll();
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
        r.parts.1.poll();

        // skip first node, because it work as byzantine
        for node in r.parts.1.iter_mut() {
            assert_consensus_state(&info, &mut node.node_service);
        }

        s.poll();
        s.filter_broadcast(&[crate::CONSENSUS_TOPIC]);
    });
}

// Test [multiple message on precomit]
// Test [multiple message on precomit (from leader)]

// TODO:
// Test Keep some validator locked on round
// Test multiple count of precommits for locked round (should save precommit from previuous round?).

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

//! Test of features build on top of consensus/blockchain stack.

use super::*;
use crate::*;
use std::collections::HashSet;
use stegos_blockchain::Block;
use stegos_blockchain::Output;
use stegos_blockchain::ValidatorAwardState;

// CASE rollback slashing:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 0, and broadcast block B1 and B1'.
// 2. Node B leader of view_change 1, and broadcast block B2.
// 3. Nodes [C, D] receive B1 and B1', and decide to remove node A from list.
// 4. Node C produce block B3 with cheating proof.
// 5. Then nodes [C, D] receive B2 and starting to resolve fork, roll back B3, and B1.
//
// Asserts that Nodes [C D] rollback blocks B3 and B1, and has last block B2;
// Asserts that Nodes [C D] save cheating proof in memory.

#[test]
fn rollback_slashing() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        skip_blocks_until(&mut s, |s| {
            let mut leaders = Vec::new();
            // first regular winner
            let first_leader_pk = s.future_view_change_leader(0);
            leaders.push(first_leader_pk);
            // second view_change leader
            let second_leader_pk = s.future_view_change_leader(1);
            leaders.push(second_leader_pk);

            // third block leader
            let view_change = 0;
            let init_random = s.first_mut().node_service.chain.last_random();
            let vrf = s
                .node(&first_leader_pk)
                .unwrap()
                .create_vrf_from_seed(init_random, view_change);
            let mut election = s.first_mut().node_service.chain.election_result().clone();
            election.random = vrf;

            let third_leader_pk = election.select_leader(view_change);
            leaders.push(third_leader_pk);

            info!(
                "Checking that all leader are different: leaders={:?}.",
                leaders
            );
            check_unique(leaders)
        });

        let start_offset = s.first().node_service.chain.offset();

        let first_leader = s.first().node_service.chain.leader();

        let second_leader = s.future_view_change_leader(1);
        info!("CREATE BLOCK. LEADER = {}", first_leader);
        s.poll();

        // init view_change

        s.wait(s.config.node.micro_block_timeout);
        s.poll();
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        let mut msgs = Vec::new();
        for node in &mut s.iter_except(&[first_leader]) {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        let new_leader_node = s.node(&second_leader).unwrap();

        info!("======= BROADCAST VIEW_CHANGES =======");
        for msg in &msgs {
            new_leader_node
                .network_service
                .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
        }
        new_leader_node.poll();

        let cheater = first_leader;
        let mut r = slash_cheater_inner(&mut s, first_leader, vec![second_leader]);
        assert_eq!(r.parts.1.nodes.len(), 2);
        assert_eq!(r.parts.0.nodes.len(), 2);

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
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
            assert!(!validators.contains(&cheater))
        }

        let new_leader_node = s.node(&second_leader).unwrap();
        info!("CREATE BLOCK FROM VIEWCHANGE. LEADER = {}", second_leader);
        new_leader_node.handle_vdf();
        new_leader_node.poll();
        let block: Block = new_leader_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        // try to rollback cheater affect, but proof should be saved
        for node in &mut s.nodes {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }

        if let Some(auditor) = s.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }

        // nodes C D should rollback fork
        let mut r = s.split(&[first_leader, second_leader]);
        r.parts.1.poll();
        r.parts.1.assert_synchronized();
        // assert that nodes recover valdators list. And has same height
        for node in r.parts.1.iter() {
            assert_eq!(start_offset + 1, node.node_service.chain.offset());
            assert_eq!(node.node_service.chain.validators().len(), 4);
        }
        // assert that each node except first one that was in partition still has a proof.
        for node in r.parts.1.iter() {
            assert_eq!(node.node_service.cheating_proofs.len(), 1)
        }

        s.filter_broadcast(&[crate::VIEW_CHANGE_TOPIC, crate::SEALED_BLOCK_TOPIC]);
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
    });
}

// CASE finalized slashing:
//
// Asserts that after macroblock slashing is finalized, and proofs are cleared.

#[test]
fn finalized_slashing() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 20;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        precondition_n_different_block_leaders(&mut s, 2);
        // next leader should be from different partition.

        let cheater = s.nodes[0].node_service.chain.leader();
        info!("CREATE BLOCK. LEADER = {}", cheater);
        s.poll();

        let mut r = slash_cheater_inner(&mut s, cheater, vec![]);

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
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
            assert!(!validators.contains(&cheater))
        }

        let offset = r.parts.1.first().node_service.chain.offset();

        for _offset in offset..r.config.chain.micro_blocks_in_epoch {
            r.parts.1.poll();
            r.parts.1.skip_micro_block();
        }
        r.parts.1.skip_macro_block();
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));
    });
}

// CASE finalized slashing with service award (with auditor node):
//
// Asserts that after service award was executed.

#[test]
fn finalized_slashing_with_service_award() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        precondition_n_different_block_leaders(&mut s, 2);
        // next leader should be from different partition.

        let cheater = s.nodes[0].node_service.chain.leader();
        info!("CREATE BLOCK. LEADER = {}", cheater);
        s.poll();

        let mut r = slash_cheater_inner(&mut s, cheater, vec![]);

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
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
            assert!(!validators.contains(&cheater))
        }

        let offset = r.parts.1.first().node_service.chain.offset();

        // ignore microblocks for auditor
        for _offset in offset..r.config.chain.micro_blocks_in_epoch {
            r.parts.1.poll();
            r.parts.1.skip_micro_block();
        }

        r.parts.1.skip_macro_block();
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));
        r.parts.1.assert_synchronized();
    });
}

// CASE finalized slashing with service award:
//
// Asserts that after service award was executed.

#[test]
fn finalized_slashing_with_service_award_for_auditor() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        precondition_n_different_block_leaders(&mut s, 2);
        // next leader should be from different partition.

        let cheater = s.nodes[0].node_service.chain.leader();
        let cheater_wallet = s.nodes[0]
            .node_service
            .chain
            .account_by_network_key(&cheater)
            .unwrap();
        info!(
            "CREATE BLOCK. LEADER = {}, ACCOUNT = {}",
            cheater, cheater_wallet
        );
        s.poll();

        let mut r = slash_cheater_inner(&mut s, cheater, vec![]);

        // ignore microblocks for auditor
        let auditor = r.parts.1.auditor.take();

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
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
            assert!(!validators.contains(&cheater))
        }

        let offset = r.parts.1.first().node_service.chain.offset();

        for _offset in offset..r.config.chain.micro_blocks_in_epoch {
            r.parts.1.poll();
            r.parts.1.skip_micro_block();
        }

        r.parts.1.auditor = auditor;
        r.parts.1.skip_macro_block();
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));
        r.parts.1.assert_synchronized();

        // assert that award state is same for node and auditor
        let award = r
            .parts
            .1
            .first()
            .node_service
            .chain
            .service_awards()
            .clone();
        let auditor_award = r
            .parts
            .1
            .auditor
            .unwrap()
            .node_service
            .chain
            .service_awards()
            .clone();
        assert_eq!(award, auditor_award);
    });
}

fn service_award_round_normal(s: &mut Sandbox, service_award_budget: i64) {
    let offset = s.first().node_service.chain.offset();
    let epoch = s.first().node_service.chain.epoch();

    // ignore microblocks for auditor
    for _offset in offset..s.config.chain.micro_blocks_in_epoch {
        s.poll();
        s.skip_micro_block();
    }

    s.skip_macro_block();
    for node in s.iter_mut() {
        //award was executed
        assert_eq!(node.node_service.chain.service_awards().budget(), 0);
        assert_eq!(
            node.node_service.chain.last_block_hash(),
            node.node_service.chain.last_macro_block_hash()
        );
        let block_hash = node.node_service.chain.last_block_hash();
        let block = node.node_service.chain.macro_block(epoch).unwrap();
        assert_eq!(Hash::digest(&block), block_hash);
        let mut outputs = Vec::new();
        for output in block.outputs {
            match output {
                Output::PublicPaymentOutput(p) => outputs.push(p),
                _ => {}
            }
        }

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].amount, service_award_budget);
    }

    s.assert_synchronized();
}

fn service_award_round_without_participants(s: &mut Sandbox) {
    let offset = s.first().node_service.chain.offset();
    let epoch = s.first().node_service.chain.epoch();

    let mut nodes: HashSet<_> = s.iter().map(|n| n.node_service.network_pkey).collect();

    // skipp all leaders atleast once
    for offset in offset..s.config.chain.micro_blocks_in_epoch {
        s.poll();

        let leader_pk = s.first().chain().leader();

        let second_leader = s.future_view_change_leader(1);
        // if leader already skipper, or next view_change_leader is current, just skip_micro_block
        if !nodes.contains(&leader_pk) || second_leader == leader_pk {
            s.skip_micro_block();
            continue;
        }

        // check that this leader didn't failed at current epoch
        for node in s.iter_mut() {
            assert_eq!(
                node.node_service
                    .chain
                    .epoch_activity()
                    .get(&leader_pk)
                    .unwrap_or(&ValidatorAwardState::Active),
                &ValidatorAwardState::Active
            );
        }

        let node = s.node(&leader_pk).unwrap();
        node.handle_vdf();
        node.poll();

        s.wait(s.config.node.micro_block_timeout);
        s.poll();

        // emulate dead leader for other nodes
        // filter messages from chain loader.
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        // filter block message from node.
        s.filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);
        info!("======= PARTITION BEGIN =======");
        let mut r = s.split(&[leader_pk]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 3);

        info!("======= BROADCAST VIEW_CHANGES =======");
        for node in &mut r.parts.1.nodes {
            for msg in &msgs {
                node.network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
        }
        r.parts.1.poll();
        r.parts.0.filter_broadcast(&[crate::VIEW_CHANGE_TOPIC]);
        let new_leader_node = r.parts.1.node(&second_leader).unwrap();
        new_leader_node.handle_vdf();
        new_leader_node.poll();
        info!("======= BROADCAST BLOCK =======");
        let block: Block = new_leader_node
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);

        for node in s.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }

        s.auditor
            .network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());

        s.poll();

        s.assert_synchronized();

        // check that after failing leader marked as failed.
        for node in s.iter_mut() {
            assert_eq!(
                node.node_service
                    .chain
                    .epoch_activity()
                    .get(&leader_pk)
                    .unwrap(),
                &ValidatorAwardState::Failed { epoch, offset }
            );
        }

        nodes.remove(&leader_pk);
    }

    assert!(
        nodes.is_empty(),
        "Too few microblocks, test failed to skip all leaders."
    );

    s.skip_macro_block();

    let service_award_budget = s.config.chain.service_award_per_epoch;
    for node in s.iter_mut() {
        //award was executed without winners, list of activity should be cleared
        assert_eq!(
            node.node_service.chain.service_awards().budget(),
            service_award_budget
        );
        assert_eq!(
            node.node_service
                .chain
                .service_awards()
                .validators_activivty()
                .len(),
            0
        );
        assert_eq!(
            node.node_service.chain.last_block_hash(),
            node.node_service.chain.last_macro_block_hash()
        );
        let block_hash = node.node_service.chain.last_block_hash();
        let block = node.node_service.chain.macro_block(epoch).unwrap();
        assert_eq!(Hash::digest(&block), block_hash);
        let mut outputs = Vec::new();
        for output in block.outputs {
            match output {
                Output::PublicPaymentOutput(p) => outputs.push(p),
                _ => {}
            }
        }
        assert_eq!(outputs.len(), 0);
    }

    s.assert_synchronized();
}

// CASE service award with 0 difficulty.
// Assert that we have one winner.
#[test]
fn service_award_state() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();

        let budget = s.config.chain.service_award_per_epoch;
        service_award_round_normal(&mut s, budget);
    });
}

// CASE service award with 0 difficulty, and every validator atleast once skip his order.
// Assert that we have no winner, budget is equal to service_award_budget, and activity map is cleared.
#[test]
fn service_award_state_no_winners() {
    let mut cfg: ChainConfig = Default::default();
    cfg.micro_blocks_in_epoch = 50;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();
        service_award_round_without_participants(&mut s);

        let budget = s.config.chain.service_award_per_epoch;
        service_award_round_normal(&mut s, budget * 2)
    });
}

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
use tokio;

use crate::protos::loader::ChainLoaderMessage;
use std::collections::HashSet;
use stegos_blockchain::Block;
use stegos_blockchain::ChainInfo;
use stegos_blockchain::Output;
use stegos_blockchain::ValidatorAwardState;
use stegos_consensus::optimistic::ViewChangeMessage;

// CASE Slash and roll back:
// Nodes [A, B, C, D]
//
// 1. Node A is the leader of round 0, and broadcasts block B1 and B1'.
// 2. Node B the leader of round 1, and broadcasts block B2.
// 3. Nodes [C, D] receive blocks B1 and B1', and decide to remove node A from list.
// 4. Node C produce block B3 with a proof of cheating.
// 5. Nodes [C, D] receive B2, start to resolve fork and roll back B3, and B1.
//
// Asserts that Nodes [C D] roll back blocks B3 and B1, and have B2 as the ast block;
// Asserts that Nodes [C D] save the proof of cheating in memory.

#[tokio::test]
async fn slash_and_roll() {
    let mut cfg = ChainConfig {
        awards_difficulty: 0,
        ..Default::default()
    };
    cfg.blocks_in_epoch = 2000;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    trace!("Ensuring three distinct leaders...");

    p.skip_ublocks_until(|p| {
        let mut leaders = Vec::new();
        // first regular winner
        let first = p.future_view_change_leader(0);
        leaders.push(first);
        // second view_change leader
        let second = p.future_view_change_leader(1);
        leaders.push(second);

        // third block leader
        let view_change = 0;
        let init_random = p.first_mut().node_service.state().chain.last_random();
        let vrf = p
            .find_mut(&first)
            .unwrap()
            .create_vrf_from_seed(init_random, view_change);
        let mut election = p
            .first_mut()
            .node_service
            .state()
            .chain
            .election_result()
            .clone();
        election.random = vrf;

        let third = election.select_leader(view_change);
        leaders.push(third);

        trace!("Checking leaders: {}, {}, {}", first, second, third);
        ensure_distinct(leaders)
    })
    .await;

    let start_offset = p.first().node_service.state().chain.offset();
    //let first_leader = p.first().node_service.state().chain.leader();
    let first_leader_pk = p.leader();
    let second_leader_pk = p.future_view_change_leader(1);

    trace!("Polling everyone...");
    p.step().await;

    trace!(
        "Initiating a microblock view change, leader = {}...",
        first_leader_pk
    );

    // Initiate a microblock view change.
    let d = config.node.ublock_timeout + Duration::from_secs(5);
    wait(d).await;
    p.step().await;

    p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
    let mut msgs = Vec::new();
    for node in &mut p.iter_except(&[first_leader_pk]) {
        let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
        msgs.push(msg);
    }
    assert_eq!(msgs.len(), 3);

    let second_leader = p.find_mut(&second_leader_pk).unwrap();

    trace!(
        "Broadcasting view changes to new leader {} ",
        second_leader_pk
    );
    for msg in &msgs {
        second_leader
            .network_service
            .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
    }
    second_leader.step().await;

    trace!("Making old leader {} cheat...", first_leader_pk);
    let cheater = first_leader_pk;
    let mut r = p
        .slash_cheater_inner(first_leader_pk, vec![second_leader_pk])
        .await;
    assert_eq!(r.parts.1.nodes.len(), 2);
    assert_eq!(r.parts.0.nodes.len(), 2);

    let pk = r.parts.1.first().node_service.state().chain.leader();
    trace!(
        "Check if cheating by {} was detected. Partition leader = {}",
        first_leader_pk,
        pk,
    );
    // Each node should have stored proof of slashing.
    r.parts
        .1
        .for_each(|node| assert_eq!(node.state().cheating_proofs.len(), 1));

    // Skip one microblock.
    let node = r.parts.1.find_mut(&pk).unwrap();
    node.step().await;
    r.parts.1.skip_ublock().await;

    // Make sure nodes in partition 1 exclude nodes from partition 0.
    for node in r.parts.1.iter() {
        let validators: HashSet<_> = node
            .node_service
            .state()
            .chain
            .validators()
            .0
            .iter()
            .map(|(p, _)| *p)
            .collect();
        assert!(!validators.contains(&cheater))
    }

    trace!(
        "Create block from view change using new leader = {}",
        second_leader_pk
    );
    let second_leader = p.find_mut(&second_leader_pk).unwrap();
    second_leader.step().await;
    let (block, _) = second_leader
        .expect_ublock()
        .await
        .expect("Expected microblock");

    // Try to rollback cheater effect but ensure proof is saved.
    trace!("Deliver the new block...");
    for node in &mut p.nodes {
        node.network_service
            .receive_broadcast(SEALED_BLOCK_TOPIC, block.clone());
        node.poll().await;
    }

    if let Some(auditor) = p.auditor_mut() {
        auditor
            .network_service
            .receive_broadcast(SEALED_BLOCK_TOPIC, block.clone());
        auditor.poll().await;
    }

    // Nodes C D should rollback fork.
    trace!("Expect rollback...");
    let mut r = p.split(&[first_leader_pk, second_leader_pk]);
    r.parts.1.poll().await;
    r.parts.1.assert_synchronized();
    // assert that nodes recover valdators list. And has same height
    for node in r.parts.1.iter() {
        assert_eq!(start_offset + 1, node.node_service.state().chain.offset());
        assert_eq!(node.node_service.state().chain.validators().0.len(), 4);
    }
    // assert that each node except first one that was in partition still has a proof.
    trace!("Expect proof...");
    for node in r.parts.1.iter() {
        assert_eq!(node.node_service.state().cheating_proofs.len(), 1)
    }

    p.filter_broadcast(&[VIEW_CHANGE_TOPIC, SEALED_BLOCK_TOPIC]);
    p.filter_unicast(&[CHAIN_LOADER_TOPIC]);
}

// CASE finalized slashing:
//
// Asserts that proofs are cleared after macroblock slashing is finalized.
#[tokio::test]
async fn finalized_slashing() {
    let cfg = ChainConfig {
        awards_difficulty: 0,
        blocks_in_epoch: 20,
        ..Default::default()
    };
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    let mut sb = Sandbox::new(config.clone());
    let mut p = sb.partition();

    precondition_n_different_block_leaders(&mut p, 2).await;
    // next leader should be from different partition.

    let cheater = p.nodes[0].node_service.state().chain.leader();
    info!("CREATE BLOCK. LEADER = {}", cheater);
    p.poll().await;

    let mut r = p.slash_cheater_inner(cheater, vec![]).await;

    info!(
        "CHECK IF CHEATER WAS DETECTED. LEADER={}",
        r.parts.1.first().node_service.state().chain.leader()
    );
    // each node should add proof of slashing into state.
    r.parts
        .1
        .for_each(|node| assert_eq!(node.state().cheating_proofs.len(), 1));

    // wait for block;
    let pk = r.parts.1.first().node_service.state().chain.leader();
    let leader = r.parts.1.find_mut(&pk).unwrap();
    leader.step().await;
    let (block, _) = leader.expect_ublock().await.expect("Expected microblock");

    // assert that nodes in partition 1 exclude node from partition 0.
    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(SEALED_BLOCK_TOPIC, block.clone());
        node.poll().await;
        let validators: HashSet<_> = node
            .node_service
            .state()
            .chain
            .validators()
            .0
            .iter()
            .map(|(p, _)| *p)
            .collect();
        trace!(
            "[{}] Checking for cheater in the list of validators...",
            node.pkey()
        );
        assert!(!validators.contains(&cheater))
    }

    info!("Checking proofs of cheating...");

    let pk = r.parts.1.first().node_service.state().chain.leader();
    let leader = r.parts.1.find_mut(&pk).unwrap();
    leader.step().await;

    let offset = r.parts.1.first().node_service.state().chain.offset();

    trace!(
        "Current offset = {}, blocks in epoch = {}",
        offset,
        r.parts.1.config.chain.blocks_in_epoch
    );
    for offset in offset..r.parts.0.config.chain.blocks_in_epoch {
        trace!("Skipping microblock for offset {}", offset);
        //r.parts.1.step().await;
        r.parts.1.skip_ublock().await;
    }

    info!("SKipping one more macroblock...");
    let pk = r.parts.1.first().node_service.state().chain.leader();
    let leader = r.parts.1.find_mut(&pk).unwrap();
    leader.step().await;

    r.parts.1.skip_mblock().await;
    r.parts
        .1
        .for_each(|node| assert_eq!(node.state().cheating_proofs.len(), 0));
}

/*
// CASE finalized slashing with service award (with auditor node):
//
// Asserts that after service award was executed.

#[test]
fn finalized_slashing_with_service_award() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        p.poll().await;

        let budget = p.config.chain.service_award_per_epoch;
        precondition_n_different_block_leaders(&mut s, 2);
        // next leader should be from different partition.

        let cheater = p.nodes[0].node_service.state().chain.leader();
        info!("CREATE BLOCK. LEADER = {}", cheater);
        p.poll().await;

        let mut r = slash_cheater_inner(&mut s, cheater, vec![]);

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.state().chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
        r.parts.1.skip_ublock();

        // assert that nodes in partition 1 exclude node from partition 0.
        for node in r.parts.1.iter() {
            let validators: HashSet<_> = node
                .node_service
                .chain
                .validators()
                .iter()
                .map(|(p, _)| *p)
                .collect();
            assert!(!validatorp.contains(&cheater))
        }

        let offset = r.parts.1.first().node_service.state().chain.offset();
        let epoch = r.parts.1.first().node_service.state().chain.epoch();

        // ignore Microblocks for auditor
        for _offset in offset..r.config.chain.blocks_in_epoch {
            r.parts.1.poll();
            r.parts.1.skip_ublock();
        }

        r.parts.1.skip_mblock();
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));
        let mut output = None;
        for node in r.parts.1.iter_mut() {
            //award was executed
            assert_eq!(node.node_service.state().chain.service_awards().budget(), 0);
            assert_eq!(
                node.node_service.state().chain.last_block_hash(),
                node.node_service.state().chain.last_mblock_hash()
            );
            let block_hash = node.node_service.state().chain.last_block_hash();
            let block = node
                .node_service
                .chain
                .Macroblock(epoch)
                .unwrap()
                .into_owned();
            assert_eq!(Hash::digest(&block), block_hash);
            let mut outputs = Vec::new();
            for output in block.outputs {
                match output {
                    Output::PublicPaymentOutput(p) => outputp.push(p),
                    _ => {}
                }
            }
            assert_eq!(outputp.len(), 4); // 3 slashing + award
            outputp.sort_by_key(|p| p.amount);
            trace!("outputs = {:?}", outputs);
            assert_eq!(outputs[0].amount, budget);
            if let Some(ref output) = output {
                assert_eq!(output, &outputs[0])
            } else {
                output = Some(outputs[0].clone());
            }
        }
        r.parts.1.assert_synchronized();

        let output = output.unwrap();
        let node = r.parts.1.first_mut();
        let mut receive = node.node.request(NodeRequest::MacroblockInfo { epoch });
        node.poll();
        let notification = receive.poll().unwrap();
        let i = match notification {
            Async::Ready(NodeResponse::MacroblockInfo(i)) => i,
            e => panic!("Expected Macroblock info, got ={:?}", e),
        };
        let p = i.epoch_info.awardp.payout.unwrap();
        assert_eq!(output.recipient, p.recipient);
        assert_eq!(output.amount, p.amount);
    });
}

// CASE finalized slashing with service award:
//
// Asserts that after service award was executed.

#[test]
fn finalized_slashing_with_service_award_for_auditor() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        p.poll().await;

        precondition_n_different_block_leaders(&mut s, 2);
        // next leader should be from different partition.

        let budget = p.config.chain.service_award_per_epoch;
        let cheater = p.nodes[0].node_service.state().chain.leader();
        let cheater_wallet = p.nodes[0]
            .node_service
            .chain
            .account_by_network_key(&cheater)
            .unwrap();
        info!(
            "CREATE BLOCK. LEADER = {}, ACCOUNT = {}",
            cheater, cheater_wallet
        );
        p.poll().await;

        let mut r = slash_cheater_inner(&mut s, cheater, vec![]);

        // ignore Microblocks for auditor
        let auditor = r.parts.1.auditor.take();

        info!(
            "CHECK IF CHEATER WAS DETECTED. LEADER={}",
            r.parts.1.first().node_service.state().chain.leader()
        );
        // each node should add proof of slashing into state.
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 1));

        // wait for block;
        r.parts.1.skip_ublock();

        // assert that nodes in partition 1 exclude node from partition 0.
        for node in r.parts.1.iter() {
            let validators: HashSet<_> = node
                .node_service
                .chain
                .validators()
                .iter()
                .map(|(p, _)| *p)
                .collect();
            assert!(!validatorp.contains(&cheater))
        }

        let offset = r.parts.1.first().node_service.state().chain.offset();
        let epoch = r.parts.1.first().node_service.state().chain.epoch();

        for _offset in offset..r.config.chain.blocks_in_epoch {
            r.parts.1.poll();
            r.parts.1.skip_ublock();
        }

        r.parts.1.auditor = auditor;
        r.parts.1.skip_mblock();
        r.parts
            .1
            .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));

        let mut output = None;
        for node in r.parts.1.iter_mut() {
            //award was executed
            assert_eq!(node.node_service.state().chain.service_awards().budget(), 0);
            assert_eq!(
                node.node_service.state().chain.last_block_hash(),
                node.node_service.state().chain.last_mblock_hash()
            );
            let block_hash = node.node_service.state().chain.last_block_hash();
            let block = node
                .node_service
                .chain
                .Macroblock(epoch)
                .unwrap()
                .into_owned();
            assert_eq!(Hash::digest(&block), block_hash);
            let mut outputs = Vec::new();
            for output in block.outputs {
                match output {
                    Output::PublicPaymentOutput(p) => outputp.push(p),
                    _ => {}
                }
            }

            assert_eq!(outputp.len(), 4); // 3 slashing + award
            outputp.sort_by_key(|p| p.amount);
            trace!("outputs = {:?}", outputs);
            assert_eq!(outputs[0].amount, budget);
            if let Some(ref output) = output {
                assert_eq!(output, &outputs[0])
            } else {
                output = Some(outputs[0].clone());
            }
        }
        r.parts.1.assert_synchronized();

        let output = output.unwrap();
        let node = r.parts.1.first_mut();
        let mut receive = node.node.request(NodeRequest::MacroblockInfo { epoch });
        node.poll();
        let notification = receive.poll().unwrap();
        let i = match notification {
            Async::Ready(NodeResponse::MacroblockInfo(i)) => i,
            e => panic!("Expected Macroblock info, got ={:?}", e),
        };
        let p = i.epoch_info.awardp.payout.unwrap();
        assert_eq!(output.recipient, p.recipient);
        assert_eq!(output.amount, p.amount);

        let node = r.parts.1.auditor.as_mut().unwrap();
        let mut receive = node.node.request(NodeRequest::MacroblockInfo { epoch });
        node.poll();
        let notification = receive.poll().unwrap();
        let i = match notification {
            Async::Ready(NodeResponse::MacroblockInfo(i)) => i,
            e => panic!("Expected Macroblock info, got ={:?}", e),
        };
        let p = i.epoch_info.awardp.payout.unwrap();
        assert_eq!(output.recipient, p.recipient);
        assert_eq!(output.amount, p.amount);
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
    let offset = p.first().node_service.state().chain.offset();
    let epoch = p.first().node_service.state().chain.epoch();

    // ignore Microblocks for auditor
    for _offset in offset..p.config.chain.blocks_in_epoch {
        p.poll().await;
        p.skip_ublock();
    }

    p.skip_mblock();
    let mut output = None;
    for node in p.iter_mut() {
        //award was executed
        assert_eq!(node.node_service.state().chain.service_awards().budget(), 0);
        assert_eq!(
            node.node_service.state().chain.last_block_hash(),
            node.node_service.state().chain.last_mblock_hash()
        );
        let block_hash = node.node_service.state().chain.last_block_hash();
        let block = node
            .node_service
            .chain
            .Macroblock(epoch)
            .unwrap()
            .into_owned();
        assert_eq!(Hash::digest(&block), block_hash);
        let mut outputs = Vec::new();
        for output in block.outputs {
            match output {
                Output::PublicPaymentOutput(p) => outputp.push(p),
                _ => {}
            }
        }

        assert_eq!(outputp.len(), 1);
        assert_eq!(outputs[0].amount, service_award_budget);
        if let Some(ref output) = output {
            assert_eq!(output, &outputs[0])
        } else {
            output = Some(outputs[0].clone());
        }
    }
    p.assert_synchronized();

    let output = output.unwrap();
    let node = p.first_mut();
    let mut receive = node.node.request(NodeRequest::MacroblockInfo { epoch });
    node.poll();
    let notification = receive.poll().unwrap();
    let i = match notification {
        Async::Ready(NodeResponse::MacroblockInfo(i)) => i,
        e => panic!("Expected Macroblock info, got ={:?}", e),
    };
    let p = i.epoch_info.awardp.payout.unwrap();
    assert_eq!(output.recipient, p.recipient);
    assert_eq!(output.amount, p.amount);
}

fn service_award_round_without_participants(s: &mut Sandbox) {
    let offset = p.first().node_service.state().chain.offset();
    let epoch = p.first().node_service.state().chain.epoch();

    let mut nodes: HashSet<_> = p.iter().map(|n| n.node_service.network_pkey).collect();

    // skipp all leaders atleast once
    for offset in offset..p.config.chain.blocks_in_epoch {
        p.poll().await;

        let leader_pk = p.first().chain().leader();

        let second_leader = p.future_view_change_leader(1);
        // if leader already skipper, or next view_change_leader is current, just skip_ub
        if !nodes.contains(&leader_pk) || second_leader == leader_pk {
            p.skip_ublock();
            continue;
        }

        // check that this leader didn't failed at current epoch
        for node in p.iter_mut() {
            assert_eq!(
                node.node_service
                    .chain
                    .epoch_activity()
                    .get(&leader_pk)
                    .unwrap_or(&ValidatorAwardState::Active),
                &ValidatorAwardState::Active
            );
        }

        let node = p.find_mut(&leader_pk).unwrap();
        node.handle_vdf();
        node.poll();

        p.wait(p.config.node.ub_timeout);
        p.poll().await;

        // emulate dead leader for other nodes
        // filter messages from chain loader.
        p.filter_unicast(&[crate::protos::loader::CHAIN_LOADER_TOPIC]);
        // filter block message from node.
        p.filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);
        info!("======= PARTITION BEGIN =======");
        let mut r = p.split(&[leader_pk]);

        let mut msgs = Vec::new();
        for node in &mut r.parts.1.nodes {
            let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
            msgp.push(msg);
        }
        assert_eq!(msgp.len(), 3);

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

        for node in p.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
        }

        p.auditor
            .network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());

        p.poll().await;

        p.assert_synchronized();

        // check that after failing leader marked as failed.
        for node in p.iter_mut() {
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
        "Too few Microblocks, test failed to skip all leaderp."
    );

    p.skip_mblock();

    let service_award_budget = p.config.chain.service_award_per_epoch;
    for node in p.iter_mut() {
        //award was executed without winners, list of activity should be cleared
        assert_eq!(
            node.node_service.state().chain.service_awards().budget(),
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
            node.node_service.state().chain.last_block_hash(),
            node.node_service.state().chain.last_mblock_hash()
        );
        let block_hash = node.node_service.state().chain.last_block_hash();
        let block = node
            .node_service
            .chain
            .Macroblock(epoch)
            .unwrap()
            .into_owned();
        assert_eq!(Hash::digest(&block), block_hash);
        let mut outputs = Vec::new();
        for output in block.outputs {
            match output {
                Output::PublicPaymentOutput(p) => outputp.push(p),
                _ => {}
            }
        }
        assert_eq!(outputp.len(), 0);
    }

    p.assert_synchronized();
}

// CASE service award with 0 difficulty.
// Assert that we have one winner, and this winner is the same as notification said.
#[test]
fn service_award_state() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 20;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        p.poll().await;

        let budget = p.config.chain.service_award_per_epoch;
        service_award_round_normal(&mut s, budget);
    });
}

// CASE service award with 0 difficulty, and every validator atleast once skip his order.
// Assert that we have no winner, budget is equal to service_award_budget, and activity map is cleared.
#[test]
fn service_award_state_no_winners() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 50;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        p.poll().await;
        service_award_round_without_participants(&mut s);

        let budget = p.config.chain.service_award_per_epoch;
        service_award_round_normal(&mut s, budget * 2)
    });
}

// CASE loader requests on view_change messages from future.

#[test]
fn view_change_from_future() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 50;
    // execute award alays
    cfg.awards_difficulty = 0;
    let config = SandboxConfig {
        num_nodes: 4,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        p.poll().await;
        p.skip_ublock();
        //        pub fn new(chain: ChainInfo, validator_id: ValidatorId, skey: &pbc::SecretKey) -> Self {

        let mut msgs = Vec::new();
        let sender = p.first_mut();
        let sender_pk = sender.node_service.network_pkey.clone();
        let source_chain_info = ChainInfo::from_blockchain(&sender.node_service.state().chain);

        let mut chain_info = source_chain_info.clone();
        chain_info.offset += 1;
        msgp.push(chain_info);

        let mut chain_info = source_chain_info.clone();
        chain_info.view_change += 1;
        msgp.push(chain_info);

        let mut chain_info = source_chain_info.clone();
        chain_info.last_block = Hash::digest("test");
        msgp.push(chain_info);

        let msgs: Vec<_> = msgs
            .into_iter()
            .map(|chain_info| {
                ViewChangeMessage::new(
                    chain_info,
                    sender.validator_id().unwrap() as u32,
                    &sender.node_service.network_skey,
                )
            })
            .collect();
        p.poll().await;
        let ref mut receiver = p.nodes[1];
        for msg in msgs {
            receiver
                .network_service
                .receive_broadcast(VIEW_CHANGE_TOPIC, msg);
            receiver.poll();
            let (recv_msg, pk): (ChainLoaderMessage, _) =
                receiver.network_service.get_unicast(CHAIN_LOADER_TOPIC);
            assert_eq!(pk, sender_pk);
            match recv_msg {
                ChainLoaderMessage::Request(_) => {}
                _ => panic!("Expected chain loader request."),
            }
        }
    });
}
*/

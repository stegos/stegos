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
        s.for_each(|node| assert_eq!(node.chain.height(), 2));

        let leader_pk = s.nodes[0].node_service.chain.leader();
        // let leader shoot his block
        s.wait(s.cfg().tx_wait_timeout);
        s.poll();
        // emulate timeout on other nodes, and wait for request
        s.wait(s.cfg().micro_block_timeout);
        info!("PARTITION BEGIN");
        s.poll();
        // emulate dead leader for other nodes
        for node in s.iter_except(&[leader_pk]) {
            assert_eq!(node.node_service.chain.view_change(), 0);
            // skip chain loader message
            let _: ChainLoaderMessage = node
                .network_service
                .get_unicast(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
        }

        let mut msgs = Vec::new();
        for node in s.iter_except(&[leader_pk]) {
            let id = node.validator_id();
            let chain = node
                .node_service
                .optimistic
                .current_chain(&node.node_service.chain);
            let msg = ViewChangeMessage::new(
                chain,
                id.unwrap() as u32,
                &node.node_service.keys.network_skey,
            );
            msgs.push(msg);
        }

        assert_eq!(msgs.len(), 3);

        info!("BROADCAST VIEW_CHANGES");
        for node in s.iter_except(&[leader_pk]) {
            for msg in &msgs {
                node.network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
        }
        s.poll();
        for node in s.iter_except(&[leader_pk]) {
            // every node should go to the next view_change, after receiving majority of msgs.
            // This assert can fail in case of bad distributions, if leader has > 1/3 slots_count.
            if node.node_service.chain.select_leader(1) == node.node_service.keys.network_pkey {
                // If node was leader, they have produced monetary block,
                assert_eq!(node.node_service.chain.view_change(), 2);
            } else {
                assert_eq!(node.node_service.chain.view_change(), 1);
            }
        }
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Nodes [A,C,D] Receive block (B2)
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
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }

        let mut starting_view_changes = 0;

        for _ in 0..(s.cfg().blocks_in_epoch - 2) {
            if s.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 1)
                != s.nodes[0].node_service.chain.leader()
            {
                break;
            }
            s.wait(s.cfg().tx_wait_timeout);
            s.skip_monetary_block();
            starting_view_changes += 1;
        }
        let leader_pk = s.nodes[0].node_service.chain.leader();

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

            let new_leader = r.parts.1.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 1);
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
                assert_eq!(
                    node.node_service.chain.view_change(),
                    starting_view_changes + 2
                );
                assert_eq!(node.node_service.chain.last_block_hash(), last_block_hash);
                assert_eq!(
                    node.node_service.chain.height(),
                    starting_view_changes as u64 + 3
                );
            }
        }
    });
}

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

#[test]
fn request_on_timeout() {
    let mut cfg: ChainConfig = Default::default();
    cfg.blocks_in_epoch = 2;
    let config = SandboxConfig {
        num_nodes: 3,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
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

        // let leader shot his block
        s.wait(s.cfg().tx_wait_timeout);
        s.poll();
        // emulate timeout on other nodes, and wait for request
        s.wait(s.cfg().micro_block_timeout);
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

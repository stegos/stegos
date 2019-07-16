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
    let cfg: ChainConfig = Default::default();
    let config = SandboxConfig {
        num_nodes: 3,
        chain: cfg,
        ..Default::default()
    };

    Sandbox::start(config, |mut s| {
        s.poll();
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

        let leader_pk = s.nodes[0].node_service.chain.leader();
        warn!("Leader: {}", leader_pk);

        // let leader shot his block
        s.poll();
        // emulate timeout on other nodes, and wait for request
        s.wait(s.config.node.micro_block_timeout);
        info!("BEFORE POLL");
        s.poll();
        s.filter_broadcast(&[crate::VIEW_CHANGE_TOPIC]); // ignore message from other modules.
        let mut p = s.split(&[leader_pk]);
        for node in &mut p.parts.1.nodes {
            let _: ChainLoaderMessage = node
                .network_service
                .get_unicast_to_peer(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
        }

        let leader = p.parts.0.first_mut();

        assert_eq!(leader_pk, leader.node_service.network_pkey);
        leader
            .network_service
            .filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
        leader
            .network_service
            .filter_broadcast(&[crate::SEALED_BLOCK_TOPIC]);
    });
}

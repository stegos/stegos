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

pub mod loopback;
mod simple_tests;
pub mod time;
pub use self::loopback::Loopback;
pub use time::*;
mod vrf_tickets;
pub use vrf_tickets::VRFHelper;
mod consensus;
use crate::*;
use assert_matches::assert_matches;
use stegos_keychain::KeyChain;

pub struct Sandbox {
    nodes: Vec<NodeSandbox>,
    nodes_keychains: Vec<KeyChain>,
}

impl Sandbox {
    fn new(num_nodes: usize) -> Self {
        let nodes_keychains: Vec<_> = (0..num_nodes).map(|_num| KeyChain::new_mem()).collect();
        let genesis = stegos_blockchain::genesis(&nodes_keychains, 1000, 1000000, 0);

        let nodes: Vec<NodeSandbox> = (0..num_nodes)
            .map(|i| NodeSandbox::new(nodes_keychains[i].clone(), genesis.clone()))
            .collect();
        Self {
            nodes,
            nodes_keychains,
        }
    }

    fn poll(&mut self) {
        for node in &mut self.nodes {
            node.poll();
        }
    }
}

struct NodeSandbox {
    pub network_service: Loopback,
    pub outbox: UnboundedSender<NodeMessage>,
    pub node_service: NodeService,
}

impl NodeSandbox {
    fn new(keychain: KeyChain, genesis: Vec<Block>) -> Self {
        // init network
        let (network_service, network) = Loopback::new();

        // Create node, with first node keychain.
        let (outbox, inbox) = unbounded();
        let mut node_service = NodeService::testing(keychain, network, inbox).unwrap();

        node_service.handle_init(genesis).unwrap();
        Self {
            network_service,
            outbox,
            node_service,
        }
    }

    fn poll(&mut self) {
        assert_eq!(self.node_service.poll(), Ok(Async::NotReady));
    }
}

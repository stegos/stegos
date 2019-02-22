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

use crate::*;
use stegos_keychain::KeyChain;

pub struct SandboxConfig {
    nodes_keychains: Vec<KeyChain>,
    genesis: Vec<Block>,
}

impl SandboxConfig {
    fn genesis(num_nodes: usize) -> Self {
        let nodes_keychains: Vec<_> = (0..num_nodes).map(|_num| KeyChain::new_mem()).collect();
        let genesis = stegos_blockchain::genesis(&nodes_keychains, 1000, 1000000, 0);
        Self {
            genesis,
            nodes_keychains,
        }
    }
}

struct NodeSandbox {
    pub config: SandboxConfig,
    pub manager: Loopback,
    pub keychain: KeyChain,
    pub outbox: UnboundedSender<NodeMessage>,
    pub node_service: NodeService,
}
impl NodeSandbox {
    fn new(num_nodes: usize) -> Self {
        let config = SandboxConfig::genesis(num_nodes);
        // init network
        let (network_manager, network) = Loopback::new();

        // Create node, with first node keychain.
        let my_keychain = config.nodes_keychains.first().unwrap().clone();
        let (outbox, inbox) = unbounded();
        let mut node_service = NodeService::testing(my_keychain.clone(), network, inbox).unwrap();
        node_service.handle_init(config.genesis.clone()).unwrap();
        Self {
            config,
            manager: network_manager,
            keychain: my_keychain,
            outbox,
            node_service,
        }
    }
}

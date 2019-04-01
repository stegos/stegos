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

mod simple_tests;
pub mod time;

pub use stegos_network::loopback::Loopback;
pub use time::*;
mod consensus;
use crate::*;
use assert_matches::assert_matches;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;

#[allow(unused)]
pub struct Sandbox {
    nodes: Vec<NodeSandbox>,
    nodes_keychains: Vec<KeyChain>,
}

impl Sandbox {
    fn new(cfg: ChainConfig, num_nodes: usize) -> Self {
        let timestamp = SystemTime::now();
        let nodes_keychains: Vec<_> = (0..num_nodes).map(|_num| KeyChain::new_mem()).collect();
        let genesis = stegos_blockchain::genesis(&nodes_keychains, 1000, 1000000, timestamp);

        let nodes: Vec<NodeSandbox> = (0..num_nodes)
            .map(|i| NodeSandbox::new(cfg.clone(), nodes_keychains[i].clone(), genesis.clone()))
            .collect();
        Self {
            nodes,
            nodes_keychains,
        }
    }

    /// Return node for publickey.
    fn node(&mut self, pk: &secure::PublicKey) -> Option<&mut NodeSandbox> {
        self.nodes
            .iter_mut()
            .find(|node| node.node_service.keys.network_pkey == *pk)
    }

    /// Iterator among all nodes, except one of
    fn iter_except<'a>(
        &'a mut self,
        validators: &'a [secure::PublicKey],
    ) -> impl Iterator<Item = &'a mut NodeSandbox> {
        self.nodes.iter_mut().filter(move |node| {
            validators
                .iter()
                .find(|key| **key == node.node_service.keys.network_pkey)
                .is_none()
        })
    }

    fn poll(&mut self) {
        for (id, node) in self.nodes.iter_mut().enumerate() {
            info!("============ POLLING node={} ============", id);
            node.poll();
        }
    }

    fn assert_synchronized(&self) {
        let height = self.nodes[0].node_service.chain.height();
        let last_block = self.nodes[0].node_service.chain.last_block_hash();
        for node in &self.nodes {
            assert_eq!(node.node_service.chain.height(), height);
            assert_eq!(node.node_service.chain.last_block_hash(), last_block);
        }
    }

    /// Take monetary block from leader, rebroadcast to other nodes.
    /// Use after block timeout.
    /// This function will poll() every node.
    fn skip_monetary_block(&mut self) {
        self.assert_synchronized();
        assert!(
            self.nodes[0].node_service.chain.blocks_in_epoch()
                <= self.nodes[0].node_service.cfg.blocks_in_epoch
        );
        let leader_pk = self.nodes[0].node_service.chain.leader();
        self.poll();
        let leader = self.node(&leader_pk).unwrap();
        let block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        self.poll();
    }
}

struct NodeSandbox {
    pub network_service: Loopback,
    pub outbox: UnboundedSender<NodeMessage>,
    pub node_service: NodeService,
}

impl NodeSandbox {
    fn new(cfg: ChainConfig, keychain: KeyChain, genesis: Vec<Block>) -> Self {
        // init network
        let (network_service, network) = Loopback::new();

        // Create node, with first node keychain.
        let (outbox, inbox) = unbounded();
        let mut node_service =
            NodeService::testing(cfg, keychain, network, genesis, inbox).unwrap();
        node_service.handle_init().unwrap();
        Self {
            network_service,
            outbox,
            node_service,
        }
    }

    fn get_id(&self) -> usize {
        let key = self.node_service.keys.network_pkey;
        self.node_service
            .chain
            .validators()
            .iter()
            .enumerate()
            .find(|(_id, keys)| key == keys.0)
            .map(|(id, _)| id)
            .unwrap()
    }

    fn poll(&mut self) {
        assert_eq!(self.node_service.poll(), Ok(Async::NotReady));
    }
}

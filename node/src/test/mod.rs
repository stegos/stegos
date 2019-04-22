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
use time::{start_test, wait, TestTimer};
mod consensus;
mod microblocks;
mod requests;
use crate::*;
use assert_matches::assert_matches;
use log::Level;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use tokio_timer::Timer;

pub struct SandboxConfig {
    pub chain: ChainConfig,
    pub num_nodes: usize,
    pub log_level: Level,
}

impl Default for SandboxConfig {
    fn default() -> SandboxConfig {
        SandboxConfig {
            chain: Default::default(),
            num_nodes: 4,
            log_level: Level::Trace,
        }
    }
}

#[allow(unused)]
pub struct Sandbox<'timer> {
    nodes: Vec<NodeSandbox>,
    nodes_keychains: Vec<KeyChain>,
    timer: &'timer mut Timer<TestTimer>,
    config: ChainConfig,
}

impl<'timer> Sandbox<'timer> {
    pub fn start<F>(cfg: SandboxConfig, test_routine: F)
    where
        F: FnOnce(Sandbox),
    {
        start_test(|timer| {
            let _ = simple_logger::init_with_level(Level::Trace);
            let num_nodes = cfg.num_nodes;
            let cfg = cfg.chain;
            let timestamp = SystemTime::now();
            let nodes_keychains: Vec<_> = (0..num_nodes).map(|_num| KeyChain::new_mem()).collect();
            let genesis = stegos_blockchain::genesis(&nodes_keychains, 1000, 1000000, timestamp);

            let nodes: Vec<NodeSandbox> = (0..num_nodes)
                .map(|i| NodeSandbox::new(cfg.clone(), nodes_keychains[i].clone(), genesis.clone()))
                .collect();
            let sandbox = Sandbox {
                nodes,
                nodes_keychains,
                timer,
                config: cfg,
            };
            test_routine(sandbox)
        });
    }

    pub fn wait(&mut self, duration: Duration) {
        wait(&mut *self.timer, duration)
    }

    pub fn cfg(&self) -> &ChainConfig {
        &self.config
    }

    fn split<'a>(&'a mut self, first_partitions_nodes: &[secure::PublicKey]) -> PartitionGuard<'a> {
        let divider = |key| {
            first_partitions_nodes
                .iter()
                .find(|item| **item == key)
                .is_some()
        };

        let mut part1 = Partition::default();
        let mut part2 = Partition::default();
        for node in self.nodes.iter_mut() {
            if divider(node.node_service.keys.network_pkey) {
                part1.nodes.push(node)
            } else {
                part2.nodes.push(node)
            }
        }

        PartitionGuard {
            timer: &mut *self.timer,
            config: &self.config,
            parts: (part1, part2),
        }
    }
}

/// Most of test related to consensus, will split network into parts.
/// This wrapper was designed to represent splitted parts of network.
#[allow(unused)]
#[derive(Default)]
struct Partition<'p> {
    nodes: Vec<&'p mut NodeSandbox>,
}
#[allow(dead_code)]
impl<'p> Partition<'p> {
    // rust borrowchecker is not smart enought to deduct that we need smaller iter lifetimes.
    // to proove that it is safe this implemetation contain intermediate vector.
    // This function can be rewrited as unsafe,
    // or may be later rewrited just as `self.into_iter().map(|i|*i)`
    fn reborrow_nodes<'a>(&'a self) -> impl Iterator<Item = &'a NodeSandbox>
    where
        'p: 'a,
    {
        use std::ops::Deref;
        let mut arr = Vec::new();
        for item in &self.nodes {
            arr.push(item.deref())
        }
        arr.into_iter()
    }
    fn reborrow_nodes_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut NodeSandbox>
    where
        'p: 'a,
    {
        use std::ops::DerefMut;
        let mut arr = Vec::new();
        for item in &mut self.nodes {
            arr.push(item.deref_mut())
        }
        arr.into_iter()
    }
}

impl Drop for NodeSandbox {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            info!("Droping node with id = {:?}", self.validator_id());
            self.network_service.assert_empty_queue();
        }
    }
}

#[allow(unused)]
struct PartitionGuard<'p> {
    timer: &'p mut Timer<TestTimer>,
    config: &'p ChainConfig,
    parts: (Partition<'p>, Partition<'p>),
}

#[allow(dead_code)]
impl<'p> PartitionGuard<'p> {
    pub fn wait(&mut self, duration: Duration) {
        wait(&mut *self.timer, duration)
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
        let node_service = NodeService::testing(cfg, keychain, network, genesis, inbox).unwrap();
        Self {
            network_service,
            outbox,
            node_service,
        }
    }

    fn validator_id(&self) -> Option<usize> {
        let key = self.node_service.keys.network_pkey;
        self.node_service
            .chain
            .validators()
            .iter()
            .enumerate()
            .find(|(_id, keys)| key == keys.0)
            .map(|(id, _)| id)
    }

    fn poll(&mut self) {
        assert_eq!(self.node_service.poll(), Ok(Async::NotReady));
    }
}

trait Api<'p> {
    fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a;

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a NodeSandbox> + 'a>
    where
        'p: 'a;

    fn first<'a>(&'a self) -> &'a NodeSandbox
    where
        'p: 'a,
    {
        self.iter()
            .next()
            .expect("Not found first node at sandbox.")
    }

    fn first_mut<'a>(&'a mut self) -> &'a mut NodeSandbox
    where
        'p: 'a,
    {
        self.iter_mut()
            .next()
            .expect("Not found first node at sandbox.")
    }
    /// Iterator among all nodes, except one of
    fn iter_except<'a>(
        &'a mut self,
        validators: &'a [secure::PublicKey],
    ) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.iter_mut().filter(move |node| {
            validators
                .iter()
                .find(|key| **key == node.node_service.keys.network_pkey)
                .is_none()
        }))
    }

    /// Checks if all sandbox nodes synchronized.
    fn assert_synchronized(&self) {
        let height = self.first().node_service.chain.height();
        let last_block = self.first().node_service.chain.last_block_hash();
        for node in self.iter() {
            assert_eq!(node.node_service.chain.height(), height);
            assert_eq!(node.node_service.chain.last_block_hash(), last_block);
        }
    }

    /// Filter messages from specific protocol_ids.
    fn filter_unicast(&mut self, protocol_ids: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_unicast(protocol_ids)
        }
    }

    /// Filter messages from specific topics.
    fn filter_broadcast(&mut self, topics: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_broadcast(topics)
        }
    }

    /// poll each node for updates.
    fn poll(&mut self) {
        for node in self.iter_mut() {
            info!(
                "============ POLLING node={:?} ============",
                node.validator_id()
            );
            node.poll();
        }
    }

    fn num_nodes(&self) -> usize {
        self.iter().count()
    }

    /// Take monetary block from leader, rebroadcast to other nodes.
    /// Use after block timeout.
    /// This function will poll() every node.
    fn skip_monetary_block(&mut self) {
        self.assert_synchronized();
        assert!(
            self.first().node_service.chain.blocks_in_epoch()
                <= self.first().node_service.cfg.blocks_in_epoch
        );
        let leader_pk = self.first().node_service.chain.leader();
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

    /// Execute some function for each node_service.
    fn for_each<F>(&self, mut function: F)
    where
        F: FnMut(&NodeService),
    {
        for node in self.iter() {
            function(&node.node_service)
        }
    }

    /// Return node for publickey.
    fn node<'a>(&'a mut self, pk: &secure::PublicKey) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        self.iter_mut()
            .find(|node| node.node_service.keys.network_pkey == *pk)
    }
}

impl<'p> Api<'p> for Partition<'p> {
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.reborrow_nodes())
    }
    fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.reborrow_nodes_mut())
    }
}

impl<'p> Api<'p> for Sandbox<'p> {
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.nodes.iter())
    }
    fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.nodes.iter_mut())
    }
}

// tests

#[test]
fn test_partition() {
    let config: SandboxConfig = Default::default();

    Sandbox::start(config, |mut s| {
        s.poll();
        let leader_pk = s.nodes[0].node_service.chain.leader();
        let r = s.split(&[leader_pk]);
        assert_eq!(r.parts.0.nodes.len(), 1);
        assert_eq!(r.parts.1.nodes.len(), 3);
    });
}

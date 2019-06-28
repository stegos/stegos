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

pub mod futures_testing;

use self::futures_testing::{start_test, wait, TestTimer};
pub use stegos_network::loopback::Loopback;
mod consensus;
mod integration;
mod microblocks;
mod requests;
use crate::*;
use assert_matches::assert_matches;
use log::Level;
use std::time::Duration;
pub use stegos_blockchain::test::*;
use stegos_crypto::pbc;
use stegos_crypto::pbc::{PublicKey, VRF};
use tokio_timer::Timer;

pub struct SandboxConfig {
    pub node: NodeConfig,
    pub chain: ChainConfig,
    pub num_nodes: usize,
    pub log_level: Level,
}

impl Default for SandboxConfig {
    fn default() -> SandboxConfig {
        SandboxConfig {
            node: Default::default(),
            chain: Default::default(),
            num_nodes: 4,
            log_level: Level::Trace,
        }
    }
}

#[allow(unused)]
pub struct Sandbox<'timer> {
    nodes: Vec<NodeSandbox>,
    timer: &'timer mut Timer<TestTimer>,
    config: SandboxConfig,
}

impl<'timer> Sandbox<'timer> {
    pub fn start<F>(config: SandboxConfig, test_routine: F)
    where
        F: FnOnce(Sandbox),
    {
        start_test(|timer| {
            let _ = simple_logger::init_with_level(Level::Trace);
            let num_nodes = config.num_nodes;
            let timestamp = Timestamp::now();

            let (keychains, genesis) = fake_genesis(
                config.chain.min_stake_amount,
                1000 * config.chain.min_stake_amount,
                num_nodes,
                timestamp,
            );
            let mut nodes = Vec::new();
            for keys in keychains {
                let node = NodeSandbox::new(
                    config.node.clone(),
                    config.chain.clone(),
                    keys.wallet_pkey,
                    keys.network_skey,
                    keys.network_pkey,
                    genesis.clone(),
                );
                nodes.push(node)
            }
            let sandbox = Sandbox {
                nodes,
                timer,
                config,
            };
            for node in sandbox.nodes.iter() {
                assert_eq!(node.node_service.chain.epoch(), 1);
                assert_eq!(node.node_service.chain.offset(), 0);
            }
            test_routine(sandbox)
        });
    }

    pub fn wait(&mut self, duration: Duration) {
        wait(&mut *self.timer, duration)
    }

    fn split<'a>(&'a mut self, first_partitions_nodes: &[pbc::PublicKey]) -> PartitionGuard<'a> {
        let divider = |key| {
            first_partitions_nodes
                .iter()
                .find(|item| **item == key)
                .is_some()
        };

        let mut part1 = Partition::default();
        let mut part2 = Partition::default();
        for node in self.nodes.iter_mut() {
            if divider(node.node_service.network_pkey) {
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
    pub config: &'p SandboxConfig,
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
    pub node: Node,
    pub node_service: NodeService,
}

impl NodeSandbox {
    fn new(
        node_cfg: NodeConfig,
        chain_cfg: ChainConfig,
        recipient_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        genesis: MacroBlock,
    ) -> Self {
        // init network
        let (network_service, network) = Loopback::new();

        // Create node, with first node keychain.
        let timestamp = Timestamp::now();
        let (storage_cfg, _temp_dir) = StorageConfig::testing();
        let chain = Blockchain::new(chain_cfg, storage_cfg, genesis, timestamp)
            .expect("Failed to create blockchain");
        let (mut node_service, node) = NodeService::new(
            node_cfg,
            chain,
            recipient_pkey,
            network_skey,
            network_pkey,
            network,
        )
        .unwrap();
        node_service.init().unwrap();
        Self {
            network_service,
            node,
            node_service,
        }
    }

    #[allow(dead_code)]
    fn create_vrf_from_seed(&self, random: Hash, view_change: u32) -> VRF {
        let seed = mix(random, view_change);
        pbc::make_VRF(&self.node_service.network_skey, &seed)
    }

    fn validator_id(&self) -> Option<usize> {
        let key = self.node_service.network_pkey;
        self.node_service
            .chain
            .validators()
            .iter()
            .enumerate()
            .find(|(_id, keys)| key == keys.0)
            .map(|(id, _)| id)
    }

    fn poll(&mut self) {
        futures_testing::execute(&mut self.node_service);
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
        validators: &'a [pbc::PublicKey],
    ) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a,
    {
        Box::new(self.iter_mut().filter(move |node| {
            validators
                .iter()
                .find(|key| **key == node.node_service.network_pkey)
                .is_none()
        }))
    }

    /// Checks if all sandbox nodes synchronized.
    fn assert_synchronized(&self) {
        let epoch = self.first().node_service.chain.epoch();
        let offset = self.first().node_service.chain.offset();
        let last_block = self.first().node_service.chain.last_block_hash();
        for node in self.iter() {
            assert_eq!(node.node_service.chain.epoch(), epoch);
            assert_eq!(node.node_service.chain.offset(), offset);
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

    /// Take micro block from leader, rebroadcast to other nodes.
    /// Use after block timeout.
    /// This function will poll() every node.
    fn skip_micro_block(&mut self) {
        self.assert_synchronized();
        assert!(
            self.first().node_service.chain.offset()
                <= self.first().node_service.chain.cfg().micro_blocks_in_epoch
        );
        let leader_pk = self.first().node_service.chain.leader();
        trace!("Acording to partition info, next leader = {}", leader_pk);
        self.poll();
        self.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
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

    fn leader(&mut self) -> pbc::PublicKey {
        self.first_mut().node_service.chain.leader()
    }

    /// Returns next leader publicKey.
    /// Returns None if some of leader in chain of election was not found in current partition.
    fn future_block_leader(&mut self, idx: u32) -> Option<pbc::PublicKey> {
        let mut leader_pk = self.first_mut().node_service.chain.leader();
        let mut view_change = self.first_mut().node_service.chain.view_change();
        let mut random = self.first_mut().node_service.chain.last_random();

        trace!("First leader pk = {}", leader_pk);

        for i in 0..idx {
            let node = self.node(&leader_pk)?;
            let vrf = node.create_vrf_from_seed(random, view_change);
            random = vrf.rand;
            view_change = 0;

            let mut election = self
                .first_mut()
                .node_service
                .chain
                .election_result()
                .clone();
            election.random = vrf;
            leader_pk = election.select_leader(view_change);
            trace!("Leader {} pk = {}", i + 1, leader_pk);
        }
        Some(leader_pk)
    }

    /// Same as next_leader, but for view_changes.
    fn future_view_change_leader(&mut self, idx: u32) -> pbc::PublicKey {
        let view_change = self.first_mut().node_service.chain.view_change();
        self.first_mut()
            .node_service
            .chain
            .select_leader(view_change + idx)
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
    fn node<'a>(&'a mut self, pk: &pbc::PublicKey) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        self.iter_mut()
            .find(|node| node.node_service.network_pkey == *pk)
    }

    /// Return node for publickey.
    fn node_ref<'a>(&'a mut self, pk: &pbc::PublicKey) -> Option<&'a NodeSandbox>
    where
        'p: 'a,
    {
        self.iter()
            .find(|node| node.node_service.network_pkey == *pk)
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

/// Inner logic specific for cheater slashing.
fn slash_cheater_inner<'a>(
    s: &'a mut Sandbox,
    leader_pk: PublicKey,
    mut filter_nodes: Vec<PublicKey>,
) -> PartitionGuard<'a> {
    s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);

    filter_nodes.push(leader_pk);
    let mut r = s.split(&filter_nodes);
    let leader = &mut r.parts.0.node(&leader_pk).unwrap();
    let b1: Block = leader
        .network_service
        .get_broadcast(crate::SEALED_BLOCK_TOPIC);
    let mut b2 = b1.clone();
    // modify timestamp for block
    match &mut b2 {
        Block::MicroBlock(ref mut b) => {
            b.header.timestamp += Duration::from_millis(1);
            let block_hash = Hash::digest(&*b);
            b.sig = pbc::sign_hash(&block_hash, &leader.node_service.network_skey);
        }
        Block::MacroBlock(_) => unreachable!(),
    }

    info!("BROADCAST BLOCK, WITH COPY.");
    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
    }
    r.parts
        .1
        .for_each(|node| assert_eq!(node.cheating_proofs.len(), 0));

    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
    }

    r.parts.1.poll();
    r
}

fn precondition_n_different_block_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.future_block_leader(id).unwrap())
            .collect();

        info!(
            "Checking that all leader are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
}

fn precondition_n_different_viewchange_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.future_view_change_leader(id))
            .collect();

        info!(
            "Checking that all leader are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
}

/// Skip blocks until condition not true
fn skip_blocks_until<F>(s: &mut Sandbox, mut condition: F)
where
    F: FnMut(&mut Sandbox) -> bool,
{
    let mut ready = false;
    for _id in 0..s.config.chain.micro_blocks_in_epoch {
        if condition(s) {
            ready = true;
            break;
        }
        info!("Skipping microlock.");
        s.wait(s.config.node.tx_wait_timeout);
        s.skip_micro_block()
    }
    assert!(ready, "Not enought micriblocks found");
}

pub fn check_unique<T: Ord + Clone + PartialEq>(original: Vec<T>) -> bool {
    let original_len = original.len();
    let mut array = original;
    array.sort_unstable();
    array.dedup();
    original_len == array.len()
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
        s.filter_unicast(&[crate::loader::CHAIN_LOADER_TOPIC]);
    });
}

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

use rand_isaac::IsaacRng;
use rand_core::SeedableRng;
use rand::{thread_rng, Rng};
use tempdir::TempDir;
//use stegos_crypto::pbc;
use stegos_network::loopback::Loopback;
use stegos_network::Network;
use stegos_crypto::pbc::VRF;

use crate::*;
use super::logger;
use super::VDFExecution;
use log::*;
pub use stegos_blockchain::test::*;

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

pub struct Sandbox {
    pub nodes: Vec<NodeSandbox>,
    pub auditor: NodeSandbox,
    pub keychains: Vec<KeyChain>,
    pub config: SandboxConfig,
    pub prng: IsaacRng,
}

impl Sandbox {
    pub fn start<F>(config: SandboxConfig, test_routine: F)
    where
        F: FnOnce(Sandbox),
    {
        stegos_crypto::init_test_network_prefix();
        let var = std::env::var("STEGOS_TEST_LOGS_LEVEL")
            .ok()
            .map(|s| s.to_lowercase());
        let level = match var.as_ref().map(AsRef::as_ref) {
            Some("off") => None,
            Some("error") => Some(Level::Error),
            Some("warn") => Some(Level::Warn),
            _ => Some(Level::Trace),
        };

        if let Some(level) = level {
            let _ = logger::init_with_level(level);
        }

        let num_nodes = config.num_nodes;
        let timestamp = Timestamp::now();

        let mut thread_rng = thread_rng();

        let starting_seed = thread_rng.gen::<[u8; 32]>();

        // to reproduce test, just uncomment this line,
        // and replace this variable from the output seed.
        //            let starting_seed = [98, 205, 131, 252, 208, 247, 228, 95, 76, 184, 202, 37, 219, 148, 172, 68, 132, 207, 102, 110, 93, 159, 16, 56, 2, 52, 104, 216, 246, 44, 148, 40];
        trace!("Start test with seed = {:?}", starting_seed);

        let mut prng = IsaacRng::from_seed(starting_seed);
        let (keychains, genesis) = fake_genesis(
            config.chain.min_stake_amount,
            1000 * config.chain.min_stake_amount,
            config.chain.max_slot_count,
            num_nodes,
            timestamp,
            Some(&mut prng),
        );
        let mut nodes = Vec::new();
        for keys in keychains.clone() {
            let node = NodeSandbox::new(
                config.node.clone(),
                config.chain.clone(),
                keys.network_skey,
                keys.network_pkey,
                genesis.clone(),
            );
            nodes.push(node)
        }
        let auditor_keychain = KeyChain::new(&mut prng);
        let auditor = NodeSandbox::new(
            config.node.clone(),
            config.chain.clone(),
            auditor_keychain.network_skey,
            auditor_keychain.network_pkey,
            genesis.clone(),
        );

        let sandbox = Sandbox {
            nodes,
            keychains,
            config,
            auditor,
            prng,
        };

        for node in sandbox.nodes.iter() {
            let chain = &node.node_service.state().chain; 
            assert_eq!(chain.epoch(), 1);
            assert_eq!(chain.offset(), 0);
        }
        test_routine(sandbox)
    }

    pub fn split<'a>(
        &'a mut self,
        first_partitions_nodes: &[pbc::PublicKey],
    ) -> PartitionGuard<'a> {
        let divider = |key| {
            first_partitions_nodes
                .iter()
                .find(|item| **item == key)
                .is_some()
        };

        let mut part1 = Partition::default();
        let mut part2 = Partition::default();
        for node in self.nodes.iter_mut() {
            if divider(node.node_service.state().network_pkey) {
                part1.nodes.push(node)
            } else {
                part2.nodes.push(node)
            }
        }

        //TODO: add support of multiple auditors, and allow to choose on which side should be auditors.
        part2.auditor = Some(&mut self.auditor);

        PartitionGuard {
            config: &self.config,
            parts: (part1, part2),
        }
    }
}

/// Most of test related to consensus, will split network into parts.
/// This wrapper was designed to represent splitted parts of network.
#[allow(unused)]
#[derive(Default)]
pub struct Partition<'p> {
    pub nodes: Vec<&'p mut NodeSandbox>,
    pub auditor: Option<&'p mut NodeSandbox>,
}
#[allow(dead_code)]
impl<'p> Partition<'p> {
    // rust borrowchecker is not smart enought to deduct that we need smaller iter lifetimes.
    // to proove that it is safe this implemetation contain intermediate vector.
    // This function can be rewrited as unsafe,
    // or may be later rewrited just as `self.into_iter().map(|i|*i)`
    pub fn reborrow_nodes<'a>(&'a self) -> impl Iterator<Item = &'a NodeSandbox>
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

    pub fn reborrow_nodes_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut NodeSandbox>
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

#[allow(unused)]
pub struct PartitionGuard<'p> {
    pub config: &'p SandboxConfig,
    pub parts: (Partition<'p>, Partition<'p>),
}

// #[allow(dead_code)]
// impl<'p> PartitionGuard<'p> {
//     pub fn wait(&mut self, duration: Duration) {
//         wait(&mut *self.timer, duration)
//     }
// }

pub struct NodeSandbox {
    pub network_service: Loopback,
    pub node: Node,
    pub node_service: NodeService,
    pub vdf_execution: VDFExecution,
    //pub future: Pin<Box<dyn Future<Output = ()>>>,
}

impl Drop for NodeSandbox {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            info!("Droping node with id = {:?}", self.validator_id());
            self.network_service.assert_empty_queue();
        }
    }
}

impl NodeSandbox {
    pub fn new(
        node_cfg: NodeConfig,
        chain_cfg: ChainConfig,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        genesis: MacroBlock,
    ) -> Self {
        // init network
        let (network_service, network, peer_id, replication_rx) = Loopback::new();

        // Create node, with first node keychain.
        let timestamp = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        let chain = Blockchain::new(
            chain_cfg,
            chain_dir.path(),
            ConsistencyCheck::Full,
            genesis,
            timestamp,
        )
        .expect("Failed to create blockchain");
        let (mut node_service, node) = NodeService::new(
            node_cfg,
            chain,
            network_skey,
            network_pkey,
            network,
            "dev".to_string(),
            peer_id,
            replication_rx,
        )
        .unwrap();
        node_service.init().unwrap();
        Self {
            vdf_execution: VDFExecution::Nothing,
            network_service,
            node,
            node_service,
        }
    }

    pub fn clone_network(&self) -> (Loopback, Network) {
        (
            self.network_service.clone(),
            self.node_service.network().box_clone(),
        )
    }

    pub fn chain(&self) -> &Blockchain {
        &self.node_service.state().chain
    }

    pub fn keys(&self) -> (&pbc::PublicKey, &pbc::SecretKey) {
        let state = self.node_service.state();
        (
            &state.network_pkey,
            &state.network_skey,
        )
    }

    #[allow(dead_code)]
    pub fn create_vrf_from_seed(&self, random: Hash, view_change: u32) -> VRF {
        let seed = mix(random, view_change);
        pbc::make_VRF(&self.node_service.state().network_skey, &seed)
    }

    pub fn validator_id(&self) -> Option<usize> {
        let state = self.node_service.state();
        let key = state.network_pkey;
        state
            .chain
            .validators()
            .iter()
            .enumerate()
            .find(|(_id, keys)| key == keys.0)
            .map(|(id, _)| id)
    }

    pub fn handle_vdf(&mut self) {
        self.vdf_execution.try_produce();
        self.vdf_execution = VDFExecution::WaitForVDF;
    }

    // pub async fn poll(&mut self) {
    //     format!("node:{}", self.node_service.network_pkey());
    //     self.node_service.poll()
    // }
}

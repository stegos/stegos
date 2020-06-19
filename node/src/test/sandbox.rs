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

use futures::pin_mut;
use futures::task::Poll;

use std::convert::TryInto;
use std::collections::HashSet;
use std::ops::{Index, IndexMut};
use std::time::Duration;

use rand::{thread_rng, Rng};
use rand_core::SeedableRng;
use rand_isaac::IsaacRng;
use tempdir::TempDir;
//use stegos_crypto::pbc;
use stegos_crypto::pbc::PublicKey;
use stegos_crypto::pbc::VRF;
use stegos_network::loopback::Loopback;
use stegos_network::Network;

use super::VDFExecution;
use crate::*;
use crate::shorthex::*;

use log::*;
pub use stegos_blockchain::test::*;

use assert_matches::assert_matches;
//use log::*;
//use std::time::Duration;
use super::tokio;
pub use stegos_blockchain::test::*;
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_consensus::optimistic::AddressedViewChangeProof;
use stegos_consensus::ConsensusMessageBody;
use stegos_crypto::pbc;

#[derive(Clone)]
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
    pub fn new(config: SandboxConfig) -> Self {
        stegos_crypto::init_test_network_prefix();
        pretty_env_logger::try_init_timed_custom_env("STEGOS_TEST_LOG").unwrap();

        // freeze the time for testing
        tokio::time::pause();

        let num_nodes = config.num_nodes;
        let timestamp = Timestamp::now();

        let mut thread_rng = thread_rng();

        let starting_seed = thread_rng.gen::<[u8; 32]>();

        // to reproduce test, just uncomment this line,
        // and replace this variable from the output seed.
        //            let starting_seed = [98, 205, 131, 252, 208, 247, 228, 95, 76, 184, 202, 37, 219, 148, 172, 68, 132, 207, 102, 110, 93, 159, 16, 56, 2, 52, 104, 216, 246, 44, 148, 40];
        trace!("Start test with seed = {:x}", starting_seed.short_hex());

        let mut prng = IsaacRng::from_seed(starting_seed);
        let (keychains, genesis) = fake_genesis(
            config.chain.min_stake_amount,
            1000 * config.chain.min_stake_amount,
            config.chain.max_slot_count,
            num_nodes,
            timestamp,
            config.chain.awards_difficulty.try_into().unwrap(),
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

        sandbox
    }

    pub fn partition(&mut self) -> Partition {
        Partition {
            nodes: self.nodes.iter_mut().collect(),
            auditor: None,
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
    pub fn reborrow_nodes(&self) -> impl Iterator<Item = &NodeSandbox> {
        use std::ops::Deref;
        let mut arr = Vec::new();
        for item in &self.nodes {
            arr.push(item.deref())
        }
        arr.into_iter()
    }

    pub fn reborrow_nodes_mut(&mut self) -> impl Iterator<Item = &mut NodeSandbox> {
        use std::ops::DerefMut;
        let mut arr = Vec::new();
        for item in &mut self.nodes {
            arr.push(item.deref_mut())
        }
        arr.into_iter()
    }

    pub fn iter(&self) -> impl Iterator<Item = &NodeSandbox> {
        self.reborrow_nodes()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut NodeSandbox> {
        self.reborrow_nodes_mut()
    }

    pub fn auditor_mut(&mut self) -> Option<&mut NodeSandbox> {
        // reborrow auditor
        if let Some(&mut ref mut s) = self.auditor {
            Some(s)
        } else {
            None
        }
    }

    pub fn auditor(&self) -> Option<&NodeSandbox> {
        // reborrow auditor
        if let Some(&mut ref s) = self.auditor {
            Some(s)
        } else {
            None
        }
    }

    pub fn first(&self) -> &NodeSandbox {
        self.iter()
            .next()
            .expect("First node not found in the sandbox")
    }

    pub fn first_mut(&mut self) -> &mut NodeSandbox {
        self.iter_mut()
            .next()
            .expect("First node not found in the sandbox.")
    }

    /// Return node for publickey.
    pub fn find_mut<'a>(&'a mut self, pk: &pbc::PublicKey) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        self.iter_mut()
            .find(|node| node.node_service.state().network_pkey == *pk)
    }

    /// Return node for publickey.
    pub fn find<'a>(&'a self, pk: &pbc::PublicKey) -> Option<&'a NodeSandbox>
    where
        'p: 'a,
    {
        self.iter()
            .find(|node| node.node_service.state().network_pkey == *pk)
    }

    /// Iterator among all nodes, except one of
    pub fn iter_except<'a>(
        &'a mut self,
        excl: &'a [pbc::PublicKey],
    ) -> impl Iterator<Item = &'a mut NodeSandbox>
    where
        'p: 'a,
    {
        let keys: HashSet<&pbc::PublicKey> = excl.iter().collect();
        self.iter_mut()
            .filter(move |node| !keys.contains(&node.node_service.state().network_pkey))
    }

    pub fn split<'a>(&'a mut self, first_partitions_nodes: &[pbc::PublicKey]) -> PartitionGuard<'a>
    where
        'p: 'a,
    {
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

        use std::ops::DerefMut;
        //TODO: add support of multiple auditors, and allow to choose on which side should be auditors.
        part2.auditor = self.auditor.as_mut().map(|x| x.deref_mut());

        PartitionGuard {
            parts: (part1, part2),
        }
    }

    /// Inner logic specific for cheater slashing.
    pub async fn slash_cheater_inner<'a>(
        part: &'a mut Partition<'a>,
        leader_pk: PublicKey,
        mut filter_nodes: Vec<PublicKey>,
    ) -> PartitionGuard<'a>
    where
        'p: 'a,
    {
        part.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        filter_nodes.push(leader_pk);
        let mut r = part.split(&filter_nodes);
        let leader = &mut r.parts.0.find_mut(&leader_pk).unwrap();
        leader.handle_vdf();
        leader.node_service.poll().await;
        let b1: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let mut b2 = b1.clone();
        // modify timestamp for block
        match &mut b2 {
            Block::MicroBlock(ref mut b) => {
                b.header.timestamp += Duration::from_millis(1);
                let block_hash = Hash::digest(&*b);
                b.sig = pbc::sign_hash(&block_hash, &leader.node_service.state().network_skey);
            }
            Block::MacroBlock(_) => unreachable!("Expected a MacroBlock"),
        }

        info!("BROADCAST BLOCK, WITH COPY.");
        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
        }

        if let Some(auditor) = r.parts.1.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
        }

        r.parts
            .1
            .iter_mut()
            .for_each(|node| assert_eq!(node.node_service.state().cheating_proofs.len(), 0));

        for node in r.parts.1.iter_mut() {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
        }

        if let Some(auditor) = r.parts.1.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
        }

        r.parts.1.poll().await;
        r
    }

    /// Checks if all sandbox nodes synchronized.
    pub fn assert_synchronized(&self) {
        let node = self.first();
        let chain = &node.node_service.state().chain;
        let epoch = chain.epoch();
        let awards = chain.epoch_info(epoch - 1).unwrap().unwrap();
        let offset = chain.offset();
        let last_block = chain.last_block_hash();
        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            trace!("Checking node = {}, {:?}", node.node_service.state().network_pkey, node.validator_id());

            assert_eq!(chain.epoch(), epoch);
            assert_eq!(chain.epoch_info(epoch - 1).unwrap().unwrap(), awards);
            assert_eq!(chain.offset(), offset);
            assert_eq!(chain.last_block_hash(), last_block);
        }

        if let Some(auditor) = self.auditor() {
            let chain = &auditor.node_service.state().chain;
            assert_eq!(chain.epoch(), epoch);
            assert_eq!(chain.epoch_info(epoch - 1).unwrap().unwrap(), awards);
            assert_eq!(chain.offset(), offset);
            assert_eq!(chain.last_block_hash(), last_block);
        }
    }

    /// Filter messages from specific protocol_ids.
    pub fn filter_unicast(&mut self, protocol_ids: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_unicast(protocol_ids)
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor.network_service.filter_unicast(protocol_ids)
        }
    }

    /// Filter messages from specific topics.
    pub fn filter_broadcast(&mut self, topics: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_broadcast(topics)
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor.network_service.filter_broadcast(topics)
        }
    }

    /// poll each node for updates.
    pub async fn poll(&mut self) {
        trace!(">>> Sandbox polling...");
        for node in self.nodes.iter_mut() {
            // poll future one time
            // - if it pending, then it waits for external event, we can drop it for now.
            // - if it complete, then it processed some event, and we can recreate it for new event
            loop {
                let future = node.poll();

                pin_mut!(future);
                let result = futures::poll!(future);

                if result == Poll::Pending {
                    break;
                }
            }
        }

        if let Some(auditor) = &mut self.auditor {
            loop {
                let future = auditor.poll();
                pin_mut!(future);

                let result = futures::poll!(future);

                if result == Poll::Pending {
                    break;
                }
            }
        }

        // Turn the timer wheel to let timers get polled. 
        // Do not use `tokio::task::yield_now().await` here 
        // as it can advance test time per the timers, e.g. by 30s.
        tokio::time::delay_for(Duration::from_secs(0)).await;
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    //TODO: This temporary solution is used to emulate broadcast in network. For example
    // when you need to send transaction over network, it should be broadcasted.
    /// Take messages from topic, and broadcast to other nodes.
    pub async fn broadcast(&mut self, topic: &str) {
        let mut messages = Vec::new();
        for node in self.iter_mut() {
            if let Some(m) = node.network_service.try_get_broadcast_raw(topic) {
                messages.push(m)
            }
        }
        debug!("found {} messages, broadcast them.", messages.len());
        for node in self.iter_mut() {
            for msg in &messages {
                node.network_service
                    .receive_broadcast_raw(topic, msg.clone());
            }
        }
        self.poll().await;
    }

    /// Take message from protocol_id, and broadcast to concrete node.
    pub async fn deliver_unicast(&mut self, protocol_id: &str) {
        // deliver all messages, even if some node send multiple broadcasts messages.
        let mut messages = HashMap::new();
        for node in self.iter_mut() {
            while let Some((msg, peer)) = node.network_service.try_get_unicast_raw(protocol_id) {
                messages
                    .entry(peer)
                    .or_insert(vec![])
                    .push((msg, node.node_service.state().network_pkey));
            }
        }
        debug!("found {} receivers, unicast them.", messages.len());
        for node in self.iter_mut() {
            let empty_slice: &[_] = &[];
            for (msg, peer) in messages
                .get(&node.node_service.state().network_pkey)
                .map(AsRef::as_ref)
                .unwrap_or(empty_slice)
            {
                node.network_service
                    .receive_unicast_raw(*peer, protocol_id, msg.clone());
            }
        }

        self.poll().await;
    }

    /// Take micro block from leader, rebroadcast to other nodes.
    /// Should be used after block timeout.
    /// This function will poll() every node.
    pub async fn skip_micro_block(&mut self) {
        trace!("Skipping microblock...");
        self.assert_synchronized();
        let chain = &self.first().node_service.state().chain;
        assert!(chain.offset() <= chain.cfg().micro_blocks_in_epoch);
        let leader_pk = chain.leader();
        trace!("Acording to partition info, next leader = {}", leader_pk);
        self.find_mut(&leader_pk).unwrap().handle_vdf();
        self.poll().await;
        trace!("Filtering unicast messages...");
        self.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let leader = self.find_mut(&leader_pk).unwrap();
        trace!("Fetching microblock for broadcast...");
        let block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        trace!("Delivering microblock to nodes");
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        trace!("Delivering microblock to the auditor");
        if let Some(auditor) = self.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        //trace!("Successfully skipped microblock, polling again...");
        //self.poll().await;
    }

    /// Emulate rollback of microblock, for wallet tests
    pub async fn rollback_microblock(&mut self) {
        let mut view_changes = Vec::new();
        let state = self.first().node_service.state();
        let chain = &state.chain;
        let epoch = chain.epoch();
        let offset = chain.offset();
        assert!(offset > 0);
        let block = chain.micro_block(epoch, offset - 1).unwrap();
        let chain_info = ChainInfo {
            epoch: block.header.epoch,
            offset: block.header.offset,
            view_change: block.header.view_change,
            last_block: block.header.previous,
        };
        for node in self.iter() {
            // chain: ChainInfo, validator_id: ValidatorId, skey: &pbc::SecretKey
            let validator_id = node.validator_id().unwrap() as u32;
            let msg = ViewChangeMessage::new(chain_info, validator_id, &state.network_skey);
            view_changes.push(msg)
        }
        let signatures = view_changes
            .iter()
            .map(|msg| (msg.validator_id, &msg.signature));
        let proof = ViewChangeProof::new(signatures, chain.validators().len());
        let view_change_proof = SealedViewChangeProof {
            chain: chain_info,
            proof,
        };
        let proof = AddressedViewChangeProof {
            view_change_proof,
            pkey: state.network_pkey,
        };
        let msg = proof.into_buffer().unwrap();
        for node in self.iter_mut() {
            node.network_service
                .receive_broadcast_raw(VIEW_CHANGE_PROOFS_TOPIC, msg.clone());
        }
        if let Some(auditor) = self.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast_raw(VIEW_CHANGE_PROOFS_TOPIC, msg.clone());
        }
        self.poll().await;
    }

    pub async fn skip_macro_block(&mut self) {
        trace!("Skipping macroblock...");
        let state = self.first().node_service.state();
        let chain = &state.chain;
        let stake_epochs = chain.cfg().stake_epochs;
        let epoch = chain.epoch();
        let round = chain.view_change();
        let last_macro_block_hash = chain.last_macro_block_hash();
        let leader_pk = chain.leader();
        self.poll().await;
        let leader_node = self.find_mut(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        trace!("Fetching macroblock proposal for broadcast...");
        let proposal: ConsensusMessage = leader_node
            .network_service
            .get_broadcast(crate::CONSENSUS_TOPIC);
        trace!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        trace!("Delivering macroblock to nodes");
        // Send this proposal to other nodes.
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::CONSENSUS_TOPIC, proposal.clone());
        }

        self.poll().await;

        trace!("Checking for pre-votes...");
        // Check for pre-votes.
        let mut prevotes: Vec<ConsensusMessage> = Vec::with_capacity(self.len());
        for node in self.iter_mut() {
            let prevote: ConsensusMessage =
                node.network_service.get_broadcast(crate::CONSENSUS_TOPIC);
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote);
            prevotes.push(prevote);
        }

        trace!("Delivering pre-votes...");
        // Send these pre-votes to nodes.
        for i in 0..self.len() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    node.network_service
                        .receive_broadcast(crate::CONSENSUS_TOPIC, prevotes[i].clone());
                }
            }
        }

        self.poll().await;

        trace!("Checking for pre-commits...");
        // Check for pre-commits.
        let mut precommits: Vec<ConsensusMessage> = Vec::with_capacity(self.len());
        for node in self.iter_mut() {
            let precommit: ConsensusMessage =
                node.network_service.get_broadcast(crate::CONSENSUS_TOPIC);
            assert_eq!(precommit.epoch, epoch);
            assert_eq!(precommit.round, round);
            assert_eq!(precommit.block_hash, proposal.block_hash);
            if let ConsensusMessageBody::Precommit(block_hash_sig) = precommit.body {
                pbc::check_hash(
                    &proposal.block_hash,
                    &block_hash_sig,
                    &node.node_service.state().network_pkey,
                )
                .unwrap();
            } else {
                panic!("Invalid packet");
            }
            precommits.push(precommit);
        }

        trace!("Delivering pre-committs...");
        // Send these pre-commits to nodes.
        for i in 0..self.len() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    node.network_service
                        .receive_broadcast(crate::CONSENSUS_TOPIC, precommits[i].clone());
                }
            }
        }

        self.poll().await;

        let restake_epoch = ((1 + epoch) % stake_epochs) == 0;
        let mut restakes: Vec<Transaction> = Vec::with_capacity(self.len());
        // Process re-stakes.
        if restake_epoch {
            debug!("Leader {} should re-stake during this epoch: {}", leader_pk, epoch);
            let restake: Transaction = self
                .find_mut(&leader_pk)
                .unwrap()
                .network_service
                .get_broadcast(crate::TX_TOPIC);
            debug!("Got restake: {:?}", restake);
            restakes.push(restake);
        }
        
        trace!("Fetching published macroblock from {}", leader_pk);
        // Receive sealed block.
        let block: Block = self
            .find_mut(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let macro_block = block.clone().unwrap_macro();
        let block_hash = Hash::digest(&macro_block);
        assert_eq!(block_hash, proposal.block_hash);
        assert_eq!(macro_block.header.epoch, epoch);
        assert_eq!(macro_block.header.previous, last_macro_block_hash);

        trace!("Delivering macroblock to nodes...");
        // Send this sealed block to all other nodes expect the leader.
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }

        trace!("Delivering macroblock to the auditor...");
        if let Some(auditor) = self.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }

        // Check state of all nodes.
        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            assert_eq!(chain.epoch(), epoch + 1);
            assert_eq!(chain.offset(), 0);
            assert_eq!(chain.last_macro_block_hash(), block_hash);
            assert_eq!(chain.last_block_hash(), block_hash);
        }

        // Process re-stakes.        
        if restake_epoch {
            self.poll().await;
            trace!("Fetching restakes...");
            for node in self.iter_except(&[leader_pk]) {
                let restake: Transaction = node.network_service.get_broadcast(crate::TX_TOPIC);
                debug!("Got restake: {:?}", restake);
                restakes.push(restake);
            }
            trace!("Delivering restakes to nodes...");
            for node in self.iter_mut() {
                for restake in restakes.iter() {
                    node.network_service
                        .receive_broadcast(crate::TX_TOPIC, restake.clone());
                }
            }
            //self.poll().await;
        }
    }

    pub fn leader(&mut self) -> pbc::PublicKey {
        self.first_mut().node_service.state().chain.leader()
    }

    /// Returns next leader publicKey.
    /// Returns None if some of leader in chain of election was not found in current partition.
    pub fn future_block_leader(&self, idx: u32) -> Option<pbc::PublicKey> {
        let chain = &self.first().node_service.state().chain;
        let mut leader_pk = chain.leader();
        let mut view_change = chain.view_change();
        let mut random = chain.last_random();

        trace!("First leader pk = {}", leader_pk);

        for i in 0..idx {
            let node = self.find(&leader_pk)?;
            let vrf = node.create_vrf_from_seed(random, view_change);
            random = vrf.rand;
            view_change = 0;

            let mut election = chain.election_result().clone();
            election.random = vrf;
            leader_pk = election.select_leader(view_change);
            trace!("Leader {} pk = {}", i + 1, leader_pk);
        }
        Some(leader_pk)
    }

    /// Same as next_leader, but for view_changes.
    pub fn future_view_change_leader(&mut self, idx: u32) -> pbc::PublicKey {
        let chain = &self.first_mut().node_service.state().chain;
        let view_change = chain.view_change();
        chain.select_leader(view_change + idx)
    }

    /// Execute some function for each node_service.
    pub fn for_each<F>(&self, mut function: F)
    where
        F: FnMut(&NodeService),
    {
        for node in self.iter() {
            function(&node.node_service)
        }
    }
}

impl<'a> Index<usize> for Partition<'a> {
    type Output = NodeSandbox;

    fn index(&self, ix: usize) -> &Self::Output {
        &self.nodes[ix]
    }
}

impl<'a> IndexMut<usize> for Partition<'a> {
    fn index_mut(&mut self, ix: usize) -> &mut Self::Output {
        &mut self.nodes[ix]
    }
}

pub struct PartitionGuard<'p> {
    pub parts: (Partition<'p>, Partition<'p>),
}

pub struct NodeSandbox {
    pub network_service: Loopback,
    pub node: Node,
    pub node_service: NodeService,
    pub vdf_execution: VDFExecution,
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
        let (network_service, network, peer_id, replication_rx) = Loopback::new(&network_pkey);

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

    pub fn state(&self) -> &NodeState {
        self.node_service.state()
    }

    pub fn keys(&self) -> (&pbc::PublicKey, &pbc::SecretKey) {
        let state = self.node_service.state();
        (&state.network_pkey, &state.network_skey)
    }

    pub async fn poll(&mut self) {
        self.node_service.poll().await;
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
}
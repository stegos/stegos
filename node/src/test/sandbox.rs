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

use futures::future::Fuse;
use futures::task::Poll;
use futures::{pin_mut, select, FutureExt};

use std::collections::{BinaryHeap, HashSet};
use std::convert::TryInto;
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

use super::{wait, VDFExecution};
use crate::shorthex::*;
use crate::*;

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

use stegos_serialization::traits::ProtoConvert;

#[derive(Clone)]
pub struct SandboxConfig {
    pub node: NodeConfig,
    pub chain: ChainConfig,
    pub num_nodes: usize,
    pub realtime: bool,
    pub log_level: Level,
}

impl Default for SandboxConfig {
    fn default() -> SandboxConfig {
        SandboxConfig {
            node: Default::default(),
            chain: Default::default(),
            num_nodes: 4,
            log_level: Level::Trace,
            realtime: false,
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

        let mut b = pretty_env_logger::formatted_timed_builder();

        if let Ok(s) = ::std::env::var("STEGOS_TEST_LOG") {
            b.parse_filters(&s);
        }

        if let Err(_) = b.is_test(true).try_init() {
            trace!("Logger already initialized!");
        }

        // freeze the time for testing
        if !config.realtime {
            info!("Using test time!");
            tokio::time::pause();
        } else {
            info!("Using real time!");
        }

        let num_nodes = config.num_nodes;
        let ts = Timestamp::now();

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
            ts,
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
        info!("Auditor = {}", auditor_keychain.network_pkey);
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
            auditor: Some(&mut self.auditor),
            config: self.config.clone(),
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
    pub config: SandboxConfig,
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

    pub fn first_except<'a>(&self, pk: &pbc::PublicKey) -> &NodeSandbox
    where
        'p: 'a,
    {
        self.iter()
            .filter(|node| node.node_service.state().network_pkey != *pk)
            .next()
            .expect("First node not found in the sandbox")
    }

    pub fn first_except_mut<'a>(&mut self, pk: &pbc::PublicKey) -> &mut NodeSandbox
    where
        'p: 'a,
    {
        self.iter_mut()
            .filter(|node| node.node_service.state().network_pkey != *pk)
            .next()
            .expect("First node not found in the sandbox")
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

        part1.config = self.config.clone();
        part2.config = self.config.clone();

        use std::ops::DerefMut;
        //TODO: add support of multiple auditors, and allow to choose on which side should be auditors.
        part2.auditor = self.auditor.as_mut().map(|x| x.deref_mut());

        PartitionGuard {
            parts: (part1, part2),
        }
    }

    /// Skip blocks until condition not true
    pub async fn skip_ublocks_until<'a, F>(&'a mut self, mut condition: F)
    where
        'p: 'a,
        F: FnMut(&mut Partition) -> bool,
    {
        trace!("Skipping microblocks until condition is met...");
        let mut ready = false;
        for i in 0..self.config.chain.blocks_in_epoch {
            if condition(self) {
                ready = true;
                trace!("Condition met at iteration {}, stopping!", i + 1);
                break;
            }
            self.skip_ublock().await;
        }
        assert!(ready, "Not enough microblocks to skip");
    }

    /// Inner logic specific for cheater slashing.
    pub async fn slash_cheater_inner<'a>(
        &'a mut self,
        leader_pk: PublicKey,
        mut filter_nodes: Vec<PublicKey>,
    ) -> PartitionGuard<'a>
    where
        'p: 'a,
    {
        self.filter_unicast(&[CHAIN_LOADER_TOPIC]);

        filter_nodes.push(leader_pk);
        let mut r = self.split(&filter_nodes);
        let leader = &mut r.parts.0.find_mut(&leader_pk).unwrap();
        leader.poll().await;
        let (b1, _) = leader.expect_ublock().await.expect("Expected microblock");

        let mut b2 = b1.clone();
        // modify timestamp for block
        match &mut b2 {
            Block::Microblock(ref mut b) => {
                b.header.timestamp += Duration::from_millis(1);
                let block_hash = Hash::digest(&*b);
                b.sig = pbc::sign_hash(&block_hash, &leader.node_service.state().network_skey);
            }
            Block::Macroblock(_) => unreachable!("Expected a macroblock"),
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
        let leader_pk = self.leader();
        let node = self.first_except(&leader_pk);
        let chain = &node.node_service.state().chain;
        let epoch = chain.epoch();
        let awards = chain.epoch_info(epoch - 1).unwrap().unwrap();
        let offset = chain.offset();
        let last_block = chain.last_block_hash();
        trace!(
            "Matching node state to first node {}, consensus leader = {}",
            node.node_service.state().network_pkey,
            leader_pk
        );
        trace!(
            "Expecting epoch = {}, offset = {}, last block = {}",
            epoch,
            offset,
            last_block
        );
        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            let pkey = node.node_service.state().network_pkey;
            trace!(
                "[{}] epoch = {}, offset = {}, last block = {}, leader = {}",
                pkey,
                chain.epoch(),
                chain.offset(),
                chain.last_block_hash(),
                chain.leader()
            );
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

    /// Poll each node for updates.
    pub async fn poll(&mut self) {
        trace!(">>> Sandbox polling...");
        for node in self.nodes.iter_mut() {
            node.poll().await;
        }

        if let Some(auditor) = &mut self.auditor {
            auditor.poll().await;
        }
    }

    /// Advance consensus
    pub fn advance(&mut self) {
        trace!(">>> Sandbox advancing consensus...");
        for node in self.nodes.iter_mut() {
            node.advance();
        }

        if let Some(auditor) = &mut self.auditor {
            auditor.advance();
        }
    }

    pub async fn step(&mut self) {
        self.poll().await;
        self.advance();
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

    #[inline]
    pub fn chain(&self) -> &Blockchain {
        &self.first().node_service.state().chain
    }

    pub async fn deliver_restakes(&mut self, txs: Vec<Transaction>) {
        for node in self.iter_mut() {
            let pk = &node.node_service.state().network_pkey;
            trace!("Delivering restakes to {}", pk);
            for tx in txs.iter() {
                node.process(crate::TX_TOPIC, tx.clone()).await;
            }
        }

        if let Some(auditor) = self.auditor_mut() {
            let pk = &auditor.node_service.state().network_pkey;
            trace!("Delivering restakes to auditor {}", pk);
            for tx in txs.iter() {
                auditor.process(crate::TX_TOPIC, tx.clone()).await;
            }
        }
    }

    /// Take micro block from leader, rebroadcast to other nodes.
    /// Should be used after block timeout.
    /// This function will poll() every node.
    pub async fn skip_ublock(&mut self) {
        trace!("Skipping microblock...");
        self.assert_synchronized();
        let chain = self.chain();
        assert!(chain.offset() <= chain.cfg().blocks_in_epoch);
        let leader_pk = self.leader();
        trace!("According to partition info, next leader = {}", leader_pk);
        self.filter_unicast(&[crate::CHAIN_LOADER_TOPIC]);

        self.poll().await;

        let leader = self.find_mut(&leader_pk).unwrap();
        let (block, restake) = leader.expect_ublock().await.expect("Expected microblock");

        // Process re-stakes.
        let mut restakes: Vec<Transaction> = Vec::new();
        if let Some(tx) = restake {
            restakes.push(tx)
        }

        for node in self.iter_except(&[leader_pk]) {
            let pk = node.node_service.state().network_pkey;
            trace!("Delivering microblock to {}", pk);
            node.process(crate::SEALED_BLOCK_TOPIC, block.clone()).await;
            if let Some(tx) = node.fetch_restake() {
                restakes.push(tx)
            }
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor
                .process(crate::SEALED_BLOCK_TOPIC, block.clone())
                .await;
        }

        self.deliver_restakes(restakes).await;

        self.advance();
        trace!("Processed microblock...");
    }

    /// Emulate rollback of Microblock, for wallet tests
    pub async fn rollback_ublock(&mut self) {
        let mut view_changes = Vec::new();
        let state = self.first().node_service.state();
        let chain = &state.chain;
        let epoch = chain.epoch();
        let offset = chain.offset();
        assert!(offset > 0);
        let block = chain.ublock(epoch, offset - 1).unwrap();
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
        let proof = ViewChangeProof::new(signatures, chain.validators().0.len());
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

    pub async fn process_except<M: ProtoConvert + Clone>(
        &mut self,
        pk: &pbc::PublicKey,
        topic: &str,
        msg: M,
    ) {
        for node in self.iter_except(&[*pk]) {
            node.process(topic, msg.clone()).await;
        }
    }

    pub async fn create_mblock(&mut self) -> (Block, Hash, Option<Transaction>) {
        trace!("Creating a macroblock...");
        let chain = self.chain();
        let epoch = chain.epoch();
        let round = chain.view_change();
        let last_mblock_hash = chain.last_mblock_hash();
        let leader_pk = self.leader();

        self.step().await;
        self.poll().await;

        let leader = self.find_mut(&leader_pk).unwrap();

        // Check for a proposal from the leader.
        trace!("Fetching macroblock proposal from {}", leader_pk);
        let proposal: ConsensusMessage =
            leader.network_service.get_broadcast(crate::CONSENSUS_TOPIC);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        self.process_except(&leader_pk, crate::CONSENSUS_TOPIC, proposal.clone())
            .await;

        // Check for pre-votes.
        let mut prevotes: Vec<ConsensusMessage> = Vec::with_capacity(self.len());
        for node in self.iter_mut() {
            trace!(
                "Fetching pre-vote from {}...",
                node.node_service.state().network_pkey
            );
            let prevote: ConsensusMessage =
                node.network_service.get_broadcast(crate::CONSENSUS_TOPIC);
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote);
            prevotes.push(prevote);
        }

        // Send these pre-votes to nodes.
        for i in 0..self.len() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    let pkey = &node.node_service.state().network_pkey;
                    trace!("Delivering pre-vote to {}", pkey);
                    node.process(crate::CONSENSUS_TOPIC, prevotes[i].clone())
                        .await;
                }
            }
        }

        // Check for pre-commits
        let mut precommits: Vec<ConsensusMessage> = Vec::with_capacity(self.len());
        for node in self.iter_mut() {
            trace!(
                "Fetching pre-commit from {}...",
                node.node_service.state().network_pkey
            );
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

        // Send these pre-commits to nodes.
        for i in 0..self.len() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    let pkey = &node.node_service.state().network_pkey;
                    trace!("Delivering pre-commit to {}", pkey);
                    node.process(crate::CONSENSUS_TOPIC, precommits[i].clone())
                        .await;
                }
            }
        }

        // Fetch restake tx
        let node = self.find_mut(&leader_pk).unwrap();
        let restake = node.fetch_restake();

        // Fetch completed block
        trace!("Fetching finished macroblock from {}", leader_pk);
        let leader = self.find_mut(&leader_pk).unwrap();
        let block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let mb = block.clone().unwrap_macro();
        let block_hash = Hash::digest(&mb);
        assert_eq!(block_hash, proposal.block_hash);
        assert_eq!(mb.header.epoch, epoch);
        assert_eq!(mb.header.previous, last_mblock_hash);
        (block, block_hash, restake)
    }

    pub async fn skip_mblock(&mut self) {
        trace!("Skipping macroblock...");
        let chain = self.chain();
        let epoch = chain.epoch();

        let (block, block_hash, leader_restake) = self.create_mblock().await;
        let leader_pk = self.leader();

        // Process re-stakes.
        let mut restakes: Vec<Transaction> = Vec::with_capacity(self.len());

        if let Some(tx) = leader_restake {
            restakes.push(tx)
        }

        // Send this sealed block to all other nodes except the leader.
        self.process_except(&leader_pk, crate::SEALED_BLOCK_TOPIC, block.clone())
            .await;

        if let Some(auditor) = self.auditor_mut() {
            auditor
                .process(crate::SEALED_BLOCK_TOPIC, block.clone())
                .await;
        }

        // Check state of all nodes.
        let old_leader_pk = leader_pk;
        let leader_pk = self.leader();

        trace!(
            "Checking node state after macroblock (leader = {})...",
            leader_pk
        );
        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            let pkey = &node.node_service.state().network_pkey;
            trace!("[{}] epoch = {}, offset = {}, last macro hash = {}, last block hash = {}, leader = {}", 
             pkey, chain.epoch(), chain.offset(), chain.last_mblock_hash(), chain.last_block_hash(), chain.leader(),
            );
            assert_eq!(chain.epoch(), epoch + 1);
            assert_eq!(chain.offset(), 0);
            assert_eq!(chain.last_mblock_hash(), block_hash);
            assert_eq!(chain.last_block_hash(), block_hash);
        }

        // Process re-stakes.
        trace!("Process restakes from non-leader nodes...");
        for node in self.iter_except(&[old_leader_pk]) {
            if let Some(tx) = node.fetch_restake() {
                restakes.push(tx);
            }
        }

        self.deliver_restakes(restakes).await;

        self.step().await;

        trace!(
            "Processed macroblock (leader: {} -> {})...",
            old_leader_pk,
            leader_pk
        );
    }

    pub fn leader(&self) -> pbc::PublicKey {
        let mut hm = HashMap::new();
        let mut bh = BinaryHeap::new();

        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            let leader_pk = chain.leader();
            let n = hm.entry(leader_pk).or_insert(0);
            *n += 1;
        }

        for v in hm {
            bh.push((v.1, v.0))
        }

        let (_, leader_pk) = bh.pop().unwrap();
        leader_pk
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
            let pkey = self.node_service.state().network_pkey;
            trace!("[{}] Droping node...", pkey);
            self.network_service.assert_empty_queue(&pkey);
        }
    }
}

impl NodeSandbox {
    pub fn new(
        node_cfg: NodeConfig,
        chain_cfg: ChainConfig,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        genesis: Macroblock,
    ) -> Self {
        // init network
        let (network_service, network, peer_id, replication_rx) = Loopback::new(&network_pkey);

        // Create node, with first node keychain.
        let ts = Timestamp::now();
        let chain_dir = TempDir::new("test").unwrap();
        let chain = Blockchain::new(
            chain_cfg,
            chain_dir.path(),
            ConsistencyCheck::Full,
            genesis,
            ts,
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

    pub fn pkey(&self) -> &pbc::PublicKey {
        &self.node_service.state().network_pkey
    }

    pub fn keys(&self) -> (&pbc::PublicKey, &pbc::SecretKey) {
        let state = self.node_service.state();
        (&state.network_pkey, &state.network_skey)
    }

    pub async fn poll(&mut self) {
        loop {
            let future = self.node_service.poll();
            pin_mut!(future);
            let result = futures::poll!(future);
            if result == Poll::Pending {
                break;
            }
        }
    }

    pub fn advance(&mut self) {
        assert_matches!(self.update_validation_status(), Ok(()));
    }

    pub async fn step(&mut self) {
        self.poll().await;
        self.advance();
    }

    pub async fn expect_ublock(&mut self) -> Option<(Block, Option<Transaction>)> {
        // Trigger the microblock proposal timer.
        self.poll().await;
        // Make sure we get to process it
        wait(Duration::from_secs(0)).await;
        self.poll().await;

        let restake = self.fetch_restake();
        let target = Instant::now() + Duration::from_secs(5);

        trace!("Fetching microblock from {}", self.pkey());

        loop {
            if let Some(msg) = self
                .network_service
                .try_get_broadcast_raw(SEALED_BLOCK_TOPIC)
            {
                let block = Block::from_buffer(&msg).unwrap();
                return Some((block, restake));
            }
            if Instant::now() > target {
                break;
            }
            //wait(Duration::from_secs(0)).await;
            tokio::task::yield_now().await;
            self.poll().await;
        }

        return None;
    }

    pub fn update_validation_status(&mut self) -> Result<(), Error> {
        self.node_service.state_mut().update_validation_status()
    }

    pub async fn process<M: ProtoConvert>(&mut self, topic: &str, msg: M) {
        self.network_service.receive_broadcast(topic, msg);
        //tokio::task::yield_now().await;
        self.poll().await;
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
            .0
            .iter()
            .enumerate()
            .find(|(_id, keys)| key == keys.0)
            .map(|(id, _)| id)
    }

    pub fn handle_vdf(&mut self) {
        self.vdf_execution.try_produce();
        self.vdf_execution = VDFExecution::WaitForVDF;
    }

    pub fn fetch_restake(&mut self) -> Option<Transaction> {
        let pk = self.pkey();
        let chain = self.chain();
        let epoch = chain.epoch();
        let stake_epochs = chain.cfg().stake_epochs;
        let is_restake_epoch = (epoch % stake_epochs) == 0;
        let offset = chain.offset();
        let restaking_offset = self.state().restaking_offset();
        let should_restake = restaking_offset == offset;
        trace!("[{}] Checking re-stake... epoch: {}, restake epoch? = {}, restaking offset = {}, should restake? = {}", 
            pk, epoch, is_restake_epoch, restaking_offset, should_restake);
        if is_restake_epoch && should_restake {
            let tx = self.network_service.get_broadcast(crate::TX_TOPIC);
            Some(tx)
        } else {
            None
        }
    }
}

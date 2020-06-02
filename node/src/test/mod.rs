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

// most of the code is used in tests, so it can false positive detected as unused during build.
#![allow(dead_code)]

mod logger;
mod sandbox;

/*
mod consensus;
mod integration;
mod microblocks;
*/

use crate::*;
use crate::CHAIN_LOADER_TOPIC;
use assert_matches::assert_matches;
use log::*;
pub use sandbox::*;
use std::time::Duration;
pub use stegos_blockchain::test::*;
pub use stegos_network::loopback::Loopback;
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_consensus::optimistic::AddressedViewChangeProof;
use stegos_consensus::ConsensusMessageBody;
use stegos_crypto::pbc;
use stegos_crypto::pbc::PublicKey;

#[derive(Debug)]
pub enum VDFExecution {
    PendingVDF {
        data: Vec<u8>,
        tx: oneshot::Sender<Vec<u8>>,
    },
    Nothing,
    WaitForVDF,
}

impl VDFExecution {
    pub(crate) fn add_vdf(&mut self, rx: &mut oneshot::Receiver<Vec<u8>>) {
        // release old vdf.
        self.try_produce();

        let (tx, mut rx_new) = oneshot::channel::<Vec<u8>>();
        std::mem::swap(rx, &mut rx_new);
        let data = futures::executor::block_on(async { rx_new.await.unwrap() });
        match self {
            // if we wait for micro block, and we are leader for micro block,
            // then synchronously wait until vdf computes.
            VDFExecution::WaitForVDF => tx.send(data).unwrap(),
            // if we not waiting for microblock, save vdf for future computation.
            VDFExecution::Nothing => {
                *self = VDFExecution::PendingVDF { tx, data };
            }
            e => panic!("VDF execution in wrong state = {:?}", e),
        }
        self.try_unset();
    }

    fn try_produce(&mut self) {
        match std::mem::replace(self, VDFExecution::Nothing) {
            VDFExecution::PendingVDF { data, tx } => drop(tx.send(data)), // drop error because tx channel could be outdated.
            e => *self = e,
        }
    }

    fn try_unset(&mut self) {
        match self {
            VDFExecution::WaitForVDF => {
                *self = VDFExecution::Nothing;
            }
            _ => (),
        }
    }
}

pub trait Api<'p> {
    fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut NodeSandbox> + 'a>
    where
        'p: 'a;

    fn auditor_mut<'a>(&'a mut self) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a;

    fn auditor<'a>(&'a self) -> Option<&'a NodeSandbox>
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
            .expect("First node not found in the sandbox")
    }

    fn first_mut<'a>(&'a mut self) -> &'a mut NodeSandbox
    where
        'p: 'a,
    {
        self.iter_mut()
            .next()
            .expect("First node not found in the sandbox.")
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
                .find(|key| **key == node.node_service.state().network_pkey)
                .is_none()
        }))
    }

    /// Checks if all sandbox nodes synchronized.
    fn assert_synchronized(&self) {
        let node = self.first();
        let chain = &node.node_service.state().chain;
        let epoch = chain.epoch();
        let awards = chain
            .epoch_info(epoch - 1)
            .unwrap()
            .unwrap();
        let offset = chain.offset();
        let last_block = chain.last_block_hash();
        for node in self.iter() {
            let chain = &node.node_service.state().chain;
            trace!("Checking node = {:?}", node.validator_id());

            assert_eq!(chain.epoch(), epoch);
            assert_eq!(
                chain
                    .epoch_info(epoch - 1)
                    .unwrap()
                    .unwrap(),
                awards
            );
            assert_eq!(chain.offset(), offset);
            assert_eq!(chain.last_block_hash(), last_block);
        }

        if let Some(auditor) = self.auditor() {
            let chain = &auditor.node_service.state().chain; 
            assert_eq!(chain.epoch(), epoch);
            assert_eq!(
                chain
                    .epoch_info(epoch - 1)
                    .unwrap()
                    .unwrap(),
                awards
            );
            assert_eq!(chain.offset(), offset);
            assert_eq!(chain.last_block_hash(), last_block);
        }
    }

    /// Filter messages from specific protocol_ids.
    fn filter_unicast(&mut self, protocol_ids: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_unicast(protocol_ids)
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor.network_service.filter_unicast(protocol_ids)
        }
    }

    /// Filter messages from specific topics.
    fn filter_broadcast(&mut self, topics: &[&str]) {
        for node in &mut self.iter_mut() {
            node.network_service.filter_broadcast(topics)
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor.network_service.filter_broadcast(topics)
        }
    }

    /// poll each node for updates.
    fn poll(&mut self) {
        futures::executor::block_on(async {
            for node in self.iter_mut() {
                info!(
                    "============ POLLING node={:?} ============",
                    node.validator_id()
                );
                node.node_service.step().await;
            }
            info!("============ POLLING auditor ============");
            if let Some(auditor) = self.auditor_mut() {
                auditor.node_service.step().await;
            }
        })
    }

    fn num_nodes(&self) -> usize {
        self.iter().count()
    }

    //TODO: This temporary solution is used to emulate broadcast in network. For example
    // when you need to send transaction over network, it should be broadcasted.
    /// Take messages from topic, and broadcast to other nodes.
    fn broadcast(&mut self, topic: &str) {
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
        self.poll();
    }
    /// Take message from protocol_id, and broadcast to concrete node.
    fn deliver_unicast(&mut self, protocol_id: &str) {
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

        self.poll();
    }
    /// Take micro block from leader, rebroadcast to other nodes.
    /// Should be used after block timeout.
    /// This function will poll() every node.
    fn skip_micro_block(&mut self) {
        self.assert_synchronized();
        let chain = &self.first().node_service.state().chain;
        assert!(chain.offset() <= chain.cfg().micro_blocks_in_epoch);
        let leader_pk = chain.leader();
        trace!("Acording to partition info, next leader = {}", leader_pk);
        self.node_mut(&leader_pk).unwrap().handle_vdf();
        self.poll();
        self.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        let leader = self.node_mut(&leader_pk).unwrap();
        let block: Block = leader
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        if let Some(auditor) = self.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        self.poll();
    }
    /// Emulate rollback of microblock, for wallet tests
    fn rollback_microblock(&mut self) {
        let mut view_changes = Vec::new();
        let state = self.first().node_service.state();
        let chain = &state.chain;
        let epoch = chain.epoch();
        let offset = chain.offset();
        assert!(offset > 0);
        let block = chain
            .micro_block(epoch, offset - 1)
            .unwrap();
        let chain_info = ChainInfo {
            epoch: block.header.epoch,
            offset: block.header.offset,
            view_change: block.header.view_change,
            last_block: block.header.previous,
        };
        for node in self.iter() {
            // chain: ChainInfo, validator_id: ValidatorId, skey: &pbc::SecretKey
            let validator_id = node.validator_id().unwrap() as u32;
            let msg =
                ViewChangeMessage::new(chain_info, validator_id, &state.network_skey);
            view_changes.push(msg)
        }
        let signatures = view_changes
            .iter()
            .map(|msg| (msg.validator_id, &msg.signature));
        let proof = ViewChangeProof::new(
            signatures,
            chain.validators().len(),
        );
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
        self.poll()
    }

    fn skip_macro_block(&mut self) {
        let state = self.first().node_service.state();
        let chain = &state.chain;
        let stake_epochs = chain.cfg().stake_epochs;
        let epoch = chain.epoch();
        let round = chain.view_change();
        let last_macro_block_hash = chain.last_macro_block_hash();
        let leader_pk = chain.leader();
        let leader_node = self.node_mut(&leader_pk).unwrap();
        // Check for a proposal from the leader.
        let proposal: ConsensusMessage = leader_node
            .network_service
            .get_broadcast(crate::CONSENSUS_TOPIC);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.epoch, epoch);
        assert_eq!(proposal.round, round);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::CONSENSUS_TOPIC, proposal.clone());
        }
        self.poll();

        // Check for pre-votes.
        let mut prevotes: Vec<ConsensusMessage> = Vec::with_capacity(self.num_nodes());
        for node in self.iter_mut() {
            let prevote: ConsensusMessage =
                node.network_service.get_broadcast(crate::CONSENSUS_TOPIC);
            assert_eq!(prevote.epoch, epoch);
            assert_eq!(prevote.round, round);
            assert_eq!(prevote.block_hash, proposal.block_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote);
            prevotes.push(prevote);
        }

        // Send these pre-votes to nodes.
        for i in 0..self.num_nodes() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    node.network_service
                        .receive_broadcast(crate::CONSENSUS_TOPIC, prevotes[i].clone());
                }
            }
        }
        self.poll();

        // Check for pre-commits.
        let mut precommits: Vec<ConsensusMessage> = Vec::with_capacity(self.num_nodes());
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

        // Send these pre-commits to nodes.
        for i in 0..self.num_nodes() {
            for (j, node) in self.iter_mut().enumerate() {
                if i != j {
                    node.network_service
                        .receive_broadcast(crate::CONSENSUS_TOPIC, precommits[i].clone());
                }
            }
        }
        self.poll();

        let restake_epoch = ((1 + epoch) % stake_epochs) == 0;
        let mut restakes: Vec<Transaction> = Vec::with_capacity(self.num_nodes());
        // Process re-stakes.
        if restake_epoch {
            debug!("Re-stake should happen in this epoch: {}", epoch);
            let restake: Transaction = self
                .node_mut(&leader_pk)
                .unwrap()
                .network_service
                .get_broadcast(crate::TX_TOPIC);
            debug!("Got restake: {:?}", restake);
            restakes.push(restake);
        }

        // Receive sealed block.
        let block: Block = self
            .node_mut(&leader_pk)
            .unwrap()
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let macro_block = block.clone().unwrap_macro();
        let block_hash = Hash::digest(&macro_block);
        assert_eq!(block_hash, proposal.block_hash);
        assert_eq!(macro_block.header.epoch, epoch);
        assert_eq!(macro_block.header.previous, last_macro_block_hash);

        // Send this sealed block to all other nodes expect the leader.
        for node in self.iter_except(&[leader_pk]) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }

        if let Some(auditor) = self.auditor_mut() {
            auditor
                .network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }

        self.poll();

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
            for node in self.iter_except(&[leader_pk]) {
                let restake: Transaction = node.network_service.get_broadcast(crate::TX_TOPIC);
                debug!("Got restake: {:?}", restake);
                restakes.push(restake);
            }
            for node in self.iter_mut() {
                for restake in restakes.iter() {
                    node.network_service
                        .receive_broadcast(crate::TX_TOPIC, restake.clone());
                }
            }
            self.poll();
        }
    }

    fn leader(&mut self) -> pbc::PublicKey {
        self.first_mut().node_service.state().chain.leader()
    }

    /// Returns next leader publicKey.
    /// Returns None if some of leader in chain of election was not found in current partition.
    fn future_block_leader(&self, idx: u32) -> Option<pbc::PublicKey> {
        let chain = &self.first().node_service.state().chain;
        let mut leader_pk = chain.leader();
        let mut view_change = chain.view_change();
        let mut random = chain.last_random();

        trace!("First leader pk = {}", leader_pk);

        for i in 0..idx {
            let node = self.node_ref(&leader_pk)?;
            let vrf = node.create_vrf_from_seed(random, view_change);
            random = vrf.rand;
            view_change = 0;

            let mut election = chain
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
        let chain = &self.first_mut().node_service.state().chain;
        let view_change = chain.view_change();
        chain.select_leader(view_change + idx)
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
    fn node_mut<'a>(&'a mut self, pk: &pbc::PublicKey) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        self.iter_mut()
            .find(|node| node.node_service.state().network_pkey == *pk)
    }

    /// Return node for publickey.
    fn node_ref<'a>(&'a self, pk: &pbc::PublicKey) -> Option<&'a NodeSandbox>
    where
        'p: 'a,
    {
        self.iter()
            .find(|node| node.node_service.state().network_pkey == *pk)
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

    fn auditor_mut<'a>(&'a mut self) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        // reborrow auditor
        if let Some(&mut ref mut s) = self.auditor {
            Some(s)
        } else {
            None
        }
    }

    fn auditor<'a>(&'a self) -> Option<&'a NodeSandbox>
    where
        'p: 'a,
    {
        // reborrow auditor
        if let Some(&mut ref s) = self.auditor {
            Some(s)
        } else {
            None
        }
    }
}

impl<'p> Api<'p> for Sandbox {
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
    fn auditor_mut<'a>(&'a mut self) -> Option<&'a mut NodeSandbox>
    where
        'p: 'a,
    {
        Some(&mut self.auditor)
    }
    fn auditor<'a>(&'a self) -> Option<&'a NodeSandbox>
    where
        'p: 'a,
    {
        Some(&self.auditor)
    }
}

/// Inner logic specific for cheater slashing.
pub async fn slash_cheater_inner<'a>(
    s: &'a mut Sandbox,
    leader_pk: PublicKey,
    mut filter_nodes: Vec<PublicKey>,
) -> PartitionGuard<'a> {
    s.filter_unicast(&[CHAIN_LOADER_TOPIC]);

    filter_nodes.push(leader_pk);
    let mut r = s.split(&filter_nodes);
    let leader = &mut r.parts.0.node_mut(&leader_pk).unwrap();
    leader.handle_vdf();
    leader.node_service.step().await;
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

    r.parts.1.poll();
    r
}

pub fn precondition_n_different_block_leaders(s: &mut Sandbox, different_leaders: u32) {
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

pub fn precondition_n_different_viewchange_leaders(s: &mut Sandbox, different_leaders: u32) {
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
pub fn skip_blocks_until<F>(s: &mut Sandbox, mut condition: F)
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
#[cfg(test)]
mod test_framework {
    use super::*;
    #[test]
    fn test_partition() {
        let config: SandboxConfig = Default::default();

        Sandbox::start(config, |mut s| {
            s.poll();
            let leader_pk = s.nodes[0].node_service.state().chain.leader();
            let r = s.split(&[leader_pk]);
            assert_eq!(r.parts.0.nodes.len(), 1);
            assert_eq!(r.parts.1.nodes.len(), 3);
            s.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        });
    }
}

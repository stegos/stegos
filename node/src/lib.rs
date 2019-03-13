//! Blockchain Node.

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

mod election;
mod error;
mod loader;
mod mempool;
pub mod protos;

mod metrics;
#[cfg(test)]
mod test;
mod tickets;
mod validation;

use crate::mempool::Mempool;
use bitvector::BitVector;

use crate::election::ElectionResult;
use crate::error::*;
use crate::loader::{ChainLoader, ChainLoaderMessage};
pub use crate::tickets::{TicketsSystem, VRFTicket};
use crate::validation::*;
use chrono::Utc;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_consensus::{
    self as consensus, BlockConsensus, BlockConsensusMessage, BlockProof, MonetaryBlockProof,
};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::{self, VRF};
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_network::UnicastMessage;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::clock;
use tokio_timer::Interval;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Blockchain Node.
#[derive(Clone, Debug)]
pub struct Node {
    outbox: UnboundedSender<NodeMessage>,
    network: Network,
}

impl Node {
    /// Create a new blockchain node.
    pub fn new(
        cfg: &StorageConfig,
        keys: KeyChain,
        network: Network,
    ) -> Result<(NodeService, Node), Error> {
        let (outbox, inbox) = unbounded();

        let service = NodeService::new(cfg, keys, network.clone(), inbox)?;
        let handler = Node { outbox, network };

        Ok((service, handler))
    }

    /// Initialize blockchain.
    pub fn init(&self, genesis: Vec<Block>) -> Result<(), Error> {
        let msg = NodeMessage::Init { genesis };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Network initialized.
    pub fn network_ready(&self) -> Result<(), Error> {
        let msg = NodeMessage::NetworkReady;
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Send transaction to node and to the network.
    pub fn send_transaction(&self, tx: Transaction) -> Result<(), Error> {
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        self.network.publish(&TX_TOPIC, data.clone())?;
        info!(
            "Sent transaction to the network: hash={}",
            Hash::digest(&tx)
        );
        let msg = NodeMessage::Transaction(data);
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Ask current state of the election.
    pub fn election_info(&self) -> Result<(), Error> {
        let msg = NodeMessage::ElectionInfo;
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Ask current state of the election.
    pub fn escrow_info(&self) -> Result<(), Error> {
        let msg = NodeMessage::EscrowInfo;
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Subscribe to epoch changes.
    pub fn subscribe_epoch(&self) -> Result<UnboundedReceiver<EpochNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeEpoch(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Subscribe to information from node.
    pub fn subscribe_info(&self) -> Result<UnboundedReceiver<InfoNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeInfo(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Subscribe to outputs.
    pub fn subscribe_outputs(&self) -> Result<UnboundedReceiver<OutputsNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeOutputs(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }
}

/// Info from node.
#[derive(Clone, Debug)]
pub enum InfoNotification {
    Election(tickets::ElectionInfo),
    Escrow(EscrowInfo),
}

/// Send when epoch is changed.
#[derive(Clone, Debug)]
pub struct EpochNotification {
    pub epoch: u64,
    pub leader: secure::PublicKey,
    pub facilitator: secure::PublicKey,
    pub validators: BTreeMap<secure::PublicKey, i64>,
}

/// Send when outputs created and/or pruned.
#[derive(Debug, Clone)]
pub struct OutputsNotification {
    pub inputs: Vec<Output>,
    pub outputs: Vec<Output>,
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// Blockchain version.
const VERSION: u64 = 1;
/// Topic used for sending transactions.
const TX_TOPIC: &'static str = "tx";
/// Topic used for consensus.
const CONSENSUS_TOPIC: &'static str = "consensus";
/// Topic used for sending sealed blocks.
const SEALED_BLOCK_TOPIC: &'static str = "block";
/// Time delta in which our messages should be delivered, or forgeted.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
/// Estimated time of block validation.
// tx_count * verify_tx = 1500 * 20ms
const BLOCK_VALIDATION_TIME: Duration = Duration::from_secs(30);
/// How long wait for transactions before starting to create a new block.
const TX_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
/// How often to check the consensus state.
const CONSENSUS_TIMER: Duration = Duration::from_secs(30);
/// How long we should wait for network stabilization.
pub const NETWORK_GRACE_TIMEOUT: Duration = Duration::from_secs(10);
/// Max count of sealed block in epoch.
const SEALED_BLOCK_IN_EPOCH: u64 = 5;
/// Max difference in timestamps of leader and validators.
const TIME_TO_RECEIVE_BLOCK: u64 = 10 * 60;
/// Fixed reward per block.
const BLOCK_REWARD: i64 = 60;
/// Fixed fee for payment transactions.
pub const PAYMENT_FEE: i64 = 1;
/// Fixed fee for the stake transactions.
pub const STAKE_FEE: i64 = 1;

#[derive(Clone, Debug)]
enum NodeMessage {
    //
    // Public API
    //
    SubscribeEpoch(UnboundedSender<EpochNotification>),
    SubscribeOutputs(UnboundedSender<OutputsNotification>),
    SubscribeInfo(UnboundedSender<InfoNotification>),
    ElectionInfo,
    EscrowInfo,
    //
    // Network Events
    //
    Transaction(Vec<u8>),
    Consensus(Vec<u8>),
    SealedBlock(Vec<u8>),
    VRFMessage(Vec<u8>),
    ChainLoaderMessage(UnicastMessage),
    //
    // Internal Events
    //
    Init { genesis: Vec<Block> },
    NetworkReady,
    ConsensusTimer(Instant),
    VRFTimer(Instant),
}

pub struct NodeService {
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,

    /// A system that restart consensus in case of fault or partition.
    /// And allow to change validators in case of epoch change.
    vrf_system: TicketsSystem,

    chain_loader: ChainLoader,

    /// A queue of consensus message from the future epoch.
    // TODO: Resolve unknown blocks using requests-responses.
    future_consensus_messages: Vec<BlockConsensusMessage>,

    //
    // Consensus
    //
    /// Memory pool of pending transactions.
    mempool: Mempool,

    /// Proof-of-stake consensus.
    consensus: Option<BlockConsensus>,

    //
    // Communication with environment.
    //
    /// Network interface.
    network: Network,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochNotification>>,
    /// Triggered when outputs created and/or pruned.
    on_outputs_changed: Vec<UnboundedSender<OutputsNotification>>,
    /// Triggered on repl ask feedback.
    on_info: Vec<UnboundedSender<InfoNotification>>,
    /// Aggregated stream of events.
    events: Box<Stream<Item = NodeMessage, Error = ()> + Send>,
}

impl NodeService {
    /// Constructor.
    fn new(
        cfg: &StorageConfig,
        keys: KeyChain,
        network: Network,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let chain = Blockchain::new(&cfg);
        Self::with_blockchain(chain, keys, network, inbox)
    }

    #[cfg(test)]
    fn testing(
        keys: KeyChain,
        network: Network,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let chain = Blockchain::testing();
        Self::with_blockchain(chain, keys, network, inbox)
    }

    fn with_blockchain(
        chain: Blockchain,
        keys: KeyChain,
        network: Network,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let future_consensus_messages = Vec::new();
        let vrf_system = TicketsSystem::new(
            VALIDATORS_MAX,
            0,
            0,
            keys.network_pkey,
            keys.network_skey.clone(),
        );
        let chain_loader = ChainLoader::new();
        let mempool = Mempool::new();

        let consensus = None;

        let on_epoch_changed = Vec::<UnboundedSender<EpochNotification>>::new();
        let on_outputs_received = Vec::<UnboundedSender<OutputsNotification>>::new();

        let mut streams = Vec::<Box<Stream<Item = NodeMessage, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Transaction Requests
        let transaction_rx = network
            .subscribe(&TX_TOPIC)?
            .map(|m| NodeMessage::Transaction(m));
        streams.push(Box::new(transaction_rx));

        // Consensus Requests
        let consensus_rx = network
            .subscribe(&CONSENSUS_TOPIC)?
            .map(|m| NodeMessage::Consensus(m));
        streams.push(Box::new(consensus_rx));

        // VRF Requests
        let ticket_system_rx = network
            .subscribe(&tickets::VRF_TICKETS_TOPIC)?
            .map(|m| NodeMessage::VRFMessage(m));
        streams.push(Box::new(ticket_system_rx));

        // Sealed blocks broadcast topic.
        let block_rx = network
            .subscribe(&SEALED_BLOCK_TOPIC)?
            .map(|m| NodeMessage::SealedBlock(m));
        streams.push(Box::new(block_rx));

        // Chain loader messages.
        let requests_rx = network
            .subscribe_unicast(loader::CHAIN_LOADER_TOPIC)?
            .map(NodeMessage::ChainLoaderMessage);
        streams.push(Box::new(requests_rx));

        // Consensus timer events
        let duration = CONSENSUS_TIMER; // every second
        let timer = Interval::new_interval(duration)
            .map(|i| NodeMessage::ConsensusTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        // VRF timer events
        let duration = tickets::TIMER; // every second
        let timer = Interval::new_interval(duration)
            .map(|i| NodeMessage::VRFTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        let events = select_all(streams);

        let service = NodeService {
            chain_loader,
            future_consensus_messages,
            vrf_system,
            chain,
            keys,
            mempool,
            consensus,
            network,
            on_epoch_changed,
            on_outputs_changed: on_outputs_received,
            on_info: Vec::new(),
            events,
        };

        Ok(service)
    }

    /// Handler for NodeMessage::Init.
    fn handle_init(&mut self, genesis: Vec<Block>) -> Result<(), Error> {
        // skip handling genesis if blockchain is not empty
        if self.chain.height() > 0 {
            //rather recover state
            self.recover_state();
            for ((height, genesis), chain) in genesis.iter().enumerate().zip(self.chain.blocks()) {
                let genesis_hash = Hash::digest(genesis);
                let chain_hash = Hash::digest(&chain);
                if genesis_hash != chain_hash {
                    error!(
                        "Found a saved chain that is not compatible to our genesis at height = {}, \
                         genesis_block = {:?}, database_block = {:?}",
                        height + 1, genesis_hash, chain_hash
                    );
                    std::process::exit(1);
                }
            }

            let last_hash = self.chain.last_block_hash();
            info!(
                "Node successfully recovered from persistent storage: height={}, hash={}",
                self.chain.height(),
                last_hash
            );
            return Ok(());
        }
        debug!("Registering genesis blocks...");
        //
        // Sic: genesis block has invalid monetary balance, so handle_monetary_block()
        // can't be used here.
        //

        let current_timestamp = Utc::now().timestamp() as u64;
        for block in genesis {
            match block {
                Block::KeyBlock(key_block) => {
                    debug!(
                        "Genesis key block: height={}, hash={:?}",
                        self.chain.height() + 1,
                        Hash::digest(&key_block)
                    );
                    let key_block2 = key_block.clone();
                    self.chain.push_key_block(key_block)?;
                    self.on_key_block_registered(&key_block2)?;
                }
                Block::MonetaryBlock(monetary_block) => {
                    debug!(
                        "Genesis payment block: height={}, hash={:?}",
                        self.chain.height() + 1,
                        Hash::digest(&monetary_block)
                    );
                    let monetary_block2 = monetary_block.clone();
                    let (inputs, outputs) = self
                        .chain
                        .push_monetary_block(monetary_block, current_timestamp)?;
                    self.on_monetary_block_registered(&monetary_block2, inputs, outputs)?;
                }
            }
        }

        if let Some(consensus) = &mut self.consensus {
            // Move to the next height.
            consensus.reset(self.chain.height() as u64);
        }
        Ok(())
    }

    fn recover_state(&mut self) {
        let len = self.chain.height();
        assert!(len > 0);
        debug!("Recovering consensus state");
        self.on_new_epoch();
        debug!("Recovering vrf system.");
        //TODO: Calculate viewchange on node restart by timeout since last known block. For this we need to track last_block time in storage.
        //Recreate vrf system
        self.vrf_system = TicketsSystem::new(
            VALIDATORS_MAX,
            0,
            len,
            self.keys.network_pkey,
            self.keys.network_skey.clone(),
        );

        debug!("Broadcast unspent outputs.");

        let unspent = self.chain.unspent();
        let outputs = self
            .chain
            .outputs_by_hashes(&unspent)
            .expect("Cannot find unspent outputs.");
        let inputs = Vec::new();
        let msg = OutputsNotification { inputs, outputs };
        self.on_outputs_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
    }

    /// Second init phase. Used to rebroadcast messages from VRF, Consensus and so on.
    fn handle_network_ready(&mut self) -> Result<(), Error> {
        // epoch ended, disable consensus and start vrf system.
        if self.chain.blocks_in_epoch() >= SEALED_BLOCK_IN_EPOCH {
            debug!("Recover at end of epoch, trying to force vrf to start.");
            self.consensus = None;
            let random = self.chain.last_random();
            let ticket = self.vrf_system.handle_epoch_end(random);
            let _ = self.broadcast_vrf_ticket(ticket);
        }

        self.request_history()
    }

    /// Update consensus state, if chain has other view of consensus group.
    fn on_new_epoch(&mut self) {
        if self.chain.validators.contains_key(&self.keys.network_pkey) {
            // Promote to Validator role
            let consensus = BlockConsensus::new(
                self.chain.height() as u64,
                self.chain.epoch,
                self.keys.network_skey.clone(),
                self.keys.network_pkey.clone(),
                self.chain.leader.clone(),
                self.chain.validators.clone(),
            );

            if consensus.is_leader() {
                consensus::metrics::CONSENSUS_ROLE
                    .set(consensus::metrics::ConsensusRole::Leader as i64);
                info!("I'm leader: epoch={}", self.chain.epoch);
            } else {
                consensus::metrics::CONSENSUS_ROLE
                    .set(consensus::metrics::ConsensusRole::Validator as i64);
                info!(
                    "I'm validator: epoch={}, leader={}",
                    self.chain.epoch, self.chain.leader
                );
            }

            self.consensus = Some(consensus);
            self.on_new_consensus();
        } else {
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Regular as i64);
            // Resign from Validator role.
            info!(
                "I'm regular node, waiting for sealed block: epoch={}, leader={}",
                self.chain.epoch, self.chain.leader
            );
            self.consensus = None;
            consensus::metrics::CONSENSUS_STATE
                .set(consensus::metrics::ConsensusState::NotInConsensus as i64);
        }

        debug!("Broadcast new epoch event.");
        let msg = EpochNotification {
            epoch: self.chain.epoch,
            leader: self.chain.leader,
            validators: self.chain.validators.clone(),
            facilitator: self.chain.facilitator,
        };
        self.on_epoch_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        // clear consensus messages when new epoch starts
        self.future_consensus_messages.clear();
    }
    /// Handle incoming transactions received from network.
    fn handle_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let tx_hash = Hash::digest(&tx);
        info!(
            "Received transaction from the network: hash={}, inputs={}, outputs={}, fee={}",
            &tx_hash,
            tx.body.txins.len(),
            tx.body.txouts.len(),
            tx.body.fee
        );

        // Validate transaction.
        let current_timestamp = Utc::now().timestamp() as u64;
        validate_transaction(&tx, &self.mempool, &self.chain, current_timestamp)?;

        // Queue to mempool.
        info!("Transaction is valid, adding to mempool: hash={}", &tx_hash);
        self.mempool.push_tx(tx_hash, tx);

        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let header = block.base_header();
        // Check previous hash.
        let previous_hash = self.chain.last_block_hash();
        if previous_hash != header.previous {
            debug!(
                "Orphan sealed block: hash={}, epoch={}, expected_previous={:?}, got_previous={:?}",
                &block_hash, header.epoch, &previous_hash, &header.previous
            );
            return self.on_orphan_block(block);
        }

        info!(
            "Received sealed block from the network: hash={}, current_height={}",
            &block_hash,
            self.chain.height()
        );

        self.apply_new_block(block)
    }

    fn apply_new_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);

        // Check that block is not registered yet.
        if self.chain.contains_block(&block_hash) {
            warn!("Block has been already registered: hash={}", &block_hash);
            // Already registered, skip.
            return Ok(());
        }

        if let Some(consensus) = &mut self.consensus {
            if consensus.should_commit() {
                // Commit the block and move to the next height.
                let (block, _proof) = consensus.get_proposal();
                let consensus_block_hash = Hash::digest(block);
                if block_hash != consensus_block_hash {
                    panic!(
                        "Network fork: received_block={:?}, consensus_block={:?}",
                        &block_hash, &consensus_block_hash
                    );
                }
            }
        };

        match block {
            Block::KeyBlock(key_block) => {
                let key_block2 = key_block.clone();
                self.chain.push_key_block(key_block)?;
                self.on_key_block_registered(&key_block2)?;
            }
            Block::MonetaryBlock(monetary_block) => {
                let current_timestamp = Utc::now().timestamp() as u64;
                let monetary_block2 = monetary_block.clone();
                let (inputs, outputs) = self
                    .chain
                    .push_monetary_block(monetary_block, current_timestamp)?;
                self.on_monetary_block_registered(&monetary_block2, inputs, outputs)?;
            }
        }

        Ok(())
    }

    /// Count sealed block in epoch, restarts timers and all systems
    /// related to block timeout.
    ///
    /// Returns error on sending message failure.
    fn on_next_block(&mut self) -> Result<(), Error> {
        self.vrf_system.handle_sealed_block();

        // epoch ended, disable consensus and start vrf system.
        if self.chain.blocks_in_epoch() >= SEALED_BLOCK_IN_EPOCH {
            self.consensus = None;
            let random = self.chain.last_random();
            let ticket = self.vrf_system.handle_epoch_end(random);
            self.broadcast_vrf_ticket(ticket)?;
        }

        if let Some(consensus) = &mut self.consensus {
            // Move to the next height.
            consensus.reset(self.chain.height() as u64);
        }

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeEpoch.
    fn handle_subscribe_epoch(
        &mut self,
        tx: UnboundedSender<EpochNotification>,
    ) -> Result<(), Error> {
        self.on_epoch_changed.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::SubscribeOutputs.
    fn handle_subscribe_outputs(
        &mut self,
        tx: UnboundedSender<OutputsNotification>,
    ) -> Result<(), Error> {
        self.on_outputs_changed.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::SubscribeInfo
    fn handle_subscribe_info(
        &mut self,
        tx: UnboundedSender<InfoNotification>,
    ) -> Result<(), Error> {
        self.on_info.push(tx);
        Ok(())
    }

    fn handle_election_info(&mut self) -> Result<(), Error> {
        let msg = InfoNotification::Election(self.vrf_system.info());
        self.on_info
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        Ok(())
    }

    fn handle_escrow_info(&mut self) -> Result<(), Error> {
        let msg = InfoNotification::Escrow(self.chain.escrow.info());
        self.on_info
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        Ok(())
    }

    /// Handler for new epoch creation procedure.
    /// This method called only on leader side, and when consensus is active.
    /// Leader should create a KeyBlock based on last random provided by VRF.
    fn create_new_epoch(
        &mut self,
        random: VRF,
        view_change: u32,
        facilitator: secure::PublicKey,
    ) -> Result<(), Error> {
        let consensus = self.consensus.as_mut().unwrap();
        let previous = self.chain.last_block_hash();
        let timestamp = Utc::now().timestamp() as u64;
        let epoch = self.chain.epoch + 1;
        let leader = consensus.leader();
        assert_eq!(&leader, &self.keys.network_pkey);

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp);
        debug!(
            "Creating a new epoch proposal: {}, with leader = {:?}",
            epoch,
            consensus.leader()
        );

        let validators = consensus.validators();
        let mut block = KeyBlock::new(
            base,
            leader,
            facilitator,
            random,
            view_change,
            validators.iter().map(|(k, _s)| *k).collect(),
        );

        let block_hash = Hash::digest(&block);

        // Create initial multi-signature.
        let (multisig, multisigmap) = create_initial_multi_signature(
            &block_hash,
            &self.keys.network_skey,
            &self.keys.network_pkey,
            &validators,
        );
        block.header.base.multisig = multisig;
        block.header.base.multisigmap = multisigmap;

        // Validate the block via blockchain (just double-checking here).
        self.chain
            .validate_key_block(&block, true)
            .expect("proposed key block is valid");

        info!(
            "Created key block block: height={}, hash={}",
            self.chain.height() + 1,
            block_hash
        );

        let proof = BlockProof::KeyBlockProof;
        let block = Block::KeyBlock(block);
        consensus.propose(block, proof);
        // Prevote for this block.
        consensus.prevote(block_hash);
        NodeService::flush_consensus_messages(consensus, &mut self.network)
    }

    /// Called when a new key block is registered.
    fn on_key_block_registered(&mut self, _key_block: &KeyBlock) -> Result<(), Error> {
        self.on_new_epoch();
        self.on_next_block()
    }

    /// Called when a new key block is registered.
    fn on_monetary_block_registered(
        &mut self,
        _monetary_block: &MonetaryBlock,
        inputs: Vec<Output>,
        outputs: Vec<Output>,
    ) -> Result<(), Error> {
        // Remove old transactions from the mempool.
        let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
        let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
        self.mempool.prune(&input_hashes, &output_hashes);
        //
        // Notify subscribers.
        //
        let msg = OutputsNotification { inputs, outputs };
        self.on_outputs_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        self.on_next_block()
    }

    /// Send block to network.
    fn send_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let data = block.into_buffer()?;
        // Don't send block to myself.
        self.network.publish(&SEALED_BLOCK_TOPIC, data)?;
        info!("Sent sealed block to the network: hash={}", block_hash);
        Ok(())
    }

    /// Request for changing group received from VRF system.
    /// Restars consensus with new params, and send new keyblock.
    fn on_change_group(&mut self, group: ElectionResult) -> Result<(), Error> {
        info!("Changing group, new group leader = {}", group.leader);
        let validators: BTreeMap<secure::PublicKey, i64> =
            group.validators.iter().cloned().collect();
        if validators.contains_key(&self.keys.network_pkey) {
            let consensus = BlockConsensus::new(
                self.chain.height() as u64,
                self.chain.epoch + 1,
                self.keys.network_skey.clone(),
                self.keys.network_pkey.clone(),
                group.leader.clone(),
                validators,
            );
            self.consensus = Some(consensus);
            let consensus = self.consensus.as_ref().unwrap();
            if consensus.is_leader() {
                self.create_new_epoch(group.random, group.view_change, group.facilitator)?;
            }
            self.on_new_consensus();
        } else {
            self.consensus = None;
        }
        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Consensus
    //----------------------------------------------------------------------------------------------

    ///
    /// Try to process messages with new consensus.
    ///
    fn on_new_consensus(&mut self) {
        let outbox = std::mem::replace(&mut self.future_consensus_messages, Vec::new());
        for msg in outbox {
            if let Err(e) = self.handle_consensus_message(msg) {
                debug!("Error in future consensus message: {}", e);
            }
        }
    }

    ///
    /// Try to commit a new block if consensus is in an appropriate state.
    ///
    fn flush_consensus_messages(
        consensus: &mut BlockConsensus,
        network: &mut Network,
    ) -> Result<(), Error> {
        // Flush message queue.
        let outbox = std::mem::replace(&mut consensus.outbox, Vec::new());
        for msg in outbox {
            let proto = msg.into_proto();
            let data = proto.write_to_bytes()?;
            network.publish(&CONSENSUS_TOPIC, data)?;
        }
        Ok(())
    }

    ///
    /// Handles incoming consensus requests received from network.
    ///
    fn handle_consensus_message(&mut self, msg: BlockConsensusMessage) -> Result<(), Error> {
        // if our consensus state is outdated, push message to future_consensus_messages.
        // TODO: remove queue and use request-responses to get message from other nodes.
        if self.consensus.is_none() || self.consensus.as_ref().unwrap().epoch() == msg.epoch + 1 {
            self.future_consensus_messages.push(msg);
            return Ok(());
        }
        let consensus = self.consensus.as_mut().unwrap();
        // Validate signature and content.
        msg.validate()?;
        consensus.feed_message(msg)?;
        // Flush pending messages.
        NodeService::flush_consensus_messages(consensus, &mut self.network)?;

        // Check if we can prevote for a block.
        if !consensus.is_leader() && consensus.should_prevote() {
            self.prevote_block();
        }
        // Check if we can commit a block.
        let consensus = self.consensus.as_ref().unwrap();
        if consensus.is_leader() && consensus.should_commit() {
            let (block, _proof, multisig, multisigmap) =
                self.consensus.as_mut().unwrap().sign_and_commit();
            self.commit_proposed_block(block, multisig, multisigmap);
        }
        Ok(())
    }

    ///
    /// Called periodically every CONSENSUS_TIMER seconds.
    ///
    fn handle_consensus_timer(&mut self) -> Result<(), Error> {
        let now = clock::now();
        let elapsed: Duration = now.duration_since(self.chain.last_block_timestamp);

        // Check that a new payment block should be proposed.
        if self.consensus.is_some()
            && self.consensus.as_ref().unwrap().should_propose()
            && elapsed >= TX_WAIT_TIMEOUT
        {
            self.propose_monetary_block()?;
        }
        Ok(())
    }

    ///
    /// Propose a new monetary block.
    ///
    fn propose_monetary_block(&mut self) -> Result<(), Error> {
        assert!(self.consensus.as_ref().unwrap().should_propose());

        let current_timestamp = Utc::now().timestamp() as u64;
        let height = self.chain.height() + 1;
        let previous = self.chain.last_block_hash();
        info!(
            "I'm leader, proposing a new monetary block: height={}, previous={}",
            height, previous
        );

        // Create a new monetary block from the mempool.
        let (mut block, fee_output, tx_hashes) = self.mempool.create_block(
            previous,
            VERSION,
            self.chain.epoch,
            BLOCK_REWARD,
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
        );
        let block_hash = Hash::digest(&block);

        // Create initial multi-signature.
        let (multisig, multisigmap) = create_initial_multi_signature(
            &block_hash,
            &self.keys.network_skey,
            &self.keys.network_pkey,
            &self.chain.validators,
        );
        block.header.base.multisig = multisig;
        block.header.base.multisigmap = multisigmap;

        // Validate the block via blockchain (just double-checking here).
        self.chain
            .validate_monetary_block(&block, true, current_timestamp)
            .expect("proposed monetary block is validproposed monetary block is valid");

        // Log info.
        info!(
            "Created monetary block: height={}, hash={}",
            height, &block_hash,
        );
        // TODO: log the number of inputs/outputs

        // Propose this block.
        let proof = MonetaryBlockProof {
            fee_output,
            tx_hashes,
        };
        let proof = BlockProof::MonetaryBlockProof(proof);
        let block = Block::MonetaryBlock(block);
        let consensus = self.consensus.as_mut().unwrap();
        consensus.propose(block, proof);

        // Prevote for this block.
        consensus.prevote(block_hash);

        // Flush pending messages.
        NodeService::flush_consensus_messages(consensus, &mut self.network)?;

        Ok(())
    }

    ///
    /// Pre-vote for a block.
    ///
    fn prevote_block(&mut self) {
        let consensus = self.consensus.as_ref().unwrap();
        assert!(!consensus.is_leader() && consensus.should_prevote());

        let (block, proof) = consensus.get_proposal();
        let request_hash = Hash::digest(block);
        debug!("Validating block: block={:?}", &request_hash);
        match Self::validate_block(consensus, &self.mempool, &self.chain, block, proof) {
            Ok(()) => {
                let consensus = self.consensus.as_mut().unwrap();
                consensus.prevote(request_hash);
                NodeService::flush_consensus_messages(consensus, &mut self.network).unwrap();
            }
            Err(e) => {
                error!(
                    "Discarded invalid block proposal: hash={:?}, error={}",
                    &request_hash, e
                );
            }
        }
    }

    ///
    /// Validate proposed block.
    ///
    fn validate_block(
        consensus: &BlockConsensus,
        mempool: &Mempool,
        chain: &Blockchain,
        block: &Block,
        proof: &BlockProof,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(block);
        let base_header = block.base_header();
        let epoch = chain.epoch;

        // Check block hash uniqueness.
        if chain.contains_block(&block_hash) {
            return Err(NodeError::BlockAlreadyRegistered(block_hash).into());
        }

        // Check block version.
        if VERSION != base_header.version {
            return Err(
                NodeError::InvalidBlockVersion(block_hash, VERSION, base_header.version).into(),
            );
        }

        // Check previous hash.
        let previous_hash = chain.last_block_hash();
        if previous_hash != base_header.previous {
            return Err(NodeError::OutOfOrderBlockHash(
                block_hash,
                previous_hash,
                base_header.previous,
            )
            .into());
        }

        let timestamp = Utc::now().timestamp() as u64;
        if base_header.timestamp.saturating_sub(timestamp) > TIME_TO_RECEIVE_BLOCK
            || timestamp.saturating_sub(base_header.timestamp) > TIME_TO_RECEIVE_BLOCK
        {
            return Err(NodeError::UnsynchronizedBlock(base_header.timestamp, timestamp).into());
        }

        match (block, proof) {
            (Block::MonetaryBlock(block), BlockProof::MonetaryBlockProof(proof)) => {
                // We can validate validators of MonetaryBlock only in current epoch.
                if epoch != base_header.epoch {
                    return Err(BlockchainError::OutOfOrderBlockEpoch(
                        block_hash,
                        epoch,
                        base_header.epoch,
                    )
                    .into());
                }
                validate_proposed_monetary_block(
                    mempool,
                    chain,
                    block_hash,
                    &block,
                    &proof.fee_output,
                    &proof.tx_hashes,
                    timestamp,
                )
            }
            (Block::KeyBlock(block), BlockProof::KeyBlockProof) => {
                validate_proposed_key_block(chain, consensus, block_hash, block)
            }
            (_, _) => unreachable!(),
        }
    }

    ///
    /// Commit sealed block into blockchain and send it to the network.
    /// NOTE: commit must never fail. Please don't use Result<(), Error> here.
    ///
    fn commit_proposed_block(
        &mut self,
        block: Block,
        multisig: secure::Signature,
        multisigmap: BitVector,
    ) {
        let current_timestamp = Utc::now().timestamp() as u64;
        match block {
            Block::KeyBlock(mut key_block) => {
                key_block.header.base.multisig = multisig;
                key_block.header.base.multisigmap = multisigmap;
                let key_block2 = key_block.clone();
                self.chain
                    .push_key_block(key_block)
                    .expect("block is validated before");
                self.on_key_block_registered(&key_block2)
                    .expect("internal error");
                self.send_sealed_block(Block::KeyBlock(key_block2))
                    .expect("failed to send sealed monetary block");
            }
            Block::MonetaryBlock(mut monetary_block) => {
                monetary_block.header.base.multisig = multisig;
                monetary_block.header.base.multisigmap = multisigmap;
                let monetary_block2 = monetary_block.clone();
                let (inputs, outputs) = self
                    .chain
                    .push_monetary_block(monetary_block, current_timestamp)
                    .expect("block is validated before");
                self.on_monetary_block_registered(&monetary_block2, inputs, outputs)
                    .expect("internal error");
                self.send_sealed_block(Block::MonetaryBlock(monetary_block2))
                    .expect("failed to send sealed monetary block");
            }
        }
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        NodeMessage::Init { genesis } => self.handle_init(genesis),
                        NodeMessage::NetworkReady => self.handle_network_ready(),
                        NodeMessage::SubscribeEpoch(tx) => self.handle_subscribe_epoch(tx),
                        NodeMessage::SubscribeOutputs(tx) => self.handle_subscribe_outputs(tx),
                        NodeMessage::SubscribeInfo(tx) => self.handle_subscribe_info(tx),
                        NodeMessage::ElectionInfo => self.handle_election_info(),
                        NodeMessage::EscrowInfo => self.handle_escrow_info(),
                        NodeMessage::Transaction(msg) => Transaction::from_buffer(&msg)
                            .and_then(|msg| self.handle_transaction(msg)),
                        NodeMessage::Consensus(msg) => BlockConsensusMessage::from_buffer(&msg)
                            .and_then(|msg| self.handle_consensus_message(msg)),
                        NodeMessage::SealedBlock(msg) => {
                            Block::from_buffer(&msg).and_then(|msg| self.handle_sealed_block(msg))
                        }
                        NodeMessage::VRFMessage(msg) => VRFTicket::from_buffer(&msg)
                            .and_then(|msg| self.handle_vrf_message(msg)),
                        NodeMessage::ChainLoaderMessage(msg) => {
                            ChainLoaderMessage::from_buffer(&msg.data)
                                .and_then(|data| self.handle_chain_loader_message(msg.from, data))
                        }

                        NodeMessage::ConsensusTimer(_now) => self.handle_consensus_timer(),
                        NodeMessage::VRFTimer(_instant) => self.handle_vrf_timer(),
                    };
                    if let Err(e) = result {
                        error!("Error: {}", e);
                    }
                }
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

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

mod error;
mod loader;
mod mempool;
pub mod protos;

mod config;
mod metrics;
#[cfg(test)]
mod test;
mod validation;

pub use crate::config::ChainConfig;
use crate::error::*;
use crate::loader::{ChainLoader, ChainLoaderMessage};
use crate::mempool::Mempool;
use crate::validation::*;
use bitvector::BitVector;
use chrono::Utc;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_consensus::{self as consensus, BlockConsensus, BlockConsensusMessage};
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
    /// Initialize blockchain.
    pub fn init(&self) -> Result<(), Error> {
        let msg = NodeMessage::Init;
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
    ElectionInfo(ElectionInfo),
    Escrow(EscrowInfo),
}

/// Send when epoch is changed.
#[derive(Clone, Debug)]
pub struct EpochNotification {
    pub epoch: u64,
    pub leader: secure::PublicKey,
    pub facilitator: secure::PublicKey,
    pub validators: Vec<(secure::PublicKey, i64)>,
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

/// Topic used for sending transactions.
const TX_TOPIC: &'static str = "tx";
/// Topic used for consensus.
const CONSENSUS_TOPIC: &'static str = "consensus";
/// Topic used for sending sealed blocks.
const SEALED_BLOCK_TOPIC: &'static str = "block";

#[derive(Clone, Debug)]
pub enum NodeMessage {
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
    ChainLoaderMessage(UnicastMessage),
    //
    // Internal Events
    //
    Init,
    NetworkReady,
    ConsensusTimer(Instant),
    ViewChangeTimer(Instant),
}

pub struct NodeService {
    /// Config.
    cfg: ChainConfig,
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,

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
    pub fn new(
        cfg: ChainConfig,
        storage_cfg: StorageConfig,
        keys: KeyChain,
        genesis: Vec<Block>,
        network: Network,
    ) -> Result<(Self, Node), Error> {
        let blockchain_cfg = BlockchainConfig {
            max_slot_count: cfg.max_slot_count,
            min_stake_amount: cfg.min_stake_amount,
            bonding_time: cfg.bonding_time,
        };
        let current_timestamp = Utc::now().timestamp() as u64;
        let (outbox, inbox) = unbounded();
        let chain = Blockchain::new(blockchain_cfg, storage_cfg, genesis, current_timestamp);
        let handler = Node {
            outbox,
            network: network.clone(),
        };
        let service = Self::with_blockchain(cfg, chain, keys, network, inbox)?;
        Ok((service, handler))
    }

    pub fn testing(
        cfg: ChainConfig,
        keys: KeyChain,
        network: Network,
        genesis: Vec<Block>,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let blockchain_cfg = BlockchainConfig {
            max_slot_count: cfg.max_slot_count,
            min_stake_amount: cfg.min_stake_amount,
            bonding_time: cfg.bonding_time,
        };
        let current_timestamp = Utc::now().timestamp() as u64;
        let chain = Blockchain::testing(blockchain_cfg, genesis, current_timestamp);
        Self::with_blockchain(cfg, chain, keys, network, inbox)
    }

    fn with_blockchain(
        cfg: ChainConfig,
        chain: Blockchain,
        keys: KeyChain,
        network: Network,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let future_consensus_messages = Vec::new();
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
        let duration = Duration::from_secs(1); // every second
        let timer = Interval::new_interval(duration)
            .map(|i| NodeMessage::ConsensusTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        // ViewChange timer events
        let duration = Duration::from_secs(cfg.micro_block_timeout); // every message_timeout
        let timer = Interval::new_interval(duration)
            .map(|i| NodeMessage::ViewChangeTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        let events = select_all(streams);

        let service = NodeService {
            cfg,
            chain_loader,
            future_consensus_messages,
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
    pub fn handle_init(&mut self) -> Result<(), Error> {
        let len = self.chain.height();
        assert!(len > 0);
        debug!("Recovering consensus state");
        self.on_new_epoch();

        // Sync wallet.
        // TODO: this implementation can consume a lot of memory.
        let unspent: Vec<Hash> = self.chain.unspent().cloned().collect();
        let outputs = self
            .chain
            .outputs_by_hashes(&unspent)
            .expect("Cannot find unspent outputs.");
        let inputs = Vec::new();
        debug!("Broadcast unspent outputs.");
        let msg = OutputsNotification { inputs, outputs };
        self.on_outputs_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        Ok(())
    }

    /// Second init phase. Used to rebroadcast messages from VRF, Consensus and so on.
    fn handle_network_ready(&mut self) -> Result<(), Error> {
        // epoch ended, disable consensus and start vrf system.
        if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
            debug!("Recover at end of epoch, trying to force vrf to start.");
            self.on_change_group()?;
        }

        self.request_history()
    }

    /// Update consensus state, if chain has other view of consensus group.
    fn on_new_epoch(&mut self) {
        consensus::metrics::CONSENSUS_ROLE.set(consensus::metrics::ConsensusRole::Regular as i64);
        // Resign from Validator role.
        let leader = self.chain.leader();
        info!(
            "Waiting for sealed block: epoch={}, leader={}",
            self.chain.epoch(),
            leader
        );
        self.consensus = None;
        consensus::metrics::CONSENSUS_STATE
            .set(consensus::metrics::ConsensusState::NotInConsensus as i64);

        debug!("Broadcast new epoch event.");
        let msg = EpochNotification {
            epoch: self.chain.epoch(),
            leader: leader,
            validators: self.chain.validators().clone(),
            facilitator: self.chain.facilitator().clone(),
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
        validate_transaction(
            &tx,
            &self.mempool,
            &self.chain,
            current_timestamp,
            self.cfg.payment_fee,
            self.cfg.stake_fee,
        )?;

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

        // TODO: validate timestamp

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

        match block {
            Block::KeyBlock(key_block) => {
                // Check for the correct block order.
                if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
                    return Err(NodeError::ExpectedMonetaryBlock(self.chain.height()).into());
                }

                // Check consensus.
                if let Some(consensus) = &mut self.consensus {
                    if consensus.should_commit() {
                        // Check for forks.
                        let (block, _proof) = consensus.get_proposal();
                        let consensus_block_hash = Hash::digest(block);
                        if block_hash != consensus_block_hash {
                            panic!(
                                "Network fork: received_block={:?}, consensus_block={:?}",
                                &block_hash, &consensus_block_hash
                            );
                        }
                    }
                }
                self.chain.push_key_block(key_block)?;
                self.on_new_epoch();
            }
            Block::MonetaryBlock(monetary_block) => {
                // Check for the correct block order.
                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    return Err(NodeError::ExpectedKeyBlock(self.chain.height()).into());
                }

                assert!(self.consensus.is_none(), "consensus is for key blocks only");

                let current_timestamp = Utc::now().timestamp() as u64;

                // Check monetary adjustment.
                if self.chain.epoch() > 0
                    && monetary_block.header.monetary_adjustment != self.cfg.block_reward
                {
                    // TODO: support slashing.
                    return Err(NodeError::InvalidBlockReward(
                        block_hash,
                        monetary_block.header.monetary_adjustment,
                        self.cfg.block_reward,
                    )
                    .into());
                }

                let (inputs, outputs) = self
                    .chain
                    .push_monetary_block(monetary_block, current_timestamp)?;

                // Remove old transactions from the mempool.
                let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
                let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
                self.mempool.prune(&input_hashes, &output_hashes);

                // Notify subscribers.
                let msg = OutputsNotification { inputs, outputs };
                self.on_outputs_changed
                    .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    debug!("Starting new election.");
                    self.on_change_group()?;
                }
            }
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
        let msg = InfoNotification::ElectionInfo(self.chain.election_info());
        self.on_info
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        Ok(())
    }

    fn handle_escrow_info(&mut self) -> Result<(), Error> {
        let msg = InfoNotification::Escrow(self.chain.escrow().info());
        self.on_info
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        Ok(())
    }

    /// Handler for new epoch creation procedure.
    /// This method called only on leader side, and when consensus is active.
    /// Leader should create a KeyBlock based on last random provided by VRF.
    fn create_new_epoch(&mut self, random: VRF) -> Result<(), Error> {
        let consensus = self.consensus.as_mut().unwrap();
        let previous = self.chain.last_block_hash();
        let timestamp = Utc::now().timestamp() as u64;
        let view_change = self.chain.view_change();
        let epoch = self.chain.epoch() + 1;
        let leader = consensus.leader();
        assert_eq!(&leader, &self.keys.network_pkey);

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp, view_change);
        debug!(
            "Creating a new epoch proposal: {}, with leader = {:?}",
            epoch,
            consensus.leader()
        );

        let validators: Vec<_> = consensus
            .validators()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        let mut block = KeyBlock::new(base, random);

        let block_hash = Hash::digest(&block);

        // Create initial multi-signature.
        let (multisig, multisigmap) = create_proposal_signature(
            &block_hash,
            &self.keys.network_skey,
            &self.keys.network_pkey,
            &validators,
        );
        block.body.multisig = multisig;
        block.body.multisigmap = multisigmap;

        // Validate the block via blockchain (just double-checking here).
        self.chain
            .validate_key_block(&block, true)
            .expect("proposed key block is valid");

        info!(
            "Created key block block: height={}, hash={}",
            self.chain.height() + 1,
            block_hash
        );

        let proof = ();
        consensus.propose(block, proof);
        // Prevote for this block.
        consensus.prevote(block_hash);
        NodeService::flush_consensus_messages(consensus, &mut self.network)
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
    fn on_change_group(&mut self) -> Result<(), Error> {
        if self
            .chain
            .validators()
            .iter()
            .find(|(key, _)| *key == self.keys.network_pkey)
            .is_none()
        {
            debug!("I am regular node, waiting for old consensus to produce blocks");
            return Ok(());
        }

        info!("I am a part of consensus, trying choose new group.");
        let consensus = BlockConsensus::new(
            self.chain.height() as u64,
            self.chain.epoch() + 1,
            self.keys.network_skey.clone(),
            self.keys.network_pkey.clone(),
            self.chain.leader(),
            self.chain.validators().iter().cloned().collect(),
        );

        self.consensus = Some(consensus);
        let consensus = self.consensus.as_ref().unwrap();
        if consensus.is_leader() {
            let last_random = self.chain.last_random();
            let seed = mix(last_random, self.chain.view_change());
            let vrf = secure::make_VRF(&self.keys.network_skey, &seed);
            self.create_new_epoch(vrf)?;
        }
        self.on_new_consensus();

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
    /// Returns true if current node is a leader.
    ///
    fn is_leader(&self) -> bool {
        self.chain.leader() == self.keys.network_pkey
    }

    ///
    /// Called periodically every CONSENSUS_TIMER seconds.
    ///
    fn handle_consensus_timer(&mut self) -> Result<(), Error> {
        let now = clock::now();
        let elapsed: Duration = now.duration_since(self.chain.last_block_timestamp());

        // Check that a new payment block should be created.
        if self.consensus.is_none()
            && elapsed >= Duration::from_secs(self.cfg.tx_wait_timeout)
            && self.is_leader()
            && self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch
        {
            self.create_monetary_block()?;
        }

        // Check that a block has been committed but haven't send by the leader.
        if self.consensus.is_some()
            && self.consensus.as_ref().unwrap().should_commit()
            && elapsed >= Duration::from_secs(self.cfg.block_timeout)
        {
            assert!(
                !self.consensus.as_ref().unwrap().is_leader(),
                "never happens on leader"
            );
            let (block, _proof, mut multisig, mut multisigmap) =
                self.consensus.as_mut().unwrap().sign_and_commit();
            let block_hash = Hash::digest(&block);
            warn!("Timed out while waiting for the committed block from the leader, applying automatically: hash={}, height={}",
                block_hash, self.chain.height()
            );
            // Augment multi-signature by leader's signature from the proposal.
            merge_multi_signature(
                &mut multisig,
                &mut multisigmap,
                &block.body.multisig,
                &block.body.multisigmap,
            );
            metrics::AUTOCOMMIT.inc();
            // Auto-commit proposed block and send it to the network.
            self.commit_proposed_block(block, multisig, multisigmap);
        }

        Ok(())
    }
    /// Request block history from leader, if no block was received
    /// retry each message_timeout.
    fn handle_view_change_timer(&mut self) -> Result<(), Error> {
        let elapsed: Duration = clock::now().duration_since(self.chain.last_block_timestamp());

        if self.consensus.is_none() && elapsed >= Duration::from_secs(self.cfg.micro_block_timeout)
        {
            metrics::FORCED_VIEW_CHANGES.inc();
            let leader = self.chain.leader();
            debug!("Timed out while waiting for monetary block, request block from last leader: leader={}", leader);
            self.request_history_from(leader)?;
        }
        Ok(())
    }
    ///
    /// Create a new monetary block.
    ///
    fn create_monetary_block(&mut self) -> Result<(), Error> {
        assert!(self.consensus.is_none());
        assert!(self.is_leader());
        assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);

        let height = self.chain.height() + 1;
        let previous = self.chain.last_block_hash();
        info!(
            "I'm leader, proposing a new monetary block: height={}, previous={}",
            height, previous
        );

        // Create a new monetary block from the mempool.
        let (mut block, _fee_output, _tx_hashes) = self.mempool.create_block(
            previous,
            VERSION,
            self.chain.epoch(),
            self.cfg.block_reward,
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            self.chain.view_change(),
        );
        let block_hash = Hash::digest(&block);
        block.body.sig = secure::sign_hash(&block_hash, &self.keys.network_skey);

        // Log info.
        info!(
            "Created monetary block: height={}, hash={}",
            height, &block_hash,
        );
        // TODO: log the number of inputs/outputs

        // TODO: swap send_sealed_block() and apply_new_block() order after removing VRF.
        let block2 = block.clone();
        self.send_sealed_block(Block::MonetaryBlock(block2))
            .expect("failed to send sealed monetary block");
        self.apply_new_block(Block::MonetaryBlock(block))?;

        Ok(())
    }

    ///
    /// Pre-vote for a block.
    ///
    fn prevote_block(&mut self) {
        let consensus = self.consensus.as_ref().unwrap();
        assert!(!consensus.is_leader() && consensus.should_prevote());

        let (block, _proof) = consensus.get_proposal();
        let request_hash = Hash::digest(block);
        debug!("Validating block: block={:?}", &request_hash);
        match validate_proposed_key_block(
            &self.cfg,
            &self.chain,
            self.chain.view_change(),
            request_hash,
            block,
        ) {
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
    /// Commit sealed block into blockchain and send it to the network.
    /// NOTE: commit must never fail. Please don't use Result<(), Error> here.
    ///
    fn commit_proposed_block(
        &mut self,
        mut key_block: KeyBlock,
        multisig: secure::Signature,
        multisigmap: BitVector,
    ) {
        key_block.body.multisig = multisig;
        key_block.body.multisigmap = multisigmap;
        let key_block2 = key_block.clone();
        self.apply_new_block(Block::KeyBlock(key_block))
            .expect("block is validated before");
        self.send_sealed_block(Block::KeyBlock(key_block2))
            .expect("failed to send sealed monetary block");
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
                        NodeMessage::Init => self.handle_init(),
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
                        NodeMessage::ChainLoaderMessage(msg) => {
                            ChainLoaderMessage::from_buffer(&msg.data)
                                .and_then(|data| self.handle_chain_loader_message(msg.from, data))
                        }
                        NodeMessage::ConsensusTimer(_now) => self.handle_consensus_timer(),
                        NodeMessage::ViewChangeTimer(_now) => self.handle_view_change_timer(),
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

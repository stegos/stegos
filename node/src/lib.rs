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

mod config;
mod error;
mod loader;
mod mempool;
pub mod metrics;
pub mod protos;
#[cfg(test)]
mod test;
mod validation;
pub use crate::config::ChainConfig;
use crate::error::*;
use crate::loader::{ChainLoader, ChainLoaderMessage};
use crate::mempool::Mempool;
use crate::validation::*;
use bitvector::BitVector;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use std::time::SystemTime;
use std::time::{Duration, Instant};
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_blockchain::*;
use stegos_consensus::optimistic::{ViewChangeCollector, ViewChangeMessage};
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
    /// Send transaction to node and to the network.
    pub fn send_transaction(&self, tx: Transaction) -> Result<(), Error> {
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        self.network.publish(&TX_TOPIC, data.clone())?;
        info!("Sent transaction to the network: tx={}", Hash::digest(&tx));
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
/// Topic for ViewChange message.
pub const VIEW_CHANGE_TOPIC: &'static str = "view_changes";
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
    ViewChangeMessage(Vec<u8>),
    ChainLoaderMessage(UnicastMessage),
    //
    // Internal Events
    //
    MicroBlockProposeTimer(Instant),
    MicroBlockViewChangeTimer(Instant),
    KeyBlockViewChangeTimer(Instant),
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

    /// Optimistic consensus part, that collect ViewChange messages.
    optimistic: ViewChangeCollector,

    /// Monotonic clock when the latest block was registered.
    last_block_clock: Instant,

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
        let timestamp = SystemTime::now();
        let (outbox, inbox) = unbounded();
        let chain = Blockchain::new(blockchain_cfg, storage_cfg, genesis, timestamp);
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
        let timestamp = SystemTime::now();
        let chain = Blockchain::testing(blockchain_cfg, genesis, timestamp);
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
        let optimistic =
            ViewChangeCollector::new(&chain, keys.network_pkey, keys.network_skey.clone());
        let last_block_clock = clock::now();

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

        let view_change_rx = network
            .subscribe(&VIEW_CHANGE_TOPIC)?
            .map(|m| NodeMessage::ViewChangeMessage(m));
        streams.push(Box::new(view_change_rx));

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

        // Timer for the micro block proposals.
        let timer = Interval::new_interval(cfg.tx_wait_timeout)
            .map(|i| NodeMessage::MicroBlockProposeTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        // Timer for the micro block view changes.
        let timer = Interval::new_interval(cfg.micro_block_timeout)
            .map(|i| NodeMessage::MicroBlockViewChangeTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        // Timer for the key block view changes.
        let timer = Interval::new_interval(cfg.key_block_timeout)
            .map(|i| NodeMessage::KeyBlockViewChangeTimer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        let events = select_all(streams);

        let mut service = NodeService {
            cfg,
            chain_loader,
            future_consensus_messages,
            chain,
            keys,
            mempool,
            consensus,
            optimistic,
            last_block_clock,
            network,
            on_epoch_changed,
            on_outputs_changed: on_outputs_received,
            on_info: Vec::new(),
            events,
        };

        debug!("Recovering consensus state");
        service.on_new_epoch();

        // Epoch ended, start consensus.
        if service.chain.blocks_in_epoch() >= service.cfg.blocks_in_epoch {
            debug!("Recover at end of epoch");
            service.on_change_group()?;
        }

        Ok(service)
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

        let msg = EpochNotification {
            epoch: self.chain.epoch(),
            leader,
            validators: self.chain.validators().clone(),
            facilitator: self.chain.facilitator().clone(),
        };
        self.on_epoch_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        // clear consensus messages when new epoch starts
        self.future_consensus_messages.clear();
        self.optimistic.on_new_consensus(&self.chain);
    }
    /// Handle incoming transactions received from network.
    fn handle_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let tx_hash = Hash::digest(&tx);
        info!(
            "Received transaction from the network: tx={}, inputs={}, outputs={}, fee={}",
            &tx_hash,
            tx.body.txins.len(),
            tx.body.txouts.len(),
            tx.body.fee
        );

        // Validate transaction.
        let timestamp = SystemTime::now();
        validate_transaction(
            &tx,
            &self.mempool,
            &self.chain,
            timestamp,
            self.cfg.payment_fee,
            self.cfg.stake_fee,
        )?;

        // Queue to mempool.
        info!("Transaction is valid, adding to mempool: tx={}", &tx_hash);
        self.mempool.push_tx(tx_hash, tx);

        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let header = block.base_header();

        // Check height.
        if header.height < self.chain.height() {
            warn!(
                "Skip outdated block: block={}, block_height={}, our_height={}",
                &block_hash,
                header.height,
                self.chain.height()
            );
            return Ok(());
        } else if header.height > self.chain.height() {
            debug!(
                "Orphan sealed block: block={}, block_height={}, our_height={}",
                &block_hash,
                header.height,
                self.chain.height()
            );
            return self.on_orphan_block(block);
        }

        // TODO: validate timestamp

        info!(
            "Received sealed block from the network: height={}, block={}",
            self.chain.height(),
            &block_hash,
        );

        self.apply_new_block(block)
    }

    fn apply_new_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let block_timestamp = block.base_header().timestamp;
        let block_height = block.base_header().height;
        match block {
            Block::KeyBlock(key_block) => {
                // Check for the correct block order.
                if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
                    return Err(NodeBlockError::ExpectedMonetaryBlock(
                        self.chain.height(),
                        block_hash,
                    )
                    .into());
                }

                // Check consensus.
                if let Some(consensus) = &mut self.consensus {
                    if consensus.should_commit() {
                        // Check for forks.
                        let (consensus_block, _proof) = consensus.get_proposal();
                        let consensus_block_hash = Hash::digest(consensus_block);
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
                    return Err(
                        NodeBlockError::ExpectedKeyBlock(self.chain.height(), block_hash).into(),
                    );
                }

                assert!(self.consensus.is_none(), "consensus is for key blocks only");

                let timestamp = SystemTime::now();

                // Check monetary adjustment.
                if self.chain.epoch() > 0
                    && monetary_block.header.monetary_adjustment != self.cfg.block_reward
                {
                    // TODO: support slashing.
                    return Err(NodeBlockError::InvalidMonetaryAdjustment(
                        block_height,
                        block_hash,
                        monetary_block.header.monetary_adjustment,
                        self.cfg.block_reward,
                    )
                    .into());
                }

                let (inputs, outputs) =
                    self.chain.push_monetary_block(monetary_block, timestamp)?;

                // Remove old transactions from the mempool.
                let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
                let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
                self.mempool.prune(&input_hashes, &output_hashes);

                // Notify subscribers.
                let msg = OutputsNotification { inputs, outputs };
                self.on_outputs_changed
                    .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    self.on_change_group()?;
                }
                self.optimistic.on_new_payment_block(&self.chain)
            }
        }

        self.last_block_clock = clock::now();

        let local_timestamp_ms = metrics::time_to_timestamp_ms(SystemTime::now());
        let remote_timestamp_ms = metrics::time_to_timestamp_ms(block_timestamp);
        metrics::BLOCK_REMOTE_TIMESTAMP.set(remote_timestamp_ms);
        metrics::BLOCK_LOCAL_TIMESTAMP.set(local_timestamp_ms);
        metrics::BLOCK_LAG.set(local_timestamp_ms - remote_timestamp_ms); // can be negative.

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeEpoch.
    fn handle_subscribe_epoch(
        &mut self,
        tx: UnboundedSender<EpochNotification>,
    ) -> Result<(), Error> {
        let msg = EpochNotification {
            epoch: self.chain.epoch(),
            leader: self.chain.leader(),
            validators: self.chain.validators().clone(),
            facilitator: self.chain.facilitator().clone(),
        };
        tx.unbounded_send(msg).ok(); // ignore error.
        self.on_epoch_changed.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::SubscribeOutputs.
    fn handle_subscribe_outputs(
        &mut self,
        tx: UnboundedSender<OutputsNotification>,
    ) -> Result<(), Error> {
        // Sent initial state.
        // TODO: this implementation can consume a lot of memory.
        let mut outputs: Vec<Output> = Vec::new();
        for output_hash in self.chain.unspent() {
            let output = self.chain.output_by_hash(output_hash)?.expect("exists");
            outputs.push(output);
        }
        let inputs = Vec::new();
        let msg = OutputsNotification { inputs, outputs };
        tx.unbounded_send(msg).ok(); // ignore error.
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
        let timestamp = SystemTime::now();
        let view_change = self.chain.view_change();
        let height = self.chain.height();
        let epoch = self.chain.epoch() + 1;
        let leader = consensus.leader();
        assert_eq!(&leader, &self.keys.network_pkey);

        let base = BaseBlockHeader::new(VERSION, previous, height, view_change, timestamp);
        debug!(
            "Creating a new key block proposal: height={}, epoch={}, leader={:?}",
            height,
            self.chain.epoch() + 1,
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
            "Created a new key block proposal: height={}, epoch={}, hash={}",
            height, epoch, block_hash
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

    /// Сhecks if it's time to create a micro block.
    fn handle_micro_block_propose_timer(&mut self) -> Result<(), Error> {
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);

        // Check that a new payment block should be created.
        if self.consensus.is_none() && elapsed >= self.cfg.tx_wait_timeout && self.is_leader() {
            assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);
            self.create_monetary_block(None)?;
        }

        Ok(())
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_key_block_viewchange_timer(&mut self) -> Result<(), Error> {
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);

        // TODO: implement view changes for key blocks.

        // Check that a block has been committed but haven't send by the leader.
        if self.consensus.is_some()
            && self.consensus.as_ref().unwrap().should_commit()
            && elapsed >= self.cfg.key_block_timeout
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

    //
    // Optimisitc consensus
    //

    fn handle_view_change(&mut self, msg: ViewChangeMessage) -> Result<(), Error> {
        if let Some(counter) = self.optimistic.handle_message(&self.chain, msg)? {
            debug!(
                "Received enough messages for change leader: height={}, last_block={}, view_change={}",
                self.chain.height(), self.chain.last_block_hash(),  counter
            );
            self.chain.set_view_change(counter);
            if self.is_leader() {
                debug!(
                    "We are leader, producing new monetary block: height={}, last_block={}",
                    self.chain.height(),
                    self.chain.last_block_hash()
                );
                let proof = self
                    .optimistic
                    .last_proof(&self.chain)
                    .expect("Collected proof");
                self.create_monetary_block(Some(proof))?;
            };
        }
        Ok(())
    }

    /// Checks if it's time to perform a view change on a monetary block.
    fn handle_micro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);

        if self.consensus.is_none() && elapsed >= self.cfg.micro_block_timeout {
            metrics::FORCED_VIEW_CHANGES.inc();
            // No block was received, request leader directly, and start collecting view_changes.
            let leader = self.chain.leader();
            debug!("Timed out while waiting for monetary block, request block from last leader: hash={}, block={}, leader={}",
                   self.chain.height(), self.chain.last_block_hash(), leader);
            self.request_history_from(leader)?;

            if let Some(msg) = self.optimistic.handle_timeout(&self.chain)? {
                self.network
                    .publish(VIEW_CHANGE_TOPIC, msg.into_buffer()?)?;
                self.handle_view_change(msg)?;
            }
        }
        Ok(())
    }

    ///
    /// Create a new monetary block.
    ///
    fn create_monetary_block(&mut self, proof: Option<ViewChangeProof>) -> Result<(), Error> {
        assert!(self.consensus.is_none());
        assert!(self.is_leader());
        assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);

        let height = self.chain.height();
        let previous = self.chain.last_block_hash();
        info!(
            "I'm leader, proposing a new monetary block: height={}, last_block={}",
            height, previous
        );

        // Create a new monetary block from the mempool.
        let (mut block, _fee_output, _tx_hashes) = self.mempool.create_block(
            previous,
            VERSION,
            self.chain.height(),
            self.cfg.block_reward,
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            self.chain.view_change(),
            proof,
        );
        let block_hash = Hash::digest(&block);
        block.body.sig = secure::sign_hash(&block_hash, &self.keys.network_skey);

        info!(
            "Created a monetary block: height={}, block={}, inputs={}, outputs={}",
            height,
            &block_hash,
            block.body.inputs.len(),
            block.body.outputs.leafs().len()
        );

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
        debug!(
            "Validating a key block: height={}, block={:?}",
            block.header.base.height, &request_hash
        );
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
                    "Discarded an invalid key block proposal: height={}, block={}, error={}",
                    block.header.base.height, &request_hash, e
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
                        NodeMessage::SubscribeEpoch(tx) => self.handle_subscribe_epoch(tx),
                        NodeMessage::SubscribeOutputs(tx) => self.handle_subscribe_outputs(tx),
                        NodeMessage::SubscribeInfo(tx) => self.handle_subscribe_info(tx),
                        NodeMessage::ElectionInfo => self.handle_election_info(),
                        NodeMessage::EscrowInfo => self.handle_escrow_info(),
                        NodeMessage::Transaction(msg) => Transaction::from_buffer(&msg)
                            .and_then(|msg| self.handle_transaction(msg)),
                        NodeMessage::Consensus(msg) => BlockConsensusMessage::from_buffer(&msg)
                            .and_then(|msg| self.handle_consensus_message(msg)),
                        NodeMessage::ViewChangeMessage(msg) => ViewChangeMessage::from_buffer(&msg)
                            .and_then(|msg| self.handle_view_change(msg)),
                        NodeMessage::SealedBlock(msg) => {
                            Block::from_buffer(&msg).and_then(|msg| self.handle_sealed_block(msg))
                        }
                        NodeMessage::ChainLoaderMessage(msg) => {
                            ChainLoaderMessage::from_buffer(&msg.data)
                                .and_then(|data| self.handle_chain_loader_message(msg.from, data))
                        }
                        NodeMessage::MicroBlockProposeTimer(_now) => {
                            self.handle_micro_block_propose_timer()
                        }
                        NodeMessage::MicroBlockViewChangeTimer(_now) => {
                            self.handle_micro_block_viewchange_timer()
                        }
                        NodeMessage::KeyBlockViewChangeTimer(_now) => {
                            self.handle_key_block_viewchange_timer()
                        }
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

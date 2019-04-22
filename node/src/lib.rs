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
#[macro_use]
pub mod timer;
mod validation;
pub use crate::config::ChainConfig;
use crate::error::*;
use crate::loader::ChainLoaderMessage;
use crate::mempool::Mempool;
use crate::timer::{Interval, TimerEvents};
use crate::validation::*;
use bitvector::BitVector;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::BTreeMap;
use std::time::SystemTime;
use std::time::{Duration, Instant};
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_blockchain::*;
use stegos_consensus::optimistic::{ViewChangeCollector, ViewChangeMessage};
use stegos_consensus::{self as consensus, BlockConsensus, BlockConsensusMessage};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_network::UnicastMessage;
use stegos_network::{NETWORK_READY_TOKEN, NETWORK_STATUS_TOPIC};
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::clock;

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

    /// Execute a Node Request.
    pub fn request(&self, request: NodeRequest) -> oneshot::Receiver<NodeResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = NodeMessage::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Subscribe to block changes.
    pub fn subscribe_block_added(&self) -> UnboundedReceiver<BlockAdded> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeBlockAdded(tx);
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Subscribe to epoch changes.
    pub fn subscribe_epoch_changed(&self) -> UnboundedReceiver<EpochChanged> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeEpochChanged(tx);
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Subscribe to UTXO changes.
    pub fn subscribe_outputs_changed(&self) -> UnboundedReceiver<OutputsChanged> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeOutputsChanged(tx);
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

///
/// RPC requests.
///
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum NodeRequest {
    ElectionInfo {},
    EscrowInfo {},
}

///
/// RPC responses.
///
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "response")]
#[serde(rename_all = "snake_case")]
pub enum NodeResponse {
    ElectionInfo(ElectionInfo),
    EscrowInfo(EscrowInfo),
}

/// Send when height is changed.
#[derive(Clone, Debug, Serialize)]
pub struct BlockAdded {
    pub height: u64,
    pub hash: Hash,
    pub lag: i64,
    pub view_change: u32,
    pub local_timestamp: i64,
    pub remote_timestamp: i64,
    pub synchronized: bool,
    pub epoch: u64,
}

/// Send when epoch is changed.
#[derive(Clone, Debug, Serialize)]
pub struct EpochChanged {
    pub epoch: u64,
    pub facilitator: secure::PublicKey,
    pub validators: Vec<(secure::PublicKey, i64)>,
}

/// Send when outputs created and/or pruned.
#[derive(Debug, Clone)]
pub struct OutputsChanged {
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

#[derive(Debug)]
pub enum NodeMessage {
    //
    // Public API
    //
    SubscribeBlockAdded(UnboundedSender<BlockAdded>),
    SubscribeEpochChanged(UnboundedSender<EpochChanged>),
    SubscribeOutputsChanged(UnboundedSender<OutputsChanged>),
    Request {
        request: NodeRequest,
        tx: oneshot::Sender<NodeResponse>,
    },
    //
    // Network Events
    //
    NetworkStatus(Vec<u8>),
    Transaction(Vec<u8>),
    Consensus(Vec<u8>),
    SealedBlock(Vec<u8>),
    ViewChangeMessage(Vec<u8>),
    ChainLoaderMessage(UnicastMessage),
}

pub struct NodeService {
    /// Config.
    cfg: ChainConfig,
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,

    /// A time when loader was started the last time
    last_sync_clock: Instant,

    /// Orphan blocks sorted by height.
    future_blocks: BTreeMap<u64, Block>,

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
    is_network_ready: bool,
    /// Triggered when height is changed.
    on_block_added: Vec<UnboundedSender<BlockAdded>>,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochChanged>>,
    /// Triggered when outputs created and/or pruned.
    on_outputs_changed: Vec<UnboundedSender<OutputsChanged>>,
    /// Aggregated stream of events.
    events: Box<Stream<Item = NodeMessage, Error = ()> + Send>,
    /// timer events
    key_block_timer: Interval,
    view_change_timer: Interval,
    propose_timer: Interval,
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
        let last_sync_clock = clock::now();
        let future_consensus_messages = Vec::new();
        let future_blocks: BTreeMap<u64, Block> = BTreeMap::new();
        let mempool = Mempool::new();

        let consensus = None;
        let optimistic =
            ViewChangeCollector::new(&chain, keys.network_pkey, keys.network_skey.clone());
        let last_block_clock = clock::now();
        let is_network_ready = false;

        let on_block_added = Vec::<UnboundedSender<BlockAdded>>::new();
        let on_epoch_changed = Vec::<UnboundedSender<EpochChanged>>::new();
        let on_outputs_changed = Vec::<UnboundedSender<OutputsChanged>>::new();

        let mut streams = Vec::<Box<Stream<Item = NodeMessage, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Network Statuses
        let network_status_rx = network
            .subscribe(&NETWORK_STATUS_TOPIC)?
            .map(|m| NodeMessage::NetworkStatus(m));
        streams.push(Box::new(network_status_rx));

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

        let events = select_all(streams);
        // Timer for the micro block proposals.
        let propose_timer = Interval::new_interval(cfg.tx_wait_timeout);

        // Timer for the micro block view changes.
        let view_change_timer = Interval::new_interval(cfg.micro_block_timeout);

        // Timer for the key block view changes.
        let key_block_timer = Interval::new_interval(cfg.key_block_timeout);

        let mut service = NodeService {
            cfg,
            last_sync_clock,
            future_blocks,
            future_consensus_messages,
            chain,
            keys,
            mempool,
            consensus,
            optimistic,
            last_block_clock,
            network,
            is_network_ready,
            on_block_added,
            on_epoch_changed,
            on_outputs_changed,
            events,
            key_block_timer,
            propose_timer,
            view_change_timer,
        };

        // Recover consensus status.
        if service.chain.blocks_in_epoch() < service.cfg.blocks_in_epoch {
            debug!("The next block is a monetary block");
            service.on_new_epoch();
        } else {
            debug!("The next block is a key block");
            service.on_change_group()?;
        }

        Ok(service)
    }

    /// Handle network status changes.
    fn handle_network_status(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        if msg == NETWORK_READY_TOKEN {
            if self.is_network_ready {
                return Ok(());
            }
            self.is_network_ready = true;
            info!("Network is ready");
            if self.consensus.is_some() {
                self.on_new_consensus()?;
            }
            self.request_history()?;
        }
        Ok(())
    }

    /// Update consensus state, if chain has other view of consensus group.
    fn on_new_epoch(&mut self) {
        consensus::metrics::CONSENSUS_ROLE.set(consensus::metrics::ConsensusRole::Regular as i64);
        // Resign from Validator role.
        self.consensus = None;
        consensus::metrics::CONSENSUS_STATE
            .set(consensus::metrics::ConsensusState::NotInConsensus as i64);

        let msg = EpochChanged {
            epoch: self.chain.epoch(),
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
        let block_height = block.base_header().height;
        debug!(
            "Received a new block from the network: height={}, block={}, current_height={}, last_block={}",
            block_height,
            block_hash,
            self.chain.height(),
            self.chain.last_block_hash()
        );

        // Check height.
        if block_height <= self.chain.last_key_block_height() {
            // A duplicate block from a finalized epoch - ignore.
            debug!(
                "Skip an outdated block: height={}, block={}, current_height={}, last_block={}",
                block_height,
                block_hash,
                self.chain.height(),
                self.chain.last_block_hash()
            );
            return Ok(());
        } else if block_height < self.chain.height() {
            // A duplicate block from the current epoch - try to resolve forks.
            let local_block = self.chain.block_by_height(block_height)?;
            let local_block_hash = Hash::digest(&local_block);
            if local_block_hash == block_hash {
                debug!(
                    "Skip a duplicate block with the same hash: height={}, block={}, current_height={}, last_block={}",
                    block_height, local_block_hash, self.chain.height(), self.chain.last_block_hash(),
                );
                return Ok(());
            }

            warn!(
                "A fork detected: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, current_height={}, last_block={}",
                block_height,
                local_block_hash,
                block_hash,
                local_block.base_header().previous,
                block.base_header().previous,
                self.chain.height(),
                self.chain.last_block_hash()
            );

            // TODO: implement fork resolution.
            metrics::FORKS.inc();

            return Ok(());
        } else if block_height > self.chain.height() + self.cfg.blocks_in_epoch {
            // Don't queue all blocks from epoch + 1 to limit the size of self.future_blocks.
            warn!("Skipped an orphan block from the future: height={}, block={}, current_height={}, last_block={}",
                  block_height,
                  block_hash,
                  self.chain.height(),
                  self.chain.last_block_hash()
            );
            self.request_history()?;
            return Ok(());
        } else if block_height > self.chain.height() {
            // Queue blocks with chain.height < height <= chain.height + blocks_in_epoch.
            self.future_blocks.insert(block_height, block); // ignore dups
            debug!("Queued an orphan block from the future: height={}, block={}, current_height={}, last_block={}",
                  block_height,
                  block_hash,
                  self.chain.height(),
                  self.chain.last_block_hash()
            );
            self.request_history()?;
            return Ok(());
        }

        // Apply received block.
        assert_eq!(block_height, self.chain.height());
        assert!(!self.future_blocks.contains_key(&block_height));
        self.apply_new_block(block)?;

        // Try to process orphan blocks.
        while let Some(block) = self.future_blocks.remove(&self.chain.height()) {
            self.apply_new_block(block)?;
        }

        Ok(())
    }

    /// Try to apply a new block to the blockchain.
    fn apply_new_block(&mut self, block: Block) -> Result<(), Error> {
        let hash = Hash::digest(&block);
        let timestamp = block.base_header().timestamp;
        let height = block.base_header().height;
        let view_change = block.base_header().view_change;
        match block {
            Block::KeyBlock(key_block) => {
                let was_synchronized = self.is_synchronized();

                // Check for the correct block order.
                if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
                    return Err(
                        NodeBlockError::ExpectedMonetaryBlock(self.chain.height(), hash).into(),
                    );
                }

                // Check consensus.
                if let Some(consensus) = &mut self.consensus {
                    if consensus.should_commit() {
                        // Check for forks.
                        let (consensus_block, _proof) = consensus.get_proposal();
                        let consensus_block_hash = Hash::digest(consensus_block);
                        if hash != consensus_block_hash {
                            panic!(
                                "Network fork: received_block={:?}, consensus_block={:?}",
                                &hash, &consensus_block_hash
                            );
                        }
                    }
                }
                self.chain.push_key_block(key_block)?;

                if !was_synchronized && self.is_synchronized() {
                    info!(
                        "Synchronized with the network: height={}, last_block={}",
                        self.chain.height(),
                        self.chain.last_block_hash()
                    );
                    metrics::SYNCHRONIZED.set(1);
                }

                self.on_new_epoch();
            }
            Block::MonetaryBlock(monetary_block) => {
                // Check for the correct block order.
                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    return Err(NodeBlockError::ExpectedKeyBlock(self.chain.height(), hash).into());
                }

                assert!(self.consensus.is_none(), "consensus is for key blocks only");

                let timestamp = SystemTime::now();

                // Check monetary adjustment.
                if self.chain.epoch() > 0
                    && monetary_block.header.monetary_adjustment != self.cfg.block_reward
                {
                    // TODO: support slashing.
                    return Err(NodeBlockError::InvalidMonetaryAdjustment(
                        height,
                        hash,
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
                let msg = OutputsChanged { inputs, outputs };
                self.on_outputs_changed
                    .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    self.on_change_group()?;
                }
                self.optimistic.on_new_payment_block(&self.chain)
            }
        }

        self.last_block_clock = clock::now();

        let local_timestamp = metrics::time_to_timestamp_ms(SystemTime::now());
        let remote_timestamp = metrics::time_to_timestamp_ms(timestamp);
        let lag = local_timestamp - remote_timestamp;
        metrics::BLOCK_REMOTE_TIMESTAMP.set(remote_timestamp);
        metrics::BLOCK_LOCAL_TIMESTAMP.set(local_timestamp);
        metrics::BLOCK_LAG.set(lag); // can be negative.

        let msg = BlockAdded {
            height,
            view_change,
            hash,
            lag,
            local_timestamp,
            remote_timestamp,
            synchronized: self.is_synchronized(),
            epoch: self.chain.epoch(),
        };
        self.on_block_added
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeHeight.
    fn handle_block_added(&mut self, tx: UnboundedSender<BlockAdded>) -> Result<(), Error> {
        self.on_block_added.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::SubscribeEpoch.
    fn handle_subscribe_epoch(&mut self, tx: UnboundedSender<EpochChanged>) -> Result<(), Error> {
        let msg = EpochChanged {
            epoch: self.chain.epoch(),
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
        tx: UnboundedSender<OutputsChanged>,
    ) -> Result<(), Error> {
        // Sent initial state.
        // TODO: this implementation can consume a lot of memory.
        let mut outputs: Vec<Output> = Vec::new();
        for output_hash in self.chain.unspent() {
            let output = self.chain.output_by_hash(output_hash)?.expect("exists");
            outputs.push(output);
        }
        let inputs = Vec::new();
        let msg = OutputsChanged { inputs, outputs };
        tx.unbounded_send(msg).ok(); // ignore error.
        self.on_outputs_changed.push(tx);
        Ok(())
    }

    /// Handler for new epoch creation procedure.
    /// This method called only on leader side, and when consensus is active.
    /// Leader should create a KeyBlock based on last random provided by VRF.
    fn create_key_block(&mut self) -> Result<(), Error> {
        let consensus = self.consensus.as_mut().unwrap();
        let timestamp = SystemTime::now();
        let view_change = consensus.round();

        let last_random = self.chain.last_random();
        let leader = consensus.leader();
        let blockchain = &self.chain;
        let keys = &self.keys;
        assert_eq!(&leader, &self.keys.network_pkey);

        let create_key_block = || {
            let seed = mix(last_random, view_change);
            let random = secure::make_VRF(&keys.network_skey, &seed);

            let previous = blockchain.last_block_hash();
            let height = blockchain.height();
            let epoch = blockchain.epoch() + 1;
            let base = BaseBlockHeader::new(VERSION, previous, height, view_change, timestamp);
            debug!(
                "Creating a new key block proposal: height={}, epoch={}, leader={:?}",
                height,
                blockchain.epoch() + 1,
                leader
            );

            let validators = blockchain.validators();
            let mut block = KeyBlock::new(base, random);

            let block_hash = Hash::digest(&block);

            // Create initial multi-signature.
            let (multisig, multisigmap) = create_proposal_signature(
                &block_hash,
                &keys.network_skey,
                &keys.network_pkey,
                validators,
            );
            block.body.multisig = multisig;
            block.body.multisigmap = multisigmap;

            // Validate the block via blockchain (just double-checking here).
            blockchain
                .validate_key_block(&block, true)
                .expect("proposed key block is valid");

            info!(
                "Created a new key block proposal: height={}, epoch={}, hash={}",
                height, epoch, block_hash
            );

            let proof = ();
            (block, proof)
        };

        consensus.propose(create_key_block);
        NodeService::flush_consensus_messages(consensus, &mut self.network)
    }

    /// Send block to network.
    fn send_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let block_height = block.base_header().height;
        let data = block.into_buffer()?;
        // Don't send block to myself.
        self.network.publish(&SEALED_BLOCK_TOPIC, data)?;
        info!(
            "Sent sealed block to the network: height={}, block={}",
            block_height, block_hash
        );
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

        let consensus = BlockConsensus::new(
            self.chain.height() as u64,
            self.chain.epoch() + 1,
            self.keys.network_skey.clone(),
            self.keys.network_pkey.clone(),
            self.chain.view_change(),
            self.chain.election_result(),
            self.chain.validators().iter().cloned().collect(),
        );
        self.consensus = Some(consensus);
        self.on_new_consensus()?;

        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Consensus
    //----------------------------------------------------------------------------------------------

    ///
    /// Try to process messages with new consensus.
    ///
    fn on_new_consensus(&mut self) -> Result<(), Error> {
        if !self.is_network_ready {
            return Ok(());
        }

        info!("I am a part of consensus, trying to choose a new group");
        // update timer, set current_time to now().
        let consensus = self.consensus.as_ref().unwrap();
        //self.key_block_timer
        //    .reset(self.cfg.key_block_timeout * consensus.round());
        self.key_block_timer.reset(self.cfg.key_block_timeout);
        if consensus.should_propose() {
            self.create_key_block()?;
        } else {
            info!(
                "Waiting for a key block: height={}, last_block={}, epoch={}, leader={}",
                self.chain.height(),
                self.chain.last_block_hash(),
                self.chain.epoch(),
                self.chain.leader(),
            );
        }

        let outbox = std::mem::replace(&mut self.future_consensus_messages, Vec::new());
        for msg in outbox {
            if let Err(e) = self.handle_consensus_message(msg) {
                debug!("Error in future consensus message: {}", e);
            }
        }

        Ok(())
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
        if self.consensus.is_none() {
            self.future_consensus_messages.push(msg);
            return Ok(());
        }
        let validate_request = |request_hash: Hash, block: &KeyBlock, round| {
            validate_proposed_key_block(&self.cfg, &self.chain, round, request_hash, block)
        };
        // Validate signature and content.
        msg.validate(validate_request)?;
        let consensus = self.consensus.as_mut().unwrap();
        consensus.feed_message(msg)?;
        // Flush pending messages.
        NodeService::flush_consensus_messages(consensus, &mut self.network)?;

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
        if !self.is_network_ready {
            return Ok(());
        }

        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);

        // Check that a new payment block should be created.
        if self.consensus.is_none() && elapsed >= self.cfg.tx_wait_timeout && self.is_leader() {
            assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);
            self.create_monetary_block(None)?;
        }

        Ok(())
    }

    /// True if the node is synchronized with the network.
    fn is_synchronized(&self) -> bool {
        let timestamp = SystemTime::now();
        let block_timestamp = self.chain.last_key_block_timestamp();
        block_timestamp
            + self.cfg.micro_block_timeout * (self.cfg.blocks_in_epoch as u32)
            + self.cfg.key_block_timeout
            >= timestamp
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_key_block_viewchange_timer(&mut self) -> Result<(), Error> {
        if self.consensus.is_none() || !self.is_network_ready {
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a key block: height={}",
            self.chain.height(),
        );

        // Check that a block has been committed but haven't send by the leader.
        if let Some(ref mut consensus) = self.consensus {
            if consensus.should_commit() {
                assert!(!consensus.is_leader(), "never happens on leader");
                let (block, _proof, mut multisig, mut multisigmap) = consensus.sign_and_commit();
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
            } else {
                // not at commit phase, go to the next round
                consensus.next_round();
                self.on_new_consensus()?;
            }
        };

        // Try to sync with the network.
        metrics::SYNCHRONIZED.set(0);
        self.request_history()?;

        // Try to perform the view change.
        metrics::KEY_BLOCK_VIEW_CHANGES.inc();

        Ok(())
    }

    //
    // Optimisitc consensus
    //

    fn handle_view_change(&mut self, msg: ViewChangeMessage) -> Result<(), Error> {
        if let Some(proof) = self.optimistic.handle_message(&self.chain, msg)? {
            debug!(
                "Received enough messages for change leader: height={}, last_block={}, view_change={}",
                self.chain.height(), self.chain.last_block_hash(), self.chain.view_change()
            );
            self.chain.set_view_change(self.chain.view_change() + 1);

            //TODO: save proof if you are not leader.
            if self.is_leader() {
                debug!(
                    "We are leader, producing new monetary block: height={}, last_block={}",
                    self.chain.height(),
                    self.chain.last_block_hash()
                );
                self.create_monetary_block(Some(proof))?;
            };
        }
        Ok(())
    }

    /// Checks if it's time to perform a view change on a monetary block.
    fn handle_micro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        if !self.is_network_ready {
            return Ok(());
        }

        // Check status of the monetary block.
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);
        if self.consensus.is_some() || elapsed < self.cfg.micro_block_timeout {
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a monetary block: height={}, elapsed={:?}",
            self.chain.height(),
            elapsed
        );

        // Try to sync with the network.
        metrics::SYNCHRONIZED.set(0);
        self.request_history()?;

        // Try to perform the view change.
        metrics::MICRO_BLOCK_VIEW_CHANGES.inc();
        if let Some(msg) = self.optimistic.handle_timeout(&self.chain)? {
            self.network
                .publish(VIEW_CHANGE_TOPIC, msg.into_buffer()?)?;
            self.handle_view_change(msg)?;
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

    /// poll internal intervals.
    ///
    /// ## Panics:
    /// If some of intevals return None.
    /// If some timer fails.
    pub fn poll_timers(&mut self) -> Async<TimerEvents> {
        poll_timer!(TimerEvents::KeyBlockViewChangeTimer => self.key_block_timer);
        poll_timer!(TimerEvents::MicroBlockViewChangeTimer => self.view_change_timer);
        poll_timer!(TimerEvents::MicroBlockProposeTimer => self.propose_timer);
        return Async::NotReady;
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Async::Ready(item) = self.poll_timers() {
            let result = match item {
                TimerEvents::MicroBlockProposeTimer(_now) => {
                    self.handle_micro_block_propose_timer()
                }
                TimerEvents::MicroBlockViewChangeTimer(_now) => {
                    self.handle_micro_block_viewchange_timer()
                }
                TimerEvents::KeyBlockViewChangeTimer(_now) => {
                    self.handle_key_block_viewchange_timer()
                }
            };
            if let Err(e) = result {
                error!("Error: {}", e);
            }
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        NodeMessage::SubscribeBlockAdded(tx) => self.handle_block_added(tx),
                        NodeMessage::SubscribeEpochChanged(tx) => self.handle_subscribe_epoch(tx),
                        NodeMessage::SubscribeOutputsChanged(tx) => {
                            self.handle_subscribe_outputs(tx)
                        }
                        NodeMessage::Request { request, tx } => {
                            let response = match request {
                                NodeRequest::ElectionInfo {} => {
                                    NodeResponse::ElectionInfo(self.chain.election_info())
                                }
                                NodeRequest::EscrowInfo {} => {
                                    NodeResponse::EscrowInfo(self.chain.escrow().info())
                                }
                            };
                            tx.send(response).ok(); // ignore errors.
                            Ok(())
                        }
                        NodeMessage::NetworkStatus(msg) => self.handle_network_status(msg),
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

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

    pub fn send_restaking_transaction(&self, tx: RestakeTransaction) -> Result<(), Error> {
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        self.network.publish(&RESTAKE_TOPIC, data.clone())?;
        info!("Sent transaction to the network: tx={}", Hash::digest(&tx));
        let msg = NodeMessage::RestakeTransaction(data);
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

    /// Revert the latest block.
    pub fn pop_block(&self) {
        let msg = NodeMessage::PopBlock;
        self.outbox.unbounded_send(msg).expect("connected");
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
    pub epoch: u64,
    pub inputs: Vec<Output>,
    pub outputs: Vec<Output>,
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// Topic used for sending transactions.
const TX_TOPIC: &'static str = "tx";
/// Topic used for restaking transactions.
const RESTAKE_TOPIC: &'static str = "restake";
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
    PopBlock,
    Request {
        request: NodeRequest,
        tx: oneshot::Sender<NodeResponse>,
    },
    //
    // Network Events
    //
    Transaction(Vec<u8>),
    RestakeTransaction(Vec<u8>),
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
    /// Triggered when height is changed.
    on_block_added: Vec<UnboundedSender<BlockAdded>>,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochChanged>>,
    /// Triggered when outputs created and/or pruned.
    on_outputs_changed: Vec<UnboundedSender<OutputsChanged>>,
    /// Aggregated stream of events.
    events: Box<Stream<Item = NodeMessage, Error = ()> + Send>,
    /// timer events
    macro_block_timer: Interval,
    view_change_timer: Interval,
    propose_timer: Interval,
}

impl NodeService {
    /// Constructor.
    pub fn new(
        cfg: ChainConfig,
        chain: Blockchain,
        keys: KeyChain,
        network: Network,
    ) -> Result<(Self, Node), Error> {
        let (outbox, inbox) = unbounded();
        let last_sync_clock = clock::now();
        let future_consensus_messages = Vec::new();
        let future_blocks: BTreeMap<u64, Block> = BTreeMap::new();
        let mempool = Mempool::new();

        let consensus = None;
        let optimistic =
            ViewChangeCollector::new(&chain, keys.network_pkey, keys.network_skey.clone());
        let last_block_clock = clock::now();

        let on_block_added = Vec::<UnboundedSender<BlockAdded>>::new();
        let on_epoch_changed = Vec::<UnboundedSender<EpochChanged>>::new();
        let on_outputs_changed = Vec::<UnboundedSender<OutputsChanged>>::new();

        let mut streams = Vec::<Box<Stream<Item = NodeMessage, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Transaction Requests
        let transaction_rx = network
            .subscribe(&TX_TOPIC)?
            .map(|m| NodeMessage::Transaction(m));
        streams.push(Box::new(transaction_rx));

        // RestakeTransaction Requests
        let transaction_rx = network
            .subscribe(&RESTAKE_TOPIC)?
            .map(|m| NodeMessage::RestakeTransaction(m));
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

        // Timer for the macro block view changes.
        let macro_block_timer = Interval::new_interval(cfg.macro_block_timeout);

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
            network: network.clone(),
            on_block_added,
            on_epoch_changed,
            on_outputs_changed,
            events,
            macro_block_timer,
            propose_timer,
            view_change_timer,
        };
        service.recover_consensus_state()?;

        let handler = Node {
            outbox,
            network: network.clone(),
        };

        Ok((service, handler))
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

    /// Handle an incoming restaking transaction from network.
    fn handle_restaking_transaction(&mut self, _tx: RestakeTransaction) -> Result<(), Error> {
        Ok(()) // dummy up for now
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

        // Limit the number of inputs and outputs.
        let utxo_count = tx.body.txins.len() + tx.body.txouts.len();
        if utxo_count > self.cfg.max_utxo_in_tx {
            return Err(NodeTransactionError::TooLarge(
                tx_hash,
                utxo_count,
                self.cfg.max_utxo_in_tx,
            )
            .into());
        }

        // Limit the maximum size of mempool.
        let utxo_in_mempool = self.mempool.inputs_len() + self.mempool.outputs_len();
        if utxo_in_mempool > self.cfg.max_utxo_in_mempool {
            return Err(NodeTransactionError::MempoolIsFull(tx_hash).into());
        }

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
        metrics::MEMPOOL_TRANSACTIONS.set(self.mempool.len() as i64);
        metrics::MEMPOOL_INPUTS.set(self.mempool.inputs_len() as i64);
        metrics::MEMPOOL_OUTPUTS.set(self.mempool.inputs_len() as i64);

        Ok(())
    }

    ///
    /// Resolve a fork using a duplicate micro block from the current epoch.
    ///
    fn resolve_fork(&mut self, remote: Block) -> Result<(), Error> {
        let height = remote.base_header().height;
        assert!(height < self.chain.height());
        assert!(height > 0);
        assert!(height > self.chain.last_macro_block_height());

        let remote_hash = Hash::digest(&remote);
        let remote = match remote {
            Block::MicroBlock(remote) => remote,
            _ => {
                return Err(NodeBlockError::ExpectedMicroBlock(height, remote_hash).into());
            }
        };

        // Check signature first.
        let remote_view_change = remote.base.view_change;

        let previous_block = self.chain.block_by_height(height - 1)?;
        let mut election_result = self.chain.election_result();
        election_result.random = previous_block.base_header().random;
        let leader = election_result.select_leader(remote_view_change);
        if leader != remote.pkey {
            return Err(BlockError::DifferentPublicKey(leader, remote.pkey).into());
        }
        if let Err(_e) = secure::check_hash(&remote_hash, &remote.sig, &leader) {
            return Err(BlockError::InvalidLeaderSignature(height, remote_hash).into());
        }

        // Get local block.
        let local = self.chain.block_by_height(height)?;
        let local_hash = Hash::digest(&local);
        let local = match local {
            Block::MicroBlock(local) => local,
            _ => {
                let e = NodeBlockError::ExpectedMicroBlock(height, local_hash);
                panic!("{}", e);
            }
        };
        let local_view_change = local.base.view_change;

        debug!("Started fork resolution: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, local_proof={:?}, remote_proof={:?}, current_height={}, last_block={}",
               height,
               local_hash,
               remote_hash,
               local.base.previous,
               remote.base.previous,
               local_view_change,
               remote_view_change,
               local.view_change_proof,
               remote.view_change_proof,
               self.chain.height(),
               self.chain.last_block_hash());

        // Check view_change.
        if remote_view_change < local_view_change {
            warn!("Discarded a block with lesser view_change: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
                  height,
                  local_hash,
                  remote_hash,
                  local.base.previous,
                  remote.base.previous,
                  local_view_change,
                  remote_view_change,
                  self.chain.height(),
                  self.chain.last_block_hash());
            return Ok(());
        } else if remote_view_change == local_view_change {
            if local_hash == remote_hash {
                debug!(
                    "Skip a duplicate block with the same hash: height={}, block={}, current_height={}, last_block={}",
                    height, local_hash, self.chain.height(), self.chain.last_block_hash(),
                );
                return Ok(());
            }

            warn!("Two micro-blocks from the same leader detected: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
                  height,
                  local_hash,
                  remote_hash,
                  local.base.previous,
                  remote.base.previous,
                  local_view_change,
                  remote_view_change,
                  self.chain.height(),
                  self.chain.last_block_hash());

            metrics::CHEATS.inc();
            // TODO: implement slashing.

            return Ok(());
        }

        assert!(remote_view_change > local_view_change);

        // Check previous hash.
        let previous = self.chain.block_by_height(height - 1)?;
        let previous_hash = Hash::digest(&previous);
        if remote.base.previous != previous_hash {
            warn!("Found a block with invalid previous hash: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
                  height,
                  local_hash,
                  remote_hash,
                  local.base.previous,
                  remote.base.previous,
                  local_view_change,
                  remote_view_change,
                  self.chain.height(),
                  self.chain.last_block_hash());
            // Request history from that node.
            let from = self.chain.select_leader(remote_view_change);
            self.request_history_from(from)?;
            return Ok(());
        }

        // Check the proof.
        assert_eq!(remote.base.previous, previous_hash);
        let chain = ChainInfo::from_block(&remote.base);
        match remote.view_change_proof {
            Some(ref proof) => {
                if let Err(e) = proof.validate(&chain, &self.chain) {
                    return Err(BlockError::InvalidViewChangeProof(
                        height,
                        remote_hash,
                        proof.clone(),
                        e,
                    )
                    .into());
                }
            }
            None => {
                return Err(BlockError::NoProofWasFound(
                    height,
                    remote_hash,
                    remote_view_change,
                    local_view_change,
                )
                .into());
            }
        }

        metrics::FORKS.inc();

        warn!(
            "A fork detected: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
            height,
            local_hash,
            remote_hash,
            local.base.previous,
            remote.base.previous,
            local_view_change,
            remote_view_change,
            self.chain.height(),
            self.chain.last_block_hash());

        // Truncate the blockchain.
        while self.chain.height() > height {
            let (inputs, outputs) = self.chain.pop_micro_block()?;
            let msg = OutputsChanged {
                epoch: self.chain.epoch(),
                inputs,
                outputs,
            };
            self.on_outputs_changed
                .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        }
        assert_eq!(height, self.chain.height());

        // Apply the block from this fork.
        self.apply_new_block(Block::MicroBlock(remote))?;
        if let Some((min_orphan_height, _block)) = self.future_blocks.iter().next() {
            assert!(
                *min_orphan_height > self.chain.height(),
                "nothing to process in orphan queue"
            );
        }

        // Request history from the new leader.
        self.request_history()?;

        return Ok(());
    }

    /// Handle incoming blocks received from network.
    fn handle_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let block_height = block.base_header().height;
        debug!(
            "Received a new block: height={}, block={}, view_change={}, current_height={}, last_block={}",
            block_height,
            block_hash,
            block.base_header().view_change,
            self.chain.height(),
            self.chain.last_block_hash()
        );

        // Check height.
        if block_height <= self.chain.last_macro_block_height() {
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
            return self.resolve_fork(block);
        } else if block_height > self.chain.last_macro_block_height() + self.cfg.blocks_in_epoch {
            // An orphan block from later epochs - ignore.
            warn!("Skipped an orphan block from the future: height={}, block={}, current_height={}, last_block={}",
                  block_height,
                  block_hash,
                  self.chain.height(),
                  self.chain.last_block_hash()
            );
            self.request_history()?;
            return Ok(());
        }

        // A block from the current epoch.
        assert!(block_height > self.chain.last_macro_block_height());
        assert!(block_height <= self.chain.last_macro_block_height() + self.cfg.blocks_in_epoch);
        let leader = self.chain.select_leader(block.base_header().view_change);

        // Check signature.
        match block {
            Block::MacroBlock(ref block) => {
                check_multi_signature(
                    &block_hash,
                    &block.body.multisig,
                    &block.body.multisigmap,
                    self.chain.validators(),
                    self.chain.total_slots(),
                )
                .map_err(|e| BlockError::InvalidBlockSignature(e, block_height, block_hash))?;
            }
            Block::MicroBlock(ref block) => {
                if let Err(_e) = secure::check_hash(&block_hash, &block.sig, &leader) {
                    return Err(BlockError::InvalidLeaderSignature(block_height, block_hash).into());
                }
            }
        }

        // Add this block to a queue.
        self.future_blocks.insert(block_height, block);

        // Process pending blocks.
        while let Some(block) = self.future_blocks.remove(&self.chain.height()) {
            let hash = Hash::digest(&block);
            let view_change = block.base_header().view_change;
            if let Err(e) = self.apply_new_block(block) {
                error!(
                    "Failed to apply block: height={}, block={}, error={}",
                    self.chain.height(),
                    hash,
                    e
                );

                if let Ok(BlockError::InvalidPreviousHash(_, _, _, _)) = e.downcast::<BlockError>()
                {
                    // A potential fork - request history from that node.
                    let from = self.chain.select_leader(view_change);
                    self.request_history_from(from)?;
                }

                break; // Stop processing.
            }
        }

        // Queue is not empty - request history from the current leader.
        if !self.future_blocks.is_empty() {
            for (height, block) in self.future_blocks.iter() {
                debug!(
                    "Orphan block: height={}, block={}, previous={}, current_height={}, last_block={}",
                    height,
                    Hash::digest(block),
                    block.base_header().previous,
                    self.chain.height(),
                    self.chain.last_block_hash()
                );
            }
            self.request_history()?;
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
            Block::MacroBlock(macro_block) => {
                let was_synchronized = self.is_synchronized();

                // Check for the correct block order.
                if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
                    return Err(
                        NodeBlockError::ExpectedMicroBlock(self.chain.height(), hash).into(),
                    );
                }

                // TODO: add rewards for MacroBlocks.
                if self.chain.epoch() > 0 && macro_block.header.block_reward != 0 {
                    // TODO: support slashing.
                    return Err(NodeBlockError::InvalidBlockReward(
                        height,
                        hash,
                        macro_block.header.block_reward,
                        self.cfg.block_reward,
                    )
                    .into());
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
                self.chain.push_macro_block(macro_block, timestamp)?;

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
            Block::MicroBlock(micro_block) => {
                // Check for the correct block order.
                if self.chain.blocks_in_epoch() >= self.cfg.blocks_in_epoch {
                    return Err(NodeBlockError::ExpectedKeyBlock(self.chain.height(), hash).into());
                }

                assert!(
                    self.consensus.is_none(),
                    "consensus is for macro blocks only"
                );

                let timestamp = SystemTime::now();

                // Check block reward.
                if self.chain.epoch() > 0
                    && micro_block.coinbase.block_reward != self.cfg.block_reward
                {
                    // TODO: support slashing.
                    return Err(NodeBlockError::InvalidBlockReward(
                        height,
                        hash,
                        micro_block.coinbase.block_reward,
                        self.cfg.block_reward,
                    )
                    .into());
                }

                let (inputs, outputs) = self.chain.push_micro_block(micro_block, timestamp)?;

                // Remove old transactions from the mempool.
                let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
                let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
                self.mempool.prune(&input_hashes, &output_hashes);
                metrics::MEMPOOL_TRANSACTIONS.set(self.mempool.len() as i64);
                metrics::MEMPOOL_INPUTS.set(self.mempool.inputs_len() as i64);
                metrics::MEMPOOL_OUTPUTS.set(self.mempool.inputs_len() as i64);

                // Notify subscribers.
                let msg = OutputsChanged {
                    epoch: self.chain.epoch(),
                    inputs,
                    outputs,
                };
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
        self.on_outputs_changed.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::PopBlock.
    fn handle_pop_block(&mut self) -> Result<(), Error> {
        warn!("Received a request to revert the latest block");
        if self.chain.blocks_in_epoch() > 1 {
            self.chain.pop_micro_block()?;
            self.recover_consensus_state()?
        } else {
            error!(
                "Attempt to revert a macro block: height={}",
                self.chain.height()
            );
        }
        Ok(())
    }

    /// Handler for new epoch creation procedure.
    /// This method called only on leader side, and when consensus is active.
    /// Leader should create a KeyBlock based on last random provided by VRF.
    fn create_new_epoch(&mut self) -> Result<(), Error> {
        let consensus = self.consensus.as_mut().unwrap();
        let timestamp = SystemTime::now();
        let view_change = consensus.round();

        let last_random = self.chain.last_random();
        let leader = consensus.leader();
        let blockchain = &self.chain;
        let keys = &self.keys;
        assert_eq!(&leader, &self.keys.network_pkey);

        let create_macro_block = || {
            let seed = mix(last_random, view_change);
            let random = secure::make_VRF(&keys.network_skey, &seed);

            let previous = blockchain.last_block_hash();
            let height = blockchain.height();
            let epoch = blockchain.epoch() + 1;
            let base =
                BaseBlockHeader::new(VERSION, previous, height, view_change, timestamp, random);
            debug!(
                "Creating a new macro block proposal: height={}, epoch={}, leader={:?}",
                height,
                blockchain.epoch() + 1,
                leader
            );

            let validators = blockchain.validators();
            let mut block = MacroBlock::empty(base, keys.network_pkey);

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
                .validate_macro_block(&block, timestamp, true)
                .expect("proposed macro block is valid");

            info!(
                "Created a new macro block proposal: height={}, epoch={}, hash={}",
                height, epoch, block_hash
            );

            let proof = ();
            (block, proof)
        };

        consensus.propose(create_macro_block);
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

        info!("I am a part of consensus, trying choose new group.");
        let leader = self.chain.leader();
        let consensus = BlockConsensus::new(
            self.chain.height() as u64,
            self.chain.epoch() + 1,
            self.keys.network_skey.clone(),
            self.keys.network_pkey.clone(),
            self.chain.election_result(),
            self.chain.validators().iter().cloned().collect(),
        );
        // update timer, set current_time to now().
        self.macro_block_timer.reset(self.cfg.macro_block_timeout);
        self.consensus = Some(consensus);
        let consensus = self.consensus.as_ref().unwrap();
        if consensus.is_leader() {
            self.create_new_epoch()?;
        } else {
            info!(
                "Waiting for a macro block: height={}, last_block={}, epoch={}, leader={}",
                self.chain.height(),
                self.chain.last_block_hash(),
                self.chain.epoch(),
                leader
            );
        }
        self.on_new_consensus();

        Ok(())
    }

    //----------------------------------------------------------------------------------------------
    // Consensus
    //----------------------------------------------------------------------------------------------

    ///
    /// Initialize consensus state after recovery.
    ///
    fn recover_consensus_state(&mut self) -> Result<(), Error> {
        // Recover consensus status.
        if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
            debug!(
                "The next block is a micro block: height={}, last_block={}",
                self.chain.height(),
                self.chain.last_block_hash()
            );
            self.on_new_epoch();
            Ok(())
        } else {
            debug!(
                "The next block is a macro block: height={}, last_block={}",
                self.chain.height(),
                self.chain.last_block_hash()
            );
            self.on_change_group()
        }
    }

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
        if self.consensus.is_none() {
            self.future_consensus_messages.push(msg);
            return Ok(());
        }
        let validate_request = |request_hash: Hash, block: &MacroBlock, round| {
            validate_proposed_macro_block(&self.cfg, &self.chain, round, request_hash, block)
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
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);

        // Check that a new payment block should be created.
        if self.consensus.is_none() && elapsed >= self.cfg.tx_wait_timeout && self.is_leader() {
            assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);
            self.create_micro_block(None)?;
        }

        Ok(())
    }

    /// True if the node is synchronized with the network.
    fn is_synchronized(&self) -> bool {
        let timestamp = SystemTime::now();
        let block_timestamp = self.chain.last_macro_block_timestamp();
        block_timestamp
            + self.cfg.micro_block_timeout * (self.cfg.blocks_in_epoch as u32)
            + self.cfg.macro_block_timeout
            >= timestamp
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_macro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        if self.consensus.is_none() {
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a macro block: height={}",
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
                assert!(self.chain.view_change() <= consensus.round());
                // not at commit phase, go to the next round
                consensus.next_round();
                let relevant_round = 1 + consensus.round() - self.chain.view_change();
                self.macro_block_timer
                    .reset(self.cfg.macro_block_timeout * relevant_round);
                let consensus = self.consensus.as_ref().unwrap();
                if consensus.is_leader() {
                    debug!("I am leader proposing a new block");
                    self.create_new_epoch()?;
                }
                self.on_new_consensus();
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
                    "We are leader, producing new micro block: height={}, last_block={}",
                    self.chain.height(),
                    self.chain.last_block_hash()
                );
                self.create_micro_block(Some(proof))?;
            };
        }
        Ok(())
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_micro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        // Check status of the micro block.
        let elapsed: Duration = clock::now().duration_since(self.last_block_clock);
        if self.consensus.is_some() || elapsed < self.cfg.micro_block_timeout {
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a micro block: height={}, elapsed={:?}",
            self.chain.height(),
            elapsed
        );

        // Try to sync with the network.
        metrics::SYNCHRONIZED.set(0);
        self.request_history()?;

        // Try to perform the view change.
        metrics::MICRO_BLOCK_VIEW_CHANGES.inc();
        if let Some(msg) = self.optimistic.handle_timeout(&self.chain)? {
            debug!(
                "Sent a view change to the network: height={}, view_change={}, last_block={}",
                msg.chain.height, msg.chain.view_change, msg.chain.last_block
            );
            self.network
                .publish(VIEW_CHANGE_TOPIC, msg.into_buffer()?)?;
            self.handle_view_change(msg)?;
        }

        Ok(())
    }

    ///
    /// Create a new micro block.
    ///
    fn create_micro_block(&mut self, proof: Option<ViewChangeProof>) -> Result<(), Error> {
        assert!(self.consensus.is_none());
        assert!(self.is_leader());
        assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);

        let height = self.chain.height();
        let previous = self.chain.last_block_hash();
        info!(
            "I'm leader, proposing a new micro block: height={}, last_block={}",
            height, previous
        );
        // Create a new micro block from the mempool.
        let mut block = self.mempool.create_block(
            previous,
            VERSION,
            self.chain.height(),
            self.cfg.block_reward,
            &self.keys,
            self.chain.last_random(),
            self.chain.view_change(),
            proof,
            self.cfg.max_utxo_in_block,
        );
        let block_hash = Hash::digest(&block);

        // Sign block.
        block.sign(&self.keys.network_skey, &self.keys.network_pkey);

        info!(
            "Created a micro block: height={}, block={}, transactions={}",
            height,
            &block_hash,
            block.transactions.len(),
        );

        // TODO: swap send_sealed_block() and apply_new_block() order after removing VRF.
        let block2 = block.clone();
        self.send_sealed_block(Block::MicroBlock(block2))
            .expect("failed to send sealed micro block");
        self.apply_new_block(Block::MicroBlock(block))?;

        Ok(())
    }

    ///
    /// Commit sealed block into blockchain and send it to the network.
    /// NOTE: commit must never fail. Please don't use Result<(), Error> here.
    ///
    fn commit_proposed_block(
        &mut self,
        mut macro_block: MacroBlock,
        multisig: secure::Signature,
        multisigmap: BitVector,
    ) {
        macro_block.body.multisig = multisig;
        macro_block.body.multisigmap = multisigmap;
        let macro_block2 = macro_block.clone();
        self.apply_new_block(Block::MacroBlock(macro_block))
            .expect("block is validated before");
        self.send_sealed_block(Block::MacroBlock(macro_block2))
            .expect("failed to send sealed micro block");
    }

    /// poll internal intervals.
    ///
    /// ## Panics:
    /// If some of intevals return None.
    /// If some timer fails.
    pub fn poll_timers(&mut self) -> Async<TimerEvents> {
        poll_timer!(TimerEvents::KeyBlockViewChangeTimer => self.macro_block_timer);
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
                    self.handle_macro_block_viewchange_timer()
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
                        NodeMessage::PopBlock => self.handle_pop_block(),
                        NodeMessage::Request { request, tx } => {
                            let response = match request {
                                NodeRequest::ElectionInfo {} => {
                                    NodeResponse::ElectionInfo(self.chain.election_info())
                                }
                                NodeRequest::EscrowInfo {} => {
                                    NodeResponse::EscrowInfo(self.chain.escrow_info())
                                }
                            };
                            tx.send(response).ok(); // ignore errors.
                            Ok(())
                        }
                        NodeMessage::Transaction(msg) => Transaction::from_buffer(&msg)
                            .and_then(|msg| self.handle_transaction(msg)),
                        NodeMessage::RestakeTransaction(msg) => {
                            RestakeTransaction::from_buffer(&msg)
                                .and_then(|msg| self.handle_restaking_transaction(msg))
                        }
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

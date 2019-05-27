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
mod proposal;
pub mod protos;
#[cfg(test)]
mod test;
mod validation;
pub use crate::config::ChainConfig;
use crate::error::*;
use crate::loader::ChainLoaderMessage;
use crate::mempool::Mempool;
use crate::validation::*;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use futures::{task, Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;
use std::time::SystemTime;
use stegos_blockchain::*;
use stegos_consensus::optimistic::{SealedViewChangeProof, ViewChangeCollector, ViewChangeMessage};
use stegos_consensus::{self as consensus, Consensus, ConsensusMessage};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_network::UnicastMessage;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::{clock, Delay};

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
    pub facilitator: pbc::PublicKey,
    pub validators: Vec<(pbc::PublicKey, i64)>,
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
/// Topic used for consensus.
const CONSENSUS_TOPIC: &'static str = "consensus";
/// Topic for ViewChange message.
pub const VIEW_CHANGE_TOPIC: &'static str = "view_changes";
/// Topic for ViewChange proofs.
pub const VIEW_CHANGE_DIRECT: &'static str = "view_changes_direct";
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
    Consensus(Vec<u8>),
    SealedBlock(Vec<u8>),
    ViewChangeMessage(Vec<u8>),
    ViewChangeProofMessage(UnicastMessage),
    ChainLoaderMessage(UnicastMessage),
}

enum BlockTimer {
    None,
    Propose(Delay),
    ViewChange(Delay),
}

enum Validation {
    MicroBlockAuditor,
    MicroBlockValidator {
        /// Collector of view change.
        view_change_collector: ViewChangeCollector,
        /// Propose or View Change timer
        block_timer: BlockTimer,
        /// A queue of consensus message from the future epoch.
        // TODO: Resolve unknown blocks using requests-responses.
        future_consensus_messages: Vec<ConsensusMessage>,
    },
    MacroBlockAuditor,
    MacroBlockValidator {
        /// pBFT consensus,
        consensus: Consensus,
        /// Propose or View Change timer
        block_timer: BlockTimer,
    },
}
use Validation::*;

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

    /// Memory pool of pending transactions.
    mempool: Mempool,

    /// Consensus state.
    validation: Validation,

    /// Monotonic clock when the latest block was registered.
    last_block_clock: Instant,

    /// Cheating detection.
    cheating_proofs: HashMap<pbc::PublicKey, SlashingProof>,

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
        let future_blocks: BTreeMap<u64, Block> = BTreeMap::new();
        let mempool = Mempool::new();

        let last_block_clock = clock::now();
        let validation = if chain.blocks_in_epoch() < cfg.blocks_in_epoch {
            MicroBlockAuditor
        } else {
            MacroBlockAuditor
        };
        let cheating_proofs = HashMap::new();

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

        // Consensus Requests
        let consensus_rx = network
            .subscribe(&CONSENSUS_TOPIC)?
            .map(|m| NodeMessage::Consensus(m));
        streams.push(Box::new(consensus_rx));

        let view_change_rx = network
            .subscribe(&VIEW_CHANGE_TOPIC)?
            .map(|m| NodeMessage::ViewChangeMessage(m));
        streams.push(Box::new(view_change_rx));

        let view_change_unicast_rx = network
            .subscribe_unicast(&VIEW_CHANGE_DIRECT)?
            .map(|m| NodeMessage::ViewChangeProofMessage(m));
        streams.push(Box::new(view_change_unicast_rx));

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

        let service = NodeService {
            cfg,
            last_sync_clock,
            future_blocks,
            chain,
            keys,
            mempool,
            validation,
            last_block_clock,
            cheating_proofs,
            network: network.clone(),
            on_block_added,
            on_epoch_changed,
            on_outputs_changed,
            events,
        };

        let handler = Node {
            outbox,
            network: network.clone(),
        };

        Ok((service, handler))
    }

    /// Invoked when network is ready.
    pub fn init(&mut self) -> Result<(), Error> {
        self.update_validation_status();
        self.request_history()?;
        Ok(())
    }

    /// Handle incoming transactions received from network.
    fn handle_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let tx_hash = Hash::digest(&tx);
        info!(
            "Received transaction from the network: tx={}, inputs={}, outputs={}, fee={}",
            &tx_hash,
            tx.txins().len(),
            tx.txouts().len(),
            tx.fee()
        );

        // Check that transaction has proper type.
        match &tx {
            Transaction::PaymentTransaction(_tx) => {}
            Transaction::RestakeTransaction(_tx) => {}
            _ => return Err(NodeTransactionError::InvalidType(tx_hash).into()),
        };

        // Limit the number of inputs and outputs.
        let utxo_count = tx.txins().len() + tx.txouts().len();
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
        validate_external_transaction(
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
    fn resolve_fork(&mut self, remote: &Block) -> ForkResult {
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

        let remote_view_change = remote.base.view_change;
        let local = self.chain.block_by_height(height)?;
        let local_hash = Hash::digest(&local);
        let local = match local {
            Block::MicroBlock(local) => local,
            _ => {
                let e = NodeBlockError::ExpectedMicroBlock(height, local_hash);
                panic!("{}", e);
            }
        };

        // check that validator is really leader for provided view_change.
        let previous_block = self.chain.block_by_height(height - 1)?;
        let mut election_result = self.chain.election_result();
        election_result.random = previous_block.base_header().random;
        let leader = election_result.select_leader(remote_view_change);
        if leader != remote.pkey {
            return Err(BlockError::DifferentPublicKey(leader, remote.pkey).into());
        };

        // check multiple blocks with same view_change
        if remote_view_change == local.base.view_change {
            if remote_hash == local_hash {
                debug!(
                    "Skip a duplicate block with the same hash: height={}, block={}, current_height={}, last_block={}",
                    height, remote_hash, self.chain.height(), self.chain.last_block_hash(),
                );
                return Err(ForkError::Canceled);
            }

            warn!("Two micro-blocks from the same leader detected: height={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
                  height,
                  local_hash,
                  remote_hash,
                  local.base.previous,
                  remote.base.previous,
                  local.base.view_change,
                  remote.base.view_change,
                  self.chain.height(),
                  self.chain.last_block_hash());

            metrics::CHEATS.inc();

            let proof = SlashingProof::new_unchecked(remote.clone(), local);

            if let Some(_proof) = self.cheating_proofs.insert(leader, proof) {
                debug!("Cheater was already detected: cheater = {}", leader);
            }

            return Err(ForkError::Canceled);
        } else if remote_view_change <= local.base.view_change {
            debug!(
                "Found a fork with lower view_change, sending blocks: pkey={}",
                leader
            );

            self.send_blocks(leader, height)?;
            return Err(ForkError::Canceled);
        }

        // Check the proof.
        let chain = ChainInfo::from_micro_block(&remote);
        let sealed_proof = match remote.view_change_proof {
            Some(ref proof) => SealedViewChangeProof {
                proof: proof.clone(),
                chain,
            },
            None => {
                return Err(BlockError::NoProofWasFound(
                    height,
                    remote_hash,
                    remote_view_change,
                    0,
                )
                .into());
            }
        };
        // seal proof, and try to resolve fork.
        return self.try_rollback(remote.pkey, sealed_proof);
    }

    /// We receive info about view_change, rollback the blocks, and set view_change to new.
    fn try_rollback(&mut self, pkey: pbc::PublicKey, proof: SealedViewChangeProof) -> ForkResult {
        let height = proof.chain.height;
        // Check height.
        if height <= self.chain.last_macro_block_height() {
            debug!(
                "Skip an outdated proof: height={}, current_height={}",
                height,
                self.chain.height()
            );
            return Err(ForkError::Canceled);
        }

        let local = if height < self.chain.height() {
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
            ChainInfo {
                height: local.base.height,
                last_block: local.base.previous,
                view_change: local.base.view_change,
            }
        } else if height == self.chain.height() {
            ChainInfo::from_blockchain(&self.chain)
        } else {
            debug!("Received proof with future height, ignoring for now: proof_height={}, our_height={}",
            height, self.chain.height());
            return Err(ForkError::Canceled);
        };

        let local_view_change = local.view_change;
        let remote_view_change = proof.chain.view_change;

        debug!("Started fork resolution: height={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, remote_proof={:?}, current_height={}",
               height,
               local.last_block,
               proof.chain.last_block,
               local_view_change,
               remote_view_change,
               proof.proof,
               self.chain.height(),
        );

        // Check view_change.
        if remote_view_change < local_view_change {
            warn!("View change proof with lesser or equal view_change: height={}, local_view_change={}, remote_view_change={}, current_height={}",
                  height,
                  local_view_change,
                  remote_view_change,
                  self.chain.height(),
            );
            return Err(ForkError::Canceled);
        }
        // Check previous hash.
        if proof.chain.last_block != local.last_block {
            warn!("Found a proof with invalid previous hash: height={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
                  height,
                  local.last_block,
                  proof.chain.last_block,
                  local_view_change,
                  remote_view_change,
                  self.chain.height(),
                  self.chain.last_block_hash());
            // Request history from that node.
            self.request_history_from(pkey)?;
            return Err(ForkError::Canceled);
        }

        assert!(remote_view_change >= local_view_change);
        assert_eq!(proof.chain.last_block, local.last_block);

        if let Err(e) = proof.proof.validate(&proof.chain, &self.chain) {
            return Err(BlockError::InvalidViewChangeProof(height, proof.proof, e).into());
        }

        metrics::FORKS.inc();

        warn!(
            "A fork detected: height={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_height={}, last_block={}",
            height,
            local.last_block,
            proof.chain.last_block,
            local_view_change,
            remote_view_change,
            self.chain.height(),
            self.chain.last_block_hash());

        // Truncate the blockchain.
        while self.chain.height() > height {
            let (inputs, outputs) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();
            let msg = OutputsChanged {
                epoch: self.chain.epoch(),
                inputs,
                outputs,
            };
            self.on_outputs_changed
                .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        }
        assert_eq!(height, self.chain.height());

        self.chain
            .set_view_change(proof.chain.view_change + 1, proof.proof);
        self.update_validation_status();
        Ok(())
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

        // Check block consistency.
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
                let leader = block.pkey;
                if let Err(_e) = pbc::check_hash(&block_hash, &block.sig, &leader) {
                    return Err(BlockError::InvalidLeaderSignature(block_height, block_hash).into());
                }
                if !self.chain.is_validator(&leader) {
                    return Err(BlockError::LeaderIsNotValidator(block_height, block_hash).into());
                }
            }
        }

        // A duplicate block from the current epoch - try to resolve forks.
        if block_height < self.chain.height() {
            match self.resolve_fork(&block) {
                //TODO: Notify sender about our blocks?
                Ok(()) => {
                    debug!(
                        "Fork resolution decide that remote chain is better: fork_height={}",
                        block_height
                    );
                    assert_eq!(
                        block_height,
                        self.chain.height(),
                        "Fork resolution rollback our chain"
                    );
                }
                Err(ForkError::Canceled) => {
                    debug!(
                        "Fork resolution decide that our chain is better: fork_height={}",
                        block_height
                    );
                    assert!(
                        block_height < self.chain.height(),
                        "Fork didn't remove any block"
                    );
                    return Ok(());
                }
                Err(ForkError::Error(e)) => return Err(e),
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
                match &mut self.validation {
                    MacroBlockAuditor => {}
                    MacroBlockValidator { consensus, .. } => {
                        if consensus.should_commit() {
                            // Check for forks.
                            let (consensus_block_hash, _block_proposal, _view_cahange) =
                                consensus.get_proposal();
                            if consensus_block_hash != consensus_block_hash {
                                panic!(
                                    "Network fork: received_block={:?}, consensus_block={:?}",
                                    &hash, &consensus_block_hash
                                );
                            }
                        }
                    }
                    _ => {
                        return Err(
                            NodeBlockError::ExpectedMacroBlock(self.chain.height(), hash).into(),
                        );
                    }
                }

                if self.chain.epoch() > 0
                    && macro_block.header.block_reward != self.cfg.block_reward
                {
                    // TODO: support slashing.
                    return Err(NodeBlockError::InvalidBlockReward(
                        height,
                        hash,
                        macro_block.header.block_reward,
                        self.cfg.block_reward,
                    )
                    .into());
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

                let msg = EpochChanged {
                    epoch: self.chain.epoch(),
                    validators: self.chain.validators().clone(),
                    facilitator: self.chain.facilitator().clone(),
                };
                self.on_epoch_changed
                    .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
                self.cheating_proofs.clear();
            }
            Block::MicroBlock(micro_block) => {
                // Check for the correct block order.
                // Check for the correct block order.
                match &self.validation {
                    MicroBlockAuditor | MicroBlockValidator { .. } => {}
                    _ => {
                        return Err(
                            NodeBlockError::ExpectedMicroBlock(self.chain.height(), hash).into(),
                        );
                    }
                }

                let timestamp = SystemTime::now();

                // Check block reward.
                if self.chain.epoch() > 0 {
                    if let Some(Transaction::CoinbaseTransaction(tx)) =
                        micro_block.transactions.get(0)
                    {
                        if tx.block_reward != self.cfg.block_reward {
                            // TODO: support slashing.
                            return Err(NodeBlockError::InvalidBlockReward(
                                height,
                                hash,
                                tx.block_reward,
                                self.cfg.block_reward,
                            )
                            .into());
                        }
                    } else {
                        // Force coinbase if reward is not zero.
                        return Err(BlockError::CoinbaseMustBeFirst(hash).into());
                    }
                }

                let leader = micro_block.pkey;
                let block_view_change = micro_block.base.view_change;
                let (inputs, outputs) = match self.chain.push_micro_block(micro_block, timestamp) {
                    Err(e @ BlockchainError::BlockError(BlockError::InvalidViewChange(..))) => {
                        warn!("Discarded a block with lesser view_change: block_view_change={}, our_view_change={}",
                              block_view_change, self.chain.view_change());

                        let mut chain = ChainInfo::from_blockchain(&self.chain);
                        let proof = self
                            .chain
                            .view_change_proof()
                            .clone()
                            .expect("last view_change proof.");
                        debug!(
                            "Sending view change proof to block sender: sender={}, proof={:?}",
                            leader, proof
                        );
                        // correct information about proof, to refer previous on view_change;
                        chain.view_change -= 1;
                        let proof = SealedViewChangeProof {
                            chain,
                            proof: proof.clone(),
                        };

                        self.network
                            .send(leader, VIEW_CHANGE_DIRECT, proof.into_buffer()?)?;
                        return Err(e.into());
                    }
                    Err(e) => return Err(e.into()),
                    Ok(v) => v,
                };
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

        self.update_validation_status();

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
            let (inputs, outputs) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();
            let msg = OutputsChanged {
                epoch: self.chain.epoch(),
                inputs,
                outputs,
            };
            self.on_outputs_changed
                .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
            self.update_validation_status()
        } else {
            error!(
                "Attempt to revert a macro block: height={}",
                self.chain.height()
            );
        }
        Ok(())
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

    //----------------------------------------------------------------------------------------------
    // Consensus
    //----------------------------------------------------------------------------------------------

    /// Called when a leader for the next micro block has changed.
    fn on_micro_block_leader_changed(&mut self) {
        let block_timer = match &mut self.validation {
            MicroBlockValidator { block_timer, .. } => block_timer,
            _ => panic!("Expected MicroBlockValidator State"),
        };

        let leader = self.chain.leader();
        if leader == self.keys.network_pkey {
            info!(
                "I'm leader, collecting transactions for the next micro block: height={}, view_change={}, last_block={}",
                self.chain.height(),
                self.chain.view_change(),
                self.chain.last_block_hash()
            );
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Leader as i64);
            let deadline = if self.chain.view_change() == 0 {
                // Wait some time to collect transactions.
                clock::now() + self.cfg.tx_wait_timeout
            } else {
                // Propose the new block immediately on the next event loop iteration.
                clock::now()
            };
            std::mem::replace(block_timer, BlockTimer::Propose(Delay::new(deadline)));
        } else {
            info!("I'm validator, waiting for the next micro block: height={}, view_change={}, last_block={}, leader={}",
                  self.chain.height(),
                  self.chain.view_change(),
                  self.chain.last_block_hash(),
                  leader);
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Validator as i64);
            let deadline = clock::now() + self.cfg.micro_block_timeout;
            std::mem::replace(block_timer, BlockTimer::ViewChange(Delay::new(deadline)));
        };

        task::current().notify();
    }

    /// Called when a leader for the next macro block has changed.
    fn on_macro_block_leader_changed(&mut self) {
        let (block_timer, consensus) = match &mut self.validation {
            MacroBlockValidator {
                block_timer,
                consensus,
                ..
            } => (block_timer, consensus),
            _ => panic!("Expected MacroBlockValidator State"),
        };

        if consensus.is_leader() {
            info!(
                "I'm leader, proposing the next macro block: height={}, view_change={}, last_block={}",
                self.chain.height(),
                consensus.round(),
                self.chain.last_block_hash()
            );
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Leader as i64);
            // Consensus may have locked proposal.
            if consensus.should_propose() {
                let deadline = clock::now();
                std::mem::replace(block_timer, BlockTimer::Propose(Delay::new(deadline)));
            }
        } else {
            info!(
                "I'm validator, waiting for the next macro block: height={}, view_change={}, last_block={}, leader={}",
                self.chain.height(),
                consensus.round(),
                self.chain.last_block_hash(),
                consensus.leader(),
            );
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Validator as i64);
            let relevant_round = 1 + consensus.round();
            let deadline = clock::now() + relevant_round * self.cfg.macro_block_timeout;
            std::mem::replace(block_timer, BlockTimer::ViewChange(Delay::new(deadline)));
        }

        task::current().notify();
    }

    ///
    /// Change validation status after applying a new block or performing a view change.
    ///
    fn update_validation_status(&mut self) {
        if self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch {
            // Expected Micro Block.
            let _prev = std::mem::replace(&mut self.validation, MicroBlockAuditor);
            if !self.chain.is_validator(&self.keys.network_pkey) {
                info!("I'm auditor, waiting for the next micro block: height={}, view_change={}, last_block={}",
                      self.chain.height(),
                      self.chain.view_change(),
                      self.chain.last_block_hash()
                );
                consensus::metrics::CONSENSUS_ROLE
                    .set(consensus::metrics::ConsensusRole::Regular as i64);
                return;
            }

            let view_change_collector = ViewChangeCollector::new(
                &self.chain,
                self.keys.network_pkey,
                self.keys.network_skey.clone(),
            );

            self.validation = MicroBlockValidator {
                view_change_collector,
                block_timer: BlockTimer::None,
                future_consensus_messages: Vec::new(),
            };
            self.on_micro_block_leader_changed();
        } else {
            // Expected Macro Block.
            let prev = std::mem::replace(&mut self.validation, MacroBlockAuditor);
            if !self.chain.is_validator(&self.keys.network_pkey) {
                info!(
                    "I'm auditor, waiting for the next macro block: height={}, last_block={}",
                    self.chain.height(),
                    self.chain.last_block_hash()
                );
                consensus::metrics::CONSENSUS_ROLE
                    .set(consensus::metrics::ConsensusRole::Regular as i64);
                return;
            }

            let mut consensus = Consensus::new(
                self.chain.height() as u64,
                self.chain.epoch() + 1,
                self.keys.network_skey.clone(),
                self.keys.network_pkey.clone(),
                self.chain.election_result(),
                self.chain.validators().iter().cloned().collect(),
            );

            // Flush pending messages.
            if let MicroBlockValidator {
                future_consensus_messages,
                ..
            } = prev
            {
                for msg in future_consensus_messages {
                    if let Err(e) = consensus.feed_message(msg) {
                        debug!("Error in future consensus message: {}", e);
                    }
                }
            }

            // Set validator state.
            self.validation = MacroBlockValidator {
                consensus,
                block_timer: BlockTimer::None,
            };

            self.on_macro_block_leader_changed();
            self.handle_consensus_events();
        }
    }

    ///
    /// Handles incoming consensus requests received from network.
    ///
    fn handle_consensus_message(&mut self, msg: ConsensusMessage) -> Result<(), Error> {
        let consensus = match &mut self.validation {
            MicroBlockAuditor | MacroBlockAuditor => {
                return Ok(());
            }
            MicroBlockValidator {
                future_consensus_messages,
                ..
            } => {
                // if our consensus state is outdated, push message to future_consensus_messages.
                // TODO: remove queue and use request-responses to get message from other nodes.
                future_consensus_messages.push(msg);
                return Ok(());
            }
            MacroBlockValidator { consensus, .. } => consensus,
        };

        // Feed message into consensus module.
        consensus.feed_message(msg)?;
        self.handle_consensus_events();
        Ok(())
    }

    fn handle_consensus_events(&mut self) {
        let consensus = match &mut self.validation {
            MacroBlockValidator { consensus, .. } => consensus,
            _ => panic!("Expected MacroBlockValidator state"),
        };

        if consensus.should_prevote() {
            let (block_hash, block_proposal, view_change) = consensus.get_proposal();
            match proposal::validate_proposed_macro_block(
                &self.cfg,
                &self.chain,
                view_change,
                block_hash,
                block_proposal,
            ) {
                Ok(macro_block) => consensus.prevote(macro_block),
                Err(e) => {
                    error!(
                        "Invalid block proposal: block_hash={}, error={}",
                        block_hash, e
                    );
                }
            }
        }

        // Check if we can commit a block.
        if consensus.is_leader() && consensus.should_commit() {
            return self.commit_proposed_block();
        }

        // Flush pending messages.
        let outbox = std::mem::replace(&mut consensus.outbox, Vec::new());
        for msg in outbox {
            let data = msg.into_buffer().expect("Failed to serialize");
            self.network
                .publish(&CONSENSUS_TOPIC, data)
                .expect("Connected");
        }
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

    /// Propose a new macro block.
    fn propose_macro_block(&mut self) -> Result<(), Error> {
        let (block_timer, consensus) = match &mut self.validation {
            MacroBlockValidator {
                block_timer,
                consensus,
                ..
            } => (block_timer, consensus),
            _ => panic!("Expected MacroBlockValidator state"),
        };
        assert_eq!(self.chain.blocks_in_epoch(), self.cfg.blocks_in_epoch);
        assert!(consensus.should_propose());

        // Set view_change timer.
        let relevant_round = 1 + consensus.round();
        let deadline = clock::now() + relevant_round * self.cfg.macro_block_timeout;
        std::mem::replace(block_timer, BlockTimer::ViewChange(Delay::new(deadline)));
        task::current().notify();

        // Propose a new block.
        let (block, block_proposal) = proposal::create_macro_block_proposal(
            &self.chain,
            consensus.round(),
            self.cfg.block_reward,
            &self.keys.wallet_pkey,
            &self.keys.network_skey,
            &self.keys.network_pkey,
        );
        let block_hash = Hash::digest(&block);
        consensus.propose(block_hash, block_proposal);
        consensus.prevote(block);
        self.handle_consensus_events();
        Ok(())
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_macro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        assert!(clock::now().duration_since(self.last_block_clock) >= self.cfg.macro_block_timeout);

        // Check that a block has been committed but haven't send by the leader.
        let consensus = match &mut self.validation {
            MacroBlockValidator { consensus, .. } => consensus,
            _ => panic!("Expected MacroValidator state"),
        };
        if consensus.should_commit() {
            assert!(!consensus.is_leader(), "never happens on leader");
            warn!("Timed out while waiting for the committed block from the leader, applying automatically: height={}",
                  self.chain.height()
            );
            metrics::AUTOCOMMIT.inc();
            // Auto-commit proposed block and send it to the network.
            self.commit_proposed_block();
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a macro block, going to the next round: height={}, view_change={}",
            self.chain.height(), consensus.round() + 1
        );

        // Go to the next round.
        metrics::MACRO_BLOCK_VIEW_CHANGES.inc();
        consensus.next_round();
        self.on_macro_block_leader_changed();
        self.handle_consensus_events();

        // Try to sync with the network.
        metrics::SYNCHRONIZED.set(0);
        self.request_history()?;

        Ok(())
    }

    //
    // Optimisitc consensus
    //

    fn handle_view_change_direct(
        &mut self,
        proof: SealedViewChangeProof,
        pkey: pbc::PublicKey,
    ) -> Result<(), Error> {
        debug!("Received sealed view change proof: proof = {:?}", proof);
        self.try_rollback(pkey, proof)?;
        return Ok(());
    }

    /// Handle incoming view_change message from the network.
    fn handle_view_change_message(&mut self, msg: ViewChangeMessage) -> Result<(), Error> {
        let view_change_collector = match &mut self.validation {
            MicroBlockValidator {
                view_change_collector,
                ..
            } => view_change_collector,
            _ => {
                // Ignore message.
                return Ok(());
            }
        };

        if let Some(proof) = view_change_collector.handle_message(&self.chain, msg)? {
            debug!(
                "Received enough messages for change leader: height={}, view_change={}, last_block={}",
                self.chain.height(), self.chain.view_change(), self.chain.last_block_hash(),
            );
            // Perform view change.
            self.chain
                .set_view_change(self.chain.view_change() + 1, proof);

            // Change leader.
            self.on_micro_block_leader_changed();
        };

        Ok(())
    }

    /// Checks if it's time to perform a view change on a micro block.
    fn handle_micro_block_viewchange_timer(&mut self) -> Result<(), Error> {
        let elapsed = clock::now().duration_since(self.last_block_clock);
        assert!(elapsed >= self.cfg.micro_block_timeout);
        warn!(
            "Timed out while waiting for a micro block: height={}, elapsed={:?}",
            self.chain.height(),
            elapsed
        );

        // Check state.
        let (view_change_collector, block_timer) = match &mut self.validation {
            MicroBlockValidator {
                view_change_collector,
                block_timer,
                ..
            } => (view_change_collector, block_timer),
            _ => panic!("Invalid state"),
        };

        // Update timer.
        let deadline = clock::now() + self.cfg.micro_block_timeout;
        std::mem::replace(block_timer, BlockTimer::ViewChange(Delay::new(deadline)));
        task::current().notify();

        // Send a view_change message.
        let chain_info = ChainInfo::from_blockchain(&self.chain);
        let msg = view_change_collector.handle_timeout(chain_info);
        self.network
            .publish(VIEW_CHANGE_TOPIC, msg.into_buffer()?)?;
        metrics::MICRO_BLOCK_VIEW_CHANGES.inc();
        debug!(
            "Sent a view change to the network: height={}, view_change={}, last_block={}",
            self.chain.height(),
            self.chain.view_change(),
            self.chain.last_block_hash(),
        );
        self.handle_view_change_message(msg)?;

        // Try to sync with the network.
        metrics::SYNCHRONIZED.set(0);
        self.request_history()?;

        Ok(())
    }

    ///
    /// Create a new micro block.
    ///
    fn create_micro_block(&mut self) -> Result<(), Error> {
        match &self.validation {
            MicroBlockValidator { .. } => {}
            _ => panic!("Expected MicroBlockValidator State"),
        };
        assert!(self.chain.leader() == self.keys.network_pkey);
        assert!(self.chain.blocks_in_epoch() < self.cfg.blocks_in_epoch);

        let height = self.chain.height();
        let previous = self.chain.last_block_hash();
        let view_change = self.chain.view_change();
        let view_change_proof = self.chain.view_change_proof().clone();
        debug!(
            "Creating a new micro block: height={}, view_change={}, last_block={}",
            height, view_change, previous
        );

        for (cheater, proof) in &self.cheating_proofs {
            // the cheater was already punished, so we keep proofs for rollback case,
            // but avoid punish them second time.
            if !self.chain.is_validator(cheater) {
                continue;
            }
            let slash_tx = confiscate_tx(&self.chain, &self.keys.network_pkey, proof.clone())?;
            let tx: Transaction = slash_tx.into();
            let tx_hash = Hash::digest(&tx);
            self.mempool.push_tx(tx_hash, tx);
        }

        // Create a new micro block from the mempool.
        let mut block = self.mempool.create_block(
            previous,
            VERSION,
            self.chain.height(),
            self.cfg.block_reward,
            &self.keys,
            self.chain.last_random(),
            view_change,
            view_change_proof,
            self.cfg.max_utxo_in_block,
        );

        let block_hash = Hash::digest(&block);

        // Sign block.
        block.sign(&self.keys.network_skey, &self.keys.network_pkey);

        info!(
            "Created a micro block: height={}, view_change={}, block={}, transactions={}",
            height,
            view_change,
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
    fn commit_proposed_block(&mut self) {
        // Commit the block.
        match std::mem::replace(&mut self.validation, Validation::MacroBlockAuditor) {
            MacroBlockValidator { consensus, .. } => {
                let macro_block = consensus.commit();
                let macro_block2 = macro_block.clone();
                self.apply_new_block(Block::MacroBlock(macro_block))
                    .expect("block is validated before");
                self.send_sealed_block(Block::MacroBlock(macro_block2))
                    .expect("failed to send sealed micro block");
            }
            _ => unreachable!(),
        }
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Poll timers first.
        let result = match &mut self.validation {
            MicroBlockAuditor
            | MicroBlockValidator {
                block_timer: BlockTimer::None,
                ..
            }
            | MacroBlockAuditor
            | MacroBlockValidator {
                block_timer: BlockTimer::None,
                ..
            } => Ok(()),
            MicroBlockValidator {
                block_timer: BlockTimer::Propose(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.create_micro_block(),
                Async::NotReady => Ok(()),
            },
            MicroBlockValidator {
                block_timer: BlockTimer::ViewChange(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.handle_micro_block_viewchange_timer(),
                Async::NotReady => Ok(()),
            },
            MacroBlockValidator {
                block_timer: BlockTimer::Propose(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.propose_macro_block(),
                Async::NotReady => Ok(()),
            },
            MacroBlockValidator {
                block_timer: BlockTimer::ViewChange(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.handle_macro_block_viewchange_timer(),
                Async::NotReady => Ok(()),
            },
        };
        if let Err(e) = result {
            error!("Error: {}", e);
        }

        // Poll other events.
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
                        NodeMessage::Consensus(msg) => ConsensusMessage::from_buffer(&msg)
                            .and_then(|msg| self.handle_consensus_message(msg)),
                        NodeMessage::ViewChangeMessage(msg) => ViewChangeMessage::from_buffer(&msg)
                            .and_then(|msg| self.handle_view_change_message(msg)),
                        NodeMessage::ViewChangeProofMessage(msg) => {
                            SealedViewChangeProof::from_buffer(&msg.data)
                                .and_then(|proof| self.handle_view_change_direct(proof, msg.from))
                        }
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

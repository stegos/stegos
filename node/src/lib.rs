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
use std::collections::HashMap;
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

/// Send when block is added.
#[derive(Clone, Debug, Serialize)]
pub struct BlockAdded {
    pub epoch: u64,
    pub offset: u32,
    pub hash: Hash,
    pub lag: i64,
    pub view_change: u32,
    pub local_timestamp: i64,
    pub remote_timestamp: i64,
    pub synchronized: bool,
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
    Block(Vec<u8>),
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
    /// Triggered when epoch is changed.
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
        let mempool = Mempool::new();

        let last_block_clock = clock::now();
        let validation = if chain.is_epoch_full() {
            MacroBlockAuditor
        } else {
            MicroBlockAuditor
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
            .map(|m| NodeMessage::Block(m));
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
    fn resolve_fork(&mut self, remote: &MicroBlock) -> ForkResult {
        assert_eq!(remote.header.epoch, self.chain.epoch());
        assert!(remote.header.offset < self.chain.offset());
        let epoch = self.chain.epoch();
        let offset = remote.header.offset;
        let remote_hash = Hash::digest(&remote);
        let remote_view_change = remote.header.view_change;
        let local = self.chain.micro_block(epoch, offset)?;
        let local_hash = Hash::digest(&local);

        // check multiple blocks with same view_change
        if remote.header.view_change == local.header.view_change {
            assert_eq!(
                remote.header.pkey, local.header.pkey,
                "checked by upper levels"
            );
            let leader = remote.header.pkey;

            if remote_hash == local_hash {
                debug!(
                    "Skip a duplicate block with the same hash: epoch={}, offset={}, block={}, our_offset={}",
                    epoch, offset, remote_hash, self.chain.offset(),
                );
                return Err(ForkError::Canceled);
            }

            warn!("Two micro-blocks from the same leader detected: epoch={}, offset={}, local_block={}, remote_block={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, our_offset={}, last_block={}",
                  epoch,
                  offset,
                  local_hash,
                  remote_hash,
                  local.header.previous,
                  remote.header.previous,
                  local.header.view_change,
                  remote.header.view_change,
                  self.chain.offset(),
                  self.chain.last_block_hash());

            metrics::CHEATS.inc();

            let proof = SlashingProof::new_unchecked(remote.clone(), local);

            if let Some(_proof) = self.cheating_proofs.insert(leader, proof) {
                debug!("Cheater was already detected: cheater = {}", leader);
            }

            return Err(ForkError::Canceled);
        } else if remote.header.view_change < local.header.view_change {
            debug!(
                "Found a fork with lower view_change, sending blocks: pkey={}",
                remote.header.pkey
            );
            self.send_blocks(remote.header.pkey, epoch, offset)?;
            return Err(ForkError::Canceled);
        }

        // Check the proof.
        let chain = ChainInfo::from_micro_block(&remote);
        let sealed_proof = match remote.header.view_change_proof {
            Some(ref proof) => SealedViewChangeProof {
                proof: proof.clone(),
                chain,
            },
            None => {
                return Err(BlockError::NoProofWasFound(
                    epoch,
                    offset,
                    remote_hash,
                    remote_view_change,
                    0,
                )
                .into());
            }
        };
        // seal proof, and try to resolve fork.
        return self.try_rollback(remote.header.pkey, sealed_proof);
    }

    /// We receive info about view_change, rollback the blocks, and set view_change to new.
    fn try_rollback(&mut self, pkey: pbc::PublicKey, proof: SealedViewChangeProof) -> ForkResult {
        // Check epoch.
        if proof.chain.epoch < self.chain.epoch() {
            debug!(
                "Skip an outdated proof: epoch={}, our_epoch={}",
                proof.chain.epoch,
                self.chain.epoch()
            );
            return Err(ForkError::Canceled);
        }
        let epoch = self.chain.epoch();

        let offset = proof.chain.offset;
        let local = if offset < self.chain.offset() {
            // Get local block.
            let local = self.chain.micro_block(epoch, offset)?;
            ChainInfo {
                epoch,
                offset: local.header.offset,
                last_block: local.header.previous,
                view_change: local.header.view_change,
            }
        } else if offset == self.chain.offset() {
            ChainInfo::from_blockchain(&self.chain)
        } else {
            debug!("Received ViewChangeProof from the future, ignoring for now: epoch={}, remote_offset={}, local_offset={}",
            epoch, offset, self.chain.offset());
            return Err(ForkError::Canceled);
        };

        let local_view_change = local.view_change;
        let remote_view_change = proof.chain.view_change;

        debug!("Started fork resolution: epoch={}, offset={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, remote_proof={:?}",
               epoch,
               offset,
               local.last_block,
               proof.chain.last_block,
               local_view_change,
               remote_view_change,
               proof.proof
        );

        // Check view_change.
        if remote_view_change < local_view_change {
            warn!("View change proof with lesser or equal view_change: epoch={}, offset={}, local_view_change={}, remote_view_change={}",
                  epoch,
                  offset,
                  local_view_change,
                  remote_view_change,
            );
            return Err(ForkError::Canceled);
        }

        // Check previous hash.
        if proof.chain.last_block != local.last_block {
            warn!("Found a proof with invalid previous hash: epoch={}, offset={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}",
                  epoch,
                  offset,
                  local.last_block,
                  proof.chain.last_block,
                  local_view_change,
                  remote_view_change);
            // Request history from that node.
            self.request_history_from(pkey)?;
            return Err(ForkError::Canceled);
        }

        assert!(remote_view_change >= local_view_change);
        assert_eq!(proof.chain.last_block, local.last_block);

        if let Err(e) = proof.proof.validate(&proof.chain, &self.chain) {
            return Err(BlockError::InvalidViewChangeProof(epoch, proof.proof, e).into());
        }

        metrics::FORKS.inc();

        warn!(
            "A fork detected: epoch={}, offset={}, local_previous={}, remote_previous={}, local_view_change={}, remote_view_change={}, current_offset={}",
            epoch,
            offset,
            local.last_block,
            proof.chain.last_block,
            local_view_change,
            remote_view_change,
            self.chain.offset());

        // Truncate the blockchain.
        while self.chain.offset() > offset {
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
        assert_eq!(offset, self.chain.offset());

        self.chain
            .set_view_change(proof.chain.view_change + 1, proof.proof);
        self.update_validation_status();
        Ok(())
    }

    /// Handle a macro block from the network.
    fn handle_macro_block(&mut self, block: MacroBlock) -> Result<(), Error> {
        if block.header.epoch < self.chain.epoch() {
            // Ignore outdated block.
            let block_hash = Hash::digest(&block);
            debug!(
                "Skip an outdated macro block: block={}, epoch={}, our_epoch={}",
                block_hash,
                block.header.epoch,
                self.chain.epoch(),
            );
            Ok(())
        } else if block.header.epoch == self.chain.epoch() {
            self.apply_macro_block(block)
        } else {
            let block_hash = Hash::digest(&block);
            debug!(
                "Skip a macro block from future: block={}, epoch={}, our_epoch={}",
                block_hash,
                block.header.epoch,
                self.chain.epoch(),
            );
            self.request_history()?;
            Ok(())
        }
    }

    /// Handle a micro block from the network.
    fn handle_micro_block(&mut self, block: MicroBlock) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        if block.header.epoch < self.chain.epoch() {
            debug!(
                "Ignore an outdated micro block: block={}, epoch={}, our_epoch={}, offset={}, our_offset={}, view_change={}, our_view_change={}, previous={}, our_previous={}",
                block_hash,
                block.header.epoch,
                self.chain.epoch(),
                block.header.offset,
                self.chain.offset(),
                block.header.view_change,
                self.chain.view_change(),
                block.header.previous,
                self.chain.last_block_hash()
            );
            return Ok(());
        } else if block.header.epoch > self.chain.epoch()
            || block.header.offset > self.chain.offset()
        {
            debug!(
                "Ignore a micro block from the future: block={}, epoch={}, our_epoch={}, offset={}, our_offset={}, view_change={}, our_view_change={}, previous={}, our_previous={}",
                block_hash,
                block.header.epoch,
                self.chain.epoch(),
                block.header.offset,
                self.chain.offset(),
                block.header.view_change,
                self.chain.view_change(),
                block.header.previous,
                self.chain.last_block_hash()
            );
            return Ok(());
        }

        assert_eq!(block.header.epoch, self.chain.epoch());
        assert!(block.header.offset <= self.chain.offset());
        let epoch = self.chain.epoch();
        let offset = block.header.offset;

        debug!(
            "Process a micro block: block={}, epoch={}, our_epoch={}, offset={}, our_offset={}, view_change={}, our_view_change={}, previous={}, our_previous={}",
            block_hash,
            block.header.epoch,
            self.chain.epoch(),
            block.header.offset,
            self.chain.offset(),
            block.header.view_change,
            self.chain.view_change(),
            block.header.previous,
            self.chain.last_block_hash()
        );

        // Check that block is created by legitimate validator.
        let election_result = self.chain.election_result_by_offset(offset)?;
        let leader = block.header.pkey;
        if !election_result.is_validator(&leader) {
            return Err(BlockError::LeaderIsNotValidator(epoch, block_hash).into());
        }
        if let Err(_e) = pbc::check_hash(&block_hash, &block.sig, &leader) {
            return Err(BlockError::InvalidLeaderSignature(epoch, block_hash).into());
        }

        // A duplicate block from the current epoch - try to resolve forks.
        if offset < self.chain.offset() {
            match self.resolve_fork(&block) {
                //TODO: Notify sender about our blocks?
                Ok(()) => {
                    debug!(
                        "Fork resolution decide that remote chain is better: fork_offset={}",
                        offset
                    );
                    assert_eq!(
                        offset,
                        self.chain.offset(),
                        "Fork resolution rollback our chain"
                    );
                }
                Err(ForkError::Canceled) => {
                    debug!(
                        "Fork resolution decide that our chain is better: fork_offset={}",
                        offset
                    );
                    assert!(offset < self.chain.offset(), "Fork didn't remove any block");
                    return Ok(());
                }
                Err(ForkError::Error(e)) => return Err(e),
            }
        }

        assert_eq!(block.header.epoch, epoch);
        assert_eq!(block.header.offset, self.chain.offset());
        let view_change = block.header.view_change;
        if let Err(e) = self.apply_micro_block(block) {
            error!(
                "Failed to apply micro block: epoch={}, offset={}, block={}, error={}",
                self.chain.epoch(),
                self.chain.offset(),
                block_hash,
                e
            );
            match e.downcast::<BlockchainError>() {
                Ok(BlockchainError::BlockError(BlockError::InvalidMicroBlockPreviousHash(..))) => {
                    // A potential fork - request history from that node.
                    let from = self.chain.select_leader(view_change);
                    self.request_history_from(from)?;
                }
                Ok(BlockchainError::BlockError(BlockError::InvalidViewChange(..))) => {
                    assert!(self.chain.view_change() > 0);
                    assert!(view_change < self.chain.view_change());
                    let leader = self.chain.select_leader(view_change);
                    warn!("Discarded a block with lesser view_change: block_view_change={}, our_view_change={}",
                          view_change, self.chain.view_change());
                    let chain_info = ChainInfo {
                        epoch: self.chain.epoch(),
                        offset: self.chain.offset(),
                        // correct information about proof, to refer previous on view_change;
                        view_change: self.chain.view_change() - 1,
                        last_block: self.chain.last_block_hash(),
                    };
                    let proof = self
                        .chain
                        .view_change_proof()
                        .clone()
                        .expect("last view_change proof.");
                    debug!(
                        "Sending view change proof to block sender: sender={}, proof={:?}",
                        leader, proof
                    );
                    let proof = SealedViewChangeProof {
                        chain: chain_info,
                        proof: proof.clone(),
                    };
                    self.network
                        .send(leader, VIEW_CHANGE_DIRECT, proof.into_buffer()?)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_block(&mut self, block: Block) -> Result<(), Error> {
        match block {
            Block::MicroBlock(block) => self.handle_micro_block(block),
            Block::MacroBlock(block) => self.handle_macro_block(block),
        }
    }

    /// Try to apply a new micro block into the blockchain.
    fn apply_macro_block(&mut self, block: MacroBlock) -> Result<(), Error> {
        let hash = Hash::digest(&block);
        let timestamp = block.header.timestamp;
        let epoch = block.header.epoch;
        let view_change = block.header.view_change;
        let was_synchronized = self.is_synchronized();

        // Validate signature.
        check_multi_signature(
            &hash,
            &block.multisig,
            &block.multisigmap,
            self.chain.validators(),
            self.chain.total_slots(),
        )
        .map_err(|e| BlockError::InvalidBlockSignature(e, epoch, hash))?;

        // Remove all micro blocks.
        while self.chain.offset() > 0 {
            let (inputs, outputs) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();
            let msg = OutputsChanged {
                epoch: self.chain.epoch(),
                inputs,
                outputs,
            };
            // TODO: merge this event with OutputsChanged below.
            self.on_outputs_changed
                .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
        }
        assert_eq!(0, self.chain.offset());

        let (inputs, outputs) = self.chain.push_macro_block(block, timestamp)?;

        if !was_synchronized && self.is_synchronized() {
            info!(
                "Synchronized with the network: epoch={}, last_block={}",
                epoch,
                self.chain.last_block_hash()
            );
            metrics::SYNCHRONIZED.set(1);
        }

        self.on_block_added(epoch, 0, view_change, hash, timestamp, inputs, outputs);

        let msg = EpochChanged {
            epoch: self.chain.epoch(),
            validators: self.chain.validators().clone(),
            facilitator: self.chain.facilitator().clone(),
        };

        self.on_epoch_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

        self.cheating_proofs.clear();
        self.update_validation_status();

        Ok(())
    }

    /// Try to apply a new micro block into the blockchain.
    fn apply_micro_block(&mut self, block: MicroBlock) -> Result<(), Error> {
        let hash = Hash::digest(&block);
        let timestamp = block.header.timestamp;
        let epoch = block.header.epoch;
        let offset = block.header.offset;
        let view_change = block.header.view_change;

        // Check for the correct block order.
        match &self.validation {
            MicroBlockAuditor | MicroBlockValidator { .. } => {}
            _ => {
                return Err(BlockchainError::ExpectedMicroBlock(epoch, offset, hash).into());
            }
        }

        let (inputs, outputs) = self.chain.push_micro_block(block, timestamp)?;
        self.on_block_added(epoch, offset, view_change, hash, timestamp, inputs, outputs);
        self.update_validation_status();

        Ok(())
    }

    fn on_block_added(
        &mut self,
        epoch: u64,
        offset: u32,
        view_change: u32,
        hash: Hash,
        timestamp: SystemTime,
        inputs: Vec<Output>,
        outputs: Vec<Output>,
    ) {
        // Remove old transactions from the mempool.
        let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
        let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
        self.mempool.prune(&input_hashes, &output_hashes);
        metrics::MEMPOOL_TRANSACTIONS.set(self.mempool.len() as i64);
        metrics::MEMPOOL_INPUTS.set(self.mempool.inputs_len() as i64);
        metrics::MEMPOOL_OUTPUTS.set(self.mempool.inputs_len() as i64);

        // Notify subscribers.
        let msg = OutputsChanged {
            epoch,
            inputs,
            outputs,
        };
        self.on_outputs_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());

        self.last_block_clock = clock::now();

        let local_timestamp = metrics::time_to_timestamp_ms(SystemTime::now());
        let remote_timestamp = metrics::time_to_timestamp_ms(timestamp);
        let lag = local_timestamp - remote_timestamp;
        metrics::BLOCK_REMOTE_TIMESTAMP.set(remote_timestamp);
        metrics::BLOCK_LOCAL_TIMESTAMP.set(local_timestamp);
        metrics::BLOCK_LAG.set(lag); // can be negative.

        let msg = BlockAdded {
            epoch,
            offset,
            view_change,
            hash,
            lag,
            local_timestamp,
            remote_timestamp,
            synchronized: self.is_synchronized(),
        };
        self.on_block_added
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
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
        if self.chain.offset() > 1 {
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
                "Attempt to revert a macro block: epoch={}",
                self.chain.epoch()
            );
        }
        Ok(())
    }

    /// Send block to network.
    fn send_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let data = block.into_buffer()?;
        self.network.publish(&SEALED_BLOCK_TOPIC, data)?;
        match block {
            Block::MacroBlock(ref block) => {
                info!(
                    "Sent macro block to the network: epoch={}, block={}, previous={}",
                    block.header.epoch, block_hash, block.header.previous
                );
            }
            Block::MicroBlock(ref block) => {
                info!(
                    "Sent micro block to the network: epoch={}, offset={}, block={}, previous={}",
                    block.header.epoch, block.header.offset, block_hash, block.header.previous
                );
            }
        }
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
                "I'm leader, collecting transactions for the next micro block: epoch={}, offset={}, view_change={}, last_block={}",
                self.chain.epoch(),
                self.chain.offset(),
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
            info!("I'm validator, waiting for the next micro block: epoch={}, offset={}, view_change={}, last_block={}, leader={}",
                  self.chain.epoch(),
                  self.chain.offset(),
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
                "I'm leader, proposing the next macro block: epoch={}, view_change={}, last_block={}",
                self.chain.epoch(),
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
                "I'm validator, waiting for the next macro block: epoch={}, view_change={}, last_block={}, leader={}",
                self.chain.epoch(),
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
        if !self.chain.is_epoch_full() {
            // Expected Micro Block.
            let _prev = std::mem::replace(&mut self.validation, MicroBlockAuditor);
            if !self.chain.is_validator(&self.keys.network_pkey) {
                info!("I'm auditor, waiting for the next micro block: epoch={}, offset={}, view_change={}, last_block={}",
                      self.chain.epoch(),
                      self.chain.offset(),
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
                    "I'm auditor, waiting for the next macro block: epoch={}, last_block={}",
                    self.chain.epoch(),
                    self.chain.last_block_hash()
                );
                consensus::metrics::CONSENSUS_ROLE
                    .set(consensus::metrics::ConsensusRole::Regular as i64);
                return;
            }

            let mut consensus = Consensus::new(
                self.chain.epoch(),
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
            + self.cfg.micro_block_timeout * self.chain.cfg().micro_blocks_in_epoch
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
        assert!(self.chain.is_epoch_full());
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
            warn!("Timed out while waiting for the committed block from the leader, applying automatically: epoch={}",
                  self.chain.epoch()
            );
            metrics::AUTOCOMMIT.inc();
            // Auto-commit proposed block and send it to the network.
            self.commit_proposed_block();
            return Ok(());
        }

        warn!(
            "Timed out while waiting for a macro block, going to the next round: epoch={}, view_change={}",
            self.chain.epoch(), consensus.round() + 1
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
                "Received enough messages for change leader: epoch={}, view_change={}, last_block={}",
                self.chain.epoch(), self.chain.view_change(), self.chain.last_block_hash(),
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
            "Timed out while waiting for a micro block: epoch={}, elapsed={:?}",
            self.chain.epoch(),
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
            "Sent a view change to the network: epoch={}, view_change={}, last_block={}",
            self.chain.epoch(),
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
        assert_eq!(self.chain.leader(), self.keys.network_pkey);
        assert!(!self.chain.is_epoch_full());

        let epoch = self.chain.epoch();
        let offset = self.chain.offset();
        let previous = self.chain.last_block_hash();
        let view_change = self.chain.view_change();
        let view_change_proof = self.chain.view_change_proof().clone();
        debug!(
            "Creating a new micro block: epoch={}, offset={}, view_change={}, last_block={}",
            epoch, offset, view_change, previous
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
            epoch,
            offset,
            view_change,
            view_change_proof,
            self.chain.last_random(),
            self.cfg.block_reward,
            &self.keys,
            self.cfg.max_utxo_in_block,
        );

        let block_hash = Hash::digest(&block);

        // Sign block.
        block.sign(&self.keys.network_skey, &self.keys.network_pkey);

        info!(
            "Created a micro block: epoch={}, offset={}, view_change={}, block={}, transactions={}",
            epoch,
            offset,
            view_change,
            &block_hash,
            block.transactions.len(),
        );

        let block2 = block.clone();
        self.apply_micro_block(block)
            .expect("created a valid block");
        self.send_block(Block::MicroBlock(block2))
            .expect("failed to send sealed micro block");

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
                self.apply_macro_block(macro_block)
                    .expect("block is validated before");
                self.send_block(Block::MacroBlock(macro_block2))
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
                        NodeMessage::Block(msg) => {
                            Block::from_buffer(&msg).and_then(|msg| self.handle_block(msg))
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

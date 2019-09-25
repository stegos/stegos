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

#![deny(warnings)]

pub mod api;
mod config;
mod error;
mod loader;
mod mempool;
pub mod metrics;
pub mod protos;
#[doc(hidden)]
pub mod test;
pub mod txpool;
mod validation;
pub use crate::api::*;
pub use crate::config::NodeConfig;
use crate::error::*;
use crate::loader::ChainLoaderMessage;
use crate::mempool::Mempool;
use crate::txpool::TransactionPoolService;
pub use crate::txpool::MAX_PARTICIPANTS;
use crate::validation::*;
use failure::{format_err, Error};
use futures::sync::{mpsc, oneshot};
use futures::{task, Async, AsyncSink, Future, Poll, Sink, Stream};
use futures_stream_select_all_send::select_all;
pub use loader::CHAIN_LOADER_TOPIC;
use log::*;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use stegos_blockchain::Timestamp;
use stegos_blockchain::*;
use stegos_consensus::optimistic::{SealedViewChangeProof, ViewChangeCollector, ViewChangeMessage};
use stegos_consensus::{self as consensus, Consensus, ConsensusMessage, MacroBlockProposal};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_network::Network;
use stegos_network::UnicastMessage;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::{clock, Delay};
use Validation::*;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Blockchain Node.
#[derive(Clone, Debug)]
pub struct Node {
    outbox: mpsc::UnboundedSender<NodeMessage>,
    network: Network,
}

impl Node {
    /// Send transaction to node and to the network.
    pub fn send_transaction(&self, transaction: Transaction) -> oneshot::Receiver<NodeResponse> {
        let (tx, rx) = oneshot::channel();
        let request = NodeRequest::AddTransaction(transaction);
        let msg = NodeMessage::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Node Request.
    pub fn request(&self, request: NodeRequest) -> oneshot::Receiver<NodeResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = NodeMessage::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// Topic used for sending transactions.
pub const TX_TOPIC: &'static str = "tx";
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
    Request {
        request: NodeRequest,
        tx: oneshot::Sender<NodeResponse>,
    },
    Transaction(Vec<u8>),
    Consensus(Vec<u8>),
    Block(Vec<u8>),
    ViewChangeMessage(Vec<u8>),
    ViewChangeProofMessage(UnicastMessage),
    ChainLoaderMessage(UnicastMessage),
}

enum MicroBlockTimer {
    None,
    Propose(oneshot::Receiver<Vec<u8>>),
    ViewChange(Delay),
}

enum MacroBlockTimer {
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
        block_timer: MicroBlockTimer,
        /// A queue of consensus message from the future epoch.
        // TODO: Resolve unknown blocks using requests-responses.
        future_consensus_messages: Vec<ConsensusMessage>,
    },
    MacroBlockAuditor,
    MacroBlockValidator {
        /// pBFT consensus,
        consensus: Consensus,
        /// Propose or View Change timer
        block_timer: MacroBlockTimer,
    },
}

/// Chain subscriber which is fed from the disk.
struct ChainReader {
    /// Current epoch.
    epoch: u64,
    /// Current offset.
    offset: u32,
    /// Channel.
    tx: mpsc::Sender<ChainNotification>,
}

impl ChainReader {
    fn poll(&mut self, chain: &Blockchain) -> Poll<(), Error> {
        // Check if subscriber has already been synchronized.
        if self.epoch == chain.epoch() && self.offset == chain.offset() {
            return Ok(Async::Ready(()));
        }

        // Feed blocks from the disk.
        for block in chain.blocks_starting(self.epoch, self.offset) {
            let (msg, next_epoch, next_offset) = match block {
                Block::MacroBlock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    let epoch_info = chain.epoch_info(block.header.epoch)?.unwrap().clone();
                    let next_epoch = block.header.epoch + 1;
                    let msg = ExtendedMacroBlock {
                        block,
                        epoch_info,
                        transaction_statuses: HashMap::new(),
                    };
                    let msg = ChainNotification::MacroBlockCommitted(msg);
                    (msg, next_epoch, 0)
                }
                Block::MicroBlock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    assert_eq!(block.header.offset, self.offset);
                    let (next_epoch, next_offset) =
                        if block.header.offset + 1 < chain.cfg().micro_blocks_in_epoch {
                            (block.header.epoch, block.header.offset + 1)
                        } else {
                            (block.header.epoch + 1, 0)
                        };
                    let transaction_statuses = block
                        .transactions
                        .iter()
                        .map(|tx| {
                            (
                                Hash::digest(&tx),
                                TransactionStatus::Prepared {
                                    epoch: block.header.epoch,
                                    offset: block.header.offset,
                                },
                            )
                        })
                        .collect();
                    let msg = ExtendedMicroBlock {
                        block,
                        transaction_statuses,
                    };
                    let msg = ChainNotification::MicroBlockPrepared(msg);
                    (msg, next_epoch, next_offset)
                }
            };

            match self.tx.start_send(msg)? {
                AsyncSink::Ready => {
                    self.epoch = next_epoch;
                    self.offset = next_offset;
                }
                AsyncSink::NotReady(_msg) => {
                    break;
                }
            }
        }

        self.tx.poll_complete()?;
        Ok(Async::NotReady)
    }
}

/// Notify all subscribers about new event.
fn notify_subscribers<T: Clone>(subscribers: &mut Vec<mpsc::Sender<T>>, msg: T) {
    let mut i = 0;
    while i < subscribers.len() {
        let tx = &mut subscribers[i];
        match tx.start_send(msg.clone()) {
            Ok(AsyncSink::Ready) => {}
            Ok(AsyncSink::NotReady(_msg)) => {
                warn!("Subscriber is slow, discarding messages");
            }
            Err(_e /* SendError<ChainNotification> */) => {
                subscribers.swap_remove(i);
                continue;
            }
        }
        if let Err(_e) = tx.poll_complete() {
            subscribers.swap_remove(i);
            continue;
        }
        i += 1;
    }
}

pub struct NodeService {
    /// Config.
    cfg: NodeConfig,
    /// Blockchain.
    chain: Blockchain,
    /// Network secret key.
    network_pkey: pbc::PublicKey,
    /// Network secret key.
    network_skey: pbc::SecretKey,

    /// Memory pool of pending transactions.
    mempool: Mempool,

    /// Consensus state.
    validation: Validation,

    /// Monotonic clock when the latest block was registered.
    last_block_clock: Instant,

    /// A timer to re-scheduler the loader.
    loader_timer: Option<Delay>,

    /// Cheating detection.
    cheating_proofs: HashMap<pbc::PublicKey, SlashingProof>,

    /// Automatic re-staking status.
    is_restaking_enabled: bool,

    //
    // Communication with environment.
    //
    /// Subscribers for status events.
    status_subscribers: Vec<mpsc::Sender<StatusNotification>>,
    /// Subscribers for chain events.
    chain_subscribers: Vec<mpsc::Sender<ChainNotification>>,
    /// Subscribers for chain events which are fed from the disk.
    /// Automatically promoted to chain_subscribers after synchronization.
    chain_readers: Vec<ChainReader>,
    /// Node interface (needed to create TransactionPoolService).
    node: Node,
    /// Network interface.
    network: Network,
    /// Aggregated stream of events.
    events: Box<dyn Stream<Item = NodeMessage, Error = ()> + Send>,

    /// Txpool
    txpool_service: Option<TransactionPoolService>,
}

impl NodeService {
    /// Constructor.
    pub fn new(
        cfg: NodeConfig,
        chain: Blockchain,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
    ) -> Result<(Self, Node), Error> {
        let (outbox, inbox) = mpsc::unbounded();
        let mempool = Mempool::new();

        let last_block_clock = clock::now();
        let validation = if chain.is_epoch_full() {
            MacroBlockAuditor
        } else {
            MicroBlockAuditor
        };
        let cheating_proofs = HashMap::new();
        let loader_timer = None;
        let is_restaking_enabled = true;

        let on_node_notification = Vec::new();

        let mut streams = Vec::<Box<dyn Stream<Item = NodeMessage, Error = ()> + Send>>::new();

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

        let chain_disk_subscribers = Vec::new();
        let chain_subscribers = Vec::new();
        let node = Node {
            outbox,
            network: network.clone(),
        };
        let txpool_service = None;

        let service = NodeService {
            cfg,
            chain,
            network_skey,
            network_pkey,
            mempool,
            validation,
            last_block_clock,
            loader_timer,
            cheating_proofs,
            is_restaking_enabled,
            chain_readers: chain_disk_subscribers,
            chain_subscribers,
            node: node.clone(),
            network: network.clone(),
            events,
            txpool_service,
            status_subscribers: on_node_notification,
        };

        Ok((service, node))
    }

    /// Invoked when network is ready.
    pub fn init(&mut self) -> Result<(), Error> {
        self.update_validation_status();
        self.on_facilitator_changed();
        self.on_status_changed();
        self.restake_expiring_stakes()?;
        self.request_history(self.chain.epoch(), "init")?;
        Ok(())
    }

    /// Send transaction to node and to the network.
    fn send_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let data = tx.into_buffer()?;
        let tx_hash = Hash::digest(&tx);
        self.network.publish(&TX_TOPIC, data.clone())?;
        info!(
            "Sent transaction to the network: tx={}, inputs={:?}, outputs={:?}, fee={}",
            &tx_hash,
            tx.txins()
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<String>>(),
            tx.txouts()
                .iter()
                .map(|o| Hash::digest(o).to_string())
                .collect::<Vec<String>>(),
            tx.fee()
        );
        self.handle_transaction(tx)?;
        Ok(())
    }

    /// Handle incoming transactions received from network.
    fn handle_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let tx_hash = Hash::digest(&tx);
        if !self.is_synchronized() {
            debug!(
                "Node is not synchronized - ignore transaction from the network: tx={}, inputs={:?}, outputs={:?}, fee={}",
                &tx_hash,
                tx.txins(),
                tx.txouts().iter().map(Hash::digest),
                tx.fee()
            );
            return Ok(());
        }
        info!(
            "Received transaction from the network: tx={}, inputs={:?}, outputs={:?}, fee={}",
            &tx_hash,
            tx.txins()
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<String>>(),
            tx.txouts()
                .iter()
                .map(|o| Hash::digest(o).to_string())
                .collect::<Vec<String>>(),
            tx.fee()
        );

        // Check that transaction has proper type.
        let check_limits = match &tx {
            Transaction::PaymentTransaction(_tx) => true,
            Transaction::RestakeTransaction(_tx) => false,
            _ => return Err(NodeTransactionError::InvalidType(tx_hash).into()),
        };

        // Ignore all limits for RestakeTransaction.
        if check_limits {
            // Limit the number of inputs and outputs.
            if tx.txins().len() > self.cfg.max_inputs_in_tx {
                return Err(NodeTransactionError::TooManyInputs(
                    tx_hash,
                    tx.txins().len(),
                    self.cfg.max_inputs_in_tx,
                )
                .into());
            }
            if tx.txouts().len() > self.cfg.max_outputs_in_tx {
                return Err(NodeTransactionError::TooManyOutputs(
                    tx_hash,
                    tx.txouts().len(),
                    self.cfg.max_outputs_in_tx,
                )
                .into());
            }

            // Limit the maximum size of mempool.
            if self.mempool.inputs_len() > self.cfg.max_inputs_in_mempool
                || self.mempool.outputs_len() > self.cfg.max_outputs_in_mempool
            {
                return Err(NodeTransactionError::MempoolIsFull(tx_hash).into());
            }
        }

        // Validate transaction.
        let timestamp = Timestamp::now();
        validate_external_transaction(
            &tx,
            &self.mempool,
            &self.chain,
            timestamp,
            self.cfg.min_payment_fee,
            self.cfg.min_stake_fee,
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
    /// Re-stake expiring stakes.
    ///
    fn restake_expiring_stakes(&mut self) -> Result<(), Error> {
        if !self.is_synchronized() || !self.is_restaking_enabled {
            // Don't re-stake during bootstrap, wait for the actual network state.
            return Ok(());
        }
        assert_eq!(self.cfg.min_stake_fee, 0);
        let mut inputs: Vec<Output> = Vec::new();
        let mut outputs: Vec<Output> = Vec::new();
        for (input_hash, amount, account_pkey, active_until_epoch) in
            self.chain.iter_validator_stakes(&self.network_pkey)
        {
            // Re-stake in one epoch before expiration.
            if active_until_epoch >= self.chain.epoch() + 1 {
                debug!(
                    "Skip restaking - stake is active: utxo={}, active_until_epoch={}, epoch={}",
                    input_hash,
                    active_until_epoch,
                    self.chain.epoch()
                );
                continue;
            }

            if let Some(tx_hash) = self.mempool.get_tx_by_input(input_hash) {
                debug!(
                    "Skip re-staking - stake is used by tx: utxo={}, tx={}",
                    input_hash, tx_hash
                );
                continue;
            }

            let input = self
                .chain
                .output_by_hash(input_hash)?
                .expect("Stake exists");

            trace!("Creating StakeUTXO...");
            let output =
                Output::new_stake(account_pkey, &self.network_skey, &self.network_pkey, amount)?;
            let output_hash = Hash::digest(&output);

            info!(
                "Restake: old_utxo={}, new_utxo={}, amount={}",
                input_hash, output_hash, amount
            );

            inputs.push(input);
            outputs.push(output);
        }
        assert_eq!(inputs.len(), outputs.len());

        if inputs.is_empty() {
            return Ok(()); // Nothing to re-stake.
        }

        trace!("Signing transaction...");
        let tx =
            RestakeTransaction::new(&self.network_skey, &self.network_pkey, &inputs, &outputs)?;
        let tx_hash = Hash::digest(&tx);
        info!(
            "Created a restaking transaction: hash={}, inputs={}, outputs={}",
            tx_hash,
            tx.txins.len(),
            tx.txouts.len()
        );

        self.send_transaction(tx.into())?;

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

            metrics::MICRO_BLOCKS_CHEATS.inc();

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
            self.request_history_from(pkey, epoch, "fork resolution")?;
            return Err(ForkError::Canceled);
        }

        assert!(remote_view_change >= local_view_change);
        assert_eq!(proof.chain.last_block, local.last_block);

        if let Err(e) = proof.proof.validate(&proof.chain, &self.chain) {
            return Err(BlockError::InvalidViewChangeProof(epoch, proof.proof, e).into());
        }

        metrics::MICRO_BLOCKS_FORKS.inc();

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
            let (pruned_outputs, recovered_inputs, txs, block) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();
            self.mempool.pop_microblock(txs.clone());
            let transaction_statuses = txs
                .iter()
                .map(|tx| {
                    (
                        Hash::digest(&tx),
                        TransactionStatus::Rollback {
                            epoch: self.chain.epoch(),
                            offset: self.chain.offset(),
                        },
                    )
                })
                .collect();
            let msg = RevertedMicroBlock {
                block,
                transaction_statuses,
                pruned_outputs,
                recovered_inputs,
            };
            notify_subscribers(&mut self.chain_subscribers, msg.into());
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
                "Skip a macro block from the future: block={}, epoch={}, our_epoch={}",
                block_hash,
                block.header.epoch,
                self.chain.epoch(),
            );
            self.request_history_from(
                block.header.pkey,
                self.chain.epoch(),
                "macro block from the future",
            )?;
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
        let leader = election_result.select_leader(block.header.view_change);
        if leader != block.header.pkey {
            return Err(BlockError::DifferentPublicKey(leader, block.header.pkey).into());
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
                    self.request_history_from(from, self.chain.epoch(), "invalid previous hash")?;
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
        let timestamp = Timestamp::now();
        let block_timestamp = block.header.timestamp;
        let epoch = block.header.epoch;
        let was_synchronized = self.is_synchronized();

        // Validate signature.
        check_multi_signature(
            &hash,
            &block.multisig,
            &block.multisigmap,
            &self.chain.validators_at_epoch_start(),
            self.chain.total_slots(),
        )
        .map_err(|e| BlockError::InvalidBlockSignature(e, epoch, hash))?;

        // Remove all micro blocks.
        while self.chain.offset() > 0 {
            let (pruned_outputs, recovered_inputs, _txs, block) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();
            let msg = RevertedMicroBlock {
                block,
                transaction_statuses: HashMap::new(),
                pruned_outputs,
                recovered_inputs,
            };

            notify_subscribers(&mut self.chain_subscribers, msg.into());
        }
        assert_eq!(0, self.chain.offset());

        let (inputs, outputs) = self.chain.push_macro_block(block.clone(), timestamp)?;

        let mut transaction_statuses = HashMap::new();
        let mut transactions = HashMap::new();
        // Remove conflict transactions from the mempool.
        let tx_info = self.mempool.prune(inputs.iter(), outputs.keys());
        for (tx_hash, (tx, full)) in tx_info {
            let status = if full {
                TransactionStatus::Committed { epoch }
            } else {
                TransactionStatus::Conflicted {
                    epoch,
                    offset: None,
                }
            };
            assert!(transaction_statuses.insert(tx_hash, status).is_none());
            assert!(transactions.insert(tx_hash, tx).is_none());
        }

        assert_eq!(transaction_statuses.len(), transactions.len());

        if !was_synchronized && self.is_synchronized() {
            // Reset loader timer.
            self.loader_timer = None;
            info!(
                "Synchronized with the network: epoch={}, last_block={}",
                epoch,
                self.chain.last_block_hash()
            );
        }
        let epoch_info = self
            .chain
            .epoch_info(epoch)?
            .expect("Expect epoch info for last macroblock.")
            .clone();

        let msg = ExtendedMacroBlock {
            block,
            epoch_info,
            transaction_statuses,
        };

        self.on_block_added(block_timestamp, true);

        notify_subscribers(&mut self.chain_subscribers, msg.into());
        self.cheating_proofs.clear();
        self.on_facilitator_changed();
        self.restake_expiring_stakes()?;

        Ok(())
    }

    /// Try to apply a new micro block into the blockchain.
    fn apply_micro_block(&mut self, block: MicroBlock) -> Result<(), Error> {
        let hash = Hash::digest(&block);
        let timestamp = Timestamp::now();
        let block_timestamp = block.header.timestamp;
        let epoch = block.header.epoch;
        let offset = block.header.offset;

        // Check for the correct block order.
        match &self.validation {
            MicroBlockAuditor | MicroBlockValidator { .. } => {}
            _ => {
                return Err(BlockchainError::ExpectedMicroBlock(epoch, offset, hash).into());
            }
        }

        // Validate Micro Block.
        let inputs_len: usize = block.transactions.iter().map(|tx| tx.txins().len()).sum();
        let outputs_len: usize = block.transactions.iter().map(|tx| tx.txouts().len()).sum();
        let txs_len = block.transactions.len();
        debug!(
            "Validating a micro block: epoch={}, offset={}, block={}, inputs_len={}, outputs_len={}, txs_len={}",
            epoch, offset, &hash, inputs_len, outputs_len, txs_len,
        );
        let start_clock = clock::now();
        let r = {
            let mut outputs: Vec<&Output> = Vec::new();
            for tx in &block.transactions {
                // Skip transactions from mempool.
                let tx_hash = Hash::digest(&tx);
                if let Some(tx2) = self.mempool.get_tx(&tx_hash) {
                    // Extra checks to avoid the second pre-image attack.
                    if tx.txins().len() == tx2.txins().len()
                        && tx.txouts().len() == tx2.txouts().len()
                    {
                        // Transaction presents in mempool.
                        // Already validated by validate_external_transaction().
                        continue;
                    }
                }
                // Transaction doesn't present in mempool.
                outputs.extend(tx.txouts());
            }
            match outputs.into_par_iter().try_for_each(Output::validate) {
                Ok(()) => {
                    let validate_utxo = false; // validated above.
                    self.chain
                        .validate_micro_block(&block, timestamp, validate_utxo)
                }
                Err(e) => Err(e),
            }
        };
        let duration = clock::now().duration_since(start_clock);
        let duration = (duration.as_secs() as f64) + (duration.subsec_nanos() as f64) * 1e-9;
        metrics::MICRO_BLOCK_VALIDATE_TIME.set(duration);
        metrics::MICRO_BLOCK_VALIDATE_TIME_HG.observe(duration);
        match r {
            Ok(()) => {
                debug!(
                    "The micro block is valid: epoch={}, offset={}, block={}, inputs_len={}, outputs_len={}, txs_len={}, duration={:.3}",
                    epoch, offset, &hash, inputs_len, outputs_len, txs_len, duration
                );
            }
            Err(e) => {
                error!(
                    "The micro block is invalid: epoch={}, offset={}, block={}, inputs_len={}, outputs_len={}, txs_len={}, duration={:.3}, e={}",
                    epoch, offset, &hash, inputs_len, outputs_len, txs_len, duration, e
                );
                return Err(e.into());
            }
        }

        // Apply Micro Block.
        let (inputs, outputs, block_transactions) =
            self.chain.push_micro_block(block.clone(), timestamp)?;

        let mut transaction_statuses = HashMap::new();
        let mut transactions = HashMap::new();
        // Remove conflict transactions from the mempool.
        let mut tx_info = self.mempool.prune(inputs.iter(), outputs.keys());
        tx_info.extend(
            block_transactions
                .clone()
                .into_iter()
                .map(|(h, tx)| (h, (tx, true))),
        );
        for (tx_hash, (tx, full)) in tx_info {
            let status = if full && block_transactions.contains_key(&tx_hash) {
                TransactionStatus::Prepared { epoch, offset }
            } else {
                TransactionStatus::Conflicted {
                    epoch,
                    offset: offset.into(),
                }
            };
            assert!(transaction_statuses.insert(tx_hash, status).is_none());
            assert!(transactions.insert(tx_hash, tx).is_none());
        }

        assert_eq!(transaction_statuses.len(), transactions.len());
        assert!(transactions.len() >= block_transactions.len());

        self.on_block_added(block_timestamp, false);

        let msg = ExtendedMicroBlock {
            block,
            transaction_statuses,
        };
        notify_subscribers(&mut self.chain_subscribers, msg.into());

        Ok(())
    }

    /// update metrics and statuses on block processing.
    fn on_block_added(&mut self, block_timestamp: Timestamp, mblock: bool) {
        metrics::MEMPOOL_TRANSACTIONS.set(self.mempool.len() as i64);
        metrics::MEMPOOL_INPUTS.set(self.mempool.inputs_len() as i64);
        metrics::MEMPOOL_OUTPUTS.set(self.mempool.inputs_len() as i64);
        let last_block_clock = self.last_block_clock;
        self.last_block_clock = clock::now();
        let local_timestamp: f64 = Timestamp::now().into();
        let remote_timestamp: f64 = block_timestamp.into();
        let lag = local_timestamp - remote_timestamp; // can be negative.
        metrics::BLOCK_REMOTE_TIMESTAMP.set(remote_timestamp);
        metrics::BLOCK_LOCAL_TIMESTAMP.set(local_timestamp);
        if mblock {
            metrics::MACRO_BLOCK_LAG.set(lag);
            metrics::MACRO_BLOCK_LAG_HG.observe(lag);
        } else {
            metrics::MICRO_BLOCK_LAG.set(lag);
            metrics::MICRO_BLOCK_LAG_HG.observe(lag);
            let interval = self.last_block_clock.duration_since(last_block_clock);
            let interval = (interval.as_secs() as f64) + (interval.subsec_nanos() as f64) * 1e-9;
            metrics::MICRO_BLOCK_INTERVAL.set(interval);
            metrics::MICRO_BLOCK_INTERVAL_HG.observe(interval);
        }
        self.on_status_changed();
        self.update_validation_status();
    }

    fn status(&self) -> StatusInfo {
        let is_synchronized = self.is_synchronized();
        StatusInfo {
            is_synchronized,
            epoch: self.chain.epoch(),
            offset: self.chain.offset(),
            view_change: self.chain.view_change(),
            last_block_hash: self.chain.last_block_hash(),
            last_macro_block_hash: self.chain.last_macro_block_hash(),
            last_macro_block_timestamp: self.chain.last_macro_block_timestamp(),
            local_timestamp: Timestamp::now(),
        }
    }

    fn on_status_changed(&mut self) {
        let msg = self.status();
        metrics::SYNCHRONIZED.set(if msg.is_synchronized { 1 } else { 0 });
        notify_subscribers(&mut self.status_subscribers, msg.into());
    }

    /// Handler subscription to status.
    fn handle_subscription_to_status(
        &mut self,
    ) -> Result<mpsc::Receiver<StatusNotification>, Error> {
        let (tx, rx) = mpsc::channel(1);
        self.status_subscribers.push(tx);
        Ok(rx)
    }

    /// Handle subscription to chain.
    fn handle_subscription_to_chain(
        &mut self,
        epoch: u64,
        offset: u32,
    ) -> Result<mpsc::Receiver<ChainNotification>, Error> {
        if epoch > self.chain.epoch() {
            return Err(format_err!(
                "Invalid epoch requested: epoch_requested={}, our_epoch={}",
                epoch,
                self.chain.epoch()
            ));
        }
        // Set buffer size to fit entire epoch plus some extra blocks.
        let buffer = self.chain.cfg().micro_blocks_in_epoch as usize + 10;
        let (tx, rx) = mpsc::channel(buffer);
        let subscriber = ChainReader { tx, epoch, offset };
        self.chain_readers.push(subscriber);
        task::current().notify();
        Ok(rx)
    }

    /// Handler for NodeRequest::AddTransaction
    fn handle_add_tx(&mut self, tx: Transaction) -> TransactionStatus {
        match self.send_transaction(tx.clone()) {
            Ok(()) => {}
            Err(e) => match e.downcast::<NodeTransactionError>() {
                Ok(NodeTransactionError::AlreadyExists(_)) => {}
                Ok(v) => {
                    return TransactionStatus::Rejected {
                        error: v.to_string(),
                    }
                }
                Err(e) => {
                    return TransactionStatus::Rejected {
                        error: e.to_string(),
                    }
                }
            },
        }
        TransactionStatus::Accepted {}
    }

    /// Handler for NodeMessage::RevertMicroBlock.
    fn handle_pop_micro_block(&mut self) -> Result<(), Error> {
        warn!("Received a request to revert the latest block");
        if self.chain.offset() > 1 {
            let (pruned_outputs, recovered_inputs, txs, block) = self.chain.pop_micro_block()?;
            self.last_block_clock = clock::now();

            self.mempool.pop_microblock(txs.clone());

            let transaction_statuses: HashMap<_, _> = txs
                .iter()
                .map(|tx| {
                    (
                        Hash::digest(&tx),
                        TransactionStatus::Rollback {
                            epoch: self.chain.epoch(),
                            offset: self.chain.offset(),
                        },
                    )
                })
                .collect();
            let msg = RevertedMicroBlock {
                block,
                transaction_statuses,
                pruned_outputs,
                recovered_inputs,
            };
            notify_subscribers(&mut self.chain_subscribers, msg.into());
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
        if leader == self.network_pkey {
            info!(
                "I'm leader, collecting transactions for the next micro block: epoch={}, offset={}, view_change={}, last_block={}",
                self.chain.epoch(),
                self.chain.offset(),
                self.chain.view_change(),
                self.chain.last_block_hash()
            );
            consensus::metrics::CONSENSUS_ROLE
                .set(consensus::metrics::ConsensusRole::Leader as i64);
            let (tx, rx) = oneshot::channel::<Vec<u8>>();
            std::mem::replace(block_timer, MicroBlockTimer::Propose(rx));
            let solver = self.chain.vdf_solver();
            let solver = move || {
                let solution = solver();
                tx.send(solution).ok(); // ignore errors.
            };
            // Spawn a background thread to solve VDF puzzle.
            thread::spawn(solver);
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
            std::mem::replace(
                block_timer,
                MicroBlockTimer::ViewChange(Delay::new(deadline)),
            );
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
                std::mem::replace(block_timer, MacroBlockTimer::Propose(Delay::new(deadline)));
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
            std::mem::replace(
                block_timer,
                MacroBlockTimer::ViewChange(Delay::new(deadline)),
            );
        }

        task::current().notify();
    }

    /// Called when facilitator is changed.
    fn on_facilitator_changed(&mut self) {
        let facilitator = self.chain.facilitator();
        if facilitator == &self.network_pkey {
            info!("I am facilitator");
            let txpool_service =
                TransactionPoolService::new(self.network.clone(), self.node.clone());
            self.txpool_service = Some(txpool_service);
        } else {
            info!("Facilitator is {}", facilitator);
            self.txpool_service = None;
        }
    }

    ///
    /// Change validation status after applying a new block or performing a view change.
    ///
    fn update_validation_status(&mut self) {
        if !self.chain.is_epoch_full() {
            // Expected Micro Block.
            let _prev = std::mem::replace(&mut self.validation, MicroBlockAuditor);
            if !self.chain.is_validator(&self.network_pkey) {
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

            let view_change_collector =
                ViewChangeCollector::new(&self.chain, self.network_pkey, self.network_skey.clone());

            self.validation = MicroBlockValidator {
                view_change_collector,
                block_timer: MicroBlockTimer::None,
                future_consensus_messages: Vec::new(),
            };
            self.on_micro_block_leader_changed();
        } else {
            // Expected Macro Block.
            let prev = std::mem::replace(&mut self.validation, MacroBlockAuditor);
            if !self.chain.is_validator(&self.network_pkey) {
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
                self.network_skey.clone(),
                self.network_pkey.clone(),
                self.chain.election_result().clone(),
                self.chain.validators_at_epoch_start().into_iter().collect(),
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
                block_timer: MacroBlockTimer::None,
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
        let epoch = self.chain.epoch();
        let consensus = match &mut self.validation {
            MacroBlockValidator { consensus, .. } => consensus,
            _ => panic!("Expected MacroBlockValidator state"),
        };

        if consensus.should_prevote() {
            let (block_hash, block_proposal, view_change) = consensus.get_proposal();
            debug!(
                "Validating a macro block proposal: epoch={}, block={}",
                epoch, &block_hash
            );
            let start_clock = clock::now();
            let r = self.chain.validate_proposed_macro_block(
                view_change,
                block_hash,
                &block_proposal.header,
                &block_proposal.transactions,
            );
            let duration = clock::now().duration_since(start_clock);
            let duration = (duration.as_secs() as f64) + (duration.subsec_nanos() as f64) * 1e-9;
            metrics::MACRO_BLOCK_VALIDATE_TIME.set(duration);
            metrics::MACRO_BLOCK_VALIDATE_TIME_HG.observe(duration);
            match r {
                Ok(macro_block) => {
                    debug!(
                        "The macro block proposal is valid: epoch={}, block={}, duration={:.3}",
                        epoch, &block_hash, duration
                    );
                    consensus.prevote(macro_block)
                }
                Err(e) => {
                    error!(
                        "The macro block proposal is invalid: epoch={}, block={}, duration={:.3}, e={}",
                        epoch, &block_hash, duration, e
                    );
                    // TODO(vldm): Didn't go to state Prevote before checking proposed macro block.
                    // for now we just return to Propose state, it's a bit hacky,
                    // but without this consensus would be in buggy state
                    consensus.reset();
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
        let timestamp = Timestamp::now();
        let block_timestamp = self.chain.last_block_timestamp();
        if self.cfg.macro_block_timeout > self.cfg.micro_block_timeout {
            block_timestamp + self.cfg.macro_block_timeout >= timestamp
        } else {
            block_timestamp + self.cfg.micro_block_timeout >= timestamp
        }
    }

    /// Get a timestamp for the next block.
    fn next_block_timestamp(&self) -> Timestamp {
        let timestamp = Timestamp::now();
        if timestamp > self.chain.last_block_timestamp() {
            timestamp
        } else {
            // Timestamp must be increasing.
            self.chain.last_block_timestamp() + Duration::from_millis(1)
        }
    }

    /// Propose a new macro block.
    fn propose_macro_block(&mut self) -> Result<(), Error> {
        let timestamp = self.next_block_timestamp();
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
        std::mem::replace(
            block_timer,
            MacroBlockTimer::ViewChange(Delay::new(deadline)),
        );
        task::current().notify();

        debug!(
            "Creating a new macro block proposal: epoch={}, view_change={}",
            self.chain.epoch(),
            consensus.round(),
        );
        let start_clock = clock::now();

        // Propose a new block.
        let recipient_pkey = self
            .chain
            .account_by_network_key(&self.network_pkey)
            .expect("Staked");

        let (block, transactions) = self.chain.create_macro_block(
            consensus.round(),
            &recipient_pkey,
            &self.network_skey,
            self.network_pkey.clone(),
            timestamp,
        );
        let block_hash = Hash::digest(&block);

        // Create block proposal.
        let block_proposal = MacroBlockProposal {
            header: block.header.clone(),
            transactions,
        };

        let duration = clock::now().duration_since(start_clock);
        let duration = (duration.as_secs() as f64) + (duration.subsec_nanos() as f64) * 1e-9;
        metrics::MACRO_BLOCK_CREATE_TIME.set(duration);
        metrics::MACRO_BLOCK_CREATE_TIME_HG.observe(duration);
        info!(
            "Created a new macro block proposal: epoch={}, view_change={}, hash={}, duration={:.3}",
            self.chain.epoch(),
            consensus.round(),
            block_hash,
            duration
        );

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
            metrics::MACRO_BLOCKS_AUTOCOMMITS.inc();
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

        self.on_status_changed();

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
        let leader = self.chain.leader();
        warn!(
            "Timed out while waiting for a micro block: epoch={}, leader={}, elapsed={:?}",
            self.chain.epoch(),
            leader,
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
        std::mem::replace(
            block_timer,
            MicroBlockTimer::ViewChange(Delay::new(deadline)),
        );
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
        self.on_status_changed();

        Ok(())
    }

    ///
    /// Create a new micro block.
    ///
    fn create_micro_block(&mut self, solution: Vec<u8>) -> Result<(), Error> {
        match &self.validation {
            MicroBlockValidator { .. } => {}
            _ => panic!("Expected MicroBlockValidator State"),
        };
        assert_eq!(self.chain.leader(), self.network_pkey);
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
        let start_clock = clock::now();

        for (cheater, proof) in &self.cheating_proofs {
            // the cheater was already punished, so we keep proofs for rollback case,
            // but avoid punish them second time.
            if !self.chain.is_validator(cheater) {
                continue;
            }
            let slash_tx = confiscate_tx(&self.chain, &self.network_pkey, proof.clone())?;
            let tx: Transaction = slash_tx.into();
            let tx_hash = Hash::digest(&tx);
            self.mempool.push_tx(tx_hash, tx);
        }

        // Create a new micro block from the mempool.
        let recipient_pkey = self
            .chain
            .account_by_network_key(&self.network_pkey)
            .expect("Staked");
        let timestamp = self.next_block_timestamp();
        let mut block = self.mempool.create_block(
            previous,
            epoch,
            offset,
            view_change,
            view_change_proof,
            self.chain.last_random(),
            solution,
            self.chain.cfg().block_reward,
            &recipient_pkey,
            &self.network_skey,
            &self.network_pkey,
            self.cfg.max_inputs_in_block,
            self.cfg.max_outputs_in_block,
            timestamp,
        );

        let block_hash = Hash::digest(&block);

        // Sign block.
        block.sign(&self.network_skey, &self.network_pkey);

        let duration = clock::now().duration_since(start_clock);
        let duration = (duration.as_secs() as f64) + (duration.subsec_nanos() as f64) * 1e-9;
        metrics::MICRO_BLOCK_CREATE_TIME.set(duration);
        metrics::MICRO_BLOCK_CREATE_TIME_HG.observe(duration);
        info!(
            "Created a micro block: epoch={}, offset={}, view_change={}, block={}, transactions={}, duration={:.3}",
            epoch,
            offset,
            view_change,
            &block_hash,
            block.transactions.len(),
            duration,
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

    fn handle_macro_block_info(&self, epoch: u64) -> Result<ExtendedMacroBlock, Error> {
        if epoch >= self.chain.epoch() {
            return Err(format_err!("Macro block doesn't exists: epoch={}", epoch));
        }

        let block = self.chain.macro_block(epoch)?;
        let epoch_info = self.chain.epoch_info(epoch)?.unwrap().clone();
        let msg = ExtendedMacroBlock {
            block,
            epoch_info,
            transaction_statuses: HashMap::new(),
        };
        Ok(msg)
    }

    fn handle_micro_block_info(
        &self,
        epoch: u64,
        offset: u32,
    ) -> Result<ExtendedMicroBlock, Error> {
        if epoch != self.chain.epoch() || offset >= self.chain.offset() {
            return Err(format_err!(
                "Micro block doesn't exists: epoch={}, offset={}",
                epoch,
                offset
            ));
        }
        let block = self.chain.micro_block(epoch, offset)?;
        let msg = ExtendedMicroBlock {
            block,
            transaction_statuses: HashMap::new(),
        };
        Ok(msg)
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Poll timers first.
        if let Some(ref mut loader_timer) = &mut self.loader_timer {
            match loader_timer.poll().unwrap() {
                Async::Ready(()) => {
                    if let Err(e) = self.request_history(self.chain.epoch(), "timer") {
                        error!("Failed to request history: {}", e);
                    }
                }
                Async::NotReady => {}
            }
        }
        let result = match &mut self.validation {
            MicroBlockAuditor
            | MicroBlockValidator {
                block_timer: MicroBlockTimer::None,
                ..
            }
            | MacroBlockAuditor
            | MacroBlockValidator {
                block_timer: MacroBlockTimer::None,
                ..
            } => Ok(()),
            MicroBlockValidator {
                block_timer: MicroBlockTimer::Propose(solver),
                ..
            } => match solver.poll().unwrap() {
                Async::Ready(solution) => self.create_micro_block(solution),
                Async::NotReady => Ok(()),
            },
            MicroBlockValidator {
                block_timer: MicroBlockTimer::ViewChange(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.handle_micro_block_viewchange_timer(),
                Async::NotReady => Ok(()),
            },
            MacroBlockValidator {
                block_timer: MacroBlockTimer::Propose(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.propose_macro_block(),
                Async::NotReady => Ok(()),
            },
            MacroBlockValidator {
                block_timer: MacroBlockTimer::ViewChange(timer),
                ..
            } => match timer.poll().unwrap() {
                Async::Ready(()) => self.handle_macro_block_viewchange_timer(),
                Async::NotReady => Ok(()),
            },
        };
        if let Err(e) = result {
            error!("Error: {}", e);
        }

        // Poll chain readers.
        let mut i = 0;
        while i < self.chain_readers.len() {
            match self.chain_readers[i].poll(&self.chain) {
                Ok(Async::Ready(())) => {
                    // Synchronized with node, convert into a subscription.
                    let subscriber = self.chain_readers.swap_remove(i);
                    self.chain_subscribers.push(subscriber.tx);
                }
                Ok(Async::NotReady) => {
                    i += 1;
                }
                Err(_e) => {
                    self.chain_readers.swap_remove(i);
                }
            }
        }

        if let Some(ref mut txpool_service) = &mut self.txpool_service {
            match txpool_service.poll().unwrap() {
                Async::Ready(_) => unreachable!(),
                Async::NotReady => {}
            };
        }

        // Poll other events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        NodeMessage::Request { request, tx } => {
                            trace!("=> {:?}", request);
                            let response = match request {
                                NodeRequest::ElectionInfo {} => {
                                    NodeResponse::ElectionInfo(self.chain.election_info())
                                }
                                NodeRequest::EscrowInfo {} => {
                                    NodeResponse::EscrowInfo(self.chain.escrow_info())
                                }
                                NodeRequest::PopMicroBlock {} => {
                                    match self.handle_pop_micro_block() {
                                        Ok(()) => NodeResponse::MicroBlockPopped,
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    }
                                }
                                NodeRequest::AddTransaction(tx) => {
                                    let hash = Hash::digest(&tx);
                                    NodeResponse::AddTransaction {
                                        hash,
                                        status: self.handle_add_tx(tx),
                                    }
                                }
                                NodeRequest::ValidateCertificate {
                                    utxo,
                                    spender,
                                    recipient,
                                    rvalue,
                                } => match self.chain.historic_output_by_hash_with_proof(&utxo) {
                                    Err(e) => NodeResponse::Error {
                                        error: format!("{}", e),
                                    },
                                    Ok(None) => NodeResponse::Error {
                                        error: format!("Missing UTXO: {}", utxo),
                                    },
                                    Ok(Some(OutputRecovery {
                                        output: Output::PaymentOutput(output),
                                        epoch,
                                        block_hash,
                                        is_final,
                                        timestamp,
                                    })) => {
                                        match output
                                            .validate_certificate(&spender, &recipient, &rvalue)
                                        {
                                            Ok(amount) => NodeResponse::CertificateValid {
                                                epoch,
                                                block_hash,
                                                is_final,
                                                timestamp,
                                                amount,
                                            },
                                            Err(e) => NodeResponse::Error {
                                                error: format!("{}", e),
                                            },
                                        }
                                    }
                                    Ok(Some(_)) => NodeResponse::Error {
                                        error: format!("Invalid UTXO type: {}", utxo),
                                    },
                                },
                                NodeRequest::EnableRestaking {} => {
                                    if self.is_restaking_enabled {
                                        NodeResponse::Error {
                                            error: format!("Re-staking is already enabled"),
                                        }
                                    } else {
                                        info!("Re-staking enabled");
                                        self.is_restaking_enabled = true;
                                        NodeResponse::RestakingEnabled
                                    }
                                }
                                NodeRequest::DisableRestaking {} => {
                                    if !self.is_restaking_enabled {
                                        NodeResponse::Error {
                                            error: format!("Re-staking is already disabled"),
                                        }
                                    } else {
                                        info!("Re-staking disabled");
                                        self.is_restaking_enabled = false;
                                        NodeResponse::RestakingDisabled
                                    }
                                }
                                NodeRequest::StatusInfo {} => {
                                    let status = self.status();
                                    NodeResponse::StatusInfo(status)
                                }
                                NodeRequest::SubscribeStatus {} => {
                                    match self.handle_subscription_to_status() {
                                        Ok(rx) => {
                                            let status = self.status();
                                            NodeResponse::SubscribedStatus {
                                                status,
                                                rx: Some(rx),
                                            }
                                        }
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    }
                                }
                                NodeRequest::MacroBlockInfo { epoch } => {
                                    match self.handle_macro_block_info(epoch) {
                                        Ok(block_info) => NodeResponse::MacroBlockInfo(block_info),
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    }
                                }
                                NodeRequest::MicroBlockInfo { epoch, offset } => {
                                    match self.handle_micro_block_info(epoch, offset) {
                                        Ok(block_info) => NodeResponse::MicroBlockInfo(block_info),
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    }
                                }
                                NodeRequest::SubscribeChain { epoch, offset } => {
                                    match self.handle_subscription_to_chain(epoch, offset) {
                                        Ok(rx) => NodeResponse::SubscribedChain {
                                            current_epoch: self.chain.epoch(),
                                            current_offset: self.chain.offset(),
                                            rx: Some(rx),
                                        },
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    }
                                }
                            };
                            trace!("<= {:?}", response);
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

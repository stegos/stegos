//! Blockchain Node.

//
// Copyright (c) 2018 Stegos
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

mod consensus;
mod election;
mod error;
pub mod protos;
mod tickets;

use crate::consensus::*;
use crate::protos::{FromProto, IntoProto};
use bitvector::BitVector;

use crate::election::ConsensusGroup;
use crate::error::*;
pub use crate::tickets::{TicketsSystem, VRFTicket};
use chrono::Utc;
use failure::{ensure, Error};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use linked_hash_map::LinkedHashMap;
use log::*;
use protobuf;
use protobuf::Message;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_config::*;
use stegos_consensus::check_multi_signature;
use stegos_crypto::bulletproofs::validate_range_proof;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;
use stegos_crypto::pbc::secure::G2;
use stegos_keychain::KeyChain;
use stegos_network::Broker;
use tokio_timer::Interval;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Load genesis blocks for tests and development.
pub fn genesis_dev() -> Result<Vec<Block>, Error> {
    // Load generated blocks
    let block1 = include_bytes!("../data/genesis0.bin");
    let block2 = include_bytes!("../data/genesis1.bin");
    let mut blocks = Vec::<Block>::new();
    for block in &[&block1[..], &block2[..]] {
        let block: protos::node::Block = protobuf::parse_from_bytes(block)?;
        let block = Block::from_proto(&block)?;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Blockchain Node.
#[derive(Clone, Debug)]
pub struct Node {
    outbox: UnboundedSender<NodeMessage>,
    broker: Broker,
}

impl Node {
    /// Create a new blockchain node.
    pub fn new(
        keys: KeyChain,
        broker: Broker,
    ) -> Result<(impl Future<Item = (), Error = ()>, Node), Error> {
        let (outbox, inbox) = unbounded();

        let service = NodeService::new(keys, broker.clone(), inbox)?;
        let handler = Node { outbox, broker };

        Ok((service, handler))
    }

    /// Initialize blockchain.
    pub fn init(&self, genesis: Vec<Block>) -> Result<(), Error> {
        let msg = NodeMessage::Init { genesis };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Send transaction to node and to the network.
    pub fn send_transaction(&self, tx: Transaction) -> Result<(), Error> {
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        self.broker.publish(&TX_TOPIC.to_string(), data.clone())?;
        info!(
            "Sent transaction to the network: hash={}",
            Hash::digest(&tx.body)
        );
        let msg = NodeMessage::Transaction(data);
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

    /// Subscribe to outputs.
    pub fn subscribe_outputs(&self) -> Result<UnboundedReceiver<OutputsNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeOutputs(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }
}

/// Send when epoch is changed.
#[derive(Clone, Debug)]
pub struct EpochNotification {
    pub epoch: u64,
    pub leader: SecurePublicKey,
    pub witnesses: BTreeSet<SecurePublicKey>,
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
/// Topic used for CoSi.
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
/// Max count of sealed block in epoch.
const SEALED_BLOCK_IN_EPOCH: usize = 5;
/// Max difference in timestamps of leader and witnesses.
const TIME_TO_RECEIVE_BLOCK: u64 = 10 * 60;

type Mempool = LinkedHashMap<Hash, Transaction>;

#[derive(Clone, Debug)]
enum NodeMessage {
    //
    // Public API
    //
    SubscribeEpoch(UnboundedSender<EpochNotification>),
    SubscribeOutputs(UnboundedSender<OutputsNotification>),

    //
    // Network Events
    //
    Transaction(Vec<u8>),
    Consensus(Vec<u8>),
    SealedBlock(Vec<u8>),
    VRFMessage(Vec<u8>),
    //
    // Internal Events
    //
    Init { genesis: Vec<Block> },
    ConsensusTimer(Instant),
    VRFTimer(Instant),
}

struct NodeService {
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,

    /// A monotonically increasing value that represents the heights of the blockchain,
    /// starting from genesis block (=0).
    epoch: u64,

    /// Number of sealed block processed during epoch,
    sealed_block_num: usize,

    /// A system that restart consensus in case of fault or partition.
    /// And allow to change validators in case of epoch change.
    vrf_system: TicketsSystem,

    /// A queue of consensus message from the future epoch.
    // TODO: Add orphan SealedBlock to the queue.
    // TODO: Resolve unknown blocks using requests-responses.
    future_consensus_messages: Vec<Vec<u8>>,

    //
    // Consensus
    //
    /// Map of all actual nodes stakes.
    /// Actual stakes.
    stakes: BTreeMap<SecurePublicKey, i64>,
    /// Snapshot of selected leader from the latest key block.
    leader: SecurePublicKey,
    /// Snapshot of validators with stakes from the latest key block.
    validators: BTreeMap<SecurePublicKey, i64>,

    /// Memory pool of pending transactions.
    mempool: Mempool,
    /// Proof-of-stake consensus.
    consensus: Option<BlockConsensus>,
    /// A timestamp when the last sealed block was received.
    last_block_timestamp: Instant,

    /// Network interface.
    broker: Broker,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochNotification>>,
    /// Triggered when outputs created and/or pruned.
    on_outputs_changed: Vec<UnboundedSender<OutputsNotification>>,
    /// Aggregated stream of events.
    events: Box<Stream<Item = NodeMessage, Error = ()> + Send>,
}

impl NodeService {
    /// Constructor.
    fn new(
        keys: KeyChain,
        broker: Broker,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let chain = Blockchain::new();
        let epoch: u64 = 0;
        let sealed_block_num = 0;
        let stakes = BTreeMap::new();
        let leader: SecurePublicKey = G2::generator().into(); // some fake key
        let validators = BTreeMap::<SecurePublicKey, i64>::new();
        let future_consensus_messages = Vec::new();
        //TODO: Calculate viewchange on node restart by timeout since last known block.
        let vrf_system = TicketsSystem::new(WITNESSES_MAX, 0, 0, keys.cosi_pkey, keys.cosi_skey);

        let mempool = Mempool::new();
        let consensus = None;
        let last_block_timestamp = Instant::now();

        let on_epoch_changed = Vec::<UnboundedSender<EpochNotification>>::new();
        let on_outputs_received = Vec::<UnboundedSender<OutputsNotification>>::new();

        let mut streams = Vec::<Box<Stream<Item = NodeMessage, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Transaction Requests
        let transaction_rx = broker
            .subscribe(&TX_TOPIC.to_string())?
            .map(|m| NodeMessage::Transaction(m));
        streams.push(Box::new(transaction_rx));

        // Consensus Requests
        let consensus_rx = broker
            .subscribe(&CONSENSUS_TOPIC.to_string())?
            .map(|m| NodeMessage::Consensus(m));
        streams.push(Box::new(consensus_rx));

        // VRF Requests
        let ticket_system_rx = broker
            .subscribe(&tickets::VRF_TICKETS_TOPIC.to_string())?
            .map(|m| NodeMessage::VRFMessage(m));
        streams.push(Box::new(ticket_system_rx));

        // Block Requests
        let block_rx = broker
            .subscribe(&SEALED_BLOCK_TOPIC.to_string())?
            .map(|m| NodeMessage::SealedBlock(m));
        streams.push(Box::new(block_rx));

        // CoSi timer events
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
            future_consensus_messages,
            sealed_block_num,
            vrf_system,
            chain,
            keys,
            epoch,
            leader,
            stakes,
            validators,
            mempool,
            consensus,
            last_block_timestamp,
            broker,
            on_epoch_changed,
            on_outputs_changed: on_outputs_received,
            events,
        };

        Ok(service)
    }

    /// Handler for NodeMessage::Init.
    fn handle_init(&mut self, genesis: Vec<Block>) -> Result<(), Error> {
        debug!("Registering genesis blocks...");

        //
        // Sic: genesis block has invalid monetary balance, so handle_monetary_block()
        // can't be used here.
        //

        for block in genesis {
            match block {
                Block::KeyBlock(key_block) => {
                    debug!(
                        "Genesis key block: height={}, hash={}",
                        self.chain.height() + 1,
                        Hash::digest(&key_block)
                    );
                    let key_block2 = key_block.clone();

                    // TODO: remove stakes initialisation.
                    let mut sum_dev_stake = key_block.header.witnesses.len() as i64 * 10;
                    for node in &key_block.header.witnesses {
                        sum_dev_stake /= 2;
                        let stake = sum_dev_stake;
                        self.stakes.insert(*node, stake);
                    }

                    self.chain.register_key_block(key_block)?;
                    self.on_key_block_registered(&key_block2)?;
                }
                Block::MonetaryBlock(monetary_block) => {
                    debug!(
                        "Genesis payment block: height={}, hash={}",
                        self.chain.height() + 1,
                        Hash::digest(&monetary_block)
                    );
                    let monetary_block2 = monetary_block.clone();
                    let inputs = self.chain.register_monetary_block(monetary_block)?;
                    self.on_monetary_block_registered(&monetary_block2, inputs);
                }
            }
        }

        if let Some(consensus) = &mut self.consensus {
            // Move to the next height.
            consensus.reset(self.chain.height() as u64);
        }

        self.last_block_timestamp = Instant::now();

        Ok(())
    }

    /// Handle incoming transactions received from network.
    fn handle_transaction(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let tx: protos::node::Transaction = protobuf::parse_from_bytes(&msg)?;
        let tx = Transaction::from_proto(&tx)?;

        let tx_hash = Hash::digest(&tx.body);
        info!(
            "Received transaction from the network: hash={}, inputs={}, outputs={}, fee={}",
            &tx_hash,
            tx.body.txins.len(),
            tx.body.txouts.len(),
            tx.body.fee
        );

        // Check that transaction exists in the mempool.
        if self.mempool.contains_key(&tx_hash) {
            return Err(NodeError::TransactionAlreadyExists(tx_hash).into());
        }

        // Check fee.
        NodeService::check_acceptable_fee(&tx)?;

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&tx.body.txins)?;

        // Validate monetary balance and signature.
        tx.validate(&inputs)?;

        // Queue to mempool.
        info!("Transaction is valid, adding to mempool: hash={}", &tx_hash);
        self.mempool.insert(tx_hash, tx);

        Ok(())
    }

    /// Handle incoming KeyBlock
    fn handle_sealed_key_block(&mut self, key_block: KeyBlock) -> Result<(), Error> {
        // TODO: How check is keyblock a valid fork?
        // We can accept any keyblock if we on bootstraping phase.
        let block_hash = Hash::digest(&key_block);
        // Check epoch.
        if self.epoch + 1 != key_block.header.base.epoch {
            error!(
                "Invalid or out-of-order block received: hash={}, expected_epoch={}, got_epoch={}",
                &block_hash, self.epoch, key_block.header.base.epoch
            );
            return Ok(());
        }
        let leader = key_block.header.leader.clone();
        let mut validators = BTreeMap::<SecurePublicKey, i64>::new();
        for validator in &key_block.header.witnesses {
            let stake = self
                .stakes
                .get(validator)
                .expect("all staked nodes have stake");
            validators.insert(validator.clone(), *stake);
        }

        // Check BLS multi-signature.
        if !check_multi_signature(
            &block_hash,
            &key_block.header.base.multisig,
            &key_block.header.base.multisigmap,
            &validators,
            &leader,
        ) {
            return Err(NodeError::InvalidBlockSignature(block_hash).into());
        }

        key_block.validate()?;
        let key_block2 = key_block.clone();
        self.chain.register_key_block(key_block)?;
        self.on_key_block_registered(&key_block2)?;
        Ok(())
    }

    /// Handle incoming MonetaryBlock
    fn handle_sealed_monetary_block(
        &mut self,
        monetary_block: MonetaryBlock,
        pkey: &SecurePublicKey,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(&monetary_block);
        // For monetary block, consensus is stable, and we can just check leader.
        // Check that message is signed by current leader.
        if *pkey != self.leader {
            return Err(
                NodeError::SealedBlockFromNonLeader(block_hash, self.leader.clone(), *pkey).into(),
            );
        }
        // Check epoch.
        if self.epoch != monetary_block.header.base.epoch {
            error!(
                "Invalid or out-of-order block received: hash={}, expected_epoch={}, got_epoch={}",
                &block_hash, self.epoch, monetary_block.header.base.epoch
            );
            return Ok(());
        }

        // Check BLS multi-signature.
        if !check_multi_signature(
            &block_hash,
            &monetary_block.header.base.multisig,
            &monetary_block.header.base.multisigmap,
            &self.validators,
            &self.leader,
        ) {
            return Err(NodeError::InvalidBlockSignature(block_hash).into());
        }

        trace!("Validating block monetary balance: hash={}..", &block_hash);

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&monetary_block.body.inputs)?;

        // Validate monetary balance.
        monetary_block.validate(&inputs)?;

        info!("Monetary block is valid: hash={}", &block_hash);

        let monetary_block2 = monetary_block.clone();
        let inputs = self.chain.register_monetary_block(monetary_block)?;

        // TODO: implement proper handling of mempool.
        self.mempool.clear();

        self.on_monetary_block_registered(&monetary_block2, inputs);
        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_sealed_block(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let msg: protos::node::SealedBlockMessage = protobuf::parse_from_bytes(&msg)?;
        let msg = SealedBlockMessage::from_proto(&msg)?;

        // Check signature and content.
        msg.validate()?;

        let block = msg.block;
        let block_hash = Hash::digest(&block);
        info!(
            "Received sealed block from the network: hash={}, current_height={}",
            &block_hash,
            self.chain.height()
        );

        // Check that block is not registered yet.
        if let Some(_) = self.chain.block_by_hash(&block_hash) {
            warn!("Block has been already registered: hash={}", &block_hash);
            // Already registered, skip.
            return Ok(());
        }

        {
            let header = block.base_header();
            // Check previous hash.
            let previous_hash = Hash::digest(self.chain.last_block());
            if previous_hash != header.previous {
                //TODO: Add orphan blocks to the self.future_consensus_messages;
                error!("Invalid or out-of-order block received: hash={}, expected_previous={}, got_previous={}",
                       &block_hash, &previous_hash, &header.previous);
                return Ok(());
            }
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
            Block::KeyBlock(key_block) => self.handle_sealed_key_block(key_block)?,
            Block::MonetaryBlock(monetary_block) => {
                self.handle_sealed_monetary_block(monetary_block, &msg.pkey)?
            }
        };
        self.on_next_block(block_hash)
    }

    fn on_next_block(&mut self, block_hash: Hash) -> Result<(), Error> {
        self.sealed_block_num += 1;
        // epoch ended, disable consensus and start vrf system.
        if self.sealed_block_num >= SEALED_BLOCK_IN_EPOCH {
            self.consensus = None;
            let ticket = self.vrf_system.handle_epoch_end(block_hash)?;
            self.broadcast_vrf_ticket(ticket)?;
        } else {
            // restart vrf system timer on new block.
            self.vrf_system.handle_sealed_block();
        }

        if let Some(consensus) = &mut self.consensus {
            // Move to the next height.
            consensus.reset(self.chain.height() as u64);
        }
        self.last_block_timestamp = Instant::now();

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeEpoch.
    fn handle_subscribe_epoch(
        &mut self,
        tx: UnboundedSender<EpochNotification>,
    ) -> Result<(), Error> {
        let msg = EpochNotification {
            epoch: self.epoch,
            leader: self.leader.clone(),
            witnesses: self.validators.keys().cloned().collect(),
        };
        tx.unbounded_send(msg)?;
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

    /// Handler for new epoch creation procedure.
    /// This method called only on leader side, and when consensus is active.
    /// Leader should create a KeyBlock based on last random provided by VRF.
    fn on_create_new_epoch(&mut self) -> Result<(), Error> {
        let consensus = self.consensus.as_mut().unwrap();
        let last = self.chain.last_block();
        let previous = Hash::digest(last);
        let timestamp = Utc::now().timestamp() as u64;
        let epoch = self.epoch + 1;

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp);
        debug!(
            "Creating a new epoch proposal: {}, with leader = {}",
            epoch,
            consensus.leader()
        );

        let block = KeyBlock::new(
            base,
            consensus.leader(),
            consensus.validators().iter().map(|(k, _s)| *k).collect(),
        );

        let block_hash = Hash::digest(&block);

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
        NodeService::flush_consensus_messages(consensus, &mut self.broker)
    }

    /// Returns new active nodes list.
    fn active_stakers(&self) -> Vec<(SecurePublicKey, i64)> {
        self.stakes
            .iter()
            .filter_map(|(k, v)| if *v > 0 { Some((*k, *v)) } else { None })
            .collect()
    }

    /// Returns stake from database.
    /// Called when witnesses list was changed.
    #[allow(dead_code)]
    fn validator_stake(&self, validator: &SecurePublicKey) -> i64 {
        self.stakes.get(validator).cloned().unwrap_or(0)
    }

    /// Adds some stake to node full stake.
    /// Returns new stake.
    #[allow(dead_code)]
    fn add_stake(&mut self, node: &SecurePublicKey, stake: i64) -> i64 {
        let old_stake = self.stakes.entry(*node).or_insert(0);
        *old_stake += stake;
        *old_stake
    }

    /// Take nodes stake.
    /// Returns value of stake;
    #[allow(dead_code)]
    fn take_stake(&mut self, node: &SecurePublicKey) -> i64 {
        let stake = self.stakes.remove(node).unwrap_or(0);
        stake
    }

    /// Called when a new key block is registered.
    fn on_key_block_registered(&mut self, key_block: &KeyBlock) -> Result<(), Error> {
        assert_eq!(self.epoch + 1, key_block.header.base.epoch);
        self.epoch = self.epoch + 1;

        self.sealed_block_num = 0;
        self.leader = key_block.header.leader.clone();
        let mut validators = BTreeMap::<SecurePublicKey, i64>::new();
        for validator in &key_block.header.witnesses {
            let stake = self
                .stakes
                .get(validator)
                .expect("all staked nodes have stake");
            validators.insert(validator.clone(), *stake);
        }
        self.validators = validators;

        if self.validators.contains_key(&self.keys.cosi_pkey) {
            // Promote to Validator role
            let consensus = BlockConsensus::new(
                self.chain.height() as u64,
                self.epoch,
                self.keys.cosi_skey.clone(),
                self.keys.cosi_pkey.clone(),
                self.leader.clone(),
                self.validators.clone(),
            );

            if consensus.is_leader() {
                info!("I'm leader: epoch={}", self.epoch);
            } else {
                info!(
                    "I'm validator: epoch={}, leader={}",
                    self.epoch, self.leader
                );
            }

            self.consensus = Some(consensus);
            self.on_new_consensus();
        } else {
            // Resign from Validator role.
            info!(
                "I'm regular node: epoch={}, leader={}",
                self.epoch, self.leader
            );
            self.consensus = None;
        }
        debug!("Validators: {:?}", &self.validators);

        // clear consensus messages when new epoch starts
        self.future_consensus_messages.clear();

        Ok(())
    }

    /// Called when a new key block is registered.
    fn on_monetary_block_registered(
        &mut self,
        monetary_block: &MonetaryBlock,
        inputs: Vec<Output>,
    ) {
        //
        // Notify subscribers.
        //

        let outputs = monetary_block
            .body
            .outputs
            .leafs()
            .drain(..)
            .map(|(o, _path)| *o.clone())
            .collect();
        let msg = OutputsNotification { inputs, outputs };
        self.on_outputs_changed
            .retain(move |ch| ch.unbounded_send(msg.clone()).is_ok());
    }

    /// Send block to network.
    fn send_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        let msg = SealedBlockMessage::new(&self.keys.cosi_skey, &self.keys.cosi_pkey, block);
        let proto = msg.into_proto();
        let data = proto.write_to_bytes()?;
        // Don't send block to myself.
        self.broker.publish(&SEALED_BLOCK_TOPIC.to_string(), data)?;
        info!("Sent sealed block to the network: hash={}", block_hash);
        Ok(())
    }

    /// Calculate fee for data transaction.
    fn data_fee(size: usize, ttl: u64) -> i64 {
        assert!(size > 0);
        let units: usize = (size + (DATA_UNIT - 1)) / DATA_UNIT;
        (units as i64) * (ttl as i64) * DATA_UNIT_FEE
    }

    /// Check minimal acceptable fee for transaction.
    fn check_acceptable_fee(tx: &Transaction) -> Result<(), NodeError> {
        let mut min_fee: i64 = 0;
        for txout in &tx.body.txouts {
            min_fee += match txout {
                Output::MonetaryOutput(_o) => MONETARY_FEE,
                Output::EscrowOutput(_o) => ESCROW_FEE,
                Output::DataOutput(o) => NodeService::data_fee(o.data_size(), o.ttl),
            };
        }

        // Transaction's fee is too low.
        if tx.body.fee < min_fee {
            return Err(NodeError::TooLowFee(min_fee, tx.body.fee));
        }
        Ok(())
    }

    ///
    /// Process transactions in mempool and create a new MonetaryBlockProposal.
    ///
    fn process_mempool(
        mempool: &mut Mempool,
        chain: &mut Blockchain,
        epoch: u64,
        skey: &SecretKey,
        pkey: &PublicKey,
    ) -> Result<((Block, BlockProof)), Error> {
        info!("I'm leader, proposing a new monetary block");

        // TODO: limit the block size.
        let tx_count = mempool.len();
        debug!(
            "Processing {}/{} transactions from mempool",
            tx_count,
            mempool.len()
        );

        let timestamp = Utc::now().timestamp() as u64;
        let mut gamma = Fr::zero();
        let mut fee = 0i64;
        let mut inputs = Vec::<Output>::new();
        let mut inputs_hashes = BTreeSet::<Hash>::new();
        let mut outputs = Vec::<Output>::new();
        let mut outputs_hashes = BTreeSet::<Hash>::new();
        let mut tx_hashes = Vec::<Hash>::with_capacity(tx_count);
        for entry in mempool.entries() {
            let tx_hash = entry.key();
            let tx = entry.get();
            assert_eq!(tx_hash, &Hash::digest(&tx.body));
            debug!("Processing transaction: hash={}", &tx_hash);

            // Check that transaction's inputs are exists.
            let tx_inputs = match chain.outputs_by_hashes(&tx.body.txins) {
                Ok(tx_inputs) => tx_inputs,
                Err(e) => {
                    error!(
                        "Discarded invalid transaction: hash={}, error={}",
                        tx_hash, e
                    );
                    continue;
                }
            };

            // Check that transaction's inputs are not used yet.
            for tx_input_hash in &tx.body.txins {
                if !inputs_hashes.insert(tx_input_hash.clone()) {
                    let e = BlockchainError::MissingUTXO(tx_input_hash.clone());
                    error!(
                        "Discarded invalid transaction: hash={}, error={}",
                        tx_hash, e
                    );
                    continue;
                }
            }

            // Check transaction's outputs.
            for tx_output in &tx.body.txouts {
                let tx_output_hash = Hash::digest(tx_output);
                if let Some(_) = chain.output_by_hash(&tx_output_hash) {
                    return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
                }
                if !outputs_hashes.insert(tx_output_hash.clone()) {
                    return Err(BlockchainError::DuplicateTransactionOutput(tx_output_hash).into());
                }
            }

            // Check transaction's signature, monetary balance, fee and others
            debug_assert!(tx.validate(&tx_inputs).is_ok()); // checked when added to mempool

            //
            // Transaction is valid
            //--------------------------------------------------------------------------------------

            gamma += tx.body.gamma;
            fee += tx.body.fee;
            tx_hashes.push(tx_hash.clone());

            inputs.extend(tx_inputs.clone());
            outputs.extend(tx.body.txouts.clone());
        }

        // Create transaction for fee
        let output_fee = if fee > 0 {
            trace!("Creating fee UTXO...");
            let (output_fee, gamma_fee) = Output::new_monetary(timestamp, skey, pkey, fee)?;
            gamma -= gamma_fee;
            info!(
                "Created fee UTXO: hash={}, amount={}",
                Hash::digest(&output_fee),
                fee
            );
            outputs.push(output_fee.clone());
            Some(output_fee)
        } else {
            None
        };

        //
        // Create a monetary block
        //
        trace!("Creating a monetary block...");
        let inputs_hashes: Vec<Hash> = inputs_hashes.into_iter().collect();

        let previous = {
            let last = chain.last_block();
            let previous = Hash::digest(last);
            previous
        };

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp);
        let block = MonetaryBlock::new(base, gamma.clone(), &inputs_hashes, &outputs);

        // Double-check the monetary balance of created block.
        let inputs = chain
            .outputs_by_hashes(&block.body.inputs)
            .expect("transactions valid");
        block.validate(&inputs)?;

        let block_hash = Hash::digest(&block);
        info!(
            "Created monetary block: height={}, hash={}, inputs={}, outputs={}",
            chain.height() + 1,
            block_hash,
            inputs_hashes.len(),
            outputs.len()
        );

        let proof = MonetaryBlockProof {
            fee_output: output_fee,
            gamma,
            tx_hashes,
        };
        let proof = BlockProof::MonetaryBlockProof(proof);
        let block = Block::MonetaryBlock(block);

        Ok((block, proof))
    }

    /// Request for changing group received from VRF system.
    /// Restars consensus with new params, and send new keyblock.
    fn on_change_group(&mut self, group: ConsensusGroup) -> Result<(), Error> {
        info!("Changing group, new group leader = {:?}", group.leader);
        self.leader = group.leader;
        self.validators = group.witnesses.iter().cloned().collect();
        if self.validators.contains_key(&self.keys.cosi_pkey) {
            let consensus = BlockConsensus::new(
                self.chain.height() as u64,
                self.epoch + 1,
                self.keys.cosi_skey.clone(),
                self.keys.cosi_pkey.clone(),
                self.leader.clone(),
                self.validators.clone(),
            );
            self.consensus = Some(consensus);
            let consensus = self.consensus.as_ref().unwrap();
            if consensus.is_leader() {
                self.on_create_new_epoch()?;
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
        broker: &mut Broker,
    ) -> Result<(), Error> {
        // Flush message queue.
        let outbox = std::mem::replace(&mut consensus.outbox, Vec::new());
        for msg in outbox {
            let proto = msg.into_proto();
            let data = proto.write_to_bytes()?;
            broker.publish(&CONSENSUS_TOPIC.to_string(), data)?;
        }
        Ok(())
    }

    ///
    /// Handles incoming consensus requests received from network.
    ///
    fn handle_consensus_message(&mut self, buffer: Vec<u8>) -> Result<(), Error> {
        // Process incoming message.
        let msg: protos::node::ConsensusMessage = protobuf::parse_from_bytes(&buffer)?;
        let msg = BlockConsensusMessage::from_proto(&msg)?;

        // if our consensus state is outdated, push message to future_consensus_messages.
        // TODO: remove queue and use request-responses to get message from other nodes.
        if self.consensus.is_none() || self.consensus.as_ref().unwrap().epoch() == msg.epoch + 1 {
            self.future_consensus_messages.push(buffer);
            return Ok(());
        }
        let consensus = self.consensus.as_mut().unwrap();
        consensus.feed_message(msg)?;
        // Flush pending messages.
        NodeService::flush_consensus_messages(consensus, &mut self.broker)?;

        // Check if we can prevote for a block.
        if !consensus.is_leader() && consensus.should_prevote() {
            self.prevote_block();
        }
        // Check if we can commit a block.
        let consensus = self.consensus.as_ref().unwrap();
        if consensus.is_leader() && consensus.should_commit() {
            let (block, _proof, multisig, multisigmap) =
                self.consensus.as_mut().unwrap().sign_and_commit();
            let block_hash = Hash::digest(&block);
            self.commit_proposed_block(block, multisig, multisigmap);
            self.on_next_block(block_hash)?;
        }
        Ok(())
    }

    ///
    /// Called periodically every CONSENSUS_TIMER seconds.
    ///
    fn handle_consensus_timer(&mut self) -> Result<(), Error> {
        let elapsed = self.last_block_timestamp.elapsed();

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

        // Create a new payment block from mempool.
        let (block, proof) = NodeService::process_mempool(
            &mut self.mempool,
            &mut self.chain,
            self.epoch,
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
        )?;

        // Propose this block.
        let request_hash = Hash::digest(&block);
        let consensus = self.consensus.as_mut().unwrap();
        consensus.propose(block, proof);
        // Prevote for this block.
        consensus.prevote(request_hash);
        // Flush pending messages.
        NodeService::flush_consensus_messages(consensus, &mut self.broker)?;
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
        debug!("Validating block: block={}", &request_hash);
        match NodeService::validate_block(
            consensus,
            &self.mempool,
            &self.chain,
            self.epoch,
            block,
            proof,
        ) {
            Ok(()) => {
                let consensus = self.consensus.as_mut().unwrap();
                consensus.prevote(request_hash);
                NodeService::flush_consensus_messages(consensus, &mut self.broker).unwrap();
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
        epoch: u64,
        block: &Block,
        proof: &BlockProof,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(block);
        let base_header = block.base_header();

        // Check block hash uniqueness.
        if let Some(_) = chain.block_by_hash(&block_hash) {
            return Err(NodeError::BlockAlreadyRegistered(block_hash).into());
        }

        // Check block version.
        if VERSION != base_header.version {
            return Err(
                NodeError::InvalidBlockVersion(block_hash, VERSION, base_header.version).into(),
            );
        }

        // Check previous hash.
        let previous_hash = Hash::digest(chain.last_block());
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
                // We can validate witnesses of MonetaryBlock only in current epoch.
                if epoch != base_header.epoch {
                    return Err(NodeError::OutOfOrderBlockEpoch(
                        block_hash,
                        epoch,
                        base_header.epoch,
                    )
                    .into());
                }
                NodeService::validate_monetary_block(
                    mempool,
                    chain,
                    block_hash,
                    &block,
                    &proof.fee_output,
                    &proof.gamma,
                    &proof.tx_hashes,
                )
            }
            (Block::KeyBlock(block), BlockProof::KeyBlockProof) => {
                // Epoch of the KeyBlock should be next our epoch.
                if epoch + 1 != base_header.epoch {
                    return Err(NodeError::OutOfOrderBlockEpoch(
                        block_hash,
                        epoch,
                        base_header.epoch,
                    )
                    .into());
                }
                NodeService::validate_key_block(consensus, block_hash, block)
            }
            (_, _) => unreachable!(),
        }
    }

    /// Process MonetaryBlockProposal CoSi message.
    fn validate_monetary_block(
        mempool: &Mempool,
        chain: &Blockchain,
        block_hash: Hash,
        block: &MonetaryBlock,
        fee_output: &Option<Output>,
        gamma: &Fr,
        tx_hashes: &Vec<Hash>,
    ) -> Result<(), Error> {
        // Check transactions.
        let mut inputs = Vec::<Output>::new();
        let mut inputs_hashes = BTreeSet::<Hash>::new();
        let mut outputs = Vec::<Output>::new();
        let mut outputs_hashes = BTreeSet::<Hash>::new();
        for tx_hash in tx_hashes {
            debug!("Processing transaction: hash={}", &tx_hash);

            // Check that transaction is present in mempool.
            let tx = mempool.get(&tx_hash);
            if tx.is_none() {
                return Err(NodeError::TransactionMissingInMempool(*tx_hash).into());
            }

            let tx = tx.unwrap();

            // Check that transaction's inputs are exists.
            let tx_inputs = chain.outputs_by_hashes(&tx.body.txins)?;

            // Check transaction's signature, monetary balance, fee and others.
            tx.validate(&tx_inputs)?;

            // Check that transaction's inputs are not used yet.
            for tx_input_hash in &tx.body.txins {
                if !inputs_hashes.insert(tx_input_hash.clone()) {
                    return Err(
                        BlockchainError::DuplicateTransactionInput(tx_input_hash.clone()).into(),
                    );
                }
            }

            // Check transaction's outputs.
            for tx_output in &tx.body.txouts {
                let tx_output_hash = Hash::digest(tx_output);
                if let Some(_) = chain.output_by_hash(&tx_output_hash) {
                    return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
                }
                if !outputs_hashes.insert(tx_output_hash.clone()) {
                    return Err(BlockchainError::DuplicateTransactionOutput(tx_output_hash).into());
                }
            }

            inputs.extend(tx_inputs.iter().cloned());
            outputs.extend(tx.body.txouts.iter().cloned());
        }

        if let Some(output_fee) = fee_output {
            let tx_output_hash = Hash::digest(output_fee);
            if let Some(_) = chain.output_by_hash(&tx_output_hash) {
                return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
            }
            if !outputs_hashes.insert(tx_output_hash.clone()) {
                return Err(BlockchainError::DuplicateTransactionOutput(tx_output_hash).into());
            }
            match &output_fee {
                Output::MonetaryOutput(o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(BlockchainError::InvalidBulletProof.into());
                    }
                }
                _ => {
                    return Err(NodeError::InvalidFeeUTXO(tx_output_hash).into());
                }
            };
            outputs.push(output_fee.clone());
        }

        drop(outputs_hashes);

        debug!("Validating monetary block");

        let inputs_hashes: Vec<Hash> = inputs_hashes.into_iter().collect();

        let base_header = block.header.base.clone();
        let block = MonetaryBlock::new(base_header, gamma.clone(), &inputs_hashes, &outputs);
        let inputs = chain
            .outputs_by_hashes(&block.body.inputs)
            .expect("check above");
        block.validate(&inputs)?;

        // TODO: block hash doesn't cover inputs and outputs
        let block_hash2 = Hash::digest(&block);

        if block_hash != block_hash2 {
            return Err(NodeError::InvalidBlockHash(block_hash, block_hash2).into());
        }

        debug!("Block proposal is valid: block={}", block_hash);

        Ok(())
    }

    /// Process MonetaryBlockProposal CoSi message.
    fn validate_key_block(
        consensus: &BlockConsensus,
        block_hash: Hash,
        block: &KeyBlock,
    ) -> Result<(), Error> {
        block.validate()?;
        ensure!(
            block.header.leader == consensus.leader(),
            "Consensus leader different from our consensus group."
        );
        ensure!(
            block.header.witnesses.len() == consensus.validators().len(),
            "Received key block proposal with wrong consensus group"
        );

        for validator in &block.header.witnesses {
            ensure!(
                consensus.validators().contains_key(validator),
                "Received Key block proposal with wrong consensus group."
            );
        }
        debug!("Key block proposal is valid: block={}", block_hash);
        Ok(())
    }

    ///
    /// Commit sealed block into blockchain and send it to the network.
    /// NOTE: commit must never fail. Please don't use Result<(), Error> here.
    ///
    fn commit_proposed_block(
        &mut self,
        block: Block,
        multisig: SecureSignature,
        multisigmap: BitVector,
    ) {
        match block {
            Block::KeyBlock(mut key_block) => {
                key_block.header.base.multisig = multisig;
                key_block.header.base.multisigmap = multisigmap;
                let key_block2 = key_block.clone();
                self.chain
                    .register_key_block(key_block)
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
                let pruned = self
                    .chain
                    .register_monetary_block(monetary_block)
                    .expect("block is validated before");
                // TODO: implement proper handling of mempool.
                self.mempool.clear();
                self.on_monetary_block_registered(&monetary_block2, pruned);
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
                        NodeMessage::SubscribeEpoch(tx) => self.handle_subscribe_epoch(tx),
                        NodeMessage::SubscribeOutputs(tx) => self.handle_subscribe_outputs(tx),
                        NodeMessage::Transaction(msg) => self.handle_transaction(msg),
                        NodeMessage::Consensus(msg) => self.handle_consensus_message(msg),
                        NodeMessage::SealedBlock(msg) => self.handle_sealed_block(msg),
                        NodeMessage::ConsensusTimer(_now) => self.handle_consensus_timer(),
                        NodeMessage::VRFMessage(msg) => self.handle_vrf_message(msg),
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;
    use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
    use stegos_wallet::create_data_transaction;
    use stegos_wallet::create_monetary_transaction;

    #[test]
    pub fn init() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keys = KeyChain::new_mem();
        let (_outbox, inbox) = unbounded();
        let (broker_tx, _broker_rx) = unbounded();
        let broker = Broker {
            upstream: broker_tx,
        };

        let mut node = NodeService::new(keys.clone(), broker, inbox).unwrap();

        assert_eq!(node.chain.blocks().len(), 0);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.epoch, 0);
        assert_ne!(node.leader, keys.cosi_pkey);
        assert!(node.validators.is_empty());

        let amount: i64 = 3_000_000;
        let genesis = genesis(&[keys.clone()], amount);
        let genesis_count = genesis.len();
        node.handle_init(genesis).unwrap();
        assert_eq!(node.chain.blocks().len(), genesis_count);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.epoch, 1);
        assert_eq!(node.leader, keys.cosi_pkey);
        assert_eq!(node.validators.len(), 1);
        assert_eq!(node.validators.keys().next().unwrap(), &node.leader);
    }

    fn simulate_consensus(node: &mut NodeService) {
        let (block, _proof) = NodeService::process_mempool(
            &mut node.mempool,
            &mut node.chain,
            node.epoch,
            &node.keys.wallet_skey,
            &node.keys.wallet_pkey,
        )
        .unwrap();

        let block_hash = Hash::digest(&block);
        let multisig = secure_sign_hash(&block_hash, &node.keys.cosi_skey);
        let mut multisigmap = BitVector::new(1);
        multisigmap.insert(0);
        node.commit_proposed_block(block, multisig, multisigmap);
    }

    fn unspent(node: &NodeService) -> HashMap<Hash, (MonetaryOutput, i64)> {
        let mut unspent: HashMap<Hash, (MonetaryOutput, i64)> = HashMap::new();
        for hash in node.chain.unspent() {
            let output = node.chain.output_by_hash(&hash).unwrap();
            if let Output::MonetaryOutput(o) = output {
                let (_delta, _gamma, amount) = o.decrypt_payload(&node.keys.wallet_skey).unwrap();
                unspent.insert(hash, (o.clone(), amount));
            }
        }
        unspent
    }

    fn simulate_payment(node: &mut NodeService, amount: i64) -> Result<(), Error> {
        let tx = create_monetary_transaction(
            &node.keys.wallet_skey,
            &node.keys.wallet_pkey,
            &node.keys.wallet_pkey,
            &unspent(node),
            amount,
        )?;
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        node.handle_transaction(data)?;
        Ok(())
    }

    fn simulate_message(node: &mut NodeService, ttl: u64, msg: Vec<u8>) -> Result<(), Error> {
        let tx = create_data_transaction(
            &node.keys.wallet_skey,
            &node.keys.wallet_pkey,
            &node.keys.wallet_pkey,
            &unspent(node),
            ttl,
            msg,
        )?;
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        node.handle_transaction(data)?;
        Ok(())
    }

    fn balance(node: &NodeService) -> i64 {
        let mut balance: i64 = 0;
        for hash in node.chain.unspent() {
            let output = node.chain.output_by_hash(&hash).unwrap();
            if let Output::MonetaryOutput(o) = output {
                let (_delta, _gamma, amount) = o.decrypt_payload(&node.keys.wallet_skey).unwrap();
                balance += amount;
            }
        }
        balance
    }

    #[test]
    pub fn monetary_requests() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keys = KeyChain::new_mem();
        let (_outbox, inbox) = unbounded();
        let (broker_tx, _broker_rx) = unbounded();
        let broker = Broker {
            upstream: broker_tx,
        };

        let mut node = NodeService::new(keys.clone(), broker, inbox).unwrap();

        let total: i64 = 3_000_000;
        let genesis = genesis(&[keys.clone()], total);
        node.handle_init(genesis).unwrap();
        let mut block_count = node.chain.blocks().len();

        // Payment without a change.
        simulate_payment(&mut node, total - MONETARY_FEE).unwrap();
        assert_eq!(node.mempool.len(), 1);
        simulate_consensus(&mut node);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for unspent in node.chain.unspent() {
            match node.chain.output_by_hash(&unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                _ => panic!(),
            }
        }
        amounts.sort();
        assert_eq!(amounts, vec![MONETARY_FEE, total - MONETARY_FEE]);
        block_count += 1;

        // Payment with a change.
        simulate_payment(&mut node, 100).unwrap();
        assert_eq!(node.mempool.len(), 1);
        simulate_consensus(&mut node);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for unspent in node.chain.unspent() {
            match node.chain.output_by_hash(&unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                _ => panic!(),
            }
        }
        amounts.sort();
        let expected = vec![2 * MONETARY_FEE, 100, total - 100 - 2 * MONETARY_FEE];
        assert_eq!(amounts, expected);

        assert_eq!(block_count, 3);
    }

    #[test]
    pub fn data_requests() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keys = KeyChain::new_mem();
        let (_outbox, inbox) = unbounded();
        let (broker_tx, _broker_rx) = unbounded();
        let broker = Broker {
            upstream: broker_tx,
        };
        let mut node = NodeService::new(keys.clone(), broker, inbox).unwrap();

        let total: i64 = 100;
        let genesis = genesis(&[keys.clone()], total);
        node.handle_init(genesis).unwrap();
        let mut block_count = node.chain.blocks().len();

        let data = b"hello".to_vec();
        let ttl = 3;
        let data_fee = NodeService::data_fee(data.len(), ttl);

        // Change money for the next test.
        simulate_payment(&mut node, data_fee).unwrap();
        simulate_consensus(&mut node);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(balance(&node), total); // fee is returned back
        assert_eq!(node.chain.unspent().len(), 3);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for unspent in node.chain.unspent() {
            match node.chain.output_by_hash(&unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                _ => panic!(),
            }
        }
        amounts.sort();
        let expected = vec![
            2 * MONETARY_FEE,
            data_fee,
            total - data_fee - 2 * MONETARY_FEE,
        ];
        assert_eq!(amounts, expected);
        block_count += 1;

        // Send data without a change.
        simulate_message(&mut node, ttl, data).unwrap();
        assert_eq!(node.mempool.len(), 1);
        simulate_consensus(&mut node);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(balance(&node), total); // fee is returned back
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        let mut unspent_data: usize = 0;
        for unspent in node.chain.unspent() {
            match node.chain.output_by_hash(&unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                Some(Output::DataOutput(_o)) => {
                    unspent_data += 1;
                }
                _ => panic!(),
            }
        }
        assert_eq!(unspent_data, 1);
        amounts.sort();
        let expected = vec![
            2 * MONETARY_FEE,
            data_fee,
            total - data_fee - 2 * MONETARY_FEE,
        ];
        assert_eq!(amounts, expected);
        block_count += 1;

        // Send data with a change.
        let data = b"hello".to_vec();
        let ttl = 10;
        let data_fee2 = NodeService::data_fee(data.len(), ttl);
        simulate_message(&mut node, ttl, data).unwrap();
        assert_eq!(node.mempool.len(), 1);
        simulate_consensus(&mut node);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(balance(&node), total); // fee is returned back
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        let mut unspent_data: usize = 0;
        for unspent in node.chain.unspent() {
            match node.chain.output_by_hash(&unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                Some(Output::DataOutput(_o)) => {
                    unspent_data += 1;
                }
                _ => panic!(),
            }
        }
        assert_eq!(unspent_data, 2);
        amounts.sort();
        let expected = vec![MONETARY_FEE + data_fee2, total - MONETARY_FEE - data_fee2];
        assert_eq!(amounts, expected);
    }

    /// Check data fee calculation.
    #[test]
    pub fn data_fee() {
        assert_eq!(NodeService::data_fee(1, 1), DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(1, 2), 2 * DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT - 1, 1), DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT - 1, 2), 2 * DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT, 1), DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT, 2), 2 * DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT + 1, 1), 2 * DATA_UNIT_FEE);
        assert_eq!(NodeService::data_fee(DATA_UNIT + 1, 2), 4 * DATA_UNIT_FEE);
    }
}

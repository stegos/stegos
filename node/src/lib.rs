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

pub mod protos;

use crate::protos::{FromProto, IntoProto};

use chrono::Utc;
use failure::{Error, Fail};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use protobuf::Message;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_consensus::*;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::G2;
use stegos_keychain::KeyChain;
use stegos_network::Broker;
use stegos_randhound::{RandHound, RandhoundEpoch};
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
}

impl Node {
    /// Create a new blockchain node.
    pub fn new(
        keys: KeyChain,
        genesis: Vec<Block>,
        broker: Broker,
        randhound: RandHound,
    ) -> Result<(impl Future<Item = (), Error = ()>, Node), Error> {
        let (outbox, inbox) = unbounded();

        let msg = NodeMessage::Init { genesis };
        outbox.unbounded_send(msg)?;

        let service = NodeService::new(keys, broker, randhound, inbox)?;
        let handler = Node { outbox };

        Ok((service, handler))
    }

    /// Subscribe to balance changes.
    pub fn subscribe_balance(&self) -> Result<UnboundedReceiver<i64>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeBalance(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Subscribe to epoch changes.
    pub fn subscribe_epoch(&self) -> Result<UnboundedReceiver<EpochNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeEpoch(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Subscribe to messages.
    pub fn subscribe_messages(&self) -> Result<UnboundedReceiver<MessageNotification>, Error> {
        let (tx, rx) = unbounded();
        let msg = NodeMessage::SubscribeMessage(tx);
        self.outbox.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Request a payment.
    pub fn pay(&self, recipient: PublicKey, amount: i64) -> Result<(), Error> {
        let msg = NodeMessage::PaymentRequest { recipient, amount };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }

    /// Send a message
    pub fn msg(&self, recipient: PublicKey, ttl: u64, data: Vec<u8>) -> Result<(), Error> {
        let msg = NodeMessage::MessageRequest {
            recipient,
            ttl,
            data,
        };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }
}

/// Send when epoch is changed.
#[derive(Clone, Debug)]
pub struct EpochNotification {
    pub epoch: u64,
    pub leader: SecurePublicKey,
    pub witnesses: Vec<SecurePublicKey>,
}

/// Send when message is received.
#[derive(Debug, Clone)]
pub struct MessageNotification {
    pub data: Vec<u8>,
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// Blockchain version.
const VERSION: u64 = 1;
/// Mempool processing interval.
// TODO: replace with randound rounds
const MEMPOOL_TTL: u64 = 15;
/// Topic used for sending transactions.
const TX_TOPIC: &'static str = "tx";
/// Topic used for CoSi.
const CONSENSUS_TOPIC: &'static str = "consensus";
/// Topic used for sending sealed blocks.
const SEALED_BLOCK_TOPIC: &'static str = "block";
/// Fixed fee for monetary transactions.
const MONETARY_FEE: i64 = 1;
/// Data unit used to calculate fee.
const DATA_UNIT: usize = 1024;
/// Fee for one DATA_UNIT.
const DATA_UNIT_FEE: i64 = 1;

#[derive(Clone, Debug)]
enum NodeMessage {
    //
    // Public API
    //
    PaymentRequest {
        recipient: PublicKey,
        amount: i64,
    },
    MessageRequest {
        recipient: PublicKey,
        ttl: u64,
        data: Vec<u8>,
    },
    SubscribeBalance(UnboundedSender<i64>),
    SubscribeEpoch(UnboundedSender<EpochNotification>),
    SubscribeMessage(UnboundedSender<MessageNotification>),

    //
    // Network Events
    //
    TransactionRequest(Vec<u8>),
    ConsensusRequest(Vec<u8>),
    SealedBlockRequest(Vec<u8>),

    // Randomness Event from RandHound
    Randomness(Hash),
    //
    // Internal Events
    //
    Init {
        genesis: Vec<Block>,
    },
    Timer(Instant), // TODO: replace with RandHound
}

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum NodeError {
    #[fail(display = "Amount should be greater than zero.")]
    ZeroOrNegativeAmount,
    #[fail(display = "Not enough money.")]
    NotEnoughMoney,
    #[fail(display = "Fee is to low: min={}, got={}", _0, _1)]
    TooLowFee(i64, i64),
}

struct NodeService {
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,
    /// Node's UXTO.
    unspent: HashMap<Hash, i64>,
    /// Calculated Node's balance.
    balance: i64,
    /// A monotonically increasing value that represents the heights of the blockchain,
    /// starting from genesis block (=0).
    epoch: u64,
    /// Randomness, generated by RandHound
    randomness: Hash,
    /// Current epoch leader.
    leader: SecurePublicKey,
    /// The list of witnesses public keys.
    witnesses: Vec<SecurePublicKey>,
    /// Memory pool of pending transactions.
    mempool: Vec<Transaction>,
    /// Hashes of UTXO used by mempool transactions,
    mempool_outputs: HashSet<Hash>,
    /// Network interface.
    broker: Broker,
    /// RandHound Service handle
    randhound: RandHound,
    /// Triggered when balance is changed.
    on_balance_changed: Vec<UnboundedSender<i64>>,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochNotification>>,
    /// Triggered when message is received.
    on_message_received: Vec<UnboundedSender<MessageNotification>>,
    /// Aggregated stream of events.
    events: Box<Stream<Item = NodeMessage, Error = ()> + Send>,
}

impl NodeService {
    /// Constructor.
    fn new(
        keys: KeyChain,
        broker: Broker,
        randhound: RandHound,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let chain = Blockchain::new();
        let balance = 0i64;
        let unspent = HashMap::new();
        let epoch: u64 = 1;
        let randomness = Hash::digest(&"0xDEADBEEF".to_string());
        let leader: SecurePublicKey = G2::generator().into(); // some fake key
        let witnesses = Vec::<SecurePublicKey>::new();
        let mempool = Vec::<Transaction>::new();
        let mempool_outputs = HashSet::<Hash>::new();
        let on_balance_changed = Vec::<UnboundedSender<i64>>::new();
        let on_epoch_changed = Vec::<UnboundedSender<EpochNotification>>::new();
        let on_message_received = Vec::<UnboundedSender<MessageNotification>>::new();

        let mut streams = Vec::<Box<Stream<Item = NodeMessage, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Transaction Requests
        let transaction_rx = broker
            .subscribe(&TX_TOPIC.to_string())?
            .map(|m| NodeMessage::TransactionRequest(m));
        streams.push(Box::new(transaction_rx));

        // Consensus Requests
        let consensus_rx = broker
            .subscribe(&CONSENSUS_TOPIC.to_string())?
            .map(|m| NodeMessage::ConsensusRequest(m));
        streams.push(Box::new(consensus_rx));

        // Block Requests
        let block_rx = broker
            .subscribe(&SEALED_BLOCK_TOPIC.to_string())?
            .map(|m| NodeMessage::SealedBlockRequest(m));
        streams.push(Box::new(block_rx));

        // Randomness events from RandHound
        let randomness_rx =
            RandHound::subscribe(&randhound)?.map(|m| NodeMessage::Randomness(m.value));
        streams.push(Box::new(randomness_rx));

        // Timer events
        let duration = Duration::from_secs(MEMPOOL_TTL);
        let timer = Interval::new_interval(duration)
            .map(|i| NodeMessage::Timer(i))
            .map_err(|_e| ()); // ignore transient timer errors
        streams.push(Box::new(timer));

        let events = select_all(streams);

        let service = NodeService {
            chain,
            keys,
            balance,
            unspent,
            epoch,
            randomness,
            leader,
            witnesses,
            mempool,
            mempool_outputs,
            broker,
            randhound,
            on_balance_changed,
            on_epoch_changed,
            on_message_received,
            events,
        };

        Ok(service)
    }

    /// Handler for NodeMessage::Init.
    fn handle_init(&mut self, genesis: Vec<Block>) -> Result<(), Error> {
        info!("Registering genesis blocks...");

        //
        // Sic: genesis block has invalid monetary balance, so handle_monetary_block_request()
        // can't be used here.
        //

        for block in genesis {
            match block {
                Block::KeyBlock(key_block) => {
                    info!("Genesis key block: hash={}", Hash::digest(&key_block));
                    let key_block2 = key_block.clone();
                    self.chain.register_key_block(key_block)?;
                    self.on_key_block_registered(&key_block2);
                }
                Block::MonetaryBlock(monetary_block) => {
                    info!(
                        "Genesis monetary block: hash={}",
                        Hash::digest(&monetary_block)
                    );
                    let monetary_block2 = monetary_block.clone();
                    let inputs = self.chain.register_monetary_block(monetary_block)?;
                    self.on_monetary_block_registered(&monetary_block2, &inputs);
                }
            }
        }

        // Kick off RandHound
        let msg = RandhoundEpoch {
            epoch: self.epoch,
            leader: self.leader.clone(),
            witnesses: self.witnesses.clone(), 
        };
        RandHound::on_epoch(&self.randhound, msg)?;

        Ok(())
    }

    /// Handler for NodeMessage::PaymentRequest.
    fn handle_payment_request(&mut self, recipient: &PublicKey, amount: i64) -> Result<(), Error> {
        debug!(
            "Received payment request: to={}, amount={}",
            recipient, amount
        );

        debug!("Creating transaction");
        let tx = self.create_monetary_transaction(recipient, amount)?;
        info!("Created transaction: hash={}", Hash::digest(&tx.body));

        self.send_transaction(tx)
    }

    /// Handler for NodeMessage::PaymentRequest.
    fn handle_message_request(
        &mut self,
        recipient: &PublicKey,
        ttl: u64,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        debug!(
            "Received message request: to={}, data={}",
            recipient,
            String::from_utf8_lossy(&data)
        );

        debug!("Creating transaction");
        let tx = self.create_data_transaction(recipient, ttl, data)?;
        info!("Created transaction: hash={}", Hash::digest(&tx.body));

        self.send_transaction(tx)
    }

    /// Handle incoming transactions received from network.
    fn handle_transaction_request(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        if !self.is_leader() {
            return Ok(());
        }

        let tx: protos::node::Transaction = protobuf::parse_from_bytes(&msg)?;
        let tx = Transaction::from_proto(&tx)?;

        let tx_hash = Hash::digest(&tx.body);
        info!("Received transaction: hash={}", &tx_hash);
        debug!("Validating transaction: hash={}..", &tx_hash);

        // Check fee.
        NodeService::check_acceptable_fee(&tx)?;

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&tx.body.txins)?;

        // Validate monetary balance and signature.
        tx.validate(&inputs)?;
        info!("Transaction is valid: hash={}", &tx_hash);

        // Check that UTXOs are not already queued to mempool.
        for hash in &tx.body.txins {
            if let Some(_) = self.mempool_outputs.get(hash) {
                error!("UTXO is already queued to mempool: hash={}", &hash);
                return Err(BlockchainError::MissingUTXO(hash.clone()).into());
            }
        }

        // Queue to mempool.
        debug!("Queuing to mempool: hash={}", &tx_hash);
        for hash in &tx.body.txins {
            let nodup = self.mempool_outputs.insert(hash.clone());
            assert!(nodup);
        }
        self.mempool.push(tx);

        Ok(())
    }

    /// Handle incoming consensus requests received from network.
    fn handle_consensus_request(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        if !self.is_leader() {
            return Ok(());
        }

        let msg: protos::node::ConsensusMessage = protobuf::parse_from_bytes(&msg)?;
        let msg = ConsensusMessage::from_proto(&msg)?;

        let msg_hash = Hash::digest(&msg);
        info!("Received consensus message: hash={}", &msg_hash);

        msg.validate()?;

        // TODO: ??

        Ok(())
    }

    /// Handle incoming KeyBlock
    fn handle_sealed_key_block_request(&mut self, key_block: KeyBlock) -> Result<(), Error> {
        let key_block2 = key_block.clone();
        self.chain.register_key_block(key_block)?;
        self.on_key_block_registered(&key_block2);
        Ok(())
    }

    /// Handle incoming KeyBlock
    fn handle_sealed_monetary_block_request(
        &mut self,
        monetary_block: MonetaryBlock,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(&monetary_block);

        debug!("Validating block monetary balance: hash={}..", &block_hash);

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&monetary_block.body.inputs)?;

        // Validate monetary balance.
        monetary_block.validate(&inputs)?;

        info!("Block monetary balance is ok: hash={}", &block_hash);

        let monetary_block2 = monetary_block.clone();
        let inputs = self.chain.register_monetary_block(monetary_block)?;
        self.on_monetary_block_registered(&monetary_block2, &inputs);
        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_sealed_block_request(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let block: protos::node::Block = protobuf::parse_from_bytes(&msg)?;
        let block = Block::from_proto(&block)?;

        let block_hash = Hash::digest(&block);
        info!("Received block: hash={}", &block_hash);

        // Check that block is not registered yet.
        if let Some(_) = self.chain.block_by_hash(&block_hash) {
            info!("Block is already registered: hash={}", &block_hash);
            // Already registered, skip.
            return Ok(());
        }

        {
            let header = block.base_header();

            // Check previous hash.
            let previous_hash = Hash::digest(self.chain.last_block());
            if previous_hash != header.previous {
                error!("Invalid or out-of-order block received: hash={}, expected_previous={}, got_previous={}",
                       &block_hash, &previous_hash, &header.previous);
                return Ok(());
            }

            // Check epoch.
            if self.epoch != header.epoch {
                error!("Invalid or out-of-order block received: hash={}, expected_epoch={}, got_epoch={}",
                       &block_hash, self.epoch, header.epoch);
                return Ok(());
            }

            // TODO: check CoSi signature
        }

        match block {
            Block::KeyBlock(key_block) => self.handle_sealed_key_block_request(key_block),
            Block::MonetaryBlock(monetary_block) => {
                self.handle_sealed_monetary_block_request(monetary_block)
            }
        }
    }

    /// Handle period timer.
    fn handle_timer(&mut self) -> Result<(), Error> {
        self.process_mempool()?;

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeBalance.
    fn handle_subscribe_balance(&mut self, tx: UnboundedSender<i64>) -> Result<(), Error> {
        tx.unbounded_send(self.balance)?;
        self.on_balance_changed.push(tx);
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
            witnesses: self.witnesses.clone(),
        };
        tx.unbounded_send(msg)?;
        self.on_epoch_changed.push(tx);
        Ok(())
    }

    /// Handler for NodeMessage::SubscribeMessage.
    fn handle_subscribe_message(
        &mut self,
        tx: UnboundedSender<MessageNotification>,
    ) -> Result<(), Error> {
        self.on_message_received.push(tx);
        Ok(())
    }

    fn handle_new_randomness(&mut self, h: Hash) -> Result<(), Error> {
        self.randomness = h;
        info!("New randomness obtained: {}", h);
        // Start new round, if we are the leader
        if self.is_leader() {
            RandHound::start_round(&self.randhound)?;
        }
        Ok(())
    }

    /// Called when balance is changed.
    fn update_balance(&mut self, amount: i64) {
        self.balance += amount;
        let balance = self.balance;
        assert!(balance >= 0);
        info!("Balance is {}", balance);
        self.on_balance_changed
            .retain(move |tx| tx.unbounded_send(balance).is_ok())
    }

    /// Returns true if current node is leader.
    fn is_leader(&self) -> bool {
        self.keys.cosi_pkey == self.leader
    }

    /// Called when a new key block is registered.
    fn on_key_block_registered(&mut self, key_block: &KeyBlock) {
        self.leader = key_block.header.leader.clone();
        self.epoch = self.epoch + 1;
        self.leader = key_block.header.leader.clone();
        self.witnesses = key_block.header.witnesses.clone();
        if self.is_leader() {
            info!("I'm leader");
        } else {
            info!("New leader is {}", &self.leader);
        }
    }

    /// Called when a new key block is registered.
    fn on_monetary_block_registered(&mut self, monetary_block: &MonetaryBlock, inputs: &[Output]) {
        //
        // Notify subscribers.
        //

        for input in inputs {
            let hash = Hash::digest(input);
            self.on_output_pruned(hash, input);
        }

        for (output, _) in monetary_block.body.outputs.leafs() {
            let hash = Hash::digest(output);
            self.on_output_created(hash, output);
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, hash: Hash, output: &Output) {
        match output {
            Output::MonetaryOutput(output) => {
                if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(&self.keys.wallet_skey)
                {
                    info!("Received monetary UTXO: hash={}, amount={}", hash, amount);
                    let missing = self.unspent.insert(hash, amount);
                    assert_eq!(missing, None);
                    self.update_balance(amount);
                }
            }
            Output::DataOutput(output) => {
                if let Ok((_delta, _gamma, data)) = output.decrypt_payload(&self.keys.wallet_skey) {
                    info!(
                        "Received data UTXO: hash={}, msg={}",
                        hash,
                        String::from_utf8_lossy(&data)
                    );
                    // Notify subscribers.
                    let msg = MessageNotification { data };
                    self.on_message_received
                        .retain(move |tx| tx.unbounded_send(msg.clone()).is_ok());

                    // Send a prune request.
                    debug!("Pruning data");
                    let tx = self
                        .create_data_ack_transaction(output.clone())
                        .expect("cannot fail");
                    info!("Created transaction: hash={}", Hash::digest(&tx.body));
                    self.send_transaction(tx).ok();
                }
            }
        }
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, hash: Hash, output: &Output) {
        match output {
            Output::MonetaryOutput(output) => {
                if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(&self.keys.wallet_skey)
                {
                    info!("Spent monetary UTXO: hash={}, amount={}", hash, amount);
                    let exists = self.unspent.remove(&hash);
                    assert_eq!(exists, Some(amount));
                    self.update_balance(-amount);
                }
            }
            Output::DataOutput(output) => {
                if let Ok((_delta, _gamma, data)) = output.decrypt_payload(&self.keys.wallet_skey) {
                    info!(
                        "Pruned data UTXO: hash={}, data={}",
                        hash,
                        String::from_utf8_lossy(&data)
                    );
                }
            }
        }
    }

    /// Send transaction to network.
    fn send_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        info!("Sending transaction: hash={}", Hash::digest(&tx.body));
        let proto = tx.into_proto();
        let data = proto.write_to_bytes()?;
        self.broker.publish(&TX_TOPIC.to_string(), data.clone())?;
        // Sic: broadcast messages are not delivered to sender itself.
        self.handle_transaction_request(data)?;
        Ok(())
    }

    /// Send consensus message to network
    #[allow(dead_code)]
    fn send_consensus_message(&mut self, msg: ConsensusMessage) -> Result<(), Error> {
        info!("Sending consensus message: hash={}", Hash::digest(&msg));
        let proto = msg.into_proto();
        let data = proto.write_to_bytes()?;
        self.broker
            .publish(&CONSENSUS_TOPIC.to_string(), data.clone())?;
        // Sic: broadcast messages are not delivered to sender itself.
        self.handle_consensus_request(data)?;
        Ok(())
    }

    /// Send block to network.
    fn send_sealed_block(&mut self, block: Block) -> Result<(), Error> {
        info!("Sending block: hash={}", Hash::digest(&block));
        let proto = block.into_proto();
        let data = proto.write_to_bytes()?;
        // Don't send block to myself.
        self.broker.publish(&SEALED_BLOCK_TOPIC.to_string(), data)?;
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
                Output::DataOutput(o) => NodeService::data_fee(o.data_size(), o.ttl),
            };
        }

        // Transaction's fee is too low.
        if tx.body.fee < min_fee {
            return Err(NodeError::TooLowFee(min_fee, tx.body.fee));
        }
        Ok(())
    }

    /// Find UTXO with exact value.
    fn find_utxo_exact(unspent: &HashMap<Hash, i64>, sum: i64) -> Option<Hash> {
        for (hash, amount) in unspent.iter() {
            if *amount == sum {
                debug!("Use UTXO: hash={}, amount={}", hash, amount);
                return Some(hash.clone());
            }
        }
        None
    }

    /// Find appropriate UTXO to spent and calculate a change.
    fn find_utxo(
        unspent: &HashMap<Hash, i64>,
        mut sum: i64,
    ) -> Result<(Vec<Hash>, i64), NodeError> {
        assert!(sum >= 0);
        let mut unspent: Vec<(i64, Hash)> = unspent
            .iter()
            .map(|(hash, amount)| (*amount, hash.clone()))
            .collect();
        // Sort ascending in order to eliminate as much outputs as possible
        unspent.sort_by_key(|(amount, _hash)| *amount);

        // Naive algorithm - try to spent as much UTXO as possible.
        let mut spent = Vec::new();
        for (amount, hash) in unspent.drain(..) {
            if sum <= 0 {
                break;
            }
            sum -= amount;
            spent.push(hash);
            debug!("Use UTXO: hash={}, amount={}", hash, amount);
        }
        drop(unspent);

        if sum > 0 {
            return Err(NodeError::NotEnoughMoney);
        }

        let change = -sum;
        return Ok((spent, change));
    }

    /// Create monetary transaction.
    fn create_monetary_transaction(
        &self,
        recipient: &PublicKey,
        amount: i64,
    ) -> Result<Transaction, Error> {
        let sender_skey = &self.keys.wallet_skey;
        let sender_pkey = &self.keys.wallet_pkey;

        if amount <= 0 {
            return Err(NodeError::ZeroOrNegativeAmount.into());
        }

        //
        // Find inputs
        //

        // Try to find exact sum plus fee, without a change.
        let (fee, change, inputs) =
            match NodeService::find_utxo_exact(&self.unspent, amount + MONETARY_FEE) {
                Some(inputs) => {
                    // If found, then charge the minimal fee.
                    let fee = MONETARY_FEE;
                    let inputs = self.chain.outputs_by_hashes(&[inputs])?;
                    (fee, 0i64, inputs)
                }
                None => {
                    // Otherwise, charge the double fee.
                    let fee = 2 * MONETARY_FEE;
                    let (inputs, change) = NodeService::find_utxo(&self.unspent, amount + fee)?;
                    let inputs = self.chain.outputs_by_hashes(&inputs)?;
                    (fee, change, inputs)
                }
            };

        info!(
            "Transaction preview: recipient={}, sent={}, spent={}, change={}, fee={}",
            recipient,
            amount,
            amount + change + fee,
            change,
            fee
        );

        //
        // Create outputs
        //

        let timestamp = Utc::now().timestamp() as u64;
        let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);

        // Create an output for payment
        debug!("Creating UTXO for payment: amount={}", amount);
        let (output1, gamma1) = Output::new_monetary(timestamp, sender_skey, recipient, amount)?;
        outputs.push(output1);
        let mut gamma = gamma1;

        if change > 0 {
            // Create an output for change
            debug!("Creating UTXO for the change: amount={}", change);
            let (output2, gamma2) =
                Output::new_monetary(timestamp, sender_skey, sender_pkey, change)?;
            outputs.push(output2);
            gamma += gamma2;
        }

        debug!("Signing transaction");
        let tx = Transaction::new(sender_skey, &inputs, &outputs, gamma, fee)?;
        // Double-check transaction
        tx.validate(&inputs)?;
        Ok(tx)
    }

    /// Create data transaction.
    fn create_data_transaction(
        &self,
        recipient: &PublicKey,
        ttl: u64,
        data: Vec<u8>,
    ) -> Result<Transaction, Error> {
        let sender_skey = &self.keys.wallet_skey;
        let sender_pkey = &self.keys.wallet_pkey;

        //
        // Find inputs
        //

        let fee = NodeService::data_fee(data.len(), ttl);
        // Try to find exact sum plus fee, without a change.
        let (fee, change, inputs) = match NodeService::find_utxo_exact(&self.unspent, fee) {
            Some(inputs) => {
                // If found, then charge the minimal fee.
                let inputs = self.chain.outputs_by_hashes(&[inputs])?;
                (fee, 0i64, inputs)
            }
            None => {
                // Otherwise, charge the double fee.
                let fee = fee + MONETARY_FEE;
                let (inputs, change) = NodeService::find_utxo(&self.unspent, fee)?;
                let inputs = self.chain.outputs_by_hashes(&inputs)?;
                (fee, change, inputs)
            }
        };

        info!(
            "Transaction preview: recipient={}, ttl={}, spent={}, change={}, fee={}",
            recipient,
            ttl,
            change + fee,
            change,
            fee
        );

        //
        // Create outputs
        //

        let timestamp = Utc::now().timestamp() as u64;
        let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);

        // Create an output for payment
        debug!("Creating UTXO for data");
        let (output1, gamma1) = Output::new_data(timestamp, sender_skey, recipient, ttl, &data)?;
        outputs.push(output1);
        let mut gamma = gamma1;

        if change > 0 {
            // Create an output for change
            debug!("Creating UTXO for the change: amount={}", change);
            let (output2, gamma2) =
                Output::new_monetary(timestamp, sender_skey, sender_pkey, change)?;
            outputs.push(output2);
            gamma += gamma2;
        }

        debug!("Signing transaction");
        let tx = Transaction::new(sender_skey, &inputs, &outputs, gamma, fee)?;

        Ok(tx)
    }

    /// Create a transaction to prune data.
    fn create_data_ack_transaction(&self, output: DataOutput) -> Result<Transaction, Error> {
        let sender_skey = &self.keys.wallet_skey;

        let inputs = [Output::DataOutput(output)];
        let outputs = [];
        let adjustment = Fr::zero();
        let fee: i64 = 0;

        debug!("Signing transaction");
        let tx = Transaction::new(sender_skey, &inputs, &outputs, adjustment, fee)?;

        Ok(tx)
    }

    /// Process transactions in mempool.
    fn process_mempool(&mut self) -> Result<(), Error> {
        if !self.is_leader() {
            assert!(self.mempool.is_empty());
            return Ok(());
        }

        if self.mempool.is_empty() {
            return Ok(());
        }

        info!("Processing mempool: size={}", self.mempool.len());
        let timestamp = Utc::now().timestamp() as u64;
        let mut gamma = Fr::zero();
        let mut fee = 0i64;

        let mut inputs = Vec::<Output>::new();
        let mut inputs_hashes = Vec::<Hash>::new();
        let mut outputs = Vec::<Output>::new();
        for tx in self.mempool.drain(..) {
            let tx_hash = Hash::digest(&tx.body);
            info!("Adding transaction: hash={}", &tx_hash);
            let tx_inputs = self
                .chain
                .outputs_by_hashes(&tx.body.txins)
                .expect("mempool transaction are validated before");
            inputs.extend(tx_inputs);
            for tx_input in &tx.body.txins {
                let exists = self.mempool_outputs.remove(tx_input);
                assert!(exists);
            }
            inputs_hashes.extend(tx.body.txins);
            outputs.extend(tx.body.txouts);

            gamma += tx.body.gamma;
            fee += tx.body.fee;
        }
        assert!(self.mempool.is_empty());
        assert!(self.mempool_outputs.is_empty());

        // Create transaction for fee
        if fee > 0 {
            debug!("Creating UTXO for fee: amount={}", fee);
            let (output_fee, gamma_fee) = Output::new_monetary(
                timestamp,
                &self.keys.wallet_skey,
                &self.keys.wallet_pkey,
                fee,
            )?;
            outputs.push(output_fee);
            gamma -= gamma_fee;
        }

        //
        // Create a block
        //

        debug!("Creating monetary block");

        let previous = {
            let last = self.chain.last_block();
            let previous = Hash::digest(last);
            previous
        };
        let epoch = self.epoch;

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp);
        let block = MonetaryBlock::new(base, gamma, &inputs_hashes, &outputs);

        // Double-check the monetary balance of created block.
        block.validate(&inputs)?;

        info!("Created block: hash={}", Hash::digest(&block));

        // TODO: implement consensus

        //
        // Seal and register the block.
        //

        let block2 = block.clone();
        let pruned = self
            .chain
            .register_monetary_block(block)
            .expect("mempool transaction are validated before");
        self.on_monetary_block_registered(&block2, &pruned);
        self.send_sealed_block(Block::MonetaryBlock(block2))?;
        Ok(())
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
                        NodeMessage::PaymentRequest { recipient, amount } => {
                            self.handle_payment_request(&recipient, amount)
                        }
                        NodeMessage::MessageRequest {
                            recipient,
                            ttl,
                            data,
                        } => self.handle_message_request(&recipient, ttl, data),
                        NodeMessage::SubscribeBalance(tx) => self.handle_subscribe_balance(tx),
                        NodeMessage::SubscribeEpoch(tx) => self.handle_subscribe_epoch(tx),
                        NodeMessage::SubscribeMessage(tx) => self.handle_subscribe_message(tx),

                        NodeMessage::TransactionRequest(msg) => {
                            self.handle_transaction_request(msg)
                        }
                        NodeMessage::ConsensusRequest(msg) => self.handle_consensus_request(msg),
                        NodeMessage::SealedBlockRequest(msg) => {
                            self.handle_sealed_block_request(msg)
                        }
                        NodeMessage::Timer(_instant) => self.handle_timer(),
                        NodeMessage::Randomness(h) => self.handle_new_randomness(h),
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
    use stegos_randhound::RandHound;

    #[test]
    pub fn init() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keys = KeyChain::new_mem();
        let (_outbox, inbox) = unbounded();
        let (broker_tx, _broker_rx) = unbounded();
        let broker = Broker {
            upstream: broker_tx,
        };

        let (_future, randhound) = RandHound::dummy();
        let mut node = NodeService::new(keys.clone(), broker, randhound, inbox).unwrap();

        assert_eq!(node.chain.blocks().len(), 0);
        assert_eq!(node.balance, 0);
        assert_eq!(node.unspent.len(), 0);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.epoch, 1);
        assert_ne!(node.leader, keys.cosi_pkey);
        assert_eq!(node.witnesses.len(), 0);

        let amount: i64 = 3_000_000;
        let genesis = genesis(&[keys.clone()], amount);
        let genesis_count = genesis.len();
        node.handle_init(genesis).unwrap();
        assert_eq!(node.chain.blocks().len(), genesis_count);
        assert_eq!(node.balance, amount);
        assert_eq!(node.unspent.len(), 1);
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.epoch, 2);
        assert_eq!(node.leader, keys.cosi_pkey);
        assert_eq!(node.witnesses.len(), 1);
        assert_eq!(node.witnesses[0], node.leader);
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

        let (_future, randhound) = RandHound::dummy();
        let mut node = NodeService::new(keys.clone(), broker, randhound, inbox).unwrap();

        let total: i64 = 3_000_000;
        let genesis = genesis(&[keys.clone()], total);
        node.handle_init(genesis).unwrap();
        let mut block_count = node.chain.blocks().len();

        // Invalid requests.
        let e = node
            .handle_payment_request(&keys.wallet_pkey, -1)
            .unwrap_err();
        assert_eq!(
            e.downcast::<NodeError>().unwrap(),
            NodeError::ZeroOrNegativeAmount
        );
        let e = node
            .handle_payment_request(&keys.wallet_pkey, 0)
            .unwrap_err();
        assert_eq!(
            e.downcast::<NodeError>().unwrap(),
            NodeError::ZeroOrNegativeAmount
        );
        let e = node
            .handle_payment_request(&keys.wallet_pkey, total)
            .unwrap_err();
        assert_eq!(
            e.downcast::<NodeError>().unwrap(),
            NodeError::NotEnoughMoney
        );

        // Payment without a change.
        node.handle_payment_request(&keys.wallet_pkey, total - MONETARY_FEE)
            .unwrap();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.balance, total); // fee is returned back
        assert_eq!(node.unspent.len(), 2);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for (unspent, _) in node.unspent.iter() {
            match node.chain.output_by_hash(unspent) {
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
        node.handle_payment_request(&keys.wallet_pkey, 100).unwrap();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.balance, total); // fee is returned back
        assert_eq!(node.unspent.len(), 3);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for (unspent, _) in node.unspent.iter() {
            match node.chain.output_by_hash(unspent) {
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
        let (_future, randhound) = RandHound::dummy();
        let mut node = NodeService::new(keys.clone(), broker, randhound, inbox).unwrap();

        let total: i64 = 100;
        let genesis = genesis(&[keys.clone()], total);
        node.handle_init(genesis).unwrap();
        let mut block_count = node.chain.blocks().len();

        // Invalid requests.
        let e = node
            .handle_message_request(&keys.wallet_pkey, 100500, b"hello".to_vec())
            .unwrap_err();
        assert_eq!(
            e.downcast::<NodeError>().unwrap(),
            NodeError::NotEnoughMoney
        );

        let data = b"hello".to_vec();
        let ttl = 3;
        let data_fee = NodeService::data_fee(data.len(), ttl);

        // Change money for the next test.
        node.handle_payment_request(&keys.wallet_pkey, data_fee)
            .unwrap();
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.balance, total); // fee is returned back
        assert_eq!(node.unspent.len(), 3);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for (unspent, _) in node.unspent.iter() {
            match node.chain.output_by_hash(unspent) {
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
        node.handle_message_request(&keys.wallet_pkey, ttl, data)
            .unwrap();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 1); // mempool contains "ack" for data
        assert_eq!(node.balance, total); // fee is returned back
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for (unspent, _) in node.unspent.iter() {
            match node.chain.output_by_hash(unspent) {
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

        // Spent data transaction.
        let unspent_len = node.chain.unspent().len();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.chain.unspent().len(), unspent_len - 1);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        block_count += 1;

        // Send data with a change.
        let data = b"hello".to_vec();
        let ttl = 10;
        let data_fee2 = NodeService::data_fee(data.len(), ttl);
        node.handle_message_request(&keys.wallet_pkey, ttl, data)
            .unwrap();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 1); // mempool contains "ack" for data
        assert_eq!(node.balance, total); // fee is returned back
        assert_eq!(node.chain.blocks().len(), block_count + 1);
        let mut amounts = Vec::new();
        for (unspent, _) in node.unspent.iter() {
            match node.chain.output_by_hash(unspent) {
                Some(Output::MonetaryOutput(o)) => {
                    let (_, _, amount) = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amounts.push(amount);
                }
                _ => panic!(),
            }
        }
        amounts.sort();
        let expected = vec![MONETARY_FEE + data_fee2, total - MONETARY_FEE - data_fee2];
        assert_eq!(amounts, expected);
        block_count += 1;

        // Spent data a transaction.
        let unspent_len = node.chain.unspent().len();
        assert_eq!(node.mempool.len(), 1);
        node.process_mempool().unwrap();
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.chain.unspent().len(), unspent_len - 1);
        assert_eq!(node.chain.blocks().len(), block_count + 1);
    }

    /// Check transaction signing and validation.
    #[test]
    pub fn find_utxo() {
        let mut unspent = HashMap::<Hash, i64>::new();
        let amounts: [i64; 5] = [100, 50, 10, 2, 1];
        for amount in amounts.iter() {
            unspent.insert(Hash::digest(amount), *amount);
        }

        let (spent, change) = NodeService::find_utxo(&unspent, 1).unwrap();
        assert_eq!(spent, vec![Hash::digest(&1i64)]);
        assert_eq!(change, 0);

        let (spent, change) = NodeService::find_utxo(&unspent, 2).unwrap();
        assert_eq!(spent, vec![Hash::digest(&1i64), Hash::digest(&2i64)]);
        assert_eq!(change, 1);

        let (spent, change) = NodeService::find_utxo(&unspent, 5).unwrap();
        assert_eq!(
            spent,
            vec![
                Hash::digest(&1i64),
                Hash::digest(&2i64),
                Hash::digest(&10i64)
            ]
        );
        assert_eq!(change, 8);

        let (spent, change) = NodeService::find_utxo(&unspent, 163).unwrap();
        assert_eq!(
            spent,
            vec![
                Hash::digest(&1i64),
                Hash::digest(&2i64),
                Hash::digest(&10i64),
                Hash::digest(&50i64),
                Hash::digest(&100i64),
            ]
        );
        assert_eq!(change, 0);

        assert!(NodeService::find_utxo(&unspent, 164).is_err());
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

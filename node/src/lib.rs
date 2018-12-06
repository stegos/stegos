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

#[macro_use]
extern crate log;
extern crate failure;
extern crate tokio_timer;
#[macro_use]
extern crate failure_derive;
extern crate chrono;
extern crate futures;
extern crate protobuf;
extern crate rand;
extern crate stegos_blockchain;
extern crate stegos_crypto;
extern crate stegos_keychain;
extern crate stegos_network;

pub mod protos;

use chrono::Utc;
use crate::protos::{FromProto, IntoProto};
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use protobuf::Message;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use stegos_blockchain::*;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::G2;
use stegos_keychain::KeyChain;
use stegos_network::Broker;
use tokio_timer::Interval;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Blockchain Node.
#[derive(Clone, Debug)]
pub struct Node {
    outbox: UnboundedSender<NodeMessage>,
}

impl Node {
    /// Create a new blockchain node.
    pub fn new(
        keys: KeyChain,
        broker: Broker,
    ) -> Result<(impl Future<Item = (), Error = ()>, Node), Error> {
        let (outbox, inbox) = unbounded();

        outbox.unbounded_send(NodeMessage::Init)?;

        let service = NodeService::new(keys, broker, inbox, outbox.clone())?;
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

    /// Request a payment.
    pub fn pay(&self, recipient: PublicKey, amount: i64) -> Result<(), Error> {
        let msg = NodeMessage::PaymentRequest { recipient, amount };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }
}

/// Send when epoch is changed.
#[derive(Debug)]
pub struct EpochNotification {
    pub epoch: u64,
    pub leader: SecurePublicKey,
    pub witnesses: Vec<SecurePublicKey>,
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

const VERSION: u64 = 1;
const MEMPOOL_TTL: u64 = 5;
const TX_TOPIC: &'static str = "tx";
const BLOCK_TOPIC: &'static str = "block";

#[derive(Clone, Debug)]
enum NodeMessage {
    Init,
    PaymentRequest { recipient: PublicKey, amount: i64 },
    SubscribeBalance(UnboundedSender<i64>),
    SubscribeEpoch(UnboundedSender<EpochNotification>),
}

#[derive(Debug, Fail)]
pub enum NodeError {
    #[fail(display = "Amount cannot be negative.")]
    ZeroOrNegativeAmount,
    #[fail(display = "Not enough money.")]
    NotEnoughMoney,
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
    /// MailBox.
    inbox: UnboundedReceiver<NodeMessage>,
    /// Used internally for testing purposes to send messages to inbox.
    #[allow(dead_code)]
    outbox: UnboundedSender<NodeMessage>,
    /// TX messages.
    transaction_rx: UnboundedReceiver<Vec<u8>>,
    /// Blocks messages.
    block_rx: UnboundedReceiver<Vec<u8>>,
    /// Timer.
    timer: Interval,
    /// Triggered when balance is changed.
    on_balance_changed: Vec<UnboundedSender<i64>>,
    /// Triggered when epoch is changed.
    on_epoch_changed: Vec<UnboundedSender<EpochNotification>>,
}

impl NodeService {
    /// Constructor.
    fn new(
        keys: KeyChain,
        broker: Broker,
        inbox: UnboundedReceiver<NodeMessage>,
        outbox: UnboundedSender<NodeMessage>,
    ) -> Result<Self, Error> {
        let chain = Blockchain::new();
        let balance = 0i64;
        let unspent = HashMap::new();
        let epoch: u64 = 1;
        let leader: SecurePublicKey = G2::generator().into(); // some fake key
        let witnesses = Vec::<SecurePublicKey>::new();
        let mempool = Vec::<Transaction>::new();
        let mempool_outputs = HashSet::<Hash>::new();
        let transaction_rx = broker.subscribe(&TX_TOPIC.to_string())?;
        let block_rx = broker.subscribe(&BLOCK_TOPIC.to_string())?;
        let timer = Interval::new_interval(Duration::from_secs(MEMPOOL_TTL));
        let on_balance_changed = Vec::<UnboundedSender<i64>>::new();
        let on_epoch_changed = Vec::<UnboundedSender<EpochNotification>>::new();

        let service = NodeService {
            chain,
            keys,
            balance,
            unspent,
            epoch,
            leader,
            witnesses,
            mempool,
            mempool_outputs,
            inbox,
            outbox,
            transaction_rx,
            block_rx,
            timer,
            broker,
            on_balance_changed,
            on_epoch_changed,
        };

        Ok(service)
    }

    /// Handler for NodeMessage::Init.
    fn handle_init(&mut self) -> Result<(), Error> {
        info!("Registering genesis blocks...");

        // Load generated blocks
        let key_block = include_bytes!("../data/genesis0.bin");
        let key_block: protos::node::KeyBlock = protobuf::parse_from_bytes(&key_block[..])?;
        let key_block = KeyBlock::from_proto(&key_block)?;

        let monetary_block = include_bytes!("../data/genesis1.bin");
        let monetary_block: protos::node::MonetaryBlock =
            protobuf::parse_from_bytes(&monetary_block[..])?;
        let monetary_block = MonetaryBlock::from_proto(&monetary_block)?;

        info!("Genesis key block: hash={}", Hash::digest(&key_block));
        info!(
            "Genesis monetary block: hash={}",
            Hash::digest(&monetary_block)
        );

        self.handle_key_block_request(key_block)?;
        self.handle_monetary_block_request(monetary_block)?;

        Ok(())
    }

    /// Handler for NodeMessage::PaymentRequest.
    fn handle_payment_request(&mut self, recipient: &PublicKey, amount: i64) -> Result<(), Error> {
        info!(
            "Received payment request: to={}, amount={}",
            recipient, amount
        );

        debug!("Creating transaction");
        let tx = self.create_transaction(recipient, amount)?;
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

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&tx.body.txins)?;

        // Validate signature.
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

    /// Handle incoming KeyBlock
    fn handle_key_block_request(&mut self, key_block: KeyBlock) -> Result<(), Error> {
        let key_block2 = key_block.clone();
        self.chain.register_key_block(key_block)?;
        self.on_key_block_registered(&key_block2);
        Ok(())
    }

    /// Handle incoming KeyBlock
    fn handle_monetary_block_request(
        &mut self,
        monetary_block: MonetaryBlock,
    ) -> Result<(), Error> {
        let monetary_block2 = monetary_block.clone();
        let inputs = self.chain.register_monetary_block(monetary_block)?;
        self.on_monetary_block_registered(&monetary_block2, &inputs);
        Ok(())
    }

    /// Handle incoming blocks received from network.
    fn handle_block_request(&mut self, msg: Vec<u8>) -> Result<(), Error> {
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
            Block::KeyBlock(key_block) => self.handle_key_block_request(key_block),
            Block::MonetaryBlock(monetary_block) => {
                self.handle_monetary_block_request(monetary_block)
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
        if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(&self.keys.wallet_skey) {
            info!("Received UTXO: hash={}, amount={}", hash, amount);
            let missing = self.unspent.insert(hash, amount);
            assert_eq!(missing, None);
            self.update_balance(amount);
        }
    }

    /// Called when UTXO is spent.
    #[allow(dead_code)]
    fn on_output_pruned(&mut self, hash: Hash, output: &Output) {
        if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(&self.keys.wallet_skey) {
            info!("Spent UTXO: hash={}, amount={}", hash, amount);
            let exists = self.unspent.remove(&hash);
            assert_eq!(exists, Some(amount));
            self.update_balance(-amount);
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

    /// Send block to network.
    fn send_block(&mut self, block: Block) -> Result<(), Error> {
        info!("Sending block: hash={}", Hash::digest(&block));
        let proto = block.into_proto();
        let data = proto.write_to_bytes()?;
        // Don't send block to myself.
        self.broker.publish(&BLOCK_TOPIC.to_string(), data)?;
        Ok(())
    }

    /// Find appropriate UTXO to spent and calculate a change.
    fn find_utxo(
        unspent: &HashMap<Hash, i64>,
        mut sum: i64,
    ) -> Result<(Vec<Hash>, i64), NodeError> {
        if sum <= 0 {
            return Err(NodeError::ZeroOrNegativeAmount);
        }

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
    fn create_transaction(&self, recipient: &PublicKey, amount: i64) -> Result<Transaction, Error> {
        let sender_skey = &self.keys.wallet_skey;
        let sender_pkey = &self.keys.wallet_pkey;

        //
        // Create inputs
        //

        // Collect unspent UTXOs
        let (spent, change) = NodeService::find_utxo(&self.unspent, amount)?;
        let inputs = self.chain.outputs_by_hashes(&spent)?;

        //
        // Create outputs
        //

        let timestamp = Utc::now().timestamp() as u64;
        let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);

        // Create an output for payment
        debug!("Creating UTXO for payment");
        let (output1, delta1) = Output::new(timestamp, sender_skey, recipient, amount)?;
        outputs.push(output1);
        let mut adjustment = delta1;

        if change > 0 {
            // Create an output for change
            debug!("Creating UTXO for the change");
            let (output2, delta2) = Output::new(timestamp, sender_skey, sender_pkey, change)?;
            outputs.push(output2);
            adjustment += delta2;
        }

        // TODO: implement fee calculation
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
        let mut adjustment = Fr::zero();
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

            adjustment += tx.body.gamma;
            fee += tx.body.fee;
        }
        assert!(self.mempool.is_empty());
        assert!(self.mempool_outputs.is_empty());

        // TODO: create a transaction for fee
        drop(fee);

        //
        // Create a block
        //

        debug!("Creating monetary block");

        let timestamp = Utc::now().timestamp() as u64;
        let previous = {
            let last = self.chain.last_block();
            let previous = Hash::digest(last);
            previous
        };
        let epoch = self.epoch;

        let base = BaseBlockHeader::new(VERSION, previous, epoch, timestamp);
        let block = MonetaryBlock::new(base, adjustment, &inputs_hashes, &outputs);

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
        self.send_block(Block::MonetaryBlock(block2))?;

        Ok(())
    }

    fn do_poll(&mut self) -> Poll<(), Error> {
        // Process control messages.
        loop {
            match self.inbox.poll() {
                Ok(Async::Ready(Some(msg))) => match msg {
                    NodeMessage::Init => {
                        self.handle_init()?;
                    }
                    NodeMessage::PaymentRequest { recipient, amount } => {
                        self.handle_payment_request(&recipient, amount)?;
                    }
                    NodeMessage::SubscribeBalance(tx) => {
                        self.handle_subscribe_balance(tx)?;
                    }
                    NodeMessage::SubscribeEpoch(tx) => {
                        self.handle_subscribe_epoch(tx)?;
                    }
                },
                Ok(Async::Ready(None)) => break, // channel closed, fall through
                Ok(Async::NotReady) => break,    // not ready, fall throughs
                Err(()) => unreachable!(),       // never happens
            }
        }

        // Process network events
        loop {
            match self.transaction_rx.poll() {
                Ok(Async::Ready(Some(msg))) => if let Err(e) = self.handle_transaction_request(msg)
                {
                    // Ignore invalid packets.
                    error!("Invalid request: {}", e);
                },
                Ok(Async::Ready(None)) => break, // channel closed, fall through
                Ok(Async::NotReady) => break,    // not ready, fall through
                Err(()) => unreachable!(),       // never happens
            }
        }

        loop {
            match self.block_rx.poll() {
                Ok(Async::Ready(Some(msg))) => if let Err(e) = self.handle_block_request(msg) {
                    // Ignore invalid packets.
                    error!("Invalid request: {}", e);
                },
                Ok(Async::Ready(None)) => break, // channel closed, fall through
                Ok(Async::NotReady) => break,    // not ready, fall through
                Err(()) => unreachable!(),       // never happens
            }
        }

        // Process timer events
        loop {
            match self.timer.poll() {
                Ok(Async::Ready(Some(_instant))) => self.handle_timer()?,
                Ok(Async::Ready(None)) => break, // timed stopped, fall through
                Ok(Async::NotReady) => break,
                Err(e) => return Err(e.into()),
            };
        }

        Ok(Async::NotReady)
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.do_poll() {
            Ok(r) => Ok(r),
            Err(e) => {
                panic!("Internal error: {}", e);
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Check transaction signing and validation.
    #[test]
    pub fn find_utxo() {
        let mut unspent = HashMap::<Hash, i64>::new();
        let amounts: [i64; 5] = [100, 50, 10, 2, 1];
        for amount in amounts.iter() {
            unspent.insert(Hash::digest(amount), *amount);
        }

        assert!(NodeService::find_utxo(&unspent, -1).is_err());
        assert!(NodeService::find_utxo(&unspent, 0).is_err());

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
}

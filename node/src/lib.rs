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

mod protos;

use chrono::Utc;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use protobuf::Message;
use protos::{FromProto, IntoProto};
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::*;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
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

    /// Request a payment.
    pub fn pay(&self, recipient: PublicKey, amount: i64) -> Result<(), Error> {
        let msg = NodeMessage::PaymentRequest { recipient, amount };
        self.outbox.unbounded_send(msg)?;
        Ok(())
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

const MEMPOOL_TTL: u64 = 5;
const TOPIC: &'static str = "tx";

#[derive(Clone, Debug)]
enum NodeMessage {
    Init,
    PaymentRequest { recipient: PublicKey, amount: i64 },
    SubscribeBalance(UnboundedSender<i64>),
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
    /// Memory pool of pending transactions.
    mempool: Vec<Transaction>,
    /// Network interface.
    broker: Broker,
    /// MailBox.
    inbox: UnboundedReceiver<NodeMessage>,
    /// Used internally for testing purposes to send messages to inbox.
    #[allow(dead_code)]
    outbox: UnboundedSender<NodeMessage>,
    /// Broadcast Input Messages.
    transaction_rx: UnboundedReceiver<Vec<u8>>,
    /// Timer.
    timer: Interval,
    /// Triggered when balance is changed.
    on_balance_changed: Vec<UnboundedSender<i64>>,
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
        let mempool = Vec::<Transaction>::new();
        let transaction_rx = broker.subscribe(&TOPIC.to_string())?;
        let timer = Interval::new_interval(Duration::from_secs(MEMPOOL_TTL));
        let on_balance_changed = Vec::<UnboundedSender<i64>>::new();

        let service = NodeService {
            chain,
            keys,
            balance,
            unspent,
            mempool,
            inbox,
            outbox,
            transaction_rx,
            timer,
            broker,
            on_balance_changed,
        };

        Ok(service)
    }

    /// Handler for NodeMessage::Init.
    fn handle_init(&mut self) {
        self.chain.bootstrap().unwrap();

        // Iterate over genesis UTXO.
        for hash in self.chain.unspent() {
            let output = self.chain.output_by_hash(&hash).unwrap().clone();
            self.on_output_created(hash, &output);
        }
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
        let proto: protos::node::Transaction = match protobuf::parse_from_bytes(&msg) {
            Ok(msg) => msg,
            Err(e) => return Err(e.into()),
        };

        let tx = Transaction::from_proto(&proto)?;

        let tx_hash = Hash::digest(&tx.body);
        info!("Received transaction: hash={}", &tx_hash);
        debug!("Validating transaction: hash={}..", &tx_hash);

        // Resolve inputs.
        let inputs = self.chain.outputs_by_hashes(&tx.body.txins)?;

        // Validate signature.
        tx.validate(&inputs)?;
        info!("Transaction is valid: hash={}", &tx_hash);

        // Queue to mempool.
        debug!("Queuing to mempool: hash={}", &tx_hash);
        self.mempool.push(tx);

        Ok(())
    }

    /// Handle period timer.
    fn handle_timer(&mut self) -> Result<(), Error> {
        self.process_mempool()?;

        Ok(())
    }

    /// Handler for NodeMessage::SubscribeBalance.
    fn handle_subscribe_balance(&mut self, tx: UnboundedSender<i64>) {
        self.on_balance_changed.push(tx);
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
        self.broker.publish(&TOPIC.to_string(), data.clone())?;
        // Sic: broadcast messages are not delivered to sender itself.
        self.handle_transaction_request(data)?;
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
            let tx_inputs = self.chain.outputs_by_hashes(&tx.body.txins)?;
            inputs.extend(tx_inputs);
            inputs_hashes.extend(tx.body.txins);
            outputs.extend(tx.body.txouts);

            adjustment += tx.body.gamma;
            fee += tx.body.fee;
        }

        // TODO: create a transaction for fee
        drop(fee);

        //
        // Create a block
        //

        debug!("Creating monetary block");

        let timestamp = Utc::now().timestamp() as u64;
        let (epoch, previous) = {
            let last = self.chain.last_block();
            let base_header = last.base_header();
            let epoch = base_header.epoch;
            let previous = Hash::digest(last);
            (epoch, previous)
        };
        let version = 1;

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let block = MonetaryBlock::new(base, adjustment, &inputs_hashes, &outputs);

        info!("Created block: hash={}", Hash::digest(&block));

        // TODO: implement consensus

        //
        // Seal and register the block.
        //

        self.chain.register_monetary_block(block)?;

        //
        // Notify subscribers.
        //

        for input in &inputs {
            let hash = Hash::digest(input);
            self.on_output_pruned(hash, input);
        }

        for output in &outputs {
            let hash = Hash::digest(output);
            self.on_output_created(hash, output);
        }

        Ok(())
    }

    fn do_poll(&mut self) -> Poll<(), Error> {
        // Process control messages.
        loop {
            match self.inbox.poll() {
                Ok(Async::Ready(Some(msg))) => match msg {
                    NodeMessage::Init => {
                        self.handle_init();
                    }
                    NodeMessage::PaymentRequest { recipient, amount } => {
                        self.handle_payment_request(&recipient, amount)?;
                    }
                    NodeMessage::SubscribeBalance(tx) => {
                        self.handle_subscribe_balance(tx);
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

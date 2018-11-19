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
extern crate futures;
extern crate stegos_blockchain;
extern crate stegos_crypto;
extern crate stegos_keychain;
extern crate stegos_network;

use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Poll, Stream};
use std::collections::HashSet;
use stegos_blockchain::{Blockchain, Output};
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::hash::Hash;
use stegos_keychain::KeyChain;
use stegos_network::Broker;

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

        let service = NodeService::new(keys, broker, inbox)?;
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

#[derive(Clone, Debug)]
enum NodeMessage {
    Init,
    PaymentRequest { recipient: PublicKey, amount: i64 },
    SubscribeBalance(UnboundedSender<i64>),
}

struct NodeService {
    /// Blockchain.
    chain: Blockchain,
    /// Key Chain.
    keys: KeyChain,
    /// Node's UXTO.
    unspent: HashSet<Hash>,
    /// Calculated Node's balance.
    balance: i64,
    /// Network interface.
    #[allow(dead_code)]
    broker: Broker,
    /// MailBox.
    inbox: UnboundedReceiver<NodeMessage>,
    /// Triggered when balance is changed.
    on_balance_changed: Vec<UnboundedSender<i64>>,
}

impl NodeService {
    /// Constructor.
    fn new(
        keys: KeyChain,
        broker: Broker,
        inbox: UnboundedReceiver<NodeMessage>,
    ) -> Result<Self, Error> {
        let unspent = HashSet::new();
        let balance = 0;
        let chain = Blockchain::new();

        let on_balance_changed = Vec::<UnboundedSender<i64>>::new();

        let service = NodeService {
            chain,
            keys,
            balance,
            unspent,
            inbox,
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
            self.on_output_created(hash, output);
        }
    }

    /// Handler for NodeMessage::PaymentRequest.
    fn handle_payment_request(&mut self, recipient: PublicKey, amount: i64) {
        info!("Payment to {} amount={}", recipient, amount);
        self.update_balance(-amount);
    }

    /// Handler for NodeMessage::SubscribeBalance.
    fn handle_subscribe_balance(&mut self, tx: UnboundedSender<i64>) {
        self.on_balance_changed.push(tx);
    }

    /// Called when balance is changed.
    fn update_balance(&mut self, amount: i64) {
        self.balance += amount;
        let balance = self.balance;
        assert!(balance > 0);
        info!("Balance is {}", balance);
        self.on_balance_changed
            .retain(move |tx| tx.unbounded_send(balance).is_ok())
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, hash: Hash, output: Output) {
        if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(self.keys.wallet_skey) {
            info!("Received UTXO({})", hash);
            let missing = self.unspent.insert(hash);
            assert!(missing);
            self.update_balance(amount);
        }
    }

    /// Called when UTXO is spent.
    #[allow(dead_code)]
    fn on_output_pruned(&mut self, hash: Hash, output: &Output) {
        if let Ok((_delta, _gamma, amount)) = output.decrypt_payload(self.keys.wallet_skey) {
            info!("Spent UTXO({})", hash);
            let exists = self.unspent.remove(&hash);
            assert!(exists);
            self.update_balance(-amount);
        }
    }
}

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.inbox.poll() {
                Ok(Async::Ready(Some(msg))) => match msg {
                    // Handle incoming messages.
                    NodeMessage::Init => {
                        self.handle_init();
                    }
                    NodeMessage::PaymentRequest { recipient, amount } => {
                        self.handle_payment_request(recipient, amount);
                    }
                    NodeMessage::SubscribeBalance(tx) => {
                        self.handle_subscribe_balance(tx);
                    }
                },
                Ok(Async::Ready(None)) => unreachable!(), // never happens
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(()) => unreachable!(), // never happens
            }
        }
    }
}

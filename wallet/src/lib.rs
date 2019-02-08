//! Wallet.

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

#![deny(warnings)]

mod api;
mod change;
mod error;
mod transaction;
mod valueshuffle;

pub use crate::api::*;
pub use crate::transaction::*;
use failure::format_err;
use failure::Error;
use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::UnboundedSender;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use futures_stream_select_all_send::select_all;
use log::*;
use std::collections::HashMap;
use stegos_blockchain::*;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_crypto::pbc::secure::G2;
use stegos_network::Network;
use stegos_node::EpochNotification;
use stegos_node::Node;
use stegos_node::OutputsNotification;
use stegos_serialization::traits::ProtoConvert;
use stegos_txpool::PoolInfo;
use stegos_txpool::PoolJoin;
use stegos_txpool::POOL_ANNOUNCE_TOPIC;
use stegos_txpool::POOL_JOIN_TOPIC;

pub struct WalletService {
    /// Secret Key.
    skey: SecretKey,
    /// Public Key.
    pkey: PublicKey,
    /// Validator's public key
    validator_pkey: secure::PublicKey,
    /// Faciliator's public key
    facilitator_pkey: secure::PublicKey,
    /// Unspent Payment UXTO.
    unspent: HashMap<Hash, (PaymentOutput, i64)>,
    /// Unspent Stake UTXO.
    unspent_stakes: HashMap<Hash, StakeOutput>,
    /// Calculated Node's balance.
    balance: i64,

    /// Network API.
    #[allow(unused)]
    network: Network,
    /// Node API.
    node: Node,

    /// Triggered when state has changed.
    subscribers: Vec<UnboundedSender<WalletNotification>>,

    /// Incoming events.
    events: Box<Stream<Item = WalletEvent, Error = ()> + Send>,
}

impl WalletService {
    /// Create a new wallet.
    pub fn new(
        skey: SecretKey,
        pkey: PublicKey,
        validator_pkey: secure::PublicKey,
        network: Network,
        node: Node,
    ) -> (Self, Wallet) {
        //
        // State.
        //
        let facilitator_pkey: secure::PublicKey = G2::generator().into(); // some fake key
        let unspent: HashMap<Hash, (PaymentOutput, i64)> = HashMap::new();
        let unspent_stakes: HashMap<Hash, StakeOutput> = HashMap::new();
        let balance: i64 = 0;

        //
        // Subscriptions.
        //
        let subscribers: Vec<UnboundedSender<WalletNotification>> = Vec::new();

        //
        // Events.
        //
        let mut events: Vec<Box<Stream<Item = WalletEvent, Error = ()> + Send>> = Vec::new();

        // Control messages.
        let (outbox, inbox) = unbounded::<WalletEvent>();
        events.push(Box::new(inbox));

        // Key blocks from node.
        let node_epochs = node
            .subscribe_epoch()
            .expect("connected")
            .map(|epoch| WalletEvent::NodeEpochChanged(epoch));
        events.push(Box::new(node_epochs));

        // Monetary blocks from node.
        let node_outputs = node
            .subscribe_outputs()
            .expect("connected")
            .map(|outputs| WalletEvent::NodeOutputsChanged(outputs));
        events.push(Box::new(node_outputs));

        // Pool formation.
        let pool_formation = network
            .subscribe_unicast(POOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| WalletEvent::PoolInfo(m.from, m.data));
        events.push(Box::new(pool_formation));

        let events = select_all(events);

        let service = WalletService {
            skey,
            pkey,
            validator_pkey,
            facilitator_pkey,
            unspent,
            unspent_stakes,
            balance,
            network,
            node,
            subscribers,
            events,
        };

        let api = Wallet { outbox };

        (service, api)
    }

    /// Send money.
    fn payment(&self, recipient: &PublicKey, amount: i64, comment: String) -> Result<(), Error> {
        let data = PaymentPayloadData::Comment(comment);
        let tx = create_payment_transaction(
            &self.skey,
            &self.pkey,
            recipient,
            &self.unspent,
            amount,
            data,
        )?;
        self.node.send_transaction(tx)?;
        Ok(())
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        _recipient: &PublicKey,
        _amount: i64,
        _comment: String,
    ) -> Result<(), Error> {
        let join = PoolJoin {};
        let msg = join.into_buffer()?;
        self.network
            .send(self.facilitator_pkey, POOL_JOIN_TOPIC, msg)?;
        info!(
            "Sent pool join request facilitator={:?}",
            self.facilitator_pkey
        );
        // TODO: implement valueshuffle
        error!("unimplemented");
        Ok(())
    }

    /// Stake money into the escrow.
    fn stake(&self, amount: i64) -> Result<(), Error> {
        let tx = create_staking_transaction(
            &self.skey,
            &self.pkey,
            &self.validator_pkey,
            &self.unspent,
            amount,
        )?;
        self.node.send_transaction(tx)?;
        Ok(())
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&self, amount: i64) -> Result<(), Error> {
        let tx = create_unstaking_transaction(
            &self.skey,
            &self.pkey,
            &self.validator_pkey,
            &self.unspent_stakes,
            amount,
        )?;
        self.node.send_transaction(tx)?;
        Ok(())
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&self) -> Result<(), Error> {
        let mut amount: i64 = 0;
        for output in self.unspent_stakes.values() {
            amount += output.amount;
        }
        self.unstake(amount)
    }

    /// Called when outputs registered and/or pruned.
    fn on_outputs_changed(&mut self, inputs: Vec<Output>, outputs: Vec<Output>) {
        let saved_balance = self.balance;

        for input in inputs {
            self.on_output_pruned(input);
        }

        for output in outputs {
            self.on_output_created(output);
        }

        if saved_balance != self.balance {
            let balance = self.balance;
            let notification = WalletNotification::BalanceChanged { balance };
            self.subscribers
                .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, output: Output) {
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Received UTXO: hash={}, amount={}, data={:?}",
                        hash, amount, data
                    );
                    let comment = match data {
                        PaymentPayloadData::Comment(comment) => comment,
                        PaymentPayloadData::ContentHash(hash) => hash.into_hex(),
                    };
                    let missing = self.unspent.insert(hash, (o, amount));
                    assert!(missing.is_none());
                    assert!(amount >= 0);
                    self.balance += amount;

                    // Notify subscribers.
                    let notification = WalletNotification::PaymentReceived { amount, comment };
                    self.subscribers
                        .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                }
            }
            Output::StakeOutput(o) => {
                if let Ok(_delta) = o.decrypt_payload(&self.skey) {
                    info!("Staked money to escrow: hash={}, amount={}", hash, o.amount);
                    let missing = self.unspent_stakes.insert(hash, o);
                    assert!(missing.is_none());
                }
            }
        };
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, output: Output) {
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Spent UTXO: hash={}, amount={}, data={:?}",
                        hash, amount, data
                    );
                    let exists = self.unspent.remove(&hash);
                    assert!(exists.is_some());
                    self.balance -= amount;
                    assert!(self.balance >= 0);
                }
            }
            Output::StakeOutput(o) => {
                if let Ok(_delta) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Unstaked money from escrow: hash={}, amount={}",
                        hash, o.amount
                    );
                    let exists = self.unspent_stakes.remove(&hash);
                    assert!(exists.is_some());
                }
            }
        }
    }

    /// Called then txpool has been formed.
    fn on_pool_formed(&mut self, members: Vec<secure::PublicKey>) -> Result<(), Error> {
        info!("Formed txpool: members={}", members.len());
        for pkey in members {
            info!("{}", pkey);
        }
        Ok(())
    }
}

// Event loop.
impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        WalletEvent::Payment {
                            recipient,
                            amount,
                            comment,
                        } => self.payment(&recipient, amount, comment),
                        WalletEvent::SecurePayment {
                            recipient,
                            amount,
                            comment,
                        } => self.secure_payment(&recipient, amount, comment),

                        WalletEvent::Stake { amount } => self.stake(amount),
                        WalletEvent::Unstake { amount } => self.unstake(amount),
                        WalletEvent::UnstakeAll {} => self.unstake_all(),
                        WalletEvent::Subscribe { tx } => {
                            self.subscribers.push(tx);
                            Ok(())
                        }
                        WalletEvent::NodeOutputsChanged(OutputsNotification {
                            inputs,
                            outputs,
                        }) => {
                            self.on_outputs_changed(inputs, outputs);
                            Ok(())
                        }
                        WalletEvent::NodeEpochChanged(EpochNotification {
                            facilitator, ..
                        }) => {
                            debug!("Changed facilitator: facilitator={:?}", facilitator);
                            self.facilitator_pkey = facilitator;
                            Ok(())
                        }
                        WalletEvent::PoolInfo(from, msg) => {
                            if from != self.facilitator_pkey {
                                Err(format_err!(
                                    "Invalid facilitator: expected={:?}, got={:?}",
                                    self.facilitator_pkey,
                                    from
                                ))
                            } else {
                                PoolInfo::from_buffer(&msg)
                                    .and_then(|pool| self.on_pool_formed(pool.participants))
                            }
                        }
                    };
                    if let Err(error) = result {
                        let error = format!("{:?}", error);
                        let msg = WalletNotification::Error { error };
                        self.subscribers
                            .retain(move |tx| tx.unbounded_send(msg.clone()).is_ok());
                    }
                }
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

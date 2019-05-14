//! Wallet.

//
// Copyright (c) 2018 Stegos AG
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
use crate::error::WalletError;
use crate::transaction::*;
use crate::valueshuffle::ValueShuffle;
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
use stegos_crypto::hash::Hash;
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_node::EpochChanged;
use stegos_node::Node;
use stegos_node::OutputsChanged;

struct PaymentValue {
    output: PaymentOutput,
    amount: i64,
    data: PaymentPayloadData,
}

struct StakeValue {
    output: StakeOutput,
    active_until_epoch: u64,
}

impl PaymentValue {
    fn to_info(&self) -> PaymentInfo {
        PaymentInfo {
            utxo: Hash::digest(&self.output),
            amount: self.amount,
            data: self.data.clone(),
        }
    }
}

impl StakeValue {
    fn to_info(&self, epoch: u64) -> StakeInfo {
        let is_active = self.active_until_epoch >= epoch;
        StakeInfo {
            utxo: Hash::digest(&self.output),
            amount: self.output.amount,
            active_until_epoch: self.active_until_epoch,
            is_active,
        }
    }
}

pub struct WalletService {
    /// Keys.
    keys: KeyChain,
    /// Current Epoch.
    epoch: u64,
    /// Unspent Payment UXTO.
    payments: HashMap<Hash, PaymentValue>,
    /// Unspent Stake UTXO.
    stakes: HashMap<Hash, StakeValue>,
    /// ValueShuffle State.
    vs: ValueShuffle,

    /// Payment fee.
    payment_fee: i64,
    /// Staking fee.
    stake_fee: i64,
    /// Lifetime of stake.
    stake_epochs: u64,

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
        keys: KeyChain,
        network: Network,
        node: Node,
        payment_fee: i64,
        stake_fee: i64,
        stake_epochs: u64,
        persistent_state: Vec<(Output, u64)>,
    ) -> (Self, Wallet) {
        info!("My wallet key: {}", keys.wallet_pkey.to_hex());
        debug!("My network key: {}", keys.network_pkey.to_hex());

        //
        // State.
        //
        let epoch = 0;
        let payments: HashMap<Hash, PaymentValue> = HashMap::new();
        let stakes: HashMap<Hash, StakeValue> = HashMap::new();
        let vs = ValueShuffle::new(
            keys.wallet_skey.clone(),
            keys.wallet_pkey.clone(),
            keys.network_pkey.clone(),
            network.clone(),
            node.clone(),
        );

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

        // Monetary blocks from node.
        let node_outputs = node
            .subscribe_outputs_changed()
            .map(|outputs| WalletEvent::NodeOutputsChanged(outputs));
        events.push(Box::new(node_outputs));

        // Key blocks from node.
        let node_epochs = node
            .subscribe_epoch_changed()
            .map(|epoch| WalletEvent::NodeEpochChanged(epoch));
        events.push(Box::new(node_epochs));

        let events = select_all(events);

        let mut service = WalletService {
            epoch,
            keys,
            payments,
            stakes,
            vs,
            payment_fee,
            stake_fee,
            stake_epochs,
            node,
            subscribers,
            events,
        };

        // Recover state.
        for (output, epoch) in persistent_state {
            service.on_output_created(epoch, output);
        }

        let api = Wallet { outbox };

        (service, api)
    }

    /// Send money.
    fn payment(
        &self,
        recipient: &PublicKey,
        amount: i64,
        comment: String,
    ) -> Result<(Hash, i64), Error> {
        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let (inputs, outputs, gamma, fee) = create_payment_transaction(
            &self.keys.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            self.payment_fee,
            data,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = Transaction::new(&self.keys.wallet_skey, &inputs, &outputs, gamma, fee)?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.body.fee;
        self.node.send_transaction(tx)?;
        Ok((tx_hash, fee))
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        recipient: &PublicKey,
        amount: i64,
        comment: String,
    ) -> Result<(), Error> {
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let (inputs, outputs, fee) = create_vs_payment_transaction(
            &self.keys.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            self.payment_fee,
            comment,
        )?;
        self.vs.queue_transaction(&inputs, &outputs, fee)?;
        Ok(())
    }

    /// Stake money into the escrow.
    fn stake(&self, amount: i64) -> Result<(Hash, i64), Error> {
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let tx = create_staking_transaction(
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            &self.keys.network_pkey,
            &self.keys.network_skey,
            unspent_iter,
            amount,
            self.payment_fee,
            self.stake_fee,
        )?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.body.fee;
        self.node.send_transaction(tx)?;
        Ok((tx_hash, fee))
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&self, amount: i64) -> Result<(Hash, i64), Error> {
        let unspent_iter = self.stakes.values().map(|v| &v.output);
        let tx = create_unstaking_transaction(
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            &self.keys.network_pkey,
            &self.keys.network_skey,
            unspent_iter,
            amount,
            self.payment_fee,
            self.stake_fee,
        )?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.body.fee;
        self.node.send_transaction(tx)?;
        Ok((tx_hash, fee))
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&self) -> Result<(Hash, i64), Error> {
        let mut amount: i64 = 0;
        for val in self.stakes.values() {
            amount += val.output.amount;
        }
        self.unstake(amount)
    }

    /// Restake all available stakes (even if not expired).
    fn restake_all(&mut self) -> Result<(Hash, i64), Error> {
        assert_eq!(self.stake_fee, 0);
        if self.stakes.is_empty() {
            return Err(WalletError::NothingToRestake.into());
        }

        let stakes = self.stakes.values().map(|val| &val.output);
        let tx = create_restaking_transaction(
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            &self.keys.network_pkey,
            &self.keys.network_skey,
            stakes,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.node.send_transaction(tx)?;
        Ok((tx_hash, 0))
    }

    /// Re-stake expiring stakes.
    fn restake_expiring(&mut self) -> Result<(), Error> {
        assert_eq!(self.stake_fee, 0);
        let epoch = self.epoch;
        let stakes: Vec<&StakeOutput> = self.stakes.iter().filter_map(|(hash, val)|
                // Re-stake in the last epoch where stake is valid.
                if val.active_until_epoch <= epoch {
                    info!("Expiring stake: utxo={}, amount={}, active_until_epoch={}, epoch={}",
                           hash, val.output.amount, val.active_until_epoch, epoch);
                    Some(&val.output)
                } else {
                    None
                }
        ).collect();

        if stakes.is_empty() {
            return Ok(()); // Nothing to re-stake.
        }

        let tx = create_restaking_transaction(
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            &self.keys.network_pkey,
            &self.keys.network_skey,
            stakes.into_iter(),
        )?;
        self.node.send_transaction(tx)?;
        Ok(())
    }

    /// Get actual balance.
    fn balance(&self) -> i64 {
        let mut balance: i64 = 0;
        for val in self.payments.values() {
            balance += val.amount;
        }
        balance
    }

    /// Called when outputs registered and/or pruned.
    fn on_outputs_changed(&mut self, epoch: u64, inputs: Vec<Output>, outputs: Vec<Output>) {
        assert_eq!(self.epoch, epoch);
        let saved_balance = self.balance();

        for input in inputs {
            self.on_output_pruned(epoch, input);
        }

        for output in outputs {
            self.on_output_created(epoch, output);
        }

        let balance = self.balance();
        if saved_balance != balance {
            debug!("Balance changed");
            self.notify(WalletNotification::BalanceChanged { balance });
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, epoch: u64, output: Output) {
        if !output.is_my_utxo(&self.keys.wallet_skey, &self.keys.wallet_pkey) {
            return;
        }
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.keys.wallet_skey)
                {
                    assert!(amount >= 0);
                    info!(
                        "Received: utxo={}, amount={}, data={:?}",
                        hash, amount, data
                    );
                    let value = PaymentValue {
                        output: o,
                        amount,
                        data: data.clone(),
                    };
                    let info = value.to_info();
                    let missing = self.payments.insert(hash, value);
                    assert!(missing.is_none());
                    self.notify(WalletNotification::Received(info));
                }
            }
            Output::PublicPaymentOutput(_o) => {
                unimplemented!();
            }
            Output::StakeOutput(o) => {
                let active_until_epoch = epoch + self.stake_epochs;
                info!(
                    "Staked money to escrow: hash={}, amount={}, active_until_epoch={}",
                    hash, o.amount, active_until_epoch
                );
                let value = StakeValue {
                    output: o,
                    active_until_epoch,
                };
                let info = value.to_info(self.epoch);
                let missing = self.stakes.insert(hash, value);
                assert!(missing.is_none(), "Inconsistent wallet state");
                self.notify(WalletNotification::Staked(info));
            }
        };
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, _epoch: u64, output: Output) {
        if !output.is_my_utxo(&self.keys.wallet_skey, &self.keys.wallet_pkey) {
            return;
        }
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.keys.wallet_skey)
                {
                    info!("Spent: utxo={}, amount={}, data={:?}", hash, amount, data);
                    match self.payments.remove(&hash) {
                        Some(value) => {
                            let info = value.to_info();
                            self.notify(WalletNotification::Spent(info));
                        }
                        None => panic!("Inconsistent wallet state"),
                    }
                }
            }
            Output::PublicPaymentOutput(_o) => {
                unimplemented!();
            }
            Output::StakeOutput(o) => {
                info!("Unstaked: utxo={}, amount={}", hash, o.amount);
                match self.stakes.remove(&hash) {
                    Some(value) => {
                        let info = value.to_info(self.epoch);
                        self.notify(WalletNotification::Unstaked(info));
                    }
                    None => panic!("Inconsistent wallet state"),
                }
            }
        }
    }

    fn on_epoch_changed(&mut self, epoch: u64) {
        self.epoch = epoch;

        if let Err(e) = self.restake_expiring() {
            error!("Failed to re-stake: {}", e);
        }
    }

    fn notify(&mut self, notification: WalletNotification) {
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }
}

impl From<Result<(Hash, i64), Error>> for WalletResponse {
    fn from(r: Result<(Hash, i64), Error>) -> Self {
        match r {
            Ok((tx_hash, fee)) => WalletResponse::TransactionCreated { tx_hash, fee },
            Err(e) => WalletResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

// Event loop.
impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if let Async::NotReady = self.vs.poll().expect("all errors are already handled") {
                break;
            }
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletEvent::Request { request, tx } => {
                        let response = match request {
                            WalletRequest::Payment {
                                recipient,
                                amount,
                                comment,
                            } => self.payment(&recipient, amount, comment).into(),
                            WalletRequest::SecurePayment {
                                recipient,
                                amount,
                                comment,
                            } => match self.secure_payment(&recipient, amount, comment) {
                                Ok(()) => WalletResponse::ValueShuffleStarted {},
                                Err(e) => WalletResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                            WalletRequest::Stake { amount } => self.stake(amount).into(),
                            WalletRequest::Unstake { amount } => self.unstake(amount).into(),
                            WalletRequest::UnstakeAll {} => self.unstake_all().into(),
                            WalletRequest::RestakeAll {} => self.restake_all().into(),
                            WalletRequest::KeysInfo {} => WalletResponse::KeysInfo {
                                wallet_pkey: self.keys.wallet_pkey,
                                network_pkey: self.keys.network_pkey,
                            },
                            WalletRequest::BalanceInfo {} => WalletResponse::BalanceInfo {
                                balance: self.balance(),
                            },
                            WalletRequest::UnspentInfo {} => {
                                let epoch = self.epoch;
                                let payments: Vec<PaymentInfo> = self
                                    .payments
                                    .values()
                                    .map(|value| value.to_info())
                                    .collect();
                                let stakes: Vec<StakeInfo> = self
                                    .stakes
                                    .values()
                                    .map(|value| value.to_info(epoch))
                                    .collect();
                                WalletResponse::UnspentInfo { payments, stakes }
                            }
                            WalletRequest::GetRecovery {} => match self.keys.show_recovery() {
                                Ok(recovery) => WalletResponse::Recovery { recovery },
                                Err(e) => WalletResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    WalletEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                    WalletEvent::NodeOutputsChanged(OutputsChanged {
                        epoch,
                        inputs,
                        outputs,
                    }) => {
                        self.on_outputs_changed(epoch, inputs, outputs);
                    }
                    WalletEvent::NodeEpochChanged(EpochChanged { epoch, .. }) => {
                        self.on_epoch_changed(epoch);
                    }
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

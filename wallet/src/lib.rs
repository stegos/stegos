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
mod metrics;
mod transaction;
mod valueshuffle;

#[cfg(test)]
mod tests;

pub use crate::api::*;
use crate::error::WalletError;
pub use crate::transaction::TransactionType;
use crate::transaction::*;
use crate::valueshuffle::ValueShuffle;
use failure::Error;
use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::UnboundedSender;
use futures::sync::oneshot;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use futures_stream_select_all_send::select_all;
use log::*;
use std::collections::{HashMap, HashSet};
use stegos_blockchain::*;
use stegos_crypto::curve1174::PublicKey;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
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

struct PublicPaymentValue {
    output: PublicPaymentOutput,
    amount: i64,
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

impl PublicPaymentValue {
    fn to_info(&self) -> PublicPaymentInfo {
        PublicPaymentInfo {
            utxo: Hash::digest(&self.output),
            amount: self.amount,
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

/// Transaction that is known by wallet.
#[derive(Debug)]
enum SavedTransaction {
    Regular(Transaction),
    /// Stub implementation for value shuffle transaction, which contain only inputs.
    ValueShuffle(Vec<Hash>),
}

impl SavedTransaction {
    fn txins(&self) -> &[Hash] {
        match self {
            SavedTransaction::Regular(t) => t.txins(),
            SavedTransaction::ValueShuffle(inputs) => &inputs,
        }
    }
}

impl Hashable for SavedTransaction {
    fn hash(&self, state: &mut Hasher) {
        match self {
            SavedTransaction::Regular(t) => t.hash(state),
            SavedTransaction::ValueShuffle(hashes) => {
                "ValueShuffle".hash(state);
                for h in hashes {
                    h.hash(state)
                }
            }
        }
    }
}

impl From<Transaction> for SavedTransaction {
    fn from(tx: Transaction) -> SavedTransaction {
        SavedTransaction::Regular(tx)
    }
}

pub struct WalletService {
    /// Keys.
    keys: KeyChain,
    /// Current Epoch.
    epoch: u64,
    /// Unspent Payment UXTO.
    payments: HashMap<Hash, PaymentValue>,

    /// Unspent Payment UXTO.
    public_payments: HashMap<Hash, PublicPaymentValue>,
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

    /// Map of inputs of transaction interests, that we wait for.
    transactions_interest: HashMap<Hash, Hash>,

    /// Set of unprocessed transactions, with pending sender.
    unprocessed_transactions:
        HashMap<Hash, (SavedTransaction, Vec<oneshot::Sender<WalletResponse>>)>,

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

        let public_payments = HashMap::new();
        let stakes: HashMap<Hash, StakeValue> = HashMap::new();
        let vs = ValueShuffle::new(
            keys.wallet_skey.clone(),
            keys.wallet_pkey.clone(),
            keys.network_pkey.clone(),
            network.clone(),
            node.clone(),
        );

        let transactions_interest = HashMap::new();
        let unprocessed_transactions = HashMap::new();

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

        // Epoch changes.
        let node_epochs = node
            .subscribe_epoch_changed()
            .map(|epoch| WalletEvent::NodeEpochChanged(epoch));
        events.push(Box::new(node_epochs));

        // UTXO changes.
        let node_outputs = node
            .subscribe_outputs_changed()
            .map(|outputs| WalletEvent::NodeOutputsChanged(outputs));
        events.push(Box::new(node_outputs));

        let events = select_all(events);

        let mut service = WalletService {
            epoch,
            keys,
            payments,
            public_payments,
            stakes,
            vs,
            payment_fee,
            stake_fee,
            stake_epochs,
            node,
            subscribers,
            events,
            transactions_interest,
            unprocessed_transactions,
        };

        // Recover state.
        for (output, epoch) in persistent_state {
            service.on_output_created(epoch, output);
        }

        metrics::WALLET_BALANCES
            .with_label_values(&[&service.keys.wallet_pkey.to_hex()])
            .set(service.balance());

        let api = Wallet { outbox };

        (service, api)
    }

    /// Send money.
    fn payment(
        &mut self,
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
            TransactionType::Regular(data),
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.keys.wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.fee;
        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
            .inc();
        //firstly check that no conflict input was found;
        self.add_transaction_interest(tx.into());

        Ok((tx_hash, fee))
    }

    /// Send money public.
    fn public_payment(&mut self, recipient: &PublicKey, amount: i64) -> Result<(Hash, i64), Error> {
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let (inputs, outputs, gamma, fee) = create_payment_transaction(
            &self.keys.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            self.payment_fee,
            TransactionType::Public,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.keys.wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.fee;
        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
            .inc();
        //firstly check that no conflict input was found;
        self.add_transaction_interest(tx.into());

        Ok((tx_hash, fee))
    }

    fn add_transaction_interest(&mut self, tx: SavedTransaction) {
        debug!("Add transaction in interest list: tx = {:?}", tx);
        let tx_hash = Hash::digest(&tx);
        let tx_ins = tx.txins();
        let mut conflict = false;
        for input in tx_ins {
            if self.transactions_interest.contains_key(&input) {
                error!("Conflict transaction found.");
                conflict = true;
                break;
            }
        }

        if !conflict {
            debug!("No conflict found, adding transaction into interest map.");
            for input in tx_ins {
                assert!(self.transactions_interest.insert(*input, tx_hash).is_none())
            }
            self.unprocessed_transactions
                .insert(tx_hash, (tx.into(), Vec::new()));
        }
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        recipient: &PublicKey,
        amount: i64,
        comment: String,
    ) -> Result<Hash, Error> {
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
        let saved_tx = SavedTransaction::ValueShuffle(inputs.iter().map(|(h, _)| *h).collect());
        let hash = Hash::digest(&saved_tx);
        metrics::WALLET_CREATEAD_SECURE_PAYMENTS
            .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
            .inc();
        self.add_transaction_interest(saved_tx);
        Ok(hash)
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
        let fee = tx.fee;
        self.node.send_transaction(tx.into())?;
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
        let fee = tx.fee;
        self.node.send_transaction(tx.into())?;
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
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, 0))
    }

    /// Re-stake expiring stakes.
    fn restake_expiring(&mut self) -> Result<(), Error> {
        assert_eq!(self.stake_fee, 0);
        let epoch = self.epoch;
        let stakes: Vec<&StakeOutput> = self
            .stakes
            .iter()
            .filter_map(|(hash, val)| {
                // Re-stake in the last epoch where stake is valid.

                trace!(
                    "Check expiring stake: utxo={}, amount={}, active_until_epoch={}, epoch={}",
                    hash,
                    val.output.amount,
                    val.active_until_epoch,
                    epoch
                );
                if val.active_until_epoch <= epoch {
                    info!(
                        "Expiring stake: utxo={}, amount={}, active_until_epoch={}, epoch={}",
                        hash, val.output.amount, val.active_until_epoch, epoch
                    );
                    Some(&val.output)
                } else {
                    None
                }
            })
            .collect();

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
        self.node.send_transaction(tx.into())?;
        Ok(())
    }

    /// Cloak all available public outputs.
    fn cloak_all(&mut self) -> Result<(Hash, i64), Error> {
        if self.public_payments.is_empty() {
            return Err(WalletError::NotEnoughMoney.into());
        }

        let public_utxos = self.public_payments.values().map(|val| &val.output);
        let tx = create_cloaking_transaction(
            &self.keys.wallet_skey,
            &self.keys.wallet_pkey,
            public_utxos,
            self.payment_fee,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, self.payment_fee))
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
        let saved_balance = self.balance();

        self.find_committed_txs(&inputs);
        for input in inputs {
            self.on_output_pruned(epoch, input);
        }

        for output in outputs {
            self.on_output_created(epoch, output);
        }

        let balance = self.balance();
        if saved_balance != balance {
            debug!("Balance changed");
            metrics::WALLET_BALANCES
                .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
                .set(balance);
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
            Output::PublicPaymentOutput(o) => {
                let PublicPaymentOutput { ref amount, .. } = &o;
                assert!(*amount >= 0);
                info!("Received public payment: utxo={}, amount={}", hash, amount);
                let value = PublicPaymentValue {
                    output: o.clone(),
                    amount: *amount,
                };
                let info = value.to_info();
                let missing = self.public_payments.insert(hash, value);
                assert!(missing.is_none());
                self.notify(WalletNotification::ReceivedPublic(info));
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
    fn wait_for_commit(&mut self, tx_hash: Hash, sender: oneshot::Sender<WalletResponse>) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut o) = self.unprocessed_transactions.entry(tx_hash) {
            debug!("Adding our sender to watcher: tx_hash = {}", tx_hash);
            o.get_mut().1.push(sender);
        } else {
            debug!(
                "Transaction was commited before, or not known to our wallet: tx_hash = {}",
                tx_hash
            );
            let _ = sender.send(WalletResponse::TransactionCommitted(
                TransactionCommitted::NotFoundInMempool {},
            ));
        }
    }

    fn find_committed_txs(&mut self, pruned_inputs: &[Output]) {
        let hash_set: HashSet<Hash> = pruned_inputs.iter().map(Hash::digest).collect();
        for input in &hash_set {
            if let Some(tx_hash) = self.transactions_interest.get(input) {
                let (tx, senders) = self
                    .unprocessed_transactions
                    .remove(tx_hash)
                    .expect("Transaction not found in set.");

                let mut conflict = false;
                for input_hash in tx.txins() {
                    self.transactions_interest.remove(input_hash).unwrap();
                    if !hash_set.contains(input_hash) {
                        conflict = true;
                    }
                }

                let commited = if conflict {
                    warn!("Conflicted transaction processed.");

                    TransactionCommitted::ConflictTransactionCommitted {
                        conflicted_output: *input,
                    }
                } else {
                    TransactionCommitted::Committed {}
                };

                match tx {
                    SavedTransaction::Regular(_) => {
                        metrics::WALLET_COMMITTED_PAYMENTS
                            .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
                            .inc();
                    }
                    SavedTransaction::ValueShuffle(_) => {
                        metrics::WALLET_COMMITTED_SECURE_PAYMENTS
                            .with_label_values(&[&self.keys.wallet_pkey.to_hex()])
                            .inc();
                    }
                };
                let msg = WalletResponse::TransactionCommitted(commited);
                // send notification about committed transaction, drop errors if found.
                senders
                    .into_iter()
                    .for_each(move |ch| drop(ch.send(msg.clone())));
            }
        }
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
            Output::PublicPaymentOutput(PublicPaymentOutput { amount, .. }) => {
                info!("Spent public payment: utxo={}, amount={}", hash, amount);
                match self.public_payments.remove(&hash) {
                    Some(value) => {
                        let info = value.to_info();
                        self.notify(WalletNotification::SpentPublic(info));
                    }
                    None => panic!("Inconsistent wallet state"),
                }
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

        trace!("Updating node epoch = {}", epoch);
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
                            WalletRequest::PublicPayment { recipient, amount } => {
                                self.public_payment(&recipient, amount).into()
                            }

                            WalletRequest::SecurePayment {
                                recipient,
                                amount,
                                comment,
                            } => match self.secure_payment(&recipient, amount, comment) {
                                Ok(session_id) => {
                                    WalletResponse::ValueShuffleStarted { session_id }
                                }
                                Err(e) => WalletResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                            WalletRequest::WaitForCommit { tx_hash } => {
                                self.wait_for_commit(tx_hash, tx);
                                continue;
                            }
                            WalletRequest::Stake { amount } => self.stake(amount).into(),
                            WalletRequest::Unstake { amount } => self.unstake(amount).into(),
                            WalletRequest::UnstakeAll {} => self.unstake_all().into(),
                            WalletRequest::RestakeAll {} => self.restake_all().into(),
                            WalletRequest::CloakAll {} => self.cloak_all().into(),
                            WalletRequest::KeysInfo {} => WalletResponse::KeysInfo {
                                wallet_pkey: self.keys.wallet_pkey,
                                network_pkey: self.keys.network_pkey,
                            },
                            WalletRequest::BalanceInfo {} => WalletResponse::BalanceInfo {
                                balance: self.balance(),
                            },
                            WalletRequest::UnspentInfo {} => {
                                let epoch = self.epoch;
                                let public_payments: Vec<PublicPaymentInfo> = self
                                    .public_payments
                                    .values()
                                    .map(|value| value.to_info())
                                    .collect();
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
                                WalletResponse::UnspentInfo {
                                    public_payments,
                                    payments,
                                    stakes,
                                }
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

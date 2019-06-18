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

//#![deny(warnings)]

mod api;
mod change;
mod error;
mod metrics;
mod protos;
mod storage;
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
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use stegos_blockchain::*;
use stegos_crypto::curve1174;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_keychain as keychain;
use stegos_network::Network;
use stegos_node::EpochChanged;
use stegos_node::Node;
use stegos_node::OutputsChanged;
use storage::*;

const STAKE_FEE: i64 = 0;

pub struct WalletService {
    //
    // Config
    //
    /// Path to wallet secret key.
    wallet_skey_file: String,
    /// Wallet Secret Key.
    wallet_skey: curve1174::SecretKey,
    /// Wallet Public Key.
    wallet_pkey: curve1174::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,

    //
    // Current state
    //
    /// Current Epoch.
    epoch: u64,
    /// Time of last macro block.
    last_macro_block_timestamp: SystemTime,

    /// Unspent Payment UXTO.
    payments: HashMap<Hash, PaymentValue>,
    /// Unspent Payment UXTO.
    public_payments: HashMap<Hash, PublicPaymentOutput>,
    /// Unspent Stake UTXO.
    stakes: HashMap<Hash, StakeValue>,
    /// Persistent part of the state.
    wallet_log: WalletLog,

    //
    // Node api (shared)
    //
    /// Node API.
    node: Node,

    //
    // Value shuffle api (owned)
    //
    /// ValueShuffle State.
    vs: ValueShuffle,

    //
    // Transaction watcher
    //
    /// Map of inputs of transaction interests, that we wait for.
    transactions_interest: HashMap<Hash, Hash>,
    /// Set of unprocessed transactions, with pending sender.
    unprocessed_transactions:
        HashMap<Hash, (SavedTransaction, Vec<oneshot::Sender<WalletResponse>>)>,

    //
    // Api subscribers
    //
    /// Triggered when state has changed.
    subscribers: Vec<UnboundedSender<WalletNotification>>,

    //
    // Events source
    //
    /// Incoming events.
    events: Box<Stream<Item = WalletEvent, Error = ()> + Send>,
}

impl WalletService {
    /// Create a new wallet.
    pub fn new(
        database_path: &Path,
        wallet_skey_file: String,
        wallet_skey: curve1174::SecretKey,
        wallet_pkey: curve1174::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        persistent_state: Vec<(Output, u64)>,
    ) -> (Self, Wallet) {
        info!("My wallet key: {}", String::from(&wallet_pkey));
        debug!("My network key: {}", network_pkey.to_hex());
        //
        // State.
        //
        let epoch = 0;
        let payments: HashMap<Hash, PaymentValue> = HashMap::new();

        let public_payments = HashMap::new();
        let stakes: HashMap<Hash, StakeValue> = HashMap::new();
        let vs = ValueShuffle::new(
            wallet_skey.clone(),
            wallet_pkey.clone(),
            network_pkey.clone(),
            network.clone(),
            node.clone(),
        );

        let transactions_interest = HashMap::new();
        let unprocessed_transactions = HashMap::new();

        let last_macro_block_timestamp = UNIX_EPOCH;

        let wallet_log = WalletLog::open(database_path);
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
            wallet_skey_file,
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
            wallet_log,
            epoch,
            payments,
            public_payments,
            stakes,
            vs,
            stake_epochs,
            last_macro_block_timestamp,
            node,
            subscribers,
            events,
            transactions_interest,
            unprocessed_transactions,
        };

        // Recover state.
        for (output, epoch) in persistent_state {
            service.on_output_created(epoch, output, false);
        }

        metrics::WALLET_BALANCES
            .with_label_values(&[&String::from(&service.wallet_pkey)])
            .set(service.balance());

        let api = Wallet { outbox };

        (service, api)
    }

    /// Unlock secret key.
    fn unlock(&self, password: String) -> Result<curve1174::SecretKey, Error> {
        let wallet_skey_path = Path::new(&self.wallet_skey_file);
        let wallet_skey = keychain::keyfile::load_wallet_skey(wallet_skey_path, &password)?;
        Ok(wallet_skey)
    }

    /// Send money.
    fn payment(
        &mut self,
        password: String,
        recipient: &curve1174::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<SystemTime>,
    ) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self
            .payments
            .values()
            .map(|v| (&v.output, v.amount, v.output.locked_timestamp.clone()));
        let (inputs, outputs, gamma, rvalues, fee) = create_payment_transaction(
            Some(&self.wallet_skey),
            &self.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Regular(data.clone()),
            locked_timestamp,
            self.last_macro_block_timestamp,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let tx_hash = Hash::digest(&tx);
        let payment_info =
            self.create_payment_transaction_info(data, *recipient, tx.clone(), &rvalues, amount);

        self.wallet_log
            .push_outgoing(SystemTime::now(), payment_info.clone())?;

        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.wallet_pkey)])
            .inc();
        //firstly check that no conflict input was found;
        self.add_transaction_interest(tx.into());

        Ok((tx_hash, fee))
    }

    fn create_payment_transaction_info(
        &self,
        _data: PaymentPayloadData,
        recipient: curve1174::PublicKey,
        tx: PaymentTransaction,
        rvalues: &[Option<curve1174::Fr>],
        amount: i64,
    ) -> PaymentTransactionValue {
        let certificates: Vec<_> = rvalues
            .iter()
            .enumerate()
            .filter_map(|(id, r)| r.clone().map(|r| (id, r)))
            .map(|(id, rvalue)| PaymentCertificate {
                id: id as u32,
                rvalue,
                recipient,
                amount,
            })
            .collect();

        assert_eq!(tx.txouts.len(), 2);
        assert_eq!(certificates.len(), 1);

        PaymentTransactionValue { certificates, tx }
    }

    /// Send money public.
    fn public_payment(
        &mut self,
        password: String,
        recipient: &curve1174::PublicKey,
        amount: i64,
        payment_fee: i64,
        locked_timestamp: Option<SystemTime>,
    ) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        let unspent_iter = self
            .payments
            .values()
            .map(|v| (&v.output, v.amount, v.output.locked_timestamp.clone()));

        let (inputs, outputs, gamma, _rvalue, fee) = create_payment_transaction(
            Some(&self.wallet_skey),
            &self.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Public,
            locked_timestamp,
            self.last_macro_block_timestamp,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.fee;
        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.wallet_pkey)])
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

    fn get_tx_history(&self, starting_from: SystemTime, limit: u64) -> Vec<LogEntryInfo> {
        self.wallet_log
            .iter_range(starting_from, limit)
            .map(|(t, e)| e.to_info(t))
            .collect()
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        password: String,
        recipient: &curve1174::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<SystemTime>,
    ) -> Result<Hash, Error> {
        let _wallet_skey = self.unlock(password)?;
        // TODO: refactor ValueShuffle to request secret key explicitly.
        let unspent_iter = self
            .payments
            .values()
            .map(|v| (&v.output, v.amount, v.output.locked_timestamp.clone()));
        let (inputs, outputs, fee) = create_vs_payment_transaction(
            &self.wallet_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            comment,
            locked_timestamp,
            self.last_macro_block_timestamp,
        )?;
        self.vs.queue_transaction(&inputs, &outputs, fee)?;
        let saved_tx = SavedTransaction::ValueShuffle(inputs.iter().map(|(h, _)| *h).collect());
        let hash = Hash::digest(&saved_tx);
        metrics::WALLET_CREATEAD_SECURE_PAYMENTS
            .with_label_values(&[&String::from(&self.wallet_pkey)])
            .inc();
        self.add_transaction_interest(saved_tx);
        Ok(hash)
    }

    /// Stake money into the escrow.
    fn stake(&self, password: String, amount: i64, payment_fee: i64) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let tx = create_staking_transaction(
            &wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
        )?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.fee;
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, fee))
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(
        &self,
        password: String,
        amount: i64,
        payment_fee: i64,
    ) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        let unspent_iter = self.stakes.values().map(|v| &v.output);
        let tx = create_unstaking_transaction(
            &wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
        )?;
        let tx_hash = Hash::digest(&tx);
        let fee = tx.fee;
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, fee))
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&self, password: String, payment_fee: i64) -> Result<(Hash, i64), Error> {
        let mut amount: i64 = 0;
        for val in self.stakes.values() {
            amount += val.output.amount;
        }
        self.unstake(password, amount, payment_fee)
    }

    /// Restake all available stakes (even if not expired).
    fn restake_all(&mut self, password: String) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        assert_eq!(STAKE_FEE, 0);
        if self.stakes.is_empty() {
            return Err(WalletError::NothingToRestake.into());
        }

        let stakes = self.stakes.values().map(|val| &val.output);
        let tx = create_restaking_transaction(
            &wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            stakes,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, 0))
    }

    /// Re-stake expiring stakes.
    fn restake_expiring(&mut self) -> Result<(), Error> {
        assert_eq!(STAKE_FEE, 0);
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
            &self.wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            stakes.into_iter(),
        )?;
        self.node.send_transaction(tx.into())?;
        Ok(())
    }

    /// Cloak all available public outputs.
    fn cloak_all(&mut self, password: String, payment_fee: i64) -> Result<(Hash, i64), Error> {
        let wallet_skey = self.unlock(password)?;
        if self.public_payments.is_empty() {
            return Err(WalletError::NotEnoughMoney.into());
        }

        let public_utxos = self.public_payments.values();
        let tx = create_cloaking_transaction(
            &wallet_skey,
            &self.wallet_pkey,
            public_utxos,
            payment_fee,
            self.last_macro_block_timestamp,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, payment_fee))
    }

    /// Change the password.
    fn change_password(&mut self, old_password: String, new_password: String) -> Result<(), Error> {
        let wallet_skey_path = Path::new(&self.wallet_skey_file);
        let wallet_skey = keychain::keyfile::load_wallet_skey(wallet_skey_path, &old_password)?;
        keychain::keyfile::write_wallet_skey(wallet_skey_path, &wallet_skey, &new_password)?;
        Ok(())
    }

    /// Return recovery codes.
    fn get_recovery(&mut self, password: String) -> Result<String, Error> {
        let wallet_skey = self.unlock(password)?;
        Ok(keychain::recovery::wallet_skey_to_recovery(&wallet_skey))
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
    fn on_outputs_changed(
        &mut self,
        epoch: u64,
        inputs: Vec<Output>,
        outputs: Vec<Output>,
        persist: bool,
    ) {
        let saved_balance = self.balance();

        self.find_committed_txs(&inputs);
        for input in inputs {
            self.on_output_pruned(epoch, input);
        }

        for output in outputs {
            self.on_output_created(epoch, output, persist);
        }

        let balance = self.balance();
        if saved_balance != balance {
            debug!("Balance changed");
            metrics::WALLET_BALANCES
                .with_label_values(&[&String::from(&self.wallet_pkey)])
                .set(balance);
            self.notify(WalletNotification::BalanceChanged { balance });
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, epoch: u64, output: Output, persist: bool) {
        if !output.is_my_utxo(&self.wallet_skey, &self.wallet_pkey) {
            return;
        }
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.wallet_skey)
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

                    if persist {
                        if let Err(e) = self
                            .wallet_log
                            .push_incomming(SystemTime::now(), value.clone().into())
                        {
                            error!("Error when adding incomming tx = {}", e)
                        }
                    }
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
                let value = o.clone();

                if persist {
                    if let Err(e) = self
                        .wallet_log
                        .push_incomming(SystemTime::now(), value.clone().into())
                    {
                        error!("Error when adding incomming tx = {}", e)
                    }
                }

                let info = public_payment_info(&value);
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
                            .with_label_values(&[&String::from(&self.wallet_pkey)])
                            .inc();
                    }
                    SavedTransaction::ValueShuffle(_) => {
                        metrics::WALLET_COMMITTED_SECURE_PAYMENTS
                            .with_label_values(&[&String::from(&self.wallet_pkey)])
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
        if !output.is_my_utxo(&self.wallet_skey, &self.wallet_pkey) {
            return;
        }
        let hash = Hash::digest(&output);

        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.wallet_skey)
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
                        let info = public_payment_info(&value);
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

    fn on_epoch_changed(&mut self, epoch: u64, time: SystemTime) {
        self.epoch = epoch;
        self.last_macro_block_timestamp = time;

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

impl From<Vec<LogEntryInfo>> for WalletResponse {
    fn from(log: Vec<LogEntryInfo>) -> Self {
        WalletResponse::HistoryInfo { log }
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
                                password,
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            } => self
                                .payment(
                                    password,
                                    &recipient,
                                    amount,
                                    payment_fee,
                                    comment,
                                    locked_timestamp,
                                )
                                .into(),
                            WalletRequest::PublicPayment {
                                password,
                                recipient,
                                amount,
                                payment_fee,
                                locked_timestamp,
                            } => self
                                .public_payment(
                                    password,
                                    &recipient,
                                    amount,
                                    payment_fee,
                                    locked_timestamp,
                                )
                                .into(),
                            WalletRequest::SecurePayment {
                                password,
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            } => match self.secure_payment(
                                password,
                                &recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            ) {
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
                            WalletRequest::Stake {
                                password,
                                amount,
                                payment_fee,
                            } => self.stake(password, amount, payment_fee).into(),
                            WalletRequest::Unstake {
                                password,
                                amount,
                                payment_fee,
                            } => self.unstake(password, amount, payment_fee).into(),
                            WalletRequest::UnstakeAll {
                                password,
                                payment_fee,
                            } => self.unstake_all(password, payment_fee).into(),
                            WalletRequest::RestakeAll { password } => {
                                self.restake_all(password).into()
                            }
                            WalletRequest::CloakAll {
                                password,
                                payment_fee,
                            } => self.cloak_all(password, payment_fee).into(),
                            WalletRequest::KeysInfo {} => WalletResponse::KeysInfo {
                                wallet_pkey: self.wallet_pkey,
                                network_pkey: self.network_pkey,
                            },
                            WalletRequest::BalanceInfo {} => WalletResponse::BalanceInfo {
                                balance: self.balance(),
                            },
                            WalletRequest::UnspentInfo {} => {
                                let epoch = self.epoch;
                                let public_payments: Vec<PublicPaymentInfo> = self
                                    .public_payments
                                    .values()
                                    .map(public_payment_info)
                                    .collect();
                                let payments: Vec<PaymentInfo> =
                                    self.payments.values().map(PaymentValue::to_info).collect();
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
                            WalletRequest::HistoryInfo {
                                starting_from,
                                limit,
                            } => self.get_tx_history(starting_from, limit).into(),
                            WalletRequest::ChangePassword {
                                old_password,
                                new_password,
                            } => match self.change_password(old_password, new_password) {
                                Ok(()) => WalletResponse::PasswordChanged,
                                Err(e) => WalletResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                            WalletRequest::GetRecovery { password } => {
                                match self.get_recovery(password) {
                                    Ok(recovery) => WalletResponse::Recovery { recovery },
                                    Err(e) => WalletResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
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
                        final_block,
                    }) => {
                        self.on_outputs_changed(epoch, inputs, outputs, final_block);
                    }
                    WalletEvent::NodeEpochChanged(EpochChanged {
                        epoch,
                        last_macro_block_timestamp,
                        ..
                    }) => {
                        self.on_epoch_changed(epoch, last_macro_block_timestamp);
                    }
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

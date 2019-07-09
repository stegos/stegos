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
mod manager;
mod metrics;
mod protos;
mod recovery;
mod storage;
#[cfg(test)]
pub mod test;
mod transaction;
mod valueshuffle;

pub use crate::api::*;
use crate::error::WalletError;
pub use crate::manager::WalletManagerService;
pub use crate::transaction::TransactionType;
use crate::transaction::*;
use crate::valueshuffle::ValueShuffle;
use failure::Error;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use futures::task;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use log::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use stegos_blockchain::Timestamp;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;
use stegos_keychain as keychain;
use stegos_keychain::keyfile::load_wallet_pkey;
use stegos_keychain::KeyError;
use stegos_network::Network;
use stegos_node::{Node, NodeNotification, NodeRequest, NodeResponse};
use storage::*;

const STAKE_FEE: i64 = 0;

pub struct UnsealedWalletService {
    //
    // Config
    //
    /// Path to RocksDB directory.
    database_dir: PathBuf,
    /// Path to wallet secret key.
    wallet_skey_file: PathBuf,
    /// Path to wallet public key.
    wallet_pkey_file: PathBuf,
    /// Wallet Secret Key.
    wallet_skey: scc::SecretKey,
    /// Wallet Public Key.
    wallet_pkey: scc::PublicKey,
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
    last_macro_block_timestamp: Timestamp,

    /// Unspent Payment UXTO.
    payments: HashMap<Hash, PaymentValue>,
    /// Unspent Payment UXTO.
    public_payments: HashMap<Hash, PublicPaymentOutput>,
    /// Unspent Stake UTXO.
    stakes: HashMap<Hash, StakeValue>,
    /// Persistent part of the state.
    wallet_log: WalletLog,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
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
    /// Recovery status.
    recovery_rx: Option<oneshot::Receiver<NodeResponse>>,
    /// API Requests.
    events: UnboundedReceiver<WalletEvent>,
    /// Notifications from node.
    node_notifications: UnboundedReceiver<NodeNotification>,
}

impl UnsealedWalletService {
    /// Create a new wallet.
    fn new(
        database_dir: PathBuf,
        wallet_skey_file: PathBuf,
        wallet_pkey_file: PathBuf,
        wallet_skey: scc::SecretKey,
        wallet_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        subscribers: Vec<UnboundedSender<WalletNotification>>,
        events: UnboundedReceiver<WalletEvent>,
    ) -> Self {
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

        let last_macro_block_timestamp = Timestamp::UNIX_EPOCH;

        let wallet_log = WalletLog::open(&database_dir);

        //
        // Recovery.
        //
        let recovery_request = NodeRequest::RecoverWallet {
            wallet_skey: wallet_skey.clone(),
            wallet_pkey: wallet_pkey.clone(),
        };
        let recovery_rx = Some(node.request(recovery_request));

        //
        // Notifications from node.
        //

        let node_notifications = node.subscribe();

        UnsealedWalletService {
            database_dir,
            wallet_skey_file,
            wallet_pkey_file,
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
            network,
            node,
            subscribers,
            recovery_rx,
            events,
            node_notifications,
            transactions_interest,
            unprocessed_transactions,
        }
    }

    /// Send money.
    fn payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
        with_certificate: bool,
    ) -> Result<PaymentTransactionValue, Error> {
        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self
            .payments
            .values()
            .map(|v| (&v.output, v.amount, v.output.locked_timestamp.clone()));
        let sender = if with_certificate {
            Some(&self.wallet_skey)
        } else {
            None
        };

        let (inputs, outputs, gamma, rvalues, fee) = create_payment_transaction(
            sender,
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
        let tx = PaymentTransaction::new(&self.wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let payment_info = PaymentTransactionValue::new_payment(
            data.into(),
            *recipient,
            tx.clone(),
            &rvalues,
            amount,
        );

        self.wallet_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.wallet_pkey)])
            .inc();
        //firstly check that no conflict input was found;
        self.add_transaction_interest(tx.into());

        Ok(payment_info)
    }

    /// Send money public.
    fn public_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        locked_timestamp: Option<Timestamp>,
    ) -> Result<PaymentTransactionValue, Error> {
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
            TransactionType::Public,
            locked_timestamp,
            self.last_macro_block_timestamp,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.wallet_skey, &inputs, &outputs, &gamma, fee)?;
        let payment_info =
            PaymentTransactionValue::new_payment(None, *recipient, tx.clone(), &rvalues, amount);

        self.wallet_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let tx: Transaction = tx.into();
        self.node.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.wallet_pkey)])
            .inc();
        //firstly check that no conflict input was found;
        self.add_transaction_interest(tx.into());

        Ok(payment_info)
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

    fn get_tx_history(&self, starting_from: Timestamp, limit: u64) -> Vec<LogEntryInfo> {
        self.wallet_log
            .iter_range(starting_from, limit)
            .map(|(t, e)| e.to_info(t))
            .collect()
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
    ) -> Result<Hash, Error> {
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
    fn stake(&mut self, amount: i64, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let unspent_iter = self.payments.values().map(|v| (&v.output, v.amount));
        let tx = create_staking_transaction(
            &self.wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
        )?;
        let payment_info = PaymentTransactionValue::new_stake(tx.clone());

        self.wallet_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        self.node.send_transaction(tx.into())?;
        Ok(payment_info)
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&self, amount: i64, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let unspent_iter = self.stakes.values().map(|v| &v.output);
        let tx = create_unstaking_transaction(
            &self.wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
        )?;
        let payment_info = PaymentTransactionValue::new_stake(tx.clone());
        self.node.send_transaction(tx.into())?;
        Ok(payment_info)
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&self, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let mut amount: i64 = 0;
        for val in self.stakes.values() {
            amount += val.output.amount;
        }
        self.unstake(amount, payment_fee)
    }

    /// Restake all available stakes (even if not expired).
    fn restake_all(&mut self) -> Result<(Hash, i64), Error> {
        assert_eq!(STAKE_FEE, 0);
        if self.stakes.is_empty() {
            return Err(WalletError::NothingToRestake.into());
        }

        let stakes = self.stakes.values().map(|val| &val.output);
        let tx = create_restaking_transaction(
            &self.wallet_skey,
            &self.wallet_pkey,
            &self.network_pkey,
            &self.network_skey,
            stakes,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.node.send_transaction(tx.into())?;
        Ok((tx_hash, 0))
    }

    /// Cloak all available public outputs.
    fn cloak_all(&mut self, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        if self.public_payments.is_empty() {
            return Err(WalletError::NotEnoughMoney.into());
        }

        let public_utxos = self.public_payments.values();
        let tx = create_cloaking_transaction(
            &self.wallet_skey,
            &self.wallet_pkey,
            public_utxos,
            payment_fee,
            self.last_macro_block_timestamp,
        )?;

        let info = PaymentTransactionValue::new_cloak(tx.clone());
        self.node.send_transaction(tx.into())?;
        Ok(info)
    }

    /// Change the password.
    fn change_password(&mut self, new_password: String) -> Result<(), Error> {
        let wallet_skey_path = Path::new(&self.wallet_skey_file);
        keychain::keyfile::write_wallet_skey(wallet_skey_path, &self.wallet_skey, &new_password)?;
        Ok(())
    }

    /// Return recovery codes.
    fn get_recovery(&mut self) -> Result<String, Error> {
        Ok(crate::recovery::wallet_skey_to_recovery(&self.wallet_skey))
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
                            .push_incomming(Timestamp::now(), value.clone().into())
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
                        .push_incomming(Timestamp::now(), value.clone().into())
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

    fn on_epoch_changed(&mut self, epoch: u64, time: Timestamp) {
        self.epoch = epoch;
        self.last_macro_block_timestamp = time;
    }

    fn notify(&mut self, notification: WalletNotification) {
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }
}

impl From<Result<PaymentTransactionValue, Error>> for WalletResponse {
    fn from(r: Result<PaymentTransactionValue, Error>) -> Self {
        match r {
            Ok(info) => WalletResponse::TransactionCreated(info.to_info()),
            Err(e) => WalletResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

impl From<Result<(Hash, i64), Error>> for WalletResponse {
    fn from(r: Result<(Hash, i64), Error>) -> Self {
        match r {
            Ok((hash, _fee)) => {
                let info = PaymentTransactionInfo {
                    tx_hash: hash,
                    certificates: vec![],
                };
                WalletResponse::TransactionCreated(info)
            }
            Err(e) => WalletResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

impl From<Vec<LogEntryInfo>> for WalletResponse {
    fn from(log: Vec<LogEntryInfo>) -> Self {
        WalletResponse::HistoryInfo { log }
    }
}

// Event loop.
impl Future for UnsealedWalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Recovery information from node.
        if let Some(mut recovery_rx) = self.recovery_rx.take() {
            match recovery_rx.poll() {
                Ok(Async::Ready(response)) => {
                    match response {
                        NodeResponse::WalletRecovered(persistent_state) => {
                            // Recover state.
                            for (output, epoch) in persistent_state {
                                self.on_output_created(epoch, output, false);
                            }
                        }
                        NodeResponse::Error { error } => {
                            // Sic: this case is hard to recover.
                            panic!("Failed to recover wallet: {:?}", error);
                        }
                        _ => unreachable!(),
                    };
                }
                Ok(Async::NotReady) => self.recovery_rx = Some(recovery_rx),
                Err(_) => panic!("disconnected"),
            }
        }

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
                            WalletRequest::Unseal { password: _ } => WalletResponse::Error {
                                error: "Already unsealed".to_string(),
                            },
                            WalletRequest::Seal {} => {
                                tx.send(WalletResponse::Sealed).ok();
                                // Finish this future.
                                return Ok(Async::Ready(()));
                            }
                            WalletRequest::Payment {
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                                with_certificate,
                            } => self
                                .payment(
                                    &recipient,
                                    amount,
                                    payment_fee,
                                    comment,
                                    locked_timestamp,
                                    with_certificate,
                                )
                                .into(),
                            WalletRequest::PublicPayment {
                                recipient,
                                amount,
                                payment_fee,
                                locked_timestamp,
                            } => self
                                .public_payment(&recipient, amount, payment_fee, locked_timestamp)
                                .into(),
                            WalletRequest::SecurePayment {
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            } => match self.secure_payment(
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
                                amount,
                                payment_fee,
                            } => self.stake(amount, payment_fee).into(),
                            WalletRequest::Unstake {
                                amount,
                                payment_fee,
                            } => self.unstake(amount, payment_fee).into(),
                            WalletRequest::UnstakeAll { payment_fee } => {
                                self.unstake_all(payment_fee).into()
                            }
                            WalletRequest::RestakeAll {} => self.restake_all().into(),
                            WalletRequest::CloakAll { payment_fee } => {
                                self.cloak_all(payment_fee).into()
                            }
                            WalletRequest::KeysInfo {} => WalletResponse::KeysInfo {
                                wallet_address: self.wallet_pkey,
                                network_address: self.network_pkey,
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
                            WalletRequest::ChangePassword { new_password } => {
                                match self.change_password(new_password) {
                                    Ok(()) => WalletResponse::PasswordChanged,
                                    Err(e) => WalletResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            WalletRequest::GetRecovery {} => match self.get_recovery() {
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
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        loop {
            match self
                .node_notifications
                .poll()
                .expect("all errors are already handled")
            {
                Async::Ready(Some(notification)) => match notification {
                    NodeNotification::NewMicroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs, false);
                    }
                    NodeNotification::NewMacroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs, true);
                        self.on_epoch_changed(block.epoch, block.last_macro_block_timestamp);
                    }
                    NodeNotification::RollbackMicroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs, false);
                    }
                    _ => {}
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}

pub struct SealedWalletService {
    /// Path to database dir.
    database_dir: PathBuf,
    /// Path to wallet secret key.
    wallet_skey_file: PathBuf,
    /// Path to wallet public key.
    wallet_pkey_file: PathBuf,
    /// Wallet Public Key.
    wallet_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
    node: Node,

    //
    // Api subscribers
    //
    subscribers: Vec<UnboundedSender<WalletNotification>>,
    /// Incoming events.
    events: UnboundedReceiver<WalletEvent>,
}

impl SealedWalletService {
    fn new(
        database_dir: PathBuf,
        wallet_skey_file: PathBuf,
        wallet_pkey_file: PathBuf,
        wallet_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        subscribers: Vec<UnboundedSender<WalletNotification>>,
        events: UnboundedReceiver<WalletEvent>,
    ) -> Self {
        SealedWalletService {
            database_dir,
            wallet_skey_file,
            wallet_pkey_file,
            wallet_pkey,
            network_skey,
            network_pkey,
            stake_epochs,
            node,
            network,
            subscribers,
            events,
        }
    }

    fn load_secret_key(&self, password: &str) -> Result<scc::SecretKey, KeyError> {
        let wallet_skey = keychain::keyfile::load_wallet_skey(&self.wallet_skey_file, password)?;

        if let Err(_e) = scc::check_keying(&wallet_skey, &self.wallet_pkey) {
            return Err(KeyError::InvalidKeying(
                self.wallet_skey_file.to_string_lossy().to_string(),
                self.wallet_pkey_file.to_string_lossy().to_string(),
            ));
        }
        Ok(wallet_skey)
    }
}

// Event loop.
impl Future for SealedWalletService {
    type Item = scc::SecretKey;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletEvent::Request { request, tx } => {
                        let response = match request {
                            WalletRequest::Unseal { password } => {
                                match self.load_secret_key(&password) {
                                    Ok(wallet_skey) => {
                                        tx.send(WalletResponse::Unsealed).ok(); // ignore errors.
                                                                                // Finish this future.
                                        return Ok(Async::Ready(wallet_skey));
                                    }
                                    Err(e) => WalletResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            WalletRequest::KeysInfo {} => WalletResponse::KeysInfo {
                                wallet_address: self.wallet_pkey,
                                network_address: self.network_pkey,
                            },
                            _ => WalletResponse::Error {
                                error: "Wallet is sealed".to_string(),
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    WalletEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

pub enum WalletService {
    Invalid,
    Sealed(SealedWalletService),
    Unsealed(UnsealedWalletService),
}

// Event loop.
impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            WalletService::Invalid => unreachable!(),
            WalletService::Sealed(sealed) => match sealed.poll().unwrap() {
                Async::Ready(wallet_skey) => {
                    let sealed = match std::mem::replace(self, WalletService::Invalid) {
                        WalletService::Sealed(old) => old,
                        _ => unreachable!(),
                    };
                    info!("Unsealed wallet: pkey={}", &sealed.wallet_pkey);
                    let unsealed = UnsealedWalletService::new(
                        sealed.database_dir,
                        sealed.wallet_skey_file,
                        sealed.wallet_pkey_file,
                        wallet_skey,
                        sealed.wallet_pkey,
                        sealed.network_skey,
                        sealed.network_pkey,
                        sealed.network,
                        sealed.node,
                        sealed.stake_epochs,
                        sealed.subscribers,
                        sealed.events,
                    );
                    std::mem::replace(self, WalletService::Unsealed(unsealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
            WalletService::Unsealed(unsealed) => match unsealed.poll().unwrap() {
                Async::Ready(()) => {
                    let unsealed = match std::mem::replace(self, WalletService::Invalid) {
                        WalletService::Unsealed(old) => old,
                        _ => unreachable!(),
                    };
                    info!("Sealed wallet: pkey={}", &unsealed.wallet_pkey);
                    let sealed = SealedWalletService::new(
                        unsealed.database_dir,
                        unsealed.wallet_skey_file,
                        unsealed.wallet_pkey_file,
                        unsealed.wallet_pkey,
                        unsealed.network_skey,
                        unsealed.network_pkey,
                        unsealed.network,
                        unsealed.node,
                        unsealed.stake_epochs,
                        unsealed.subscribers,
                        unsealed.events,
                    );
                    std::mem::replace(self, WalletService::Sealed(sealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
        }
        Ok(Async::NotReady)
    }
}

impl WalletService {
    /// Create a new wallet.
    pub fn new(
        database_dir: &Path,
        wallet_skey_file: &Path,
        wallet_pkey_file: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
    ) -> Result<(Self, Wallet), KeyError> {
        let wallet_pkey = load_wallet_pkey(wallet_pkey_file)?;
        let subscribers: Vec<UnboundedSender<WalletNotification>> = Vec::new();
        let (outbox, events) = unbounded::<WalletEvent>();
        let service = SealedWalletService::new(
            database_dir.to_path_buf(),
            wallet_skey_file.to_path_buf(),
            wallet_pkey_file.to_path_buf(),
            wallet_pkey,
            network_skey,
            network_pkey,
            network,
            node,
            stake_epochs,
            subscribers,
            events,
        );
        let service = WalletService::Sealed(service);
        let api = Wallet { outbox };
        Ok((service, api))
    }
}

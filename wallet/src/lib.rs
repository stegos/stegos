//! Account.

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

pub mod api;
mod change;
mod error;
mod metrics;
mod protos;
mod recovery;
mod snowball;
mod storage;
#[cfg(test)]
mod test;
mod transaction;

use self::error::WalletError;
use self::recovery::recovery_to_account_skey;
use self::snowball::{Snowball, SnowballOutput, State as SnowballState};
use self::storage::*;
use self::transaction::*;
use api::*;
use failure::{bail, format_err, Error};
use futures::future::IntoFuture;
use futures::sync::{mpsc, oneshot};
use futures::{task, Async, Future, Poll, Stream};
use log::*;
use std::collections::HashMap;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::keyfile::{load_account_pkey, write_account_pkey, write_account_skey};
use stegos_keychain::KeyError;
use stegos_network::Network;
use stegos_node::{ChainNotification, Node, NodeRequest, NodeResponse, TransactionStatus};
use tokio::runtime::TaskExecutor;
use tokio_timer::{clock, Interval};

const STAKE_FEE: i64 = 0;
const RESEND_TX_INTERVAL: Duration = Duration::from_secs(2 * 60);
const PENDING_UTXO_TIME: Duration = Duration::from_secs(5 * 60);
const CHECK_PENDING_UTXO: Duration = Duration::from_secs(10);

///
/// Events.
///
#[derive(Debug)]
enum AccountEvent {
    //
    // Public API.
    //
    Subscribe {
        tx: mpsc::UnboundedSender<AccountNotification>,
    },
    Request {
        request: AccountRequest,
        tx: oneshot::Sender<AccountResponse>,
    },
}

/// Helper for NodeRequest::SubscribeChain.
enum ChainSubscription {
    // Waiting for subscription.
    Pending(oneshot::Receiver<NodeResponse>),
    // Subscribed/
    Active(mpsc::Receiver<ChainNotification>),
}

impl ChainSubscription {
    fn new(node: &Node, epoch: u64, offset: u32) -> Self {
        let request = NodeRequest::SubscribeChain { epoch, offset };
        let rx = node.request(request);
        ChainSubscription::Pending(rx)
    }

    fn poll_subscribed(&mut self) -> Poll<&mut mpsc::Receiver<ChainNotification>, Error> {
        match self {
            ChainSubscription::Pending(rx) => match rx.poll()? {
                Async::Ready(response) => match response {
                    NodeResponse::SubscribedChain { rx, .. } => {
                        let rx = rx.unwrap();
                        std::mem::replace(self, ChainSubscription::Active(rx));
                        match self {
                            ChainSubscription::Active(rx) => Ok(Async::Ready(rx)),
                            _ => unreachable!("Expected ChainSubscription::Active state"),
                        }
                    }
                    _ => unreachable!(
                        "Expected SubscribeChain response NodeResponse: {:?}",
                        response
                    ),
                },
                Async::NotReady => Ok(Async::NotReady),
            },
            ChainSubscription::Active(rx) => Ok(Async::Ready(rx)),
        }
    }
}

struct UnsealedAccountService {
    //
    // Config
    //
    /// Path to RocksDB directory.
    database_dir: PathBuf,
    /// Path to account secret key.
    account_skey_file: PathBuf,
    /// Path to account public key.
    account_pkey_file: PathBuf,
    /// Account Secret Key.
    account_skey: scc::SecretKey,
    /// Account Public Key.
    account_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,
    /// Maximum allowed count of input UTXOs (from Node config)
    max_inputs_in_tx: usize,

    //
    // Current state
    //
    /// Current Epoch.
    epoch: u64,
    /// Is last update of UTXO was in current epoch.
    current_epoch_balance_changed: bool,
    /// Time of last macro block.
    last_macro_block_timestamp: Timestamp,
    /// Faciliator's PBC public key
    facilitator_pkey: pbc::PublicKey,
    // Store time in Instant, to be more compatible with tokio-timer.
    /// List of pending utxos.
    pending_payments: HashMap<Hash, PendingOutput>,
    /// Persistent part of the state.
    database: AccountDatabase,
    /// Map of public addresses to address id.
    public_addresses: HashMap<scc::PublicKey, u32>,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
    node: Node,
    /// Resend timeout.
    resend_tx: Interval,

    /// Check for pending utxos.
    check_pending_utxos: Interval,
    //
    // Snowball state (owned)
    //
    snowball: Option<(Snowball, oneshot::Sender<AccountResponse>)>,
    //
    // Response from mempool about transaction.
    //
    transaction_response: Option<oneshot::Receiver<NodeResponse>>,

    //
    // Api subscribers
    //
    /// Triggered when state has changed.
    subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,

    //
    // Events source
    //
    /// API Requests.
    events: mpsc::UnboundedReceiver<AccountEvent>,
    /// Chain notifications
    chain_notifications: ChainSubscription,
}

impl UnsealedAccountService {
    /// Create a new account.
    fn new(
        database_dir: PathBuf,
        account_skey_file: PathBuf,
        account_pkey_file: PathBuf,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
    ) -> Self {
        info!("My account key: {}", String::from(&account_pkey));
        debug!("My network key: {}", network_pkey.to_hex());

        let pending_payments = HashMap::new();
        let facilitator_pkey: pbc::PublicKey = pbc::PublicKey::dum();
        let snowball = None;
        let last_macro_block_timestamp = Timestamp::UNIX_EPOCH;

        debug!("Loading account {}", account_pkey);
        // TODO: add proper handling for I/O errors.
        let (mut database, epoch) = AccountDatabase::open(&database_dir);
        let last_public_address_id = database.last_public_address_id().expect("I/O error");
        debug!(
            "Opened database: epoch={}, last_public_address_id={}",
            epoch, last_public_address_id
        );
        let transaction_response = None;
        let resend_tx = Interval::new(clock::now(), RESEND_TX_INTERVAL);
        let check_pending_utxos = Interval::new(clock::now(), CHECK_PENDING_UTXO);
        let chain_notifications = ChainSubscription::new(&node, epoch, 0);
        let current_epoch_balance_changed = false;

        // Recover public addresses.
        let mut public_addresses: HashMap<scc::PublicKey, u32> = HashMap::new();
        for public_address_id in 1..=last_public_address_id {
            match account_pkey.subkey(public_address_id) {
                Ok(public_address) => {
                    debug!(
                        "Adding public address #{} {}",
                        public_address_id,
                        public_address.to_string()
                    );
                    let prev = public_addresses.insert(public_address, public_address_id);
                    assert!(prev.is_none());
                }
                Err(_e) => continue, // skip this account_id.
            }
        }

        info!("Loaded account {}", account_pkey);
        UnsealedAccountService {
            database_dir,
            account_skey_file,
            account_pkey_file,
            account_skey,
            account_pkey,
            network_skey,
            network_pkey,
            database,
            public_addresses,
            epoch,
            current_epoch_balance_changed,
            facilitator_pkey,
            pending_payments,
            resend_tx,
            check_pending_utxos,
            snowball,
            stake_epochs,
            max_inputs_in_tx,
            last_macro_block_timestamp,
            network,
            node,
            subscribers,
            events,
            chain_notifications,
            transaction_response,
        }
    }

    /// Create a new address.
    fn new_public_address(&mut self) -> Result<(scc::PublicKey, u32), Error> {
        let mut last_public_address_id = self.database.last_public_address_id()?;
        loop {
            last_public_address_id += 1;
            match self.account_pkey.subkey(last_public_address_id) {
                Ok(public_address) => {
                    self.database
                        .update_last_public_address_id(last_public_address_id)?;
                    let prev = self
                        .public_addresses
                        .insert(public_address.clone(), last_public_address_id);
                    assert!(prev.is_none());
                    break Ok((public_address, last_public_address_id));
                }
                Err(_e) => continue,
            }
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
    ) -> Result<TransactionInfo, Error> {
        let payment_balance = self.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughPayment(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self.available_payment_outputs();
        let sender = if with_certificate {
            Some(&self.account_skey)
        } else {
            None
        };

        let (inputs, outputs, gamma, extended_outputs, fee) = create_payment_transaction(
            sender,
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Regular(data.clone()),
            locked_timestamp,
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;

        let payment_info = TransactionValue::new_payment(tx.clone(), extended_outputs);

        self.database
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            trace!("Add new pending utxo = {}", input);
            assert!(self
                .pending_payments
                .insert(*input, PendingOutput { time })
                .is_none());
        }

        let tx: Transaction = tx.into();
        self.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        Ok(payment_info.to_info(self.epoch))
    }

    /// Returns an iterator over available payment outputs.
    fn available_payment_outputs<'a>(&'a self) -> impl Iterator<Item = (PaymentOutput, i64)> + 'a {
        self.database
            .iter_unspent()
            .filter_map(|(k, v)| v.payment().map(|v| (k, v)))
            .filter(move |(h, _)| self.pending_payments.get(h).is_none())
            .filter(move |(_h, v)| match &v.output.locked_timestamp {
                Some(time) if time >= &self.last_macro_block_timestamp => false,
                _ => true,
            })
            .inspect(|(h, _)| trace!("Using PaymentOutput: hash={}", h))
            .map(|(_, v)| (v.output, v.amount))
    }

    /// Returns an iterator over available public payment outputs.
    fn available_public_payment_outputs<'a>(
        &'a self,
    ) -> impl Iterator<Item = (PublicPaymentOutput, Option<u32>)> + 'a {
        self.database
            .iter_unspent()
            .filter_map(|(k, v)| v.public_payment().map(|v| (k, v)))
            .filter(move |(h, _)| self.pending_payments.get(h).is_none())
            .filter(move |(_h, v)| match &v.output.locked_timestamp {
                Some(time) if time >= &self.last_macro_block_timestamp => false,
                _ => true,
            })
            .inspect(|(h, _)| trace!("Using PublicPaymentOutput: hash={}", h))
            .map(|(_, v)| (v.output, v.public_address_id))
    }

    /// Returns an iterator over available stake outputs.
    fn available_stake_outputs<'a>(&'a self) -> impl Iterator<Item = StakeOutput> + 'a {
        self.database
            .iter_unspent()
            .filter_map(|(_k, v)| v.stake())
            // All stake unspent utxo should be with info about active epoch.
            .filter_map(|v| v.active_until_epoch.map(|epoch| (v.output, epoch)))
            .filter(move |(_v, epoch)| *epoch <= self.epoch)
            .map(|(o, _e)| o)
    }

    /// Send money public.
    fn public_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        locked_timestamp: Option<Timestamp>,
    ) -> Result<TransactionInfo, Error> {
        let payment_balance = self.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughPayment(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let unspent_iter = self.available_payment_outputs();
        let (inputs, outputs, gamma, extended_outputs, fee) = create_payment_transaction(
            Some(&self.account_skey),
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Public,
            locked_timestamp,
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;
        let payment_info = TransactionValue::new_payment(tx.clone(), extended_outputs);

        self.database
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            assert!(self
                .pending_payments
                .insert(*input, PendingOutput { time })
                .is_none());
        }

        let tx: Transaction = tx.into();
        self.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        Ok(payment_info.to_info(self.epoch))
    }

    fn get_tx_history(&self, starting_from: Timestamp, limit: u64) -> Vec<LogEntryInfo> {
        self.database
            .iter_range(starting_from, limit)
            .map(|(timestamp, e)| match e {
                LogEntry::Incoming {
                    output: ref output_value,
                } => {
                    let mut output_info = output_value.to_info(self.epoch);
                    // Update information about change.
                    if let OutputInfo::Payment(ref mut p) = output_info {
                        p.is_change = self.database.is_known_changes(p.output_hash);
                    }

                    LogEntryInfo::Incoming {
                        timestamp,
                        output: output_info,
                    }
                }
                LogEntry::Outgoing { ref tx } => LogEntryInfo::Outgoing {
                    timestamp,
                    tx: tx.to_info(self.epoch),
                },
            })
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
    ) -> Result<Snowball, Error> {
        if self.snowball.is_some() {
            return Err(WalletError::SnowballBusy.into());
        }
        let payment_balance = self.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughPayment(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }
        let data = PaymentPayloadData::Comment(comment);

        let unspent_iter = self.available_payment_outputs();
        let (inputs, outputs, fee) = create_snowball_transaction(
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            data,
            locked_timestamp,
            snowball::MAX_UTXOS,
        )?;
        assert!(inputs.len() <= snowball::MAX_UTXOS);

        let time = clock::now();
        for (input, _) in &inputs {
            assert!(self
                .pending_payments
                .insert(*input, PendingOutput { time })
                .is_none());
        }

        let snowball = Snowball::new(
            self.account_skey.clone(),
            self.account_pkey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.facilitator_pkey.clone(),
            inputs,
            outputs,
            fee,
        );

        metrics::WALLET_CREATEAD_SECURE_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();
        Ok(snowball)
    }

    fn stake_all(&mut self, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let mut payment_amount: i64 = 0;
        let mut outputs: Vec<_> = self.available_payment_outputs().collect();
        outputs.sort_by_key(|o| o.1);
        if outputs.len() > self.max_inputs_in_tx {
            warn!(
                "Found too many payment outputs, \
                 limiting to max_inputs_in_tx: outputs_len={}, max_inputs_in_tx={}",
                outputs.len(),
                self.max_inputs_in_tx
            );
        }
        for output in outputs.into_iter().rev().take(self.max_inputs_in_tx) {
            payment_amount += output.1;
        }

        if payment_amount <= payment_fee {
            return Err(WalletError::NotEnoughMoney.into());
        }

        info!("Found payment outputs: amount={}", payment_amount);

        self.stake(payment_amount, payment_fee)
    }

    /// Stake money into the escrow.
    fn stake(&mut self, amount: i64, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let payment_balance = self.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughPayment(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let unspent_iter = self.available_payment_outputs();
        let (tx, outputs) = create_staking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.max_inputs_in_tx,
        )?;
        let payment_info = TransactionValue::new_stake(tx.clone(), outputs);

        self.database
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            assert!(self
                .pending_payments
                .insert(*input, PendingOutput { time })
                .is_none());
        }

        self.send_transaction(tx.into())?;
        Ok(payment_info.to_info(self.epoch))
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&mut self, amount: i64, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let stake_balance = self.balance().stake;
        if amount > stake_balance.available {
            return Err(
                WalletError::NoEnoughStake(stake_balance.current, stake_balance.available).into(),
            );
        }

        let unspent_iter = self.available_stake_outputs();
        let (tx, outputs) = create_unstaking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.max_inputs_in_tx,
        )?;
        let payment_info = TransactionValue::new_stake(tx.clone(), outputs);
        self.send_transaction(tx.into())?;
        Ok(payment_info.to_info(self.epoch))
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&mut self, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let mut amount: i64 = 0;
        let mut outputs: Vec<_> = self.available_stake_outputs().collect();
        outputs.sort_by_key(|o| o.amount);
        if outputs.len() > self.max_inputs_in_tx {
            warn!(
                "Found too many stake outputs, \
                 limiting to max_inputs_in_tx: outputs_len={}, max_inputs_in_tx={}",
                outputs.len(),
                self.max_inputs_in_tx
            );
        }
        for output in outputs.into_iter().rev().take(self.max_inputs_in_tx) {
            amount += output.amount;
        }
        if amount <= payment_fee {
            return Err(WalletError::NotEnoughMoney.into());
        }
        self.unstake(amount, payment_fee)
    }

    /// Restake all available stakes (even if not expired).
    fn restake_all(&mut self) -> Result<TransactionInfo, Error> {
        assert_eq!(STAKE_FEE, 0);
        if self.available_stake_outputs().count() == 0 {
            return Err(WalletError::NothingToRestake.into());
        }

        let stakes = self.available_stake_outputs();
        let (tx, outputs) = create_restaking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            stakes,
        )?;

        let transaction = TransactionValue::restake_tx_info(tx.clone(), outputs, self.epoch);
        self.send_transaction(tx.into())?;
        Ok(transaction)
    }

    /// Cloak all available public outputs.
    fn cloak_all(&mut self, fee: i64) -> Result<TransactionInfo, Error> {
        // Secret key to sign the transaction.
        // =sum((input.skey + input.delta + input.gamma) for input in inputs)
        let mut sign_skey = scc::Fr::zero();
        // Gamma Adjustment
        // =sum(input.gamma for input in inputs) - sum(output.gamma for output in outputs)
        let mut gamma = scc::Fr::zero();
        // TX inputs.
        let mut txins: Vec<Hash> = Vec::new();
        let mut txins_expanded: Vec<Output> = Vec::new();
        // TX outputs.
        let mut txouts: Vec<Output> = Vec::new();

        let mut outputs: Vec<_> = self.available_public_payment_outputs().collect();
        outputs.sort_by_key(|o| o.0.amount);
        if outputs.len() > self.max_inputs_in_tx {
            warn!(
                "Found too many public outputs, \
                 limiting to max_inputs_in_tx: outputs_len={}, max_inputs_in_tx={}",
                outputs.len(),
                self.max_inputs_in_tx
            );
        }
        //
        // Get inputs.
        //
        let mut amount = 0;
        for (input, address_id) in outputs.into_iter().rev().take(self.max_inputs_in_tx) {
            let input_hash = Hash::digest(&input);
            debug!(
                "Using PublicUTXO: utxo={}, amount={}",
                input_hash, input.amount
            );
            let skey = match address_id {
                Some(address_id) => {
                    // PublicPayment to a subkey.
                    let pkey = self
                        .account_pkey
                        .subkey(address_id)
                        .expect("address id is valid");
                    assert_eq!(input.recipient, pkey, "corrupted UTXO database");
                    self.account_skey
                        .subkey(address_id)
                        .expect("address id is valid")
                }
                None => {
                    // PublicPayment to the primary key.
                    self.account_skey.clone()
                }
            };
            amount += input.amount;
            txins.push(input_hash);
            txins_expanded.push(input.into());
            sign_skey += scc::Fr::from(skey);
        }
        if amount < fee {
            // Don't have enough PublicPaymentUTXO to pay `fee`.
            return Err(WalletError::NoEnoughPublicPayment(amount).into());
        }
        amount -= fee;
        assert!(!txins.is_empty());
        assert_eq!(txins.len(), txins_expanded.len());

        //
        // Create outputs.
        //
        let extended_output = {
            let recipient = self.account_pkey.clone();
            let data = PaymentPayloadData::Comment(String::from("Cloaked from the public UTXOs"));
            data.validate().unwrap();
            trace!("Creating PaymentUTXO...");
            let (output, output_gamma, _rvalue) =
                PaymentOutput::with_payload(None, &recipient, amount, data.clone(), None)?;
            let output_hash = Hash::digest(&output);
            debug!(
                "Created PaymentUTXO: utxo={}, recipient={}, amount={}, data={:?}",
                output_hash, recipient, amount, data
            );
            let extended_output = PaymentValue {
                amount,
                rvalue: None,
                recipient,
                data,
                output: output.clone(),
                is_change: false,
            };
            gamma -= output_gamma;
            txouts.push(output.into());
            extended_output
        };

        //
        // Create a transaction.
        //
        let mut tx = PaymentTransaction {
            txins,
            txouts,
            gamma,
            fee,
            sig: scc::SchnorrSig::new(),
        };

        //
        // Sign and validate created transaction.
        //
        let tx_hash = Hash::digest(&tx);
        let sign_skey: scc::SecretKey = sign_skey.into();
        tx.sig = scc::sign_hash(&tx_hash, &sign_skey);
        drop(sign_skey);
        tx.validate(&txins_expanded).expect("Invalid TX created");
        info!(
            "Created cloak transaction: tx={}, amount={}, fee={}",
            tx_hash, amount, fee
        );

        //
        // Update the database.
        //
        let extended_tx = TransactionValue::new_cloak(tx.clone(), extended_output.into());
        let time = clock::now();
        for input_hash in tx.txins.iter() {
            assert!(self
                .pending_payments
                .insert(*input_hash, PendingOutput { time })
                .is_none());
        }
        let tx_info = extended_tx.to_info(self.epoch);

        //
        // Send the transaction to the network.
        //
        self.send_transaction(tx.into())?;
        Ok(tx_info)
    }

    /// Change the password.
    fn change_password(&mut self, new_password: String) -> Result<(), Error> {
        let account_skey_path = Path::new(&self.account_skey_file);
        keychain::keyfile::write_account_skey(
            account_skey_path,
            &self.account_skey,
            &new_password,
        )?;
        Ok(())
    }

    /// Return recovery codes.
    fn get_recovery(&mut self) -> Result<AccountRecovery, Error> {
        let last_public_address_id = self.database.last_public_address_id()?;
        let recovery = crate::recovery::account_skey_to_recovery(&self.account_skey);
        Ok(AccountRecovery {
            recovery,
            last_public_address_id,
        })
    }

    /// Get actual balance.
    fn balance(&self) -> AccountBalance {
        let time = Timestamp::now();
        let mut balance: AccountBalance = Default::default();
        for (hash, val) in self.database.iter_unspent() {
            match val {
                OutputValue::Payment(PaymentValue {
                    amount,
                    output:
                        PaymentOutput {
                            locked_timestamp, ..
                        },
                    ..
                }) => {
                    balance.payment.current += amount;
                    if let Some(t) = locked_timestamp {
                        if t > time {
                            continue;
                        }
                    }
                    if self.pending_payments.get(&hash).is_some() {
                        continue;
                    }
                    balance.payment.available += amount;
                }
                OutputValue::PublicPayment(PublicPaymentValue {
                    output: PublicPaymentOutput { amount, .. },
                    ..
                }) => {
                    balance.public_payment.current += amount;
                    if self.pending_payments.get(&hash).is_some() {
                        continue;
                    }
                    balance.public_payment.available += amount;
                }
                OutputValue::Stake(StakeValue {
                    output: StakeOutput { amount, .. },
                    active_until_epoch,
                    ..
                }) => {
                    balance.stake.current += amount;
                    if self.pending_payments.get(&hash).is_some() {
                        continue;
                    }
                    if let Some(active_until_epoch) = active_until_epoch {
                        if active_until_epoch >= self.epoch + 1 {
                            continue;
                        }
                    }
                    balance.stake.available += amount;
                }
            }
        }
        balance.total.current =
            balance.payment.current + balance.stake.current + balance.public_payment.current;
        balance.total.available =
            balance.payment.available + balance.stake.available + balance.public_payment.available;
        assert!(balance.total.available <= balance.total.current);
        balance.is_final = !self.current_epoch_balance_changed || !self.pending_payments.is_empty();
        balance
    }

    /// Called when outputs registered and/or pruned.
    fn on_outputs_changed<'a, I, O>(
        &mut self,
        epoch: u64,
        inputs: I,
        outputs: O,
        is_final: bool,
        block_timestamp: Timestamp,
    ) where
        I: Iterator<Item = &'a Hash>,
        O: Iterator<Item = &'a Output>,
    {
        let saved_balance = self.balance();

        // This order is important - first create outputs, then remove inputs.
        // Otherwise it will fail in case of annihilated input/output in a macro block.
        for output in outputs {
            self.on_output_created(epoch, output, block_timestamp);
        }
        for input_hash in inputs {
            self.on_output_pruned(input_hash);
        }

        // finalize epoch balance, before checking balance info.
        if is_final {
            self.current_epoch_balance_changed = false;
        }
        let balance = self.balance();
        if saved_balance != balance {
            self.notify_balance_changed(balance);
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, epoch: u64, output: &Output, block_timestamp: Timestamp) {
        let hash = Hash::digest(&output);
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.account_pkey, &self.account_skey)
                {
                    assert!(amount >= 0);
                    info!(
                        "Received: utxo={}, amount={}, data={:?}",
                        hash, amount, data
                    );
                    self.current_epoch_balance_changed = true;
                    let value = PaymentValue {
                        output: o.clone(),
                        amount,
                        recipient: self.account_pkey,
                        data: data.clone(),
                        rvalue: None,
                        is_change: false,
                    };

                    if let Err(e) = self
                        .database
                        .push_incomming(block_timestamp, value.clone().into())
                    {
                        error!("Error when adding incomming tx = {}", e)
                    }

                    let info = value.to_info(None);
                    let missing = self
                        .database
                        .get_unspent(&hash)
                        .expect("Cannot read database");
                    assert!(missing.is_none());
                    self.database
                        .insert_unspent(value.into())
                        .expect("Cannot write to database.");
                    self.notify(AccountNotification::Received(info));
                }
            }
            Output::PublicPaymentOutput(o) => {
                let public_address_id = if o.recipient == self.account_pkey {
                    None
                } else if let Some(id) = self.public_addresses.get(&o.recipient) {
                    Some(*id)
                } else {
                    return;
                };
                let PublicPaymentOutput { ref amount, .. } = &o;
                assert!(*amount >= 0);
                info!("Received public payment: utxo={}, amount={}", hash, amount);
                self.current_epoch_balance_changed = true;
                let value = PublicPaymentValue {
                    output: o.clone(),
                    public_address_id,
                };

                if let Err(e) = self
                    .database
                    .push_incomming(block_timestamp, value.clone().into())
                {
                    error!("Error when adding incomming tx = {}", e)
                }

                let info = value.to_info(None);
                let missing = self
                    .database
                    .get_unspent(&hash)
                    .expect("Cannot read database");
                assert!(missing.is_none());
                self.database
                    .insert_unspent(value.into())
                    .expect("Cannot write to database.");
                self.notify(AccountNotification::ReceivedPublic(info));
            }
            Output::StakeOutput(o) => {
                if &o.recipient != &self.account_pkey {
                    return;
                }
                let active_until_epoch = epoch + self.stake_epochs;
                info!(
                    "Staked money to escrow: hash={}, amount={}, active_until_epoch={}",
                    hash, o.amount, active_until_epoch
                );
                self.current_epoch_balance_changed = true;
                let value = StakeValue {
                    output: o.clone(),
                    active_until_epoch: active_until_epoch.into(),
                };

                let info = value.to_info(self.epoch);
                let missing = self
                    .database
                    .get_unspent(&hash)
                    .expect("Cannot read database");
                assert!(missing.is_none(), "Inconsistent account state");
                self.database
                    .insert_unspent(value.into())
                    .expect("Cannot write to database.");
                self.notify(AccountNotification::Staked(info));
            }
        };
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, hash: &Hash) {
        let output = match self
            .database
            .get_unspent(&hash)
            .expect("Cannot read database")
        {
            Some(o) => o,
            None => return,
        };
        self.current_epoch_balance_changed = true;
        match output {
            OutputValue::Payment(p) => {
                let o = p.output;
                let PaymentPayload { amount, data, .. } = o
                    .decrypt_payload(&self.account_pkey, &self.account_skey)
                    .expect("is my utxo");
                info!("Spent: utxo={}, amount={}, data={:?}", hash, amount, data);
                match self
                    .database
                    .get_unspent(&hash)
                    .expect("Cannot read database")
                {
                    Some(OutputValue::Payment(value)) => {
                        self.database
                            .remove_unspent(&hash)
                            .expect("Cannot write database");
                        let info = value.to_info(self.pending_payments.get(&hash));
                        self.notify(AccountNotification::Spent(info));
                    }
                    _ => panic!("Inconsistent account state"),
                }
            }
            OutputValue::PublicPayment(p) => {
                let o = &p.output;
                assert!(
                    o.recipient == self.account_pkey
                        || self.public_addresses.contains_key(&o.recipient),
                    "is my utxo"
                );
                info!("Spent public payment: utxo={}, amount={}", hash, o.amount);
                match self
                    .database
                    .get_unspent(&hash)
                    .expect("Cannot read database")
                {
                    Some(OutputValue::PublicPayment(value)) => {
                        self.database
                            .remove_unspent(&hash)
                            .expect("Cannot write database");
                        let info = value.to_info(self.pending_payments.get(&hash));
                        self.notify(AccountNotification::SpentPublic(info));
                    }
                    _ => panic!("Inconsistent account state"),
                }
            }
            OutputValue::Stake(s) => {
                let o = s.output;
                assert_eq!(o.recipient, self.account_pkey, "is my utxo");
                info!("Unstaked: utxo={}, amount={}", hash, o.amount);
                match self
                    .database
                    .get_unspent(&hash)
                    .expect("Cannot read database")
                {
                    Some(OutputValue::Stake(value)) => {
                        self.database
                            .remove_unspent(&hash)
                            .expect("Cannot write database");
                        let info = value.to_info(self.epoch);
                        self.notify(AccountNotification::Unstaked(info));
                    }
                    _ => panic!("Inconsistent account state"),
                }
            }
        }
    }

    fn send_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        if self.transaction_response.is_some() {
            bail!(
                "Cannot create new transaction, tx={}, \
                 old transaction stil on the way to mempool.",
                Hash::digest(&tx)
            )
        } else {
            self.transaction_response = Some(self.node.send_transaction(tx.clone()));
            task::current().notify();
        }
        Ok(())
    }

    fn on_epoch_changed(
        &mut self,
        epoch: u64,
        facilitator_pkey: pbc::PublicKey,
        last_macro_block_timestamp: Timestamp,
    ) {
        debug!(
            "Epoch changed: epoch={}, facilitator={}, last_macro_block_timestamp={}",
            epoch, facilitator_pkey, last_macro_block_timestamp
        );
        self.epoch = epoch;
        self.facilitator_pkey = facilitator_pkey;
        if let Some((ref mut snowball, _)) = &mut self.snowball {
            snowball.change_facilitator(self.facilitator_pkey.clone());
        }
        self.last_macro_block_timestamp = last_macro_block_timestamp;
        let updated_statuses = self
            .database
            .finalize_epoch(epoch)
            .expect("Cannot write to db.");
        self.on_tx_statuses_changed(&updated_statuses);
    }

    fn handle_snowball_transaction(
        &mut self,
        tx: PaymentTransaction,
        is_leader: bool,
        outputs: Vec<OutputValue>,
    ) -> Result<TransactionInfo, Error> {
        metrics::WALLET_PUBLISHED_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        let payment_info = TransactionValue::new_snowball(tx.clone(), outputs);

        self.database
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        if is_leader {
            // if I'm leader, then send the completed super-transaction
            // to the blockchain.
            debug!("Sending SuperTransaction to BlockChain");
            self.send_transaction(tx.into())?
        }
        Ok(payment_info.to_info(self.epoch))
    }

    fn on_tx_status(&mut self, tx_hash: &Hash, status: &TransactionStatus) {
        if let Some(timestamp) = self.database.tx_entry(*tx_hash) {
            // update persistent info.
            self.database
                .update_tx_status(*tx_hash, timestamp, status.clone())
                .expect("Cannot update status.");

            // update metrics
            match status {
                TransactionStatus::Committed { .. } | TransactionStatus::Prepared { .. } => {
                    metrics::WALLET_COMMITTED_PAYMENTS
                        .with_label_values(&[&String::from(&self.account_pkey)])
                        .inc();
                }
                TransactionStatus::Rollback { .. } => {
                    metrics::WALLET_COMMITTED_PAYMENTS
                        .with_label_values(&[&String::from(&self.account_pkey)])
                        .dec();
                }
                _ => {}
            }

            let msg = AccountNotification::TransactionStatus {
                tx_hash: *tx_hash,
                status: status.clone(),
            };
            self.notify(msg);
        } else {
            trace!("Transaction was not found = {}", tx_hash);
        }
    }

    fn on_tx_statuses_changed(&mut self, changes: &HashMap<Hash, TransactionStatus>) {
        trace!("Updated mempool event");
        for (tx_hash, status) in changes {
            self.on_tx_status(tx_hash, status)
        }
    }

    fn handle_resend_pending_txs(&mut self) {
        trace!("Handle resend pending transactions");
        let txs: Vec<_> = self.database.pending_txs().collect();
        for tx in txs {
            match tx {
                Ok(tx) => {
                    debug!(
                        "Found pending transaction for resending: tx_hash = {}, status = {:?}",
                        Hash::digest(&tx.tx),
                        tx.status
                    );
                    // ignore error.
                    let _ = self.send_transaction(tx.tx.into());
                }
                Err(e) => error!("Error during processing database = {}", e),
            }
        }
    }

    fn handle_check_pending_utxos(&mut self, now: Instant) {
        trace!("Handle check pending utxo transactions");
        let pending = std::mem::replace(&mut self.pending_payments, HashMap::new());
        let mut balance_unlocked = false;
        for (hash, p) in pending {
            if p.time + PENDING_UTXO_TIME <= now {
                trace!("Found outdated pending utxo = {}", hash);
                balance_unlocked = true;
                if let Some((snowball, _)) = &self.snowball {
                    if !snowball.is_my_input(hash) {
                        continue;
                    }
                    // Terminate Snowball session.
                    error!("Snowball timed out");
                    let (_snowball, tx) = self.snowball.take().unwrap();
                    self.notify(AccountNotification::SnowballStatus(SnowballState::Failed));
                    let response = AccountResponse::Error {
                        error: "Snowball timed out".to_string(),
                    };
                    let _ = tx.send(response);

                    info!(
                        "Some outputs of snowball are now outdated: snowball_session = {}",
                        hash
                    );
                    warn!("Resetting Snowball on timeout.");
                    self.snowball = None;
                }
            } else {
                assert!(self.pending_payments.insert(hash, p).is_none());
            }
        }

        if !balance_unlocked {
            return;
        }

        // if balance was changed return new balance.
        let balance = self.balance();
        self.notify_balance_changed(balance);
    }

    fn notify_balance_changed(&mut self, balance: AccountBalance) {
        debug!("Balance changed");
        let account = String::from(&self.account_pkey);
        let label = &[account.as_str()];
        metrics::ACCOUNT_CURRENT_BALANCE
            .with_label_values(label)
            .set(balance.total.current);
        metrics::ACCOUNT_CURRENT_PAYMENT_BALANCE
            .with_label_values(label)
            .set(balance.payment.current);
        metrics::ACCOUNT_CURRENT_STAKE_BALANCE
            .with_label_values(label)
            .set(balance.stake.current);
        metrics::ACCOUNT_CURRENT_PUBLIC_PAYMENT_BALANCE
            .with_label_values(label)
            .set(balance.public_payment.current);
        metrics::ACCOUNT_AVAILABLE_BALANCE
            .with_label_values(label)
            .set(balance.total.available);
        metrics::ACCOUNT_AVAILABLE_PAYMENT_BALANCE
            .with_label_values(label)
            .set(balance.payment.available);
        metrics::ACCOUNT_AVAILABLE_STAKE_BALANCE
            .with_label_values(label)
            .set(balance.stake.available);
        metrics::ACCOUNT_AVAILABLE_PUBLIC_PAYMENT_BALANCE
            .with_label_values(label)
            .set(balance.public_payment.available);
        self.notify(AccountNotification::BalanceChanged(balance));
    }

    fn notify(&mut self, notification: AccountNotification) {
        trace!("Created notification = {:?}", notification);
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }
}

/// This could be used for non PaymentTx.
impl From<Result<TransactionInfo, Error>> for AccountResponse {
    fn from(r: Result<TransactionInfo, Error>) -> Self {
        match r {
            Ok(info) => AccountResponse::TransactionCreated(info),
            Err(e) => AccountResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

impl From<Vec<LogEntryInfo>> for AccountResponse {
    fn from(log: Vec<LogEntryInfo>) -> Self {
        AccountResponse::HistoryInfo { log }
    }
}

#[derive(Debug)]
enum UnsealedAccountResult {
    /// Internal shutdown, on some component failure.
    Terminated,
    /// Transient to sealed state.
    Sealed,
    /// External disable event
    Disabled(oneshot::Sender<AccountResponse>),
}

impl Eq for UnsealedAccountResult {}
impl PartialEq for UnsealedAccountResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (UnsealedAccountResult::Terminated, UnsealedAccountResult::Terminated) => true,
            (UnsealedAccountResult::Sealed, UnsealedAccountResult::Sealed) => true,
            (UnsealedAccountResult::Disabled(_), UnsealedAccountResult::Disabled(_)) => true,
            _ => false,
        }
    }
}

// Event loop.
impl Future for UnsealedAccountService {
    type Item = UnsealedAccountResult;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(mut transaction_response) = self.transaction_response.take() {
            match transaction_response.poll().expect("connected") {
                Async::Ready(response) => {
                    match response {
                        NodeResponse::AddTransaction { hash, status } => {
                            // Recover state.
                            self.on_tx_status(&hash, &status);
                        }
                        NodeResponse::Error { error } => {
                            error!("Failed to get transaction status: {:?}", error);
                        }
                        _ => unreachable!("Expected AddTransaction|Error response"),
                    };
                }
                Async::NotReady => self.transaction_response = Some(transaction_response),
            }
        }

        loop {
            match self.resend_tx.poll().expect("no errors in timers") {
                Async::Ready(Some(_t)) => self.handle_resend_pending_txs(),
                Async::NotReady => break,
                e => panic!("Error in handling resend tx timer = {:?}", e),
            }
        }

        loop {
            match self
                .check_pending_utxos
                .poll()
                .expect("no errors in timers")
            {
                Async::Ready(Some(t)) => self.handle_check_pending_utxos(t),
                Async::NotReady => break,
                e => panic!("Error in handling check pending utxos timer = {:?}", e),
            }
        }

        if let Some((mut snowball, response_sender)) = mem::replace(&mut self.snowball, None) {
            let state = snowball.state();
            match snowball.poll() {
                Ok(Async::Ready(Some(SnowballOutput {
                    tx,
                    is_leader,
                    outputs,
                }))) => {
                    self.notify(AccountNotification::SnowballStatus(
                        SnowballState::Succeeded,
                    ));
                    let response = match self.handle_snowball_transaction(tx, is_leader, outputs) {
                        Ok(tx) => AccountResponse::TransactionCreated(tx),
                        Err(e) => {
                            error!("Error during processing snowball transaction = {}", e);
                            AccountResponse::Error {
                                error: e.to_string(),
                            }
                        }
                    };
                    let _ = response_sender.send(response);
                }
                Ok(Async::Ready(None)) => {
                    return Ok(Async::Ready(UnsealedAccountResult::Terminated))
                } // Shutdown.
                Err((error, inputs)) => {
                    error!("Snowball failed: error={}", error);
                    self.notify(AccountNotification::SnowballStatus(SnowballState::Failed));
                    for (input_hash, _input) in inputs {
                        assert!(self.pending_payments.remove(&input_hash).is_some())
                    }
                    let response = AccountResponse::Error {
                        error: error.to_string(),
                    };
                    let _ = response_sender.send(response);
                }
                Ok(Async::NotReady) => {
                    if state != snowball.state() {
                        // Notify about state changes.
                        self.notify(AccountNotification::SnowballStatus(snowball.state()));
                    }
                    self.snowball = (snowball, response_sender).into();
                }
            }
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    AccountEvent::Request { request, tx } => {
                        let response = match request {
                            AccountRequest::Unseal { password: _ } => AccountResponse::Error {
                                error: "Already unsealed".to_string(),
                            },
                            AccountRequest::Disable {} => {
                                info!("Stopping account for future removing.");
                                return Ok(Async::Ready(UnsealedAccountResult::Disabled(tx)));
                            }
                            AccountRequest::Seal {} => {
                                tx.send(AccountResponse::Sealed).ok();
                                // Finish this future.
                                return Ok(Async::Ready(UnsealedAccountResult::Sealed));
                            }
                            AccountRequest::CreatePublicAddress => {
                                match self.new_public_address() {
                                    Ok((public_address, public_address_id)) => {
                                        AccountResponse::PublicAddressCreated {
                                            public_address,
                                            public_address_id,
                                        }
                                    }
                                    Err(e) => AccountResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            AccountRequest::Payment {
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
                            AccountRequest::PublicPayment {
                                recipient,
                                amount,
                                payment_fee,
                                locked_timestamp,
                            } => self
                                .public_payment(&recipient, amount, payment_fee, locked_timestamp)
                                .into(),
                            AccountRequest::StakeAll { payment_fee } => {
                                self.stake_all(payment_fee).into()
                            }
                            AccountRequest::Stake {
                                amount,
                                payment_fee,
                            } => self.stake(amount, payment_fee).into(),
                            AccountRequest::Unstake {
                                amount,
                                payment_fee,
                            } => self.unstake(amount, payment_fee).into(),
                            AccountRequest::UnstakeAll { payment_fee } => {
                                self.unstake_all(payment_fee).into()
                            }
                            AccountRequest::RestakeAll {} => self.restake_all().into(),
                            AccountRequest::CloakAll { payment_fee } => {
                                self.cloak_all(payment_fee).into()
                            }
                            AccountRequest::AccountInfo {} => {
                                let account_info = AccountInfo {
                                    account_pkey: self.account_pkey.clone(),
                                    network_pkey: self.network_pkey.clone(),
                                };
                                AccountResponse::AccountInfo(account_info)
                            }
                            AccountRequest::PublicAddressesInfo {} => {
                                let public_addresses = self
                                    .public_addresses
                                    .iter()
                                    .map(|(address, id)| {
                                        (
                                            id.to_string(),
                                            PublicAddressInfo {
                                                address: address.clone(),
                                            },
                                        )
                                    })
                                    .collect();
                                AccountResponse::PublicAddressesInfo { public_addresses }
                            }
                            AccountRequest::BalanceInfo {} => {
                                let balance = self.balance();
                                AccountResponse::BalanceInfo(balance)
                            }
                            AccountRequest::UnspentInfo {} => {
                                let mut public_payments = Vec::new();
                                let mut stakes = Vec::new();
                                let mut payments = Vec::new();
                                for utxo in self.database.iter_unspent() {
                                    match utxo.1 {
                                        OutputValue::Stake(s) => stakes.push(s.to_info(self.epoch)),
                                        OutputValue::Payment(p) => payments
                                            .push(p.to_info(self.pending_payments.get(&utxo.0))),
                                        OutputValue::PublicPayment(p) => public_payments
                                            .push(p.to_info(self.pending_payments.get(&utxo.0))),
                                    }
                                }
                                AccountResponse::UnspentInfo {
                                    public_payments,
                                    payments,
                                    stakes,
                                }
                            }
                            AccountRequest::HistoryInfo {
                                starting_from,
                                limit,
                            } => self.get_tx_history(starting_from, limit).into(),
                            AccountRequest::ChangePassword { new_password } => {
                                match self.change_password(new_password) {
                                    Ok(()) => AccountResponse::PasswordChanged,
                                    Err(e) => AccountResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            AccountRequest::GetRecovery {} => match self.get_recovery() {
                                Ok(recovery) => AccountResponse::Recovery(recovery),
                                Err(e) => AccountResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                            AccountRequest::SecurePayment {
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
                                Ok(snowball) => {
                                    let state = snowball.state();
                                    self.notify(AccountNotification::SnowballStatus(state));
                                    self.snowball = (snowball, tx).into();
                                    continue;
                                }
                                Err(e) => AccountResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    AccountEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(UnsealedAccountResult::Terminated)), // Shutdown.
                Async::NotReady => break,
            }
        }

        // Process chain notifications.
        loop {
            let rx = match self.chain_notifications.poll_subscribed() {
                Ok(Async::Ready(rx)) => rx,
                Ok(Async::NotReady) => break,
                Err(e) => panic!("Failed to subscribe for chain changes: {:?}", e),
            };
            match rx.poll().expect("all errors are already handled") {
                Async::Ready(Some(notification)) => match notification {
                    ChainNotification::MicroBlockPrepared(block) => {
                        trace!(
                            "Prepared a micro block: epoch={}, offset={}, block={}",
                            block.block.header.epoch,
                            block.block.header.offset,
                            Hash::digest(&block.block)
                        );
                        self.on_tx_statuses_changed(&block.transaction_statuses);
                        self.on_outputs_changed(
                            block.block.header.epoch,
                            block.inputs(),
                            block.outputs(),
                            false,
                            block.block.header.timestamp,
                        );
                    }
                    ChainNotification::MacroBlockCommitted(block) => {
                        trace!(
                            "Committed a macro block: epoch={}, block={}",
                            block.block.header.epoch,
                            Hash::digest(&block.block)
                        );
                        self.on_tx_statuses_changed(&block.transaction_statuses);
                        self.on_outputs_changed(
                            block.block.header.epoch,
                            block.inputs(),
                            block.outputs(),
                            true,
                            block.block.header.timestamp,
                        );
                        self.on_epoch_changed(
                            block.block.header.epoch,
                            block.epoch_info.facilitator,
                            block.block.header.timestamp,
                        );
                    }
                    ChainNotification::MicroBlockReverted(block) => {
                        trace!(
                            "Reverted a micro block: epoch={}, offset={}, block={}, inputs={:?}, outputs={:?}",
                            block.block.header.epoch,
                            block.block.header.offset,
                            Hash::digest(&block.block),
                            block
                                .pruned_outputs()
                                .cloned()
                                .map(|k| k.to_string())
                                .collect::<Vec<_>>(),
                            block
                                .recovered_inputs()
                                .map(Hash::digest)
                                .map(|k| k.to_string())
                                .collect::<Vec<_>>(),
                        );

                        self.on_tx_statuses_changed(&block.transaction_statuses);
                        self.on_outputs_changed(
                            block.block.header.epoch,
                            block.pruned_outputs(),
                            block.recovered_inputs(),
                            false,
                            block.block.header.timestamp,
                        );
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(UnsealedAccountResult::Terminated)), // Shutdown.
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}

struct SealedAccountService {
    /// Path to database dir.
    database_dir: PathBuf,
    /// Path to account secret key.
    account_skey_file: PathBuf,
    /// Path to account public key.
    account_pkey_file: PathBuf,
    /// Account Public Key.
    account_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,
    /// Maximum allowed count of input UTXOs
    max_inputs_in_tx: usize,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
    node: Node,

    //
    // Api subscribers
    //
    subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
    /// Incoming events.
    events: mpsc::UnboundedReceiver<AccountEvent>,
}

impl SealedAccountService {
    fn new(
        database_dir: PathBuf,
        account_skey_file: PathBuf,
        account_pkey_file: PathBuf,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
    ) -> Self {
        SealedAccountService {
            database_dir,
            account_skey_file,
            account_pkey_file,
            account_pkey,
            network_skey,
            network_pkey,
            stake_epochs,
            max_inputs_in_tx,
            node,
            network,
            subscribers,
            events,
        }
    }

    fn load_secret_key(&self, password: &str) -> Result<scc::SecretKey, KeyError> {
        let account_skey = keychain::keyfile::load_account_skey(&self.account_skey_file, password)?;

        if let Err(_e) = scc::check_keying(&account_skey, &self.account_pkey) {
            return Err(KeyError::InvalidKeying(
                self.account_skey_file.to_string_lossy().to_string(),
                self.account_pkey_file.to_string_lossy().to_string(),
            ));
        }
        Ok(account_skey)
    }
}

// Event loop.
impl Future for SealedAccountService {
    type Item = Option<scc::SecretKey>;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    AccountEvent::Request { request, tx } => {
                        let response = match request {
                            AccountRequest::Unseal { password } => {
                                match self.load_secret_key(&password) {
                                    Ok(account_skey) => {
                                        tx.send(AccountResponse::Unsealed).ok(); // ignore errors.
                                                                                 // Finish this future.
                                        return Ok(Async::Ready(Some(account_skey)));
                                    }
                                    Err(e) => AccountResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            AccountRequest::AccountInfo {} => {
                                let account_info = AccountInfo {
                                    account_pkey: self.account_pkey,
                                    network_pkey: self.network_pkey,
                                };
                                AccountResponse::AccountInfo(account_info)
                            }
                            AccountRequest::Disable {} => {
                                info!("Stopping account for future removing.");
                                return Ok(Async::Ready(None));
                            }
                            _ => AccountResponse::Error {
                                error: "Account is sealed".to_string(),
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    AccountEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(None)), // Shutdown.
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

enum AccountService {
    Invalid,
    Sealed(SealedAccountService),
    Unsealed(UnsealedAccountService),
}

// Event loop.
impl Future for AccountService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            AccountService::Invalid => unreachable!("Invalid state"),
            AccountService::Sealed(sealed) => match sealed.poll().unwrap() {
                Async::Ready(None) => {
                    debug!("Terminated");
                    return Ok(Async::Ready(()));
                }
                Async::Ready(Some(account_skey)) => {
                    let sealed = match std::mem::replace(self, AccountService::Invalid) {
                        AccountService::Sealed(old) => old,
                        _ => unreachable!("Expected Sealed state"),
                    };
                    info!("Unsealed account: address={}", &sealed.account_pkey);
                    let unsealed = UnsealedAccountService::new(
                        sealed.database_dir,
                        sealed.account_skey_file,
                        sealed.account_pkey_file,
                        account_skey,
                        sealed.account_pkey,
                        sealed.network_skey,
                        sealed.network_pkey,
                        sealed.network,
                        sealed.node,
                        sealed.stake_epochs,
                        sealed.max_inputs_in_tx,
                        sealed.subscribers,
                        sealed.events,
                    );
                    std::mem::replace(self, AccountService::Unsealed(unsealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
            AccountService::Unsealed(unsealed) => match unsealed.poll().unwrap() {
                Async::Ready(UnsealedAccountResult::Terminated) => {
                    debug!("Terminated");
                    return Ok(Async::Ready(()));
                }
                Async::Ready(UnsealedAccountResult::Disabled(tx)) => {
                    let unsealed = match std::mem::replace(self, AccountService::Invalid) {
                        AccountService::Unsealed(old) => old,
                        _ => unreachable!("Expected Unsealed state"),
                    };
                    drop(unsealed);
                    debug!("Account disabled, feel free to remove");
                    tx.send(AccountResponse::Disabled).ok();
                    return Ok(Async::Ready(()));
                }
                Async::Ready(UnsealedAccountResult::Sealed) => {
                    let unsealed = match std::mem::replace(self, AccountService::Invalid) {
                        AccountService::Unsealed(old) => old,
                        _ => unreachable!("Expected Unsealed state"),
                    };
                    info!("Sealed account: address={}", &unsealed.account_pkey);
                    let sealed = SealedAccountService::new(
                        unsealed.database_dir,
                        unsealed.account_skey_file,
                        unsealed.account_pkey_file,
                        unsealed.account_pkey,
                        unsealed.network_skey,
                        unsealed.network_pkey,
                        unsealed.network,
                        unsealed.node,
                        unsealed.stake_epochs,
                        unsealed.max_inputs_in_tx,
                        unsealed.subscribers,
                        unsealed.events,
                    );
                    std::mem::replace(self, AccountService::Sealed(sealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
        }
        Ok(Async::NotReady)
    }
}

impl AccountService {
    /// Create a new wallet.
    fn new(
        database_dir: &Path,
        account_skey_file: &Path,
        account_pkey_file: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
    ) -> Result<(Self, Account), KeyError> {
        let account_pkey = load_account_pkey(account_pkey_file)?;
        let subscribers: Vec<mpsc::UnboundedSender<AccountNotification>> = Vec::new();
        let (outbox, events) = mpsc::unbounded::<AccountEvent>();
        let service = SealedAccountService::new(
            database_dir.to_path_buf(),
            account_skey_file.to_path_buf(),
            account_pkey_file.to_path_buf(),
            account_pkey,
            network_skey,
            network_pkey,
            network,
            node,
            stake_epochs,
            max_inputs_in_tx,
            subscribers,
            events,
        );
        let service = AccountService::Sealed(service);
        let api = Account { outbox };
        Ok((service, api))
    }
}

#[derive(Debug, Clone)]
struct Account {
    outbox: mpsc::UnboundedSender<AccountEvent>,
}

impl Account {
    /// Subscribe for changes.
    fn subscribe(&self) -> mpsc::UnboundedReceiver<AccountNotification> {
        let (tx, rx) = mpsc::unbounded();
        let msg = AccountEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a request.
    fn request(&self, request: AccountRequest) -> oneshot::Receiver<AccountResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = AccountEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

#[derive(Debug)]
enum WalletEvent {
    Subscribe {
        tx: mpsc::UnboundedSender<WalletNotification>,
    },
    Request {
        request: WalletRequest,
        tx: oneshot::Sender<WalletResponse>,
    },
}

struct AccountHandle {
    /// Account public key.
    account_pkey: scc::PublicKey,
    /// Account API.
    account: Account,
    /// Account Notifications.
    account_notifications: mpsc::UnboundedReceiver<AccountNotification>,
}

pub struct WalletService {
    accounts_dir: PathBuf,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    network: Network,
    node: Node,
    executor: TaskExecutor,
    stake_epochs: u64,
    max_inputs_in_tx: usize,
    accounts: HashMap<AccountId, AccountHandle>,
    subscribers: Vec<mpsc::UnboundedSender<WalletNotification>>,
    events: mpsc::UnboundedReceiver<WalletEvent>,
    chain_notifications: ChainSubscription,
    last_epoch: u64,
}

impl WalletService {
    pub fn new(
        accounts_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        executor: TaskExecutor,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        last_epoch: u64,
    ) -> Result<(Self, Wallet), Error> {
        let (outbox, events) = mpsc::unbounded::<WalletEvent>();
        let subscribers: Vec<mpsc::UnboundedSender<WalletNotification>> = Vec::new();
        let chain_notifications = ChainSubscription::new(&node, last_epoch, 0);
        let mut service = WalletService {
            accounts_dir: accounts_dir.to_path_buf(),
            network_skey,
            network_pkey,
            network,
            node,
            executor,
            stake_epochs,
            max_inputs_in_tx,
            accounts: HashMap::new(),
            subscribers,
            events,
            chain_notifications,
            last_epoch,
        };

        info!("Scanning directory {:?} for accounts", accounts_dir);

        // Scan directory for accounts.
        for entry in fs::read_dir(accounts_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string();
            // Skip non-UTF-8 filenames
            if name.is_err() {
                continue;
            }
            if name.unwrap().starts_with(".") || !entry.file_type()?.is_dir() {
                continue;
            }

            // Find a secret key.
            let account_skey_file = entry.path().join("account.skey");
            let account_pkey_file = entry.path().join("account.pkey");
            if !account_skey_file.exists() || !account_pkey_file.exists() {
                continue;
            }

            // Extract account name.
            let account_id: String = match entry.file_name().into_string() {
                Ok(id) => id,
                Err(os_string) => {
                    warn!("Invalid folder name: folder={:?}", os_string);
                    continue;
                }
            };

            service.open_account(&account_id, false, None)?;
        }

        info!("Recovered {} account(s)", service.accounts.len());
        let api = Wallet { outbox };
        Ok((service, api))
    }

    ///
    /// Open existing account.
    ///
    fn open_account(
        &mut self,
        account_id: &str,
        is_new: bool,
        last_public_address_id: Option<u32>,
    ) -> Result<(), Error> {
        let account_dir = self.accounts_dir.join(account_id);
        let account_database_dir = account_dir.join("history");
        let account_skey_file = account_dir.join("account.skey");
        let account_pkey_file = account_dir.join("account.pkey");
        let account_pkey = load_account_pkey(&account_pkey_file)?;
        debug!("Found account id={}, pkey={}", account_id, account_pkey);

        // Check for duplicates.
        for handle in self.accounts.values() {
            if handle.account_pkey == account_pkey {
                return Err(WalletError::DuplicateAccount(account_pkey).into());
            }
        }

        if is_new {
            // Initialize database.
            let (mut database, epoch) = AccountDatabase::open(&account_database_dir);

            // Save the last finalized epoch to skip recovery for the new fresh account.
            assert_eq!(epoch, 0, "account is not recovered");
            database.finalize_epoch(self.last_epoch)?;
            if let Some(last_public_address_id) = last_public_address_id {
                database.update_last_public_address_id(last_public_address_id)?;
            }
            drop(database);
        }

        let (account_service, account) = AccountService::new(
            &account_database_dir,
            &account_skey_file,
            &account_pkey_file,
            self.network_skey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.stake_epochs,
            self.max_inputs_in_tx,
        )?;
        let account_notifications = account.subscribe();
        let handle = AccountHandle {
            account_pkey,
            account,
            account_notifications,
        };
        let prev = self.accounts.insert(account_id.to_string(), handle);
        assert!(prev.is_none(), "account_id is unique");
        self.executor.spawn(account_service);
        info!("Recovered account {}, is_new:{}", account_pkey, is_new);
        Ok(())
    }

    /// Find the next available account id.
    fn find_account_id(&self) -> AccountId {
        for i in 1..std::u64::MAX {
            let account_id = i.to_string();
            let account_dir = self.accounts_dir.join(&account_id);
            if !self.accounts.contains_key(&account_id) && !account_dir.exists() {
                return account_id;
            }
        }
        unreachable!("Failed to find the next account id");
    }

    ///
    /// Create a new account for provided keys.
    ///
    fn create_account(
        &mut self,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        password: &str,
    ) -> Result<AccountId, Error> {
        let account_id = self.find_account_id();
        let account_dir = self.accounts_dir.join(format!("{}", account_id));
        fs::create_dir_all(&account_dir)?;
        let account_skey_file = account_dir.join("account.skey");
        let account_pkey_file = account_dir.join("account.pkey");
        write_account_pkey(&account_pkey_file, &account_pkey)?;
        write_account_skey(&account_skey_file, &account_skey, password)?;
        Ok(account_id)
    }

    fn handle_control_request(
        &mut self,
        request: WalletControlRequest,
    ) -> Result<WalletControlResponse, Error> {
        match request {
            WalletControlRequest::ListAccounts {} => {
                let accounts = self
                    .accounts
                    .iter()
                    .map(|(account_id, AccountHandle { account_pkey, .. })| {
                        (
                            account_id.clone(),
                            AccountInfo {
                                account_pkey: account_pkey.clone(),
                                network_pkey: self.network_pkey.clone(),
                            },
                        )
                    })
                    .collect();
                Ok(WalletControlResponse::AccountsInfo { accounts })
            }
            WalletControlRequest::CreateAccount { password } => {
                let (account_skey, account_pkey) = scc::make_random_keys();
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                info!("Created a new account {}", account_pkey);
                self.open_account(&account_id, true, Some(0))?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::RecoverAccount {
                recovery:
                    AccountRecovery {
                        recovery,
                        last_public_address_id,
                    },
                password,
            } => {
                let account_skey = recovery_to_account_skey(&recovery)?;
                let account_pkey: scc::PublicKey = account_skey.clone().into();
                // Check for duplicates.
                for handle in self.accounts.values() {
                    if handle.account_pkey == account_pkey {
                        return Err(WalletError::DuplicateAccount(account_pkey).into());
                    }
                }
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                info!("Restored account from 24-word phrase {}", account_pkey);
                self.open_account(&account_id, false, Some(last_public_address_id))?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::DeleteAccount { .. } => {
                unreachable!("Delete account should be already processed in different routine")
            }
        }
    }

    fn handle_account_request(
        &mut self,
        account_id: String,
        request: AccountRequest,
        tx: oneshot::Sender<WalletResponse>,
    ) {
        match self.accounts.get(&account_id) {
            Some(handle) => {
                let fut = handle
                    .account
                    .request(request)
                    .into_future()
                    .map_err(|_| ())
                    .map(move |response| {
                        let r = WalletResponse::AccountResponse {
                            account_id,
                            response,
                        };
                        tx.send(r).ok(); // ignore error;
                    });
                self.executor.spawn(fut);
            }
            None => {
                let r = WalletControlResponse::Error {
                    error: format!("Unknown account: {}", account_id),
                };
                let r = WalletResponse::WalletControlResponse(r);
                tx.send(r).ok(); // ignore error;
            }
        }
    }

    fn handle_account_delete(
        &mut self,
        account_id: AccountId,
        tx: oneshot::Sender<WalletResponse>,
    ) {
        let accounts_dir = self.accounts_dir.clone();
        match self.accounts.remove(&account_id) {
            Some(handle) => {
                warn!("Removing account {}", account_id);
                // Try to seal account, and then perform removing.
                let fut = handle
                    .account
                    .request(AccountRequest::Disable)
                    .into_future()
                    .then(move |response| {
                        futures::future::result(match response {
                            // oneshot can be closed before we process event.
                            Ok(AccountResponse::Disabled) => {
                                Self::delete_account(account_id, accounts_dir)
                            }

                            Err(e) => Err(format_err!("Error processing disable: {}", e)),
                            Ok(response) => Err(format_err!(
                                "Wrong reponse to disable account: {:?}",
                                response
                            )),
                        })
                    })
                    .then(|e| {
                        let r = match e {
                            Ok(account_id) => WalletControlResponse::AccountDeleted { account_id },
                            Err(e) => WalletControlResponse::Error {
                                error: e.to_string(),
                            },
                        };
                        let response = WalletResponse::WalletControlResponse(r);
                        futures::future::ok::<(), ()>(drop(tx.send(response)))
                    });
                self.executor.spawn(fut);
            }
            None => {
                let r = WalletControlResponse::Error {
                    error: format!("Unknown account: {}", account_id),
                };
                let response = WalletResponse::WalletControlResponse(r);
                tx.send(response).ok();
            }
        }
    }

    fn delete_account(account_id: AccountId, accounts_dir: PathBuf) -> Result<AccountId, Error> {
        let account_dir = accounts_dir.join(&account_id);
        if account_dir.exists() {
            let suffix = Timestamp::now()
                .duration_since(Timestamp::UNIX_EPOCH)
                .as_secs();
            let trash_dir = accounts_dir.join(".trash");
            if !trash_dir.exists() {
                fs::create_dir_all(&trash_dir)?;
            }
            let account_dir_bkp = trash_dir.join(format!("{}-{}", &account_id, suffix));
            warn!("Renaming {:?} to {:?}", account_dir, account_dir_bkp);
            fs::rename(account_dir, account_dir_bkp)?;
            return Ok(account_id);
        }
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Account dir was not found").into(),
        );
    }
}

impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Process events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                    WalletEvent::Request { request, tx } => {
                        match request {
                            // process DeleteAccount seperately, because we need to end account future before.
                            WalletRequest::WalletControlRequest(
                                WalletControlRequest::DeleteAccount { account_id },
                            ) => self.handle_account_delete(account_id, tx),
                            WalletRequest::WalletControlRequest(request) => {
                                let response = match self.handle_control_request(request) {
                                    Ok(r) => r,
                                    Err(e) => WalletControlResponse::Error {
                                        error: format!("{}", e),
                                    },
                                };
                                let response = WalletResponse::WalletControlResponse(response);
                                tx.send(response).ok(); // ignore errors.
                            }
                            WalletRequest::AccountRequest {
                                account_id,
                                request,
                            } => self.handle_account_request(account_id, request, tx),
                        }
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
                Async::NotReady => break,
            }
        }

        // Forward notifications.
        for (account_id, handle) in self.accounts.iter_mut() {
            loop {
                match handle.account_notifications.poll().unwrap() {
                    Async::Ready(Some(notification)) => {
                        let notification = WalletNotification {
                            account_id: account_id.clone(),
                            notification,
                        };
                        self.subscribers
                            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
                    Async::NotReady => break,
                }
            }
        }

        loop {
            let rx = match self.chain_notifications.poll_subscribed() {
                Ok(Async::Ready(rx)) => rx,
                Ok(Async::NotReady) => break,
                Err(e) => panic!("Failed to subscribe for chain changes: {:?}", e),
            };
            match rx.poll().unwrap() {
                Async::Ready(Some(ChainNotification::MacroBlockCommitted(info))) => {
                    let epoch = info.block.header.epoch;
                    trace!(
                        "Update last known epoch in wallet control service: epoch={}",
                        epoch
                    );
                    self.last_epoch = epoch;
                }
                Async::Ready(Some(_)) => {} // ignore.
                Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
                Async::NotReady => break,
            };
        }

        Ok(Async::NotReady)
    }
}

#[derive(Debug, Clone)]
pub struct Wallet {
    outbox: mpsc::UnboundedSender<WalletEvent>,
}

impl Wallet {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<WalletNotification> {
        let (tx, rx) = mpsc::unbounded();
        let msg = WalletEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Wallet Request.
    pub fn request(&self, request: WalletRequest) -> oneshot::Receiver<WalletResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = WalletEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

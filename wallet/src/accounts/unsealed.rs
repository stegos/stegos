//! Unsealed Account.

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

use crate::metrics;

use crate::api::*;
use crate::error::WalletError;
use crate::storage::*;
use crate::transaction::*;

use crate::AccountEvent;

use crate::CanaryProcessed;
use crate::ReplicationOutEvent;
use bit_vec::BitVec;
use failure::{format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::select;
use log::*;
use std::collections::HashMap;
use std::path::PathBuf;
use stegos_blockchain::TransactionStatus;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::keyfile::load_network_keypair;
use stegos_network::Network;
use stegos_serialization::traits::ProtoConvert;
use tokio::time::Interval;

use crate::STAKE_FEE;
use crate::{CHECK_LOCKED_INPUTS, PENDING_UTXO_TIME, RESEND_TX_INTERVAL, TX_TOPIC};

#[derive(Debug)]
pub enum UnsealedAccountResult {
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

pub struct UnsealedAccountService {
    //
    // Config
    //
    /// Path to RocksDB directory.
    pub(super) database_dir: PathBuf,
    /// Path to account key folder.
    pub(super) account_dir: PathBuf,
    /// Account Secret Key.
    pub(super) account_skey: scc::SecretKey,
    /// Account Public Key.
    pub(super) account_pkey: scc::PublicKey,
    /// Network Secret Key.
    pub(super) network_skey: pbc::SecretKey,
    /// Network Public Key.
    pub(super) network_pkey: pbc::PublicKey,
    /// Maximum allowed count of input UTXOs (from Node config)
    pub(super) max_inputs_in_tx: usize,

    //
    // Current state
    //
    /// Persistent part of the state.
    pub(super) database: LightDatabase,

    /// Network API (shared).
    pub(super) network: Network,
    /// Resend timeout.
    resend_tx: Interval,

    /// Check for pending utxos.
    expire_locked_inputs: Interval,
    //
    // Snowball state (owned)
    //
    // snowball: Option<(Snowball, oneshot::Sender<AccountResponse>)>,

    //
    // Api subscribers
    //
    /// Triggered when state has changed.
    pub(super) subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,

    //
    // Events source
    //
    /// API Requests.
    pub(super) events: mpsc::UnboundedReceiver<AccountEvent>,
    /// Chain notifications
    pub(super) chain_notifications: mpsc::Receiver<ReplicationOutEvent>,
    /// Incoming transactions from the network.
    /// Sic: this subscription is only needed for outgoing messages.
    /// Floodsub doesn't accept outgoing messages if you are not subscribed
    /// to the topic.
    transaction_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl UnsealedAccountService {
    /// Create a new account.
    pub fn new(
        database_dir: PathBuf,
        account_dir: PathBuf,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        genesis_hash: Hash,
        chain_cfg: ChainConfig,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
        chain_notifications: mpsc::Receiver<ReplicationOutEvent>,
    ) -> Self {
        info!("My account key: {}", String::from(&account_pkey));
        debug!("My network key: {}", network_pkey.to_hex());

        // let snowball = None;

        debug!("Loading account {}", account_pkey);
        // TODO: add proper handling for I/O errors.
        let database = LightDatabase::open(&database_dir, genesis_hash, chain_cfg);
        let epoch = database.epoch();
        debug!("Opened database: epoch={}", epoch);
        let resend_tx = tokio::time::interval(RESEND_TX_INTERVAL);
        let expire_locked_inputs = tokio::time::interval(CHECK_LOCKED_INPUTS);
        let transaction_rx = network.subscribe(&TX_TOPIC).unwrap();

        info!("Loaded account {}", account_pkey);
        let mut service = UnsealedAccountService {
            database_dir,
            account_dir,
            account_skey,
            account_pkey,
            network_skey,
            network_pkey,
            database,
            resend_tx,
            expire_locked_inputs,
            // snowball,
            max_inputs_in_tx,
            network,
            subscribers,
            events,
            chain_notifications,
            transaction_rx,
        };
        service.notify(AccountNotification::Unsealed);
        service.notify_status();
        service
    }

    pub fn last_epoch(&self) -> u64 {
        self.database.epoch()
    }

    /// Send money.
    fn payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        with_certificate: bool,
    ) -> Result<TransactionValue, Error> {
        let payment_balance = self.database.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughToPay(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self.database.available_payment_outputs();
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
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;

        let tx_value = TransactionValue::new_payment(tx.clone(), extended_outputs);
        let _tx_info = self.send_and_log_transaction(tx_value.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();
        Ok(tx_value)
    }

    /// Send money public.
    fn public_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
    ) -> Result<TransactionValue, Error> {
        let payment_balance = self.database.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughToPay(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let unspent_iter = self.database.available_payment_outputs();
        let (inputs, outputs, gamma, extended_outputs, fee) = create_payment_transaction(
            Some(&self.account_skey),
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Public,
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;
        let tx_value = TransactionValue::new_payment(tx.clone(), extended_outputs);
        let _tx_info = self.send_and_log_transaction(tx_value.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();
        Ok(tx_value)
    }

    fn get_tx_history(&self, starting_from: Timestamp, limit: u64) -> Vec<LogEntryInfo> {
        self.database
            .iter_range(starting_from, limit)
            .map(|(timestamp, e)| match e {
                LogEntry::Incoming {
                    output: ref output_value,
                } => {
                    let mut output_info = output_value.to_info(self.database.epoch());
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
                    tx: tx.to_info(self.database.epoch()),
                },
            })
            .collect()
    }

    fn stake_all(&mut self, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let mut payment_amount: i64 = 0;
        let mut outputs: Vec<_> = self.database.available_payment_outputs().collect();
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
            return Err(WalletError::AmountTooSmall(payment_fee, payment_amount).into());
        }

        info!("Found payment outputs: amount={}", payment_amount);

        self.stake(payment_amount, payment_fee)
    }

    fn stake_inner(
        &mut self,
        amount: i64,
        payment_fee: i64,
        network_pkey: pbc::PublicKey,
        network_skey: pbc::SecretKey,
    ) -> Result<TransactionInfo, Error> {
        let payment_balance = self.database.balance().payment;
        if amount > payment_balance.available {
            return Err(WalletError::NoEnoughToPay(
                payment_balance.current,
                payment_balance.available,
            )
            .into());
        }

        let unspent_iter = self.database.available_payment_outputs();
        let (tx, outputs) = create_staking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &network_pkey,
            &network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.max_inputs_in_tx,
        )?;

        let tx_value = TransactionValue::new_stake(tx.clone(), outputs);
        let tx_info = self.send_and_log_transaction(tx_value)?;
        Ok(tx_info)
    }

    /// Stake money into the escrow, for remote node.
    fn stake_remote(&mut self, amount: i64, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let network_pkey_file = self.account_dir.join("network.pkey");
        let network_skey_file = self.account_dir.join("network.skey");
        let (network_skey, network_pkey) =
            load_network_keypair(&network_skey_file, &network_pkey_file)?;
        self.stake_inner(amount, payment_fee, network_pkey, network_skey)
    }

    /// Stake money into the escrow.
    fn stake(&mut self, amount: i64, payment_fee: i64) -> Result<TransactionInfo, Error> {
        self.stake_inner(
            amount,
            payment_fee,
            self.network_pkey,
            self.network_skey.clone(),
        )
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&mut self, amount: i64, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let stake_balance = self.database.balance().stake;
        if amount > stake_balance.available {
            return Err(WalletError::NoEnoughToStake(
                stake_balance.current,
                stake_balance.available,
            )
            .into());
        }

        let unspent_iter = self.database.available_stake_outputs();
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
        let tx_value = TransactionValue::new_stake(tx.clone(), outputs);
        let tx_info = self.send_and_log_transaction(tx_value)?;
        Ok(tx_info)
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&mut self, payment_fee: i64) -> Result<TransactionInfo, Error> {
        let mut amount: i64 = 0;
        let mut outputs: Vec<_> = self.database.available_stake_outputs().collect();
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
            return Err(WalletError::AmountTooSmall(payment_fee, amount).into());
        }
        self.unstake(amount, payment_fee)
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

        let mut outputs: Vec<_> = self.database.available_public_payment_outputs().collect();
        outputs.sort_by_key(|o| o.amount);
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
        for input in outputs.into_iter().rev().take(self.max_inputs_in_tx) {
            let input_hash = Hash::digest(&input);
            debug!(
                "Using PublicUTXO: utxo={}, amount={}",
                input_hash, input.amount
            );
            amount += input.amount;
            txins.push(input_hash);
            txins_expanded.push(input.into());
            sign_skey += scc::Fr::from(self.account_skey);
        }
        if amount < fee {
            // Don't have enough PublicPaymentUTXO to pay `fee`.
            return Err(WalletError::NoEnoughToPayPublicly(amount).into());
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
                PaymentOutput::with_payload(None, &recipient, amount, data.clone())?;
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

        let tx_value = TransactionValue::new_cloak(tx.clone(), extended_output.into());
        let tx_info = self.send_and_log_transaction(tx_value)?;
        Ok(tx_info)
    }

    /// Change the password.
    fn change_password(&mut self, new_password: String) -> Result<(), Error> {
        let account_skey_file = self.account_dir.join("account.skey");
        keychain::keyfile::write_account_skey(
            &account_skey_file,
            &self.account_skey,
            &new_password,
        )?;
        Ok(())
    }

    /// Return recovery codes.
    fn get_recovery(&mut self) -> Result<AccountRecovery, Error> {
        let recovery = crate::recovery::account_skey_to_recovery(&self.account_skey);
        Ok(AccountRecovery { recovery })
    }

    fn apply_light_micro_block(
        &mut self,
        header: MicroBlockHeader,
        sig: pbc::Signature,
        input_hashes: Vec<Hash>,
        output_hashes: Vec<Hash>,
        canaries: Vec<Canary>,
        outputs: Vec<Output>, // TODO: split validate and apply, to validate before applying.
    ) -> Result<(), Error> {
        if header.epoch < self.database.epoch() || header.offset < self.database.offset() {
            let block_hash = Hash::digest(&header);
            debug!(
                "Skip an outdated micro block: block={}, epoch={}, offset={}, our_epoch={}, our_offset={}",
                block_hash,
                header.epoch,
                header.offset,
                self.database.epoch(),
                self.database.offset()
            );
            return Ok(());
        } else if header.epoch > self.database.epoch() || header.offset > self.database.offset() {
            let block_hash = Hash::digest(&header);
            let err = format!("A micro block from the future: block={}, block_epoch={}, block_offset={}, our_epoch={}, our_offset={}",
                block_hash,
                header.epoch,
                header.offset,
                self.database.epoch(),
                self.database.offset()
            );
            error!("{}", err);
            return Err(format_err!("{}", err));
        }

        //
        // Validate block.
        //
        assert_eq!(header.epoch, self.database.epoch());
        assert_eq!(header.offset, self.database.offset());
        self.database.validate_light_micro_block(
            &header,
            &sig,
            &input_hashes,
            &output_hashes,
            &canaries,
        )?;

        //
        // Register block.
        //
        let transaction_statuses = self.database.apply_light_micro_block(
            header,
            input_hashes.iter(),
            outputs.iter(),
            &self.account_pkey,
            &self.account_skey,
        );

        self.on_tx_statuses_changed(&transaction_statuses);
        if transaction_statuses.len() > 0 || outputs.len() > 0 {
            self.notify_balance_changed(self.database.balance());
        }

        self.notify_status();
        Ok(())
    }

    fn apply_light_macro_block(
        &mut self,
        header: MacroBlockHeader,
        multisig: pbc::Signature,
        multisigmap: BitVec,
        input_hashes: Vec<Hash>,
        outputs_hashes: Vec<Hash>,
        canaries: Vec<Canary>,
        outputs: Vec<Output>, // TODO: split validate and apply methods.
        validators: StakersGroup,
    ) -> Result<(), Error> {
        if header.epoch < self.database.epoch() {
            let block_hash = Hash::digest(&header);
            debug!(
                "Skip an outdated macro block: block={}, block_epoch={}, our_epoch={}",
                block_hash,
                header.epoch,
                self.database.epoch()
            );
            return Ok(());
        } else if header.epoch > self.database.epoch() {
            let block_hash = Hash::digest(&header);
            let err = format!(
                "A macro block from the future: block={}, block_epoch={}, our_epoch={}",
                block_hash,
                header.epoch,
                self.database.epoch()
            );
            error!("{}", err);
            return Err(format_err!("{}", err));
        }

        //
        // Validate block.
        //
        assert_eq!(header.epoch, self.database.epoch());
        self.database.validate_macro_block(
            &header,
            &multisig,
            &multisigmap,
            &input_hashes,
            &outputs_hashes,
            &canaries,
            &validators,
        )?;

        //
        // Register block
        //
        let transaction_statuses = self.database.apply_light_macro_block(
            header,
            input_hashes.iter(),
            outputs.iter(),
            validators,
            &self.account_pkey,
            &self.account_skey,
        );

        // if let Some((ref mut snowball, _)) = &mut self.snowball {
        //     snowball.change_facilitator(self.database.facilitator_pkey().clone());
        // }
        self.on_tx_statuses_changed(&transaction_statuses);
        if transaction_statuses.len() > 0 || outputs.len() > 0 {
            self.notify_balance_changed(self.database.balance());
        }

        self.notify_status();
        Ok(())
    }

    /// Send transaction to node and to the network.
    fn send_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let data = tx.into_buffer()?;
        let tx_hash = Hash::digest(&tx);
        self.network.publish(&TX_TOPIC, data.clone())?;
        debug!(
            "Sent transaction to the network: tx={}, inputs={:?}, outputs={:?}, fee={}",
            &tx_hash,
            tx.txins()
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<String>>(),
            tx.txouts()
                .iter()
                .map(|o| Hash::digest(o).to_string())
                .collect::<Vec<String>>(),
            tx.fee()
        );
        Ok(())
    }

    fn send_and_log_transaction(
        &mut self,
        tx_value: TransactionValue,
    ) -> Result<TransactionInfo, Error> {
        for input in &tx_value.tx.txins {
            self.database.lock_input(input);
        }
        let tx_info = tx_value.to_info(self.database.epoch());
        self.database
            .push_outgoing(Timestamp::now(), tx_value.clone())?;
        self.send_transaction(tx_value.tx.into())?;
        Ok(tx_info)
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
                Ok((tx_hash, tx_timestamp, tx)) => {
                    if tx_timestamp + PENDING_UTXO_TIME < Timestamp::now() {
                        trace!("Found transaction that is too old, mark as rejected.");
                        self.on_tx_status(
                            &tx_hash,
                            &TransactionStatus::Rejected {
                                error: String::from("Removed from pending list."),
                            },
                        );
                        continue;
                    }
                    debug!(
                        "Found pending transaction for resending: tx_hash = {}, status = {:?}",
                        Hash::digest(&tx.tx),
                        tx.status
                    );
                    // ignore error.
                    let _ = self.send_transaction(tx.tx.clone().into());
                }
                Err(e) => error!("Error during processing database = {}", e),
            }
        }
    }

    fn expire_locked_inputs(&mut self) {
        trace!("Handle check pending utxo transactions");
        let pending = self.database.expire_locked_inputs(PENDING_UTXO_TIME);
        let mut balance_unlocked = false;
        for hash in pending {
            trace!("Found outdated pending utxo = {}", hash);
            balance_unlocked = true;
        }

        if !balance_unlocked {
            return;
        }

        // if balance was changed return new balance.
        let balance = self.database.balance();
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

    fn notify_status(&mut self) {
        let status = self.database.status();
        self.notify(AccountNotification::StatusChanged(status));
    }

    fn notify(&mut self, notification: AccountNotification) {
        trace!("Created notification = {:?}", notification);
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }

    // Event loop.
    pub async fn process(&mut self) -> UnsealedAccountResult {
        loop {
            let mut pending_tx = Box::pin(self.resend_tx.tick()).fuse();
            let mut expire_locked_inputs = Box::pin(self.expire_locked_inputs.tick()).fuse();
            select! {
                _ = pending_tx => {
                    drop((expire_locked_inputs, pending_tx));

                    self.handle_resend_pending_txs()
                },
                _ = expire_locked_inputs => {
                    drop((expire_locked_inputs, pending_tx));

                    self.expire_locked_inputs()
                },
                _ = self.transaction_rx.next() => {}, // ignore incomming transactions
                event = self.events.next() => {
                    drop((expire_locked_inputs, pending_tx));
                    if let Some(event) = event {
                        match event {
                            AccountEvent::Request { request, tx } => {
                                let response = match request {
                                    AccountRequest::Unseal { password: _ } => AccountResponse::Error {
                                        error: "Already unsealed".to_string(),
                                    },
                                    AccountRequest::Disable {} => {
                                        info!("Stopping account for future removing.");
                                        return UnsealedAccountResult::Disabled(tx);
                                    }
                                    AccountRequest::Seal {} => {
                                        tx.send(AccountResponse::Sealed).ok();
                                        // Finish this future.
                                        return UnsealedAccountResult::Sealed;
                                    }
                                    AccountRequest::Payment {
                                        recipient,
                                        amount,
                                        payment_fee,
                                        comment,
                                        with_certificate,
                                        raw,
                                    } =>  {
                                        match self.payment(&recipient, amount, payment_fee, comment, with_certificate) {
                                            Err(e) => AccountResponse::Error {
                                                error: e.to_string(),
                                            },
                                            Ok(tx) => {
                                                if raw {
                                                    AccountResponse::RawTransactionCreated {
                                                        data: tx.tx.into()
                                                    }
                                                } else {
                                                    Ok(tx.to_info(self.database.epoch())).into()
                                                }
                                            }
                                        }
                                    }
                                    AccountRequest::PublicPayment {
                                        recipient,
                                        amount,
                                        payment_fee,
                                        raw,
                                    } => {
                                        match self.public_payment(&recipient, amount, payment_fee) {
                                            Err(e) => AccountResponse::Error {
                                                error: e.to_string(),
                                            },
                                            Ok(tx) => {
                                                if raw {
                                                    AccountResponse::RawTransactionCreated {
                                                        data: tx.tx.into()
                                                    }
                                                } else {
                                                    Ok(tx.to_info(self.database.epoch())).into()
                                                }
                                            }
                                        }
                                    }
                                    AccountRequest::StakeAll { payment_fee } => {
                                        self.stake_all(payment_fee).into()
                                    }
                                    AccountRequest::Stake {
                                        amount,
                                        payment_fee,
                                    } => self.stake(amount, payment_fee).into(),
                                    AccountRequest::StakeRemote {
                                        amount,
                                        payment_fee,
                                    } => self.stake_remote(amount, payment_fee).into(),
                                    AccountRequest::Unstake {
                                        amount,
                                        payment_fee,
                                    } => self.unstake(amount, payment_fee).into(),
                                    AccountRequest::UnstakeAll { payment_fee } => {
                                        self.unstake_all(payment_fee).into()
                                    }
                                    AccountRequest::CloakAll { payment_fee } => {
                                        self.cloak_all(payment_fee).into()
                                    }
                                    AccountRequest::AccountInfo {} => {
                                        let account_info = AccountInfo {
                                            account_pkey: self.account_pkey.clone(),
                                            network_pkey: self.network_pkey.clone(),
                                            status: self.database.status(),
                                        };
                                        AccountResponse::AccountInfo(account_info)
                                    }
                                    AccountRequest::BalanceInfo {} => {
                                        let balance = self.database.balance();
                                        AccountResponse::BalanceInfo(balance)
                                    }
                                    AccountRequest::UnspentInfo {} => {
                                        // TODO: this part should be refactored.
                                        let mut public_payments = Vec::new();
                                        let mut stakes = Vec::new();
                                        let mut payments = Vec::new();
                                        let unspent: HashMap<Hash, OutputValue> =
                                            self.database.iter_unspent().collect();
                                        for (output_hash, output_value) in unspent {
                                            match output_value {
                                                OutputValue::Stake(s) => {
                                                    stakes.push(s.to_info(self.database.epoch()))
                                                }
                                                OutputValue::Payment(p) => payments.push(
                                                    p.to_info(self.database.is_input_locked(&output_hash)),
                                                ),
                                                OutputValue::PublicPayment(p) => public_payments.push(
                                                    p.to_info(self.database.is_input_locked(&output_hash)),
                                                ),
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
                                    } => {
                                        error!("Snowball deprecated.");
                                        AccountResponse::Error {
                                                error: format!("Snowball was deprecated"),
                                        }
                                    }
                                };
                                tx.send(response).ok(); // ignore errors.
                            }
                            AccountEvent::Subscribe { tx } => {
                                self.subscribers.push(tx);
                            }
                        }
                    }
                },
                event = self.chain_notifications.next() => {
                    drop((expire_locked_inputs, pending_tx));
                    match event {
                        Some(ReplicationOutEvent::CanaryList {canaries, outputs, tx}) => {
                            debug!("ReplicationOutEvent::CanaryList");
                            let needed_outputs = canaries.into_iter().zip(outputs).enumerate().filter_map(|(id, (c, hash))|{
                                if c.is_my(&self.account_pkey, &self.account_skey) {
                                    info!("Found my output in outputs list: output_hash={}", hash);
                                    Some((id as u32, hash))
                                }
                                else {
                                    None
                                }
                            }).collect();
                            if let Err(e) = tx.send(CanaryProcessed {
                                needed_outputs,
                            }) {
                                error!("Error during processing oneshot sender = {:?}", e);
                            }
                        }
                        Some(ReplicationOutEvent::FullBlock {block, outputs}) => {
                            let r = match block {
                                LightBlock::LightMacroBlock(block) => {
                                    debug!("Got a macro block: epoch={}, inputs={:?}", block.header.epoch, block.input_hashes);
                                    self.apply_light_macro_block(
                                        block.header,
                                        block.multisig,
                                        block.multisigmap,
                                        block.input_hashes,
                                        block.output_hashes,
                                        block.canaries,
                                        outputs,
                                        block.validators,
                                    )
                                }
                                LightBlock::LightMicroBlock(block) => {
                                    debug!(
                                        "Got a micro block: epoch={}, offset={}, inputs={:?}",
                                        block.header.epoch, block.header.offset, block.input_hashes
                                    );
                                    self.apply_light_micro_block(
                                        block.header,
                                        block.sig,
                                        block.input_hashes,
                                        block.output_hashes,
                                        block.canaries,
                                        outputs,
                                    )
                                }
                            };
                            if let Err(e) = r {
                                self.notify(AccountNotification::UpstreamError(format!("{}", e)));
                            }
                        }
                        None => unreachable!(),
                    }
                }

            }
        }
    }
}

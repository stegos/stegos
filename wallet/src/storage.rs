//! LightNode + Wallet database.

//
// Copyright (c) 2019 Stegos AG
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

use crate::api::*;
use bit_vec::BitVec;
use byteorder::{BigEndian, ByteOrder};
use failure::{bail, Error};
use log::*;
use rocksdb::{Direction, IteratorMode, Options, WriteBatch, DB};
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::path::Path;
use stegos_blockchain::api::StatusInfo;
use stegos_blockchain::mvcc::MultiVersionedMap;
use stegos_blockchain::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_crypto::scc::{self, Fr};
use stegos_serialization::traits::ProtoConvert;
use tokio::time::{Duration, Instant};

// colon families.
const HISTORY: &'static str = "history";
const UNSPENT: &'static str = "unspent";
const META: &'static str = "meta";
const COLON_FAMILIES: &[&'static str] = &[HISTORY, UNSPENT, META];

// Keys in meta cf
const EPOCH_KEY: &[u8; 5] = b"epoch";

/// A special offset used to tore Macro Blocks on the disk.
const MACRO_BLOCK_OFFSET: u32 = u32::max_value();

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
struct LSN(u64, u32); // use `struct` to disable explicit casts.

type OutputByHashMap = MultiVersionedMap<Hash, OutputValue, LSN>;

#[derive(Debug, Clone)]
pub enum LogEntry {
    Incoming { output: OutputValue },
    Outgoing { tx: TransactionValue },
}

///
/// LightNode + Wallet database.
///
pub struct LightDatabase {
    /// RocksDB database object.
    database: DB,
    /// Configuration.
    cfg: ChainConfig,
    /// Current Epoch.
    epoch: u64,
    /// The hash of genesis block.
    genesis_hash: Hash,
    /// Copy of the last macro block hash.
    last_macro_block_hash: Hash,
    /// Copy of the last macro block random.
    last_macro_block_random: Hash,
    /// Copy of the last macro block timestamp.
    last_macro_block_timestamp: Timestamp,
    /// Validators on the start of the epoch.
    validators: StakersGroup,
    /// Facilitator.
    facilitator_pkey: pbc::PublicKey,
    /// Micro blocks for the current epoch.
    micro_blocks: Vec<MicroBlockHeader>,

    /// In-memory index of all UTXOs.
    utxos: OutputByHashMap,
    /// Index of UTXOS that known to be change.
    known_changes: HashSet<Hash>,
    /// Is last update of UTXO was in current epoch.
    current_epoch_balance_changed: bool,
    /// Index of all created UTXOs by this wallet.
    utxos_list: HashMap<Hash, Timestamp>,
    /// Index of all created transactions by this wallet.
    created_txs: HashMap<Hash, Timestamp>,
    /// List of locked inputs.
    // Store time in Instant, to be more compatible with tokio-timer.
    locked_inputs: HashMap<Hash, LockedInput>,
    /// Index of all transactions that wasn't rejected or committed.
    pending_txs: HashSet<Hash>,
    /// Index of inputs of pending_txs,
    inputs: HashMap<Hash, Hash>,
    /// Index of outputs of pending_txs,
    outputs: HashMap<Hash, Hash>,
    /// Transactions that was created in current epoch.
    epoch_transactions: HashSet<Hash>,
}

impl LightDatabase {
    /// Open database.
    pub fn open(path: &Path, genesis_hash: Hash, cfg: ChainConfig) -> LightDatabase {
        debug!("Database path = {}", path.to_string_lossy());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let database = DB::open_cf(&opts, path, COLON_FAMILIES).expect("couldn't open database");
        debug!("Loading database");

        let mut log = LightDatabase {
            database,
            epoch: 0,
            cfg,
            genesis_hash,
            last_macro_block_hash: Hash::digest("genesis"),
            last_macro_block_random: Hash::digest("genesis"),
            last_macro_block_timestamp: Timestamp::now(),
            validators: vec![],
            facilitator_pkey: pbc::PublicKey::dum(),
            micro_blocks: Vec::new(),
            created_txs: HashMap::new(),
            locked_inputs: HashMap::new(),
            pending_txs: HashSet::new(),
            inputs: HashMap::new(),
            outputs: HashMap::new(),
            epoch_transactions: HashSet::new(),
            utxos_list: HashMap::new(),
            known_changes: HashSet::new(),
            utxos: MultiVersionedMap::new(),
            current_epoch_balance_changed: false,
        };
        log.recover_state();
        log
    }

    pub fn is_known_changes(&self, utxo: Hash) -> bool {
        let exist = self.known_changes.contains(&utxo);
        trace!("Checking is change = {}, exist={}", utxo, exist);
        exist
    }

    /// Returns true if the chain is synchronized with the network.
    pub fn is_synchronized(&self) -> bool {
        let timestamp = Timestamp::now();
        let block_timestamp = self.last_block_timestamp();
        block_timestamp + self.cfg.sync_timeout >= timestamp
    }

    /// Returns current status.
    pub fn status(&self) -> StatusInfo {
        let is_synchronized = self.is_synchronized();
        StatusInfo {
            is_synchronized,
            epoch: self.epoch(),
            offset: self.offset(),
            view_change: 0,
            last_block_hash: self.last_block_hash(),
            last_macro_block_hash: self.last_macro_block_hash,
            last_macro_block_timestamp: self.last_macro_block_timestamp,
            local_timestamp: Timestamp::now(),
        }
    }

    /// Return the current blockchain epoch.
    #[inline(always)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the number of blocks in the current epoch.
    #[inline(always)]
    pub fn offset(&self) -> u32 {
        self.micro_blocks.len() as u32
    }

    /// Returns a hash of genetic block.
    #[inline(always)]
    pub fn genesis_hash(&self) -> &Hash {
        &self.genesis_hash
    }

    #[allow(dead_code)]
    /// Returns facilitator's public key.
    #[inline(always)]
    pub fn facilitator_pkey(&self) -> &pbc::PublicKey {
        &self.facilitator_pkey
    }

    /// Returns chain configuration.
    #[inline(always)]
    pub fn cfg(&self) -> &ChainConfig {
        &self.cfg
    }

    /// Returns the last block hash.
    pub fn last_block_hash(&self) -> Hash {
        if let Some(header) = self.micro_blocks.last() {
            Hash::digest(header)
        } else {
            self.last_macro_block_hash
        }
    }

    /// Returns the last random.
    pub fn last_block_random(&self) -> Hash {
        if let Some(header) = self.micro_blocks.last() {
            header.random.rand
        } else {
            self.last_macro_block_random
        }
    }

    /// Returns the last block timestamp.
    pub fn last_block_timestamp(&self) -> Timestamp {
        if let Some(header) = self.micro_blocks.last() {
            header.timestamp
        } else {
            self.last_macro_block_timestamp
        }
    }

    /// Get actual balance.
    pub fn balance(&self) -> AccountBalance {
        let mut balance: AccountBalance = Default::default();
        for (hash, val) in self.iter_unspent() {
            match val {
                OutputValue::Payment(PaymentValue {
                    amount,
                    output: PaymentOutput { .. },
                    ..
                }) => {
                    balance.payment.current += amount;
                    if self.locked_inputs.get(&hash).is_some() {
                        continue;
                    }
                    balance.payment.available += amount;
                }
                OutputValue::PublicPayment(PublicPaymentValue {
                    output: PublicPaymentOutput { amount, .. },
                    ..
                }) => {
                    balance.public_payment.current += amount;
                    if self.locked_inputs.get(&hash).is_some() {
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
                    if self.locked_inputs.get(&hash).is_some() {
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
        balance.is_final = !self.current_epoch_balance_changed || !self.locked_inputs.is_empty();
        balance.epoch = self.epoch;
        balance
    }

    /// Returns an iterator over available payment outputs.
    pub fn available_payment_outputs<'a>(
        &'a self,
    ) -> impl Iterator<Item = (PaymentOutput, i64)> + 'a {
        self.iter_unspent()
            .filter_map(|(k, v)| v.payment().map(|v| (k, v)))
            .filter(move |(h, _)| self.locked_inputs.get(h).is_none())
            .inspect(|(h, _)| trace!("Using PaymentOutput: hash={}", h))
            .map(|(_, v)| (v.output, v.amount))
    }

    /// Returns an iterator over available public payment outputs.
    pub fn available_public_payment_outputs<'a>(
        &'a self,
    ) -> impl Iterator<Item = PublicPaymentOutput> + 'a {
        self.iter_unspent()
            .filter_map(|(k, v)| v.public_payment().map(|v| (k, v)))
            .filter(move |(h, _)| self.locked_inputs.get(h).is_none())
            .inspect(|(h, _)| trace!("Using PublicPaymentOutput: hash={}", h))
            .map(|(_, v)| v.output)
    }

    /// Returns an iterator over available stake outputs.
    pub fn available_stake_outputs<'a>(&'a self) -> impl Iterator<Item = StakeOutput> + 'a {
        self.iter_unspent()
            .filter_map(|(_k, v)| v.stake())
            // All stake unspent utxo should be with info about active epoch.
            .filter_map(|v| v.active_until_epoch.map(|epoch| (v.output, epoch)))
            .filter(move |(_v, epoch)| *epoch <= self.epoch)
            .map(|(o, _e)| o)
    }

    /// Returns id of first unknown epoch
    fn recover_state(&mut self) {
        let meta_cf = self.database.cf_handle(META).expect("META cf created");
        let epoch_info = match self
            .database
            .get_cf(meta_cf, EPOCH_KEY)
            .expect("cannot read epoch_key")
        {
            Some(epoch_info) => epoch_info,
            None => {
                info!("Created an empty database");
                return; /* nothing to recover */
            }
        };
        let epoch_info = LightEpochInfo::from_buffer(&epoch_info).expect("LightEpochInfo is valid");
        self.epoch = epoch_info.header.epoch + 1;
        assert!(self.micro_blocks.is_empty());
        self.last_macro_block_hash = Hash::digest(&epoch_info.header);
        self.last_macro_block_random = epoch_info.header.random.rand;
        self.last_macro_block_timestamp = epoch_info.header.timestamp;
        self.facilitator_pkey = epoch_info.facilitator;
        self.validators = epoch_info.validators;
        let lsn = LSN(epoch_info.header.epoch, MACRO_BLOCK_OFFSET);
        let cf_unspent = self
            .database
            .cf_handle(UNSPENT)
            .expect("UNSPENT cf created");
        for (unspent_hash, unspent) in self
            .database
            .iterator_cf(cf_unspent, IteratorMode::Start)
            .expect("Cannot read UNSPENT cf.")
            .map(|(k, v)| {
                let k = Hash::from_buffer(&*k).expect("couldn't deserialize UNSPENT key.");
                let v = OutputValue::from_buffer(&*v).expect("couldn't deserialize UNSPENT entry.");
                (k, v)
            })
        {
            self.utxos.insert(lsn, unspent_hash, unspent);
        }

        let starting_time = Timestamp::UNIX_EPOCH;
        // Motivation: We need to update in memory indexes while iterating over DB.
        // 1) We update only in memory indexes, without modifying database.
        // 2) rocksdb internally support modifying while iterating,
        // but rust binding limiting us with this..
        let static_db: &'static DB = unsafe { mem::transmute(&self.database) };
        let static_iter = Self::iter_range_inner(static_db, starting_time, u64::max_value());

        for (timestamp, entry) in static_iter {
            match entry {
                LogEntry::Incoming { output } => {
                    let output_hash = Hash::digest(&output.to_output());
                    trace!("Recovered output: output={}", output_hash,);
                    assert!(self.utxos_list.insert(output_hash, timestamp).is_none());
                }
                LogEntry::Outgoing { tx } => {
                    let tx_hash = Hash::digest(&tx.tx);
                    let status = tx.status.clone();
                    trace!("Recovered tx: tx={}, status={:?}", tx_hash, status);
                    assert!(self.created_txs.insert(tx_hash, timestamp).is_none());
                    self.update_tx_indexes(tx.clone());
                    for utxo in tx.outputs.iter() {
                        if utxo.is_change() {
                            let utxo_hash = Hash::digest(&utxo.to_output());
                            self.known_changes.insert(utxo_hash);
                        }
                    }
                }
            }
        }
        drop(static_db);

        info!(
            "Recovered database: epoch={}, last_macro_block={}",
            self.epoch, self.last_macro_block_hash
        );
    }

    pub fn iter_unspent<'a>(&'a self) -> impl Iterator<Item = (Hash, OutputValue)> + 'a {
        // TODO: remove cloned().
        self.utxos.iter().map(|(k, v)| (k.clone(), v.clone()))
    }

    fn filter_inputs_and_outputs<'a, InputsIter, OutputsIter>(
        &self,
        inputs_iter: InputsIter,
        outputs_iter: OutputsIter,
        account_pkey: &scc::PublicKey,
        account_skey: &scc::SecretKey,
    ) -> (Vec<Hash>, Vec<OutputValue>)
    where
        InputsIter: Iterator<Item = &'a Hash>,
        OutputsIter: Iterator<Item = &'a Output>,
    {
        let mut my_inputs: HashSet<Hash> = HashSet::new();
        let mut my_outputs: HashMap<Hash, OutputValue> = HashMap::new();
        for output in outputs_iter {
            let value: OutputValue = match output {
                Output::PaymentOutput(o) => {
                    if let Ok(PaymentPayload { amount, data, .. }) =
                        o.decrypt_payload(&account_pkey, &account_skey)
                    {
                        assert!(amount >= 0);
                        let value = PaymentValue {
                            output: o.clone(),
                            amount,
                            recipient: account_pkey.clone(),
                            data,
                            rvalue: None,
                            is_change: false,
                        };
                        value.into()
                    } else {
                        continue; // not our UTXO.
                    }
                }
                Output::PublicPaymentOutput(o) => {
                    if &o.recipient != account_pkey {
                        continue; // not our UTXO.
                    };
                    let value = PublicPaymentValue { output: o.clone() };
                    value.into()
                }
                Output::StakeOutput(o) => {
                    if &o.recipient != account_pkey {
                        continue; // not our UTXO.
                    }
                    let active_until_epoch = self.epoch + self.cfg.stake_epochs;
                    let value = StakeValue {
                        output: o.clone(),
                        active_until_epoch: active_until_epoch.into(),
                    };
                    value.into()
                }
            };

            let output_hash = Hash::digest(&output);
            my_outputs.insert(output_hash, value);
        }

        for input_hash in inputs_iter {
            trace!("Process input inputs={}", input_hash);
            let _ = my_outputs.remove(&input_hash); // anihilate this output

            let _input = match self.output_by_hash(&input_hash) {
                Some(_o) => {
                    my_inputs.insert(*input_hash);
                }
                None => continue, // not our UTXO.
            };
        }

        let my_inputs: Vec<Hash> = my_inputs.into_iter().collect();
        let my_outputs: Vec<OutputValue> = my_outputs.into_iter().map(|(_k, v)| v).collect();
        (my_inputs, my_outputs)
    }

    ///
    /// Common part of push_macro_block()/push_micro_block().
    ///
    fn register_inputs_and_outputs(
        &mut self,
        lsn: LSN,
        block_hash: Hash,
        offset: Option<u32>,
        timestamp: Timestamp,
        input_hashes: Vec<Hash>,
        outputs: Vec<OutputValue>,
    ) -> HashMap<Hash, TransactionStatus> {
        trace!("Register inputs and outputs: inputs={:?}", input_hashes);
        //
        // Process inputs.
        //
        for input_hash in &input_hashes {
            let input_value = if let Some(input) = self.utxos.remove(lsn, &input_hash) {
                input
            } else {
                panic!(
                    "Missing input UTXO: epoch={}, block={}, utxo={}",
                    self.epoch, block_hash, input_hash
                );
            };

            match input_value {
                OutputValue::Payment(p) => {
                    info!(
                        "Spent: utxo={}, amount={}, data={:?}",
                        input_hash, p.amount, p.data
                    );
                }
                OutputValue::PublicPayment(p) => {
                    let o = &p.output;
                    info!(
                        "Spent public payment: utxo={}, amount={}",
                        input_hash, o.amount
                    );
                }
                OutputValue::Stake(s) => {
                    let o = s.output;
                    let active_until_epoch = self.epoch + self.cfg.stake_epochs;
                    info!(
                        "Unstaked: hash={}, amount={}, active_until_epoch={}",
                        input_hash, o.amount, active_until_epoch
                    );
                }
            }
        }

        //
        // Process outputs.
        //
        let mut output_hashes = Vec::with_capacity(outputs.len());
        for output_value in &outputs {
            let output = output_value.to_output();
            let output_hash = Hash::digest(&output);

            // Update indexes.
            if let Some(_) = self
                .utxos
                .insert(lsn, output_hash.clone(), output_value.clone())
            {
                panic!(
                    "UTXO hash collision: epoch={}, block={}, utxo={}",
                    self.epoch, &block_hash, &output_hash
                );
            }
            assert_eq!(self.utxos.current_lsn(), lsn);

            // Update history.
            self.push_incoming(timestamp, output_value.clone().into())
                .expect("I/O error");

            match output_value {
                OutputValue::Payment(p) => {
                    info!(
                        "Received: utxo={}, amount={}, data={:?}",
                        output_hash, p.amount, p.data
                    );
                }
                OutputValue::PublicPayment(p) => {
                    let PublicPaymentOutput { ref amount, .. } = &p.output;
                    assert!(*amount >= 0);
                    info!(
                        "Received public payment: utxo={}, amount={}",
                        output_hash, amount
                    );
                }
                OutputValue::Stake(p) => {
                    let output = &p.output;
                    let active_until_epoch = self.epoch + self.cfg.stake_epochs;
                    info!(
                        "Staked: hash={}, amount={}, active_until_epoch={}",
                        output_hash, output.amount, active_until_epoch
                    );
                }
            }
            output_hashes.push(output_hash);
        }

        //
        // Update transaction statuses.
        //
        let transaction_statuses = self
            .prune_txs(input_hashes.iter(), output_hashes.iter())
            .expect("I/O error")
            .into_iter()
            .map(|(k, v)| {
                let status = if v.1 {
                    match offset {
                        None => TransactionStatus::Committed { epoch: self.epoch },
                        Some(offset) => TransactionStatus::Prepared {
                            epoch: self.epoch,
                            offset,
                        },
                    }
                } else {
                    TransactionStatus::Conflicted {
                        epoch: self.epoch,
                        offset,
                    }
                };

                (k, status)
            })
            .collect();

        transaction_statuses
    }

    ///
    /// Validates the light macro block.
    ///
    pub fn validate_macro_block(
        &mut self,
        header: &MacroBlockHeader,
        multisig: &pbc::Signature,
        multisigmap: &BitVec,
        input_hashes: &[Hash],
        output_hashes: &[Hash],
        canaries: &[Canary],
        validators: &StakersGroup,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(header);

        // Check genesis.
        if self.epoch == 0 && block_hash != self.genesis_hash {
            return Err(BlockchainError::IncompatibleGenesis(self.genesis_hash, block_hash).into());
        }

        // Check block version.
        if header.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                header.epoch,
                block_hash,
                header.version,
                VERSION,
            )
            .into());
        }

        // Check epoch.
        if header.epoch != self.epoch {
            return Err(
                BlockError::OutOfOrderMacroBlock(block_hash, header.epoch, self.epoch).into(),
            );
        }

        // Check previous hash.
        if self.last_macro_block_hash != header.previous {
            return Err(BlockError::InvalidMacroBlockPreviousHash(
                header.epoch,
                block_hash,
                header.previous,
                self.last_macro_block_hash,
            )
            .into());
        }

        //
        // Validate multi-signature.
        //
        if header.epoch > 0 {
            check_multi_signature(
                &block_hash,
                multisig,
                &multisigmap,
                &self.validators,
                self.cfg.max_slot_count,
            )
            .map_err(|e| BlockError::InvalidBlockSignature(e, header.epoch, block_hash))?;
        }

        // Check VRF.
        let seed = mix(self.last_macro_block_random.clone(), header.view_change);
        if !pbc::validate_VRF_source(&header.random, &header.pkey, &seed).is_ok() {
            return Err(BlockError::IncorrectRandom(header.epoch, block_hash).into());
        }

        //
        // Validate inputs.
        //
        if header.inputs_len as usize != input_hashes.len() {
            return Err(BlockError::InvalidMacroBlockInputsLen(
                header.epoch,
                block_hash,
                header.inputs_len as usize,
                input_hashes.len(),
            )
            .into());
        }
        let inputs_range_hash = Merkle::root_hash_from_array(&input_hashes);
        if header.inputs_range_hash != inputs_range_hash {
            return Err(BlockError::InvalidMacroBlockInputsHash(
                header.epoch,
                block_hash,
                inputs_range_hash,
                header.inputs_range_hash,
            )
            .into());
        }

        //
        // Validate outputs.
        //
        if header.outputs_len as usize != output_hashes.len() {
            return Err(BlockError::InvalidMacroBlockInputsLen(
                header.epoch,
                block_hash,
                header.outputs_len as usize,
                output_hashes.len(),
            )
            .into());
        }
        let outputs_range_hash = Merkle::root_hash_from_array(&output_hashes);
        if header.outputs_range_hash != outputs_range_hash {
            return Err(BlockError::InvalidMacroBlockOutputsHash(
                header.epoch,
                block_hash,
                outputs_range_hash,
                header.outputs_range_hash,
            )
            .into());
        }

        //
        // Validate canaries.
        //
        let canary_hashes: Vec<Hash> = canaries.iter().map(Hash::digest).collect();
        let canaries_range_hash = Merkle::root_hash_from_array(&canary_hashes);
        if header.canaries_range_hash != canaries_range_hash {
            return Err(BlockError::InvalidMacroBlockCanariesHash(
                header.epoch,
                block_hash,
                canaries_range_hash,
                header.canaries_range_hash,
            )
            .into());
        }

        //
        // Validate validators.
        //
        let validators_len = validators.len();
        if header.validators_len as usize != validators_len {
            panic!(
                "Invalid validators_len: expected={}, got={}",
                validators_len, header.validators_len,
            );
        }
        let validators_range_hash = Merkle::root_hash_from_array(validators);
        if header.validators_range_hash != validators_range_hash {
            panic!(
                "Invalid validators_range_hash: expected={}, got={}",
                validators_range_hash, header.validators_range_hash
            );
        }

        Ok(())
    }

    ///
    /// Validate the light micro block.
    ///
    pub fn validate_light_micro_block(
        &mut self,
        header: &MicroBlockHeader,
        sig: &pbc::Signature,
        input_hashes: &[Hash],
        output_hashes: &[Hash],
        canaries: &[Canary],
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(header);

        // Check block version.
        if header.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                header.epoch,
                block_hash,
                header.version,
                VERSION,
            )
            .into());
        }

        // Check epoch and offset.
        if header.epoch != self.epoch() || header.offset != self.offset() {
            return Err(BlockError::OutOfOrderMicroBlock(
                block_hash,
                header.epoch,
                header.offset,
                self.epoch(),
                self.offset(),
            )
            .into());
        }

        // Check the block order.
        if self.offset() >= self.cfg.micro_blocks_in_epoch {
            return Err(
                BlockchainError::ExpectedMacroBlock(self.epoch, self.offset(), block_hash).into(),
            );
        }

        // Check previous hash.
        if self.last_block_hash() != header.previous {
            return Err(BlockError::InvalidMicroBlockPreviousHash(
                header.epoch,
                header.offset,
                block_hash,
                header.previous,
                self.last_block_hash(),
            )
            .into());
        }

        // Check signature.
        let last_random = self.last_block_random();
        let leader = election::select_leader(&self.validators, &last_random, header.view_change);
        if leader != header.pkey {
            return Err(BlockError::DifferentPublicKey(leader, header.pkey).into());
        }
        if let Err(_e) = pbc::check_hash(&block_hash, sig, &leader) {
            return Err(BlockError::InvalidLeaderSignature(header.epoch, block_hash).into());
        }

        // Check VRF.
        let seed = mix(last_random.clone(), header.view_change);
        if !pbc::validate_VRF_source(&header.random, &header.pkey, &seed).is_ok() {
            return Err(BlockError::IncorrectRandom(header.epoch, block_hash).into());
        }

        //
        // Validate inputs.
        //
        if header.inputs_len as usize != input_hashes.len() {
            return Err(BlockError::InvalidMicroBlockInputsLen(
                header.epoch,
                header.offset,
                block_hash,
                header.inputs_len as usize,
                input_hashes.len(),
            )
            .into());
        }
        let inputs_range_hash = Merkle::root_hash_from_array(&input_hashes);
        if header.inputs_range_hash != inputs_range_hash {
            return Err(BlockError::InvalidMicroBlockInputsHash(
                header.epoch,
                header.offset,
                block_hash,
                inputs_range_hash,
                header.inputs_range_hash,
            )
            .into());
        }

        //
        // Validate outputs.
        //
        if header.outputs_len as usize != output_hashes.len() {
            return Err(BlockError::InvalidMicroBlockInputsLen(
                header.epoch,
                header.offset,
                block_hash,
                header.outputs_len as usize,
                output_hashes.len(),
            )
            .into());
        }
        let outputs_range_hash = Merkle::root_hash_from_array(&output_hashes);
        if header.outputs_range_hash != outputs_range_hash {
            return Err(BlockError::InvalidMicroBlockOutputsHash(
                header.epoch,
                header.offset,
                block_hash,
                outputs_range_hash,
                header.outputs_range_hash,
            )
            .into());
        }

        //
        // Validate canaries.
        //
        let canary_hashes: Vec<Hash> = canaries.iter().map(Hash::digest).collect();
        let canaries_range_hash = Merkle::root_hash_from_array(&canary_hashes);
        if header.canaries_range_hash != canaries_range_hash {
            return Err(BlockError::InvalidMicroBlockCanariesHash(
                header.epoch,
                header.offset,
                block_hash,
                canaries_range_hash,
                header.canaries_range_hash,
            )
            .into());
        }

        Ok(())
    }

    ///
    /// Applies the light macro block.
    ///
    /// Inputs && outputs are automatically filtered out by account_pkey/account_skey.
    ///
    pub fn apply_light_macro_block<'a, InputsIter, OutputsIter>(
        &mut self,
        header: MacroBlockHeader,
        inputs_iter: InputsIter,
        outputs_iter: OutputsIter,
        validators: StakersGroup,
        account_pkey: &scc::PublicKey,
        account_skey: &scc::SecretKey,
    ) -> HashMap<Hash, TransactionStatus>
    where
        InputsIter: Iterator<Item = &'a Hash>,
        OutputsIter: Iterator<Item = &'a Output>,
    {
        assert_eq!(self.epoch, header.epoch, "block order");
        let epoch = header.epoch;

        //
        // Revert micro blocks.
        //
        let mut transaction_statuses: HashMap<Hash, TransactionStatus> = HashMap::new();
        while self.micro_blocks.len() > 0 {
            for (tx_hash, tx_status) in self.revert_micro_block() {
                transaction_statuses.insert(tx_hash, tx_status);
            }
        }

        let (my_inputs, my_outputs) =
            self.filter_inputs_and_outputs(inputs_iter, outputs_iter, account_pkey, account_skey);
        assert!(self.micro_blocks.is_empty(), "micro blocks are removed");
        let block_hash = Hash::digest(&header);
        let lsn = LSN(epoch, MACRO_BLOCK_OFFSET);
        let mut batch = rocksdb::WriteBatch::default();
        let transaction_statuses2 = self.register_inputs_and_outputs(
            lsn,
            block_hash,
            None,
            header.timestamp,
            my_inputs,
            my_outputs,
        );
        for (tx_hash, tx_status) in transaction_statuses2 {
            transaction_statuses.insert(tx_hash, tx_status);
        }

        let facilitator = election::select_facilitator(&header.random.rand, &validators);
        self.facilitator_pkey = facilitator;
        self.epoch += 1;
        self.micro_blocks.clear();
        self.last_macro_block_hash = block_hash;
        self.last_macro_block_random = header.random.rand;
        self.last_macro_block_timestamp = header.timestamp;
        self.validators = validators;
        self.current_epoch_balance_changed = false;

        let unspent = self.database.cf_handle(UNSPENT).expect("cf created");
        let meta_cf = self.database.cf_handle(META).expect("cf created");
        Blockchain::write_log(&mut batch, unspent, self.utxos.checkpoint()).expect("I/O error");
        let epoch_info = LightEpochInfo {
            header,
            validators: self.validators.clone(),
            facilitator: self.facilitator_pkey.clone(),
        };
        batch
            .put_cf(
                meta_cf,
                EPOCH_KEY,
                epoch_info.into_buffer().expect("Serialization error"),
            )
            .expect("I/O error");
        for (tx_hash, tx_status) in &transaction_statuses {
            let timestamp = self
                .tx_entry(tx_hash.clone())
                .expect("Transaction should be found in tx list");

            let mut updated_tx = None;
            self.update_log_entry(timestamp, |mut e| {
                match &mut e {
                    LogEntry::Outgoing { ref mut tx } => {
                        tx.status = tx_status.clone();
                        updated_tx = Some(tx.clone());
                    }
                    LogEntry::Incoming { .. } => bail!("Expected outgoing transaction."),
                };
                Ok(e)
            })
            .expect("I/O error");

            if let Some(tx) = updated_tx {
                self.update_tx_indexes(tx);
            }
        }
        self.epoch_transactions.clear();
        self.database.write(batch).expect("I/O error");

        info!(
            "Applied a macro block: epoch={}, block={}",
            epoch, &block_hash,
        );

        transaction_statuses
    }

    ///
    /// Applies the light micro block.
    ///
    /// Inputs && outputs are automatically filtered out by account_pkey/account_skey.
    ///
    pub fn apply_light_micro_block<'a, InputsIter, OutputsIter>(
        &mut self,
        header: MicroBlockHeader,
        inputs_iter: InputsIter,
        outputs_iter: OutputsIter,
        account_pkey: &scc::PublicKey,
        account_skey: &scc::SecretKey,
    ) -> HashMap<Hash, TransactionStatus>
    where
        InputsIter: Iterator<Item = &'a Hash>,
        OutputsIter: Iterator<Item = &'a Output>,
    {
        assert_eq!(header.version, VERSION);
        assert_eq!(self.epoch, header.epoch);
        assert_eq!(self.offset(), header.offset);
        assert_eq!(header.previous, self.last_block_hash());
        let epoch = self.epoch;
        let offset = self.offset();

        let (my_inputs, my_outputs) =
            self.filter_inputs_and_outputs(inputs_iter, outputs_iter, account_pkey, account_skey);
        let is_balance_changed = my_outputs.len() > 0;
        if is_balance_changed {
            self.current_epoch_balance_changed = true;
        }

        let block_hash = Hash::digest(&header);
        let lsn = LSN(epoch, offset);
        let transaction_statuses = self.register_inputs_and_outputs(
            lsn,
            block_hash,
            Some(self.offset()),
            header.timestamp,
            my_inputs,
            my_outputs,
        );
        self.micro_blocks.push(header);

        info!(
            "Applied a micro block: epoch={}, offset={}, block={}",
            epoch, offset, &block_hash,
        );

        transaction_statuses
    }

    ///
    /// Revertts the light micro block.
    ///
    pub fn revert_micro_block(&mut self) -> HashMap<Hash, TransactionStatus> {
        let header = self.micro_blocks.pop().expect("have microblocks");
        let block_hash = Hash::digest(&header);
        let lsn = if self.micro_blocks.len() == 0 {
            LSN(self.epoch - 1, MACRO_BLOCK_OFFSET)
        } else {
            LSN(self.epoch, (self.micro_blocks.len() - 1) as u32)
        };
        self.utxos.rollback_to_lsn(lsn);
        let current_offset = self.offset();
        let cf = self.database.cf_handle(HISTORY).expect("cf created");
        let mut txs = HashMap::new();
        for tx_hash in &self.epoch_transactions {
            let tx_key = self.created_txs.get(&tx_hash).expect("transaction exists");
            let key = Self::bytes_from_timestamp(*tx_key);
            let value = self
                .database
                .get_cf(cf, &key)
                .expect("I/O error")
                .expect("Log entry not found.");
            let entry = LogEntry::from_buffer(&value).expect("Deserialization error");
            let tx = match entry {
                LogEntry::Outgoing { tx } => tx,
                e => panic!("Expected outgoing, found={:?}", e),
            };
            match tx.status {
                TransactionStatus::Prepared { offset, .. } => {
                    if offset != current_offset {
                        continue;
                    }
                }
                status => panic!(
                    "Expect prepared status, for `epoch_transactions` entry, found={:?}.",
                    status
                ),
            }

            for utxo in tx.outputs.iter() {
                let utxo_hash = Hash::digest(&utxo.to_output());
                if utxo.is_change() {
                    self.known_changes.insert(utxo_hash);
                }
                self.outputs.insert(utxo_hash, *tx_hash);
            }
            for txin in tx.tx.txins.iter() {
                self.inputs.insert(*txin, *tx_hash);
            }

            info!("Recovered transaction: hash={}", tx_hash);
            assert!(txs.insert(*tx_hash, tx).is_none());
        }

        if txs.len() > 0 {
            self.current_epoch_balance_changed = true;
        }

        let transaction_statuses = txs
            .into_iter()
            .map(|(k, _)| {
                let status = TransactionStatus::Created {};
                (k, status)
            })
            .collect();

        info!(
            "Reverted a micro block: epoch={}, offset={}, block={}",
            self.epoch, header.offset, &block_hash,
        );

        transaction_statuses
    }

    ///
    /// Resolve UTXO by its hash.
    ///
    fn output_by_hash(&self, hash: &Hash) -> Option<OutputValue> {
        if let Some(output) = self.utxos.get(hash) {
            return Some(output.clone());
        } else {
            None
        }
    }

    /// Mark pending transactions as spent.
    pub fn prune_txs<'a, HashIterator>(
        &mut self,
        input_hashes: HashIterator,
        output_hashes: HashIterator,
    ) -> Result<HashMap<Hash, (TransactionValue, bool)>, Error>
    where
        HashIterator: Iterator<Item = &'a Hash>,
    {
        let input_hashes: HashSet<_> = input_hashes.cloned().collect();
        let output_hashes: HashSet<_> = output_hashes.cloned().collect();
        let mut tx_hashes: HashSet<Hash> = HashSet::new();
        // Collect transactions affected by inputs.
        for input_hash in &input_hashes {
            if let Some(tx_hash) = self.inputs.remove(&input_hash) {
                tx_hashes.insert(tx_hash);
            }
        }

        // Collect transactions affected by outputs.
        for output_hash in &output_hashes {
            if let Some(tx_hash) = self.outputs.remove(&output_hash) {
                tx_hashes.insert(tx_hash);
            }
        }

        let cf = self.database.cf_handle(HISTORY).expect("cf created");
        let mut txs = HashMap::new();
        // Prune transactions.
        for tx_hash in tx_hashes {
            let tx_key = self.created_txs.get(&tx_hash).expect("transaction exists");
            let key = Self::bytes_from_timestamp(*tx_key);
            let value = self
                .database
                .get_cf(cf, &key)?
                .expect("Log entry not found.");
            let entry = LogEntry::from_buffer(&value)?;
            let tx = match entry {
                LogEntry::Outgoing { tx } => tx,
                e => panic!("Expected outgoing, found={:?}", e),
            };
            for input_hash in &tx.tx.txins {
                if let Some(tx_hash2) = self.inputs.remove(input_hash) {
                    assert_eq!(tx_hash2, tx_hash);
                }
            }
            for output in &tx.tx.txouts {
                let output_hash = Hash::digest(output);
                if let Some(tx_hash2) = self.outputs.remove(&output_hash) {
                    assert_eq!(tx_hash2, tx_hash);
                }
            }
            assert!(txs.insert(tx_hash, tx).is_none());
        }

        let mut statuses = HashMap::new();

        for (hash, tx) in txs {
            let mut full = true;
            for input_hash in &tx.tx.txins {
                if !input_hashes.contains(input_hash) {
                    debug!("Input hash not found: tx={}, hash={}", hash, input_hash);
                    full = false;
                    break;
                }
            }

            info!("Removing transaction: hash={}, full={}", hash, full);
            assert!(statuses.insert(hash, (tx, full)).is_none());
        }
        Ok(statuses)
    }

    fn update_tx_indexes(&mut self, tx: TransactionValue) {
        let tx_hash = Hash::digest(&tx.tx);
        let status = tx.status;
        // update epoch transactions
        match status {
            TransactionStatus::Prepared { .. } => {
                self.epoch_transactions.insert(tx_hash);
            }
            _ => {
                trace!("Found status that is not equal to Prepare.");
                let _ = self.epoch_transactions.remove(&tx_hash);
            }
        }

        // update pending transactions
        match status {
            TransactionStatus::Created {} | TransactionStatus::Accepted {} => {
                let tx_timestamp = *self
                    .created_txs
                    .get(&tx_hash)
                    .expect("transaction in created list");
                trace!(
                    "Found transaction with status = {:?}, with timestamp = {}, adding to list.",
                    status,
                    tx_timestamp
                );
                self.pending_txs.insert(tx_hash);
                for utxo in tx.outputs.iter() {
                    let utxo_hash = Hash::digest(&utxo.to_output());
                    if utxo.is_change() {
                        self.known_changes.insert(utxo_hash);
                    }
                    self.outputs.insert(utxo_hash, tx_hash);
                }
                for txin in tx.tx.txins.iter() {
                    self.inputs.insert(*txin, tx_hash);
                }
            }
            _ => {
                trace!("Found status that is final, didn't add transaction to pending list.");
                let _ = self.pending_txs.remove(&tx_hash);
            }
        }
    }

    /// Return iterator over transactions
    pub fn pending_txs<'a>(
        &'a self,
    ) -> impl Iterator<Item = Result<(Hash, Timestamp, TransactionValue), Error>> + 'a {
        let cf = self.database.cf_handle(HISTORY).expect("cf created");
        self.pending_txs.iter().map(move |tx_hash| {
            let tx_key = self
                .created_txs
                .get(tx_hash)
                .expect("Transaction should exist");
            let key = Self::bytes_from_timestamp(*tx_key);
            let value = self
                .database
                .get_cf(cf, &key)?
                .expect("Log entry not found.");
            let entry = LogEntry::from_buffer(&value)?;
            Ok(match entry {
                LogEntry::Outgoing { tx } => (*tx_hash, *tx_key, tx),
                _ => panic!("Found link to incomming entry, in transaaction list."),
            })
        })
    }

    /// Returns exact timestamp of created transaction, if tx found.
    pub fn tx_entry(&self, tx_hash: Hash) -> Option<Timestamp> {
        self.created_txs.get(&tx_hash).cloned()
    }

    /// Insert log entry as last entry in log.
    fn push_incoming(
        &mut self,
        timestamp: Timestamp,
        incoming: OutputValue,
    ) -> Result<Timestamp, Error> {
        let output_hash = Hash::digest(&incoming.to_output());
        trace!("Push incoming utxo = {:?}", output_hash);
        if let Some(time) = self.utxos_list.get(&output_hash) {
            trace!("Skip adding, log already contain output = {}", output_hash);
            return Ok(*time);
        }

        let entry = LogEntry::Incoming { output: incoming };
        let timestamp = self.push_entry(timestamp, entry)?;
        assert!(self.utxos_list.insert(output_hash, timestamp).is_none());
        Ok(timestamp)
    }

    pub fn lock_input(&mut self, input: &Hash) {
        let time = Instant::now();
        assert!(self
            .locked_inputs
            .insert(*input, LockedInput { time })
            .is_none());
    }

    pub fn is_input_locked(&mut self, input: &Hash) -> Option<&LockedInput> {
        self.locked_inputs.get(input)
    }

    pub fn expire_locked_inputs(&mut self, pending_time: Duration) -> Vec<Hash> {
        let now = Instant::now();
        let mut expired_inputs = Vec::new();
        let pending = std::mem::replace(&mut self.locked_inputs, HashMap::new());
        for (input_hash, p) in pending {
            if p.time + pending_time <= now {
                expired_inputs.push(input_hash);
            } else {
                assert!(self.locked_inputs.insert(input_hash, p).is_none());
            }
        }
        expired_inputs
    }

    /// Insert log entry as last entry in log.
    pub fn push_outgoing(
        &mut self,
        timestamp: Timestamp,
        tx: TransactionValue,
    ) -> Result<Timestamp, Error> {
        let tx_hash = Hash::digest(&tx.tx);
        trace!("Push outgoing tx={}", tx_hash);
        let entry = LogEntry::Outgoing { tx: tx.clone() };
        let timestamp = self.push_entry(timestamp, entry)?;
        assert!(self.created_txs.insert(tx_hash, timestamp).is_none());
        self.update_tx_indexes(tx);
        Ok(timestamp)
    }

    fn push_entry(
        &mut self,
        mut timestamp: Timestamp,
        entry: LogEntry,
    ) -> Result<Timestamp, Error> {
        let log_cf = self.database.cf_handle(HISTORY).expect("cf created");

        let data = entry.into_buffer().expect("couldn't serialize block.");

        // avoid key collisions by increasing time.
        while let Some(_) = self
            .database
            .get_cf(log_cf, &Self::bytes_from_timestamp(timestamp))?
        {
            timestamp += Duration::from_millis(1);
        }

        let mut batch = WriteBatch::default();
        // writebatch put fails if size exceeded u32::max, which is not our case.
        batch.put_cf(log_cf, &Self::bytes_from_timestamp(timestamp), &data)?;
        self.database.write(batch)?;
        Ok(timestamp)
    }

    /// Edit log entry as by idx.
    pub fn update_tx_status(
        &mut self,
        _tx_hash: Hash,
        timestamp: Timestamp,
        status: TransactionStatus,
    ) -> Result<(), Error> {
        let mut updated_tx = None;
        self.update_log_entry(timestamp, |mut e| {
            match &mut e {
                LogEntry::Outgoing { ref mut tx } => {
                    if tx.status != status {
                        tx.status = status.clone();
                        updated_tx = Some(tx.clone());
                    }
                }
                LogEntry::Incoming { .. } => bail!("Expected outgoing transaction."),
            };
            Ok(e)
        })?;

        // If status updated, update indexes.
        if let Some(tx) = updated_tx {
            self.update_tx_indexes(tx);
        }
        Ok(())
    }

    /// For internall usage only create a iter from database .
    fn iter_range_inner<'a>(
        database: &'a DB,
        starting_from: Timestamp,
        limit: u64,
    ) -> impl Iterator<Item = (Timestamp, LogEntry)> + 'a {
        let log_cf = database.cf_handle(HISTORY).expect("cf created");
        let key = Self::bytes_from_timestamp(starting_from);
        let mode = IteratorMode::From(&key, Direction::Forward);
        database
            .iterator_cf(log_cf, mode)
            .expect("cannot open cf")
            .map(|(k, v)| {
                let k = Self::timestamp_from_bytes(&k).expect("parsable time");
                let v = LogEntry::from_buffer(&*v).expect("couldn't deserialize entry.");
                (k, v)
            })
            .take(limit as usize)
    }

    /// List log entries starting from `offset`, limited by `limit`.
    pub fn iter_range<'a>(
        &'a self,
        starting_from: Timestamp,
        limit: u64,
    ) -> impl Iterator<Item = (Timestamp, LogEntry)> + 'a {
        Self::iter_range_inner(&self.database, starting_from, limit)
    }

    //
    // Internal api.
    //

    /// Edit log entry as by idx.
    fn update_log_entry<F>(&mut self, timestamp: Timestamp, mut func: F) -> Result<(), Error>
    where
        F: FnMut(LogEntry) -> Result<LogEntry, Error>,
    {
        let log_cf = self.database.cf_handle(HISTORY).expect("cf created");

        let key = Self::bytes_from_timestamp(timestamp);
        let value = self
            .database
            .get_cf(log_cf, &key)?
            .expect("Log entry not found.");
        let entry = LogEntry::from_buffer(&value)?;

        let entry = func(entry)?;

        let data = entry.into_buffer().expect("couldn't serialize block.");

        let mut batch = WriteBatch::default();
        // writebatch put fails if size exceeded u32::max, which is not our case.
        batch.put_cf(log_cf, &key, &data)?;
        self.database.write(batch)?;

        Ok(())
    }

    /// Convert timestamp to bytearray.
    fn bytes_from_timestamp(timestamp: Timestamp) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        BigEndian::write_u64(&mut bytes[0..8], timestamp.into());
        bytes
    }

    /// Convert bytearray to timestamp.
    fn timestamp_from_bytes(bytes: &[u8]) -> Option<Timestamp> {
        if bytes.len() == 8 {
            let millis = BigEndian::read_u64(&bytes[0..8]);
            Some(millis.into())
        } else {
            None
        }
    }
}

pub struct LockedInput {
    pub time: Instant,
}

/// Information about created transactions
#[derive(Clone, Debug)]
pub struct TransactionValue {
    pub tx: PaymentTransaction,
    pub status: TransactionStatus,
    pub outputs: Vec<OutputValue>,
}

/// Represents Outputs created by account.
/// With extended info about its creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputValue {
    Payment(PaymentValue),
    PublicPayment(PublicPaymentValue),
    Stake(StakeValue),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentValue {
    pub output: PaymentOutput,
    pub amount: i64,
    /// Uncloaked public key of the owner
    pub recipient: scc::PublicKey,
    pub data: PaymentPayloadData,
    pub rvalue: Option<Fr>,
    pub is_change: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPaymentValue {
    pub output: PublicPaymentOutput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeValue {
    pub output: StakeOutput,
    /// Info about stake lock, if epoch is less than current, stake is free to unstake.
    ///
    /// This value is used for StakeOutput that is committed in chain,
    /// and for out of chain (in uncommitted transaction), that's why its optional.
    pub active_until_epoch: Option<u64>,
}

impl TransactionValue {
    pub fn new_payment(tx: PaymentTransaction, outputs: Vec<OutputValue>) -> TransactionValue {
        assert!(tx.txouts.len() <= 2);
        assert_eq!(tx.txouts.len(), outputs.len());

        TransactionValue {
            outputs,
            tx,
            status: TransactionStatus::Created {},
        }
    }

    pub fn new_cloak(tx: PaymentTransaction, output: OutputValue) -> TransactionValue {
        assert_eq!(tx.txouts.len(), 1);

        TransactionValue {
            outputs: vec![output],
            tx,
            status: TransactionStatus::Created {},
        }
    }

    pub fn new_stake(tx: PaymentTransaction, outputs: Vec<OutputValue>) -> TransactionValue {
        TransactionValue {
            outputs,
            tx,
            status: TransactionStatus::Created {},
        }
    }
}

impl OutputValue {
    fn is_change(&self) -> bool {
        match self {
            // Change only possible in PaymentUtxo.
            OutputValue::Payment(p) => p.is_change,
            _ => false,
        }
    }

    pub fn payment(self) -> Option<PaymentValue> {
        match self {
            OutputValue::Payment(p) => Some(p),
            _ => None,
        }
    }

    pub fn public_payment(self) -> Option<PublicPaymentValue> {
        match self {
            OutputValue::PublicPayment(p) => Some(p),
            _ => None,
        }
    }

    pub fn stake(self) -> Option<StakeValue> {
        match self {
            OutputValue::Stake(s) => Some(s),
            _ => None,
        }
    }
}

//
// Converting to api.
//

impl TransactionValue {
    pub fn to_info(&self, current_epoch: u64) -> TransactionInfo {
        let tx_hash = Hash::digest(&self.tx);

        // merge output with extended info.
        let outputs = self
            .outputs
            .iter()
            .map(|e| e.to_info(current_epoch))
            .collect();

        TransactionInfo {
            tx_hash,
            outputs,
            fee: self.tx.fee,
            inputs: self.tx.txins.clone(),
            status: self.status.clone(),
        }
    }
}

/// Convert Time from instant to timestamp, for visualise in API.
fn pending_timestamp(pending: Option<&LockedInput>) -> Option<Timestamp> {
    pending.and_then(|p| {
        let now = Instant::now();
        if p.time + super::PENDING_UTXO_TIME < now {
            return None;
        }
        let duration_to_end = p.time + super::PENDING_UTXO_TIME - now;
        Some(Timestamp::now() + duration_to_end)
    })
}

impl PaymentValue {
    pub fn to_info(&self, pending: Option<&LockedInput>) -> PaymentInfo {
        let pending_timestamp = pending_timestamp(pending);
        PaymentInfo {
            output_hash: Hash::digest(&self.output),
            amount: self.amount,
            data: self.data.clone(),
            pending_timestamp,
            recipient: self.recipient,
            rvalue: self.rvalue.clone(),
            is_change: self.is_change,
        }
    }
}

impl PublicPaymentValue {
    pub fn to_info(&self, pending: Option<&LockedInput>) -> PublicPaymentInfo {
        let pending_timestamp = pending_timestamp(pending);
        PublicPaymentInfo {
            output_hash: Hash::digest(&self.output),
            amount: self.output.amount,
            pending_timestamp,
            recipient: self.output.recipient,
        }
    }
}

impl StakeValue {
    pub fn to_info(&self, epoch: u64) -> StakeInfo {
        let is_active = self
            .active_until_epoch
            .map(|active_until_epoch| active_until_epoch >= epoch);
        StakeInfo {
            account_pkey: self.output.recipient,
            output_hash: Hash::digest(&self.output),
            amount: self.output.amount,
            active_until_epoch: self.active_until_epoch,
            is_active,
        }
    }
}

impl OutputValue {
    pub fn to_info(&self, epoch: u64) -> OutputInfo {
        match self {
            OutputValue::Payment(o) => o.to_info(None).into(),
            OutputValue::PublicPayment(o) => o.to_info(None).into(),
            OutputValue::Stake(o) => o.to_info(epoch).into(),
        }
    }

    pub fn to_output(&self) -> Output {
        match self {
            OutputValue::Payment(o) => o.output.clone().into(),
            OutputValue::PublicPayment(o) => o.output.clone().into(),
            OutputValue::Stake(o) => o.output.clone().into(),
        }
    }
}

//
// Converting implementation
//

impl From<PaymentValue> for OutputValue {
    fn from(value: PaymentValue) -> OutputValue {
        OutputValue::Payment(value)
    }
}

impl From<PublicPaymentValue> for OutputValue {
    fn from(value: PublicPaymentValue) -> OutputValue {
        OutputValue::PublicPayment(value)
    }
}

impl From<StakeValue> for OutputValue {
    fn from(value: StakeValue) -> OutputValue {
        OutputValue::Stake(value)
    }
}

//
// Hashable implementations
//

impl Hashable for TransactionValue {
    fn hash(&self, hasher: &mut Hasher) {
        self.tx.hash(hasher);
        self.status.hash(hasher);
        for output in &self.outputs {
            output.hash(hasher);
        }
    }
}

impl Hashable for OutputValue {
    fn hash(&self, hasher: &mut Hasher) {
        match self {
            OutputValue::Payment(v) => v.hash(hasher),
            OutputValue::PublicPayment(v) => v.hash(hasher),
            OutputValue::Stake(v) => v.hash(hasher),
        }
    }
}

impl Hashable for PaymentValue {
    fn hash(&self, hasher: &mut Hasher) {
        self.output.hash(hasher);
        self.amount.hash(hasher);
        self.recipient.hash(hasher);
        self.data.hash(hasher);
        self.is_change.hash(hasher);
        self.rvalue.hash(hasher);
    }
}

impl Hashable for PublicPaymentValue {
    fn hash(&self, hasher: &mut Hasher) {
        self.output.hash(hasher);
    }
}

impl Hashable for StakeValue {
    fn hash(&self, hasher: &mut Hasher) {
        self.output.hash(hasher);
        self.active_until_epoch.hash(hasher);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use stegos_blockchain::test::fake_genesis;
    use stegos_crypto::scc;
    use tempdir::TempDir;

    impl LightDatabase {
        fn testing(path: &Path) -> LightDatabase {
            let genesis_hash = Hash::digest("ignored");
            let cfg = ChainConfig::default();
            LightDatabase::open(path, genesis_hash, cfg)
        }
    }

    impl LogEntry {
        #[allow(unused)]
        fn testing_stub(id: usize) -> LogEntry {
            let (_s, p) = scc::make_random_keys();
            let output = PublicPaymentOutput::new(&p, id as i64);
            let public = PublicPaymentValue { output };

            LogEntry::Incoming {
                output: OutputValue::PublicPayment(public),
            }
        }

        #[allow(unused)]
        fn is_testing_stub(&self, id: usize) -> bool {
            match self {
                LogEntry::Incoming {
                    output: OutputValue::PublicPayment(value),
                    ..
                } => value.output.amount == id as i64,
                _ => false,
            }
        }
    }

    fn create_entry(id: usize) -> (Timestamp, LogEntry) {
        let time = Timestamp::UNIX_EPOCH + Duration::from_millis(id as u64 + 1);
        let entry = LogEntry::testing_stub(id);
        (time, entry)
    }

    #[test]
    fn smoke_test() {
        let _ = simple_logger::init();

        let entries: Vec<_> = (0..5).map(create_entry).collect();

        let temp_dir = TempDir::new("account").expect("couldn't create temp dir");
        let mut db = LightDatabase::testing(temp_dir.path());
        for (time, e) in entries.iter() {
            db.push_entry(*time, e.clone()).unwrap();
        }

        // ignore that limit 10, still return 5 items
        for ((id, (t, ref saved)), (time2, _)) in db
            .iter_range(Timestamp::UNIX_EPOCH, 10)
            .enumerate()
            .zip(entries.iter())
        {
            debug!("saved = {:?}", saved);
            assert!(saved.is_testing_stub(id));
            assert_eq!(&t, time2);
        }
    }

    #[test]
    fn iter_order_bytes() {
        let _ = simple_logger::init();

        let entries: Vec<_> = (0..256).map(create_entry).collect();

        let temp_dir = TempDir::new("account").expect("couldn't create temp dir");
        let genesis_hash = Hash::digest("ignored");
        let cfg = ChainConfig::default();
        let mut db = LightDatabase::open(temp_dir.path(), genesis_hash, cfg);
        for (time, e) in entries.iter() {
            db.push_entry(*time, e.clone()).unwrap();
        }

        for ((id, (t, ref saved)), (time2, _)) in db
            .iter_range(Timestamp::UNIX_EPOCH, 1000)
            .enumerate()
            .zip(entries.iter())
        {
            debug!("saved = {:?}", saved);
            assert!(saved.is_testing_stub(id));
            assert_eq!(&t, time2);
        }
    }

    #[test]
    fn push_duplicate_time() {
        let _ = simple_logger::init();

        let entries: Vec<_> = (0..2).map(create_entry).collect();
        let time = Timestamp::UNIX_EPOCH + Duration::from_millis(5);
        let temp_dir = TempDir::new("account").expect("couldn't create temp dir");
        let mut db = LightDatabase::testing(temp_dir.path());
        for (_, e) in entries.iter() {
            db.push_entry(time, e.clone()).unwrap();
        }

        for (id, (t, ref saved)) in db.iter_range(Timestamp::UNIX_EPOCH, 5).enumerate() {
            debug!("saved = {:?}", saved);
            assert!(saved.is_testing_stub(id));
            assert_eq!(t, time + Duration::from_millis(id as u64));
        }
    }

    #[test]
    fn basic() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let timestamp = Timestamp::now();
        let cfg: ChainConfig = Default::default();
        let (_keychains, genesis) = fake_genesis(
            cfg.min_stake_amount,
            10 * cfg.min_stake_amount,
            cfg.max_slot_count,
            3,
            timestamp,
            None,
        );
        let chain_dir = TempDir::new("account").expect("couldn't create temp dir");
        let genesis_hash = Hash::digest(&genesis);
        let db = LightDatabase::open(chain_dir.path(), genesis_hash, cfg.clone());
        assert_eq!(db.epoch(), 0);
        assert_eq!(db.offset(), 0);
        assert_eq!(db.last_block_hash(), Hash::digest("genesis"));

        drop(db);
        let db = LightDatabase::open(chain_dir.path(), genesis_hash, cfg.clone());
        // TODO: check
        drop(db);
    }
}

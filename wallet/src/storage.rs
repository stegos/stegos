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

//!
//! Data objects used to store information about transaction, produced outputs, and consumed inputs.
//!

use crate::api::*;
use byteorder::{BigEndian, ByteOrder};
use failure::{bail, Error};
use log::{debug, trace};
use rocksdb::{Direction, IteratorMode, Options, WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::path::Path;
use std::time::{Duration, Instant};
use stegos_blockchain::{
    Output, PaymentOutput, PaymentPayloadData, PaymentTransaction, PublicPaymentOutput,
    RestakeTransaction, StakeOutput, Timestamp,
};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc::{Fr, PublicKey};
use stegos_node::TransactionStatus;
use stegos_serialization::traits::ProtoConvert;
use tempdir::TempDir;

// colon families.
const HISTORY: &'static str = "history";
const UNSPENT: &'static str = "unspent";
const META: &'static str = "meta";
const COLON_FAMILIES: &[&'static str] = &[HISTORY, UNSPENT, META];

// Keys in meta cf
const EPOCH_KEY: &[u8; 9] = b"epoch_key";

#[derive(Debug, Clone)]
pub enum LogEntry {
    Incoming { output: OutputValue },
    Outgoing { tx: TransactionValue },
}

/// Currently we support only transaction that have 2 outputs,
/// one for recipient, and one for change.
pub struct AccountDatabase {
    /// Guard object for temporary directory.
    _temp_dir: Option<TempDir>,
    /// RocksDB database object.
    database: DB,

    //
    // Indexes
    //
    /// Index of epoch UTXOS, that is not final.
    utxos: HashMap<Hash, UnspentOutput>,
    /// Index of UTXOS that known to be change.
    known_changes: HashSet<Hash>,
    /// Index of all created transactions by this wallet.
    utxos_list: HashMap<Hash, Timestamp>,
    /// Index of all created transactions by this wallet.
    created_txs: HashMap<Hash, Timestamp>,
    /// Index of all transactions that wasn't rejected or committed.
    pending_txs: HashSet<Hash>,
    /// Transactions that was created in current epoch.
    epoch_transactions: HashSet<Hash>,
}

//Account log api.
impl AccountDatabase {
    /// Open database.
    pub fn open(path: &Path) -> (AccountDatabase, u64) {
        debug!("Database path = {}", path.to_string_lossy());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let database = DB::open_cf(&opts, path, COLON_FAMILIES).expect("couldn't open database");
        debug!("Loading database");

        let mut log = AccountDatabase {
            _temp_dir: None,
            database,
            created_txs: HashMap::new(),
            pending_txs: HashSet::new(),
            epoch_transactions: HashSet::new(),
            utxos_list: HashMap::new(),
            known_changes: HashSet::new(),
            utxos: HashMap::new(),
        };
        let epoch = log.recover_state();
        (log, epoch)
    }

    #[allow(unused)]
    pub fn testing() -> AccountDatabase {
        let temp_dir = TempDir::new("account").expect("couldn't create temp dir");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let database =
            DB::open_cf(&opts, temp_dir.path(), COLON_FAMILIES).expect("couldn't open database");
        AccountDatabase {
            _temp_dir: Some(temp_dir),
            database,
            created_txs: HashMap::new(),
            pending_txs: HashSet::new(),
            epoch_transactions: HashSet::new(),
            utxos_list: HashMap::new(),
            known_changes: HashSet::new(),
            utxos: HashMap::new(),
        }
    }

    pub fn is_known_changes(&self, utxo: Hash) -> bool {
        let exist = self.known_changes.contains(&utxo);
        trace!("Checking is change = {}, exist={}", utxo, exist);
        exist
    }

    /// Returns id of first unknown epoch
    pub fn recover_state(&mut self) -> u64 {
        // TODO: limit time for recover
        // (for example, if some transaction was created weak ago, it's no reason to resend it)
        let starting_time = Timestamp::UNIX_EPOCH;
        for (timestamp, entry) in self.iter_range(starting_time, u64::max_value()) {
            match entry {
                LogEntry::Incoming { output } => {
                    let output_hash = Hash::digest(&output.to_output());
                    trace!("Recovered output: output={}", output_hash,);
                    assert!(self.utxos_list.insert(output_hash, timestamp).is_none());
                }
                LogEntry::Outgoing { tx } => {
                    let tx_hash = Hash::digest(&tx.tx);
                    let status = tx.status;
                    trace!("Recovered tx: tx={}, status={:?}", tx_hash, status);
                    assert!(self.created_txs.insert(tx_hash, timestamp).is_none());
                    self.update_tx_indexes(tx_hash, status.clone());
                    for utxo in tx.outputs.iter() {
                        if utxo.is_change() {
                            let utxo_hash = Hash::digest(&utxo.to_output());
                            self.known_changes.insert(utxo_hash);
                        }
                    }
                }
            }
        }

        let meta_cf = self.database.cf_handle(META).expect("cf created");

        let epoch = self
            .database
            .get_cf(meta_cf, EPOCH_KEY)
            .expect("cannot read epoch");
        epoch
            .and_then(|b| Self::u64_from_bytes(&b))
            .map(|i| i + 1)
            .unwrap_or(0)
    }

    pub fn iter_unspent<'a>(&'a self) -> impl Iterator<Item = (Hash, OutputValue)> + 'a {
        let cf = self.database.cf_handle(UNSPENT).expect("cf created");

        let mode = IteratorMode::Start;
        let iter = self
            .database
            .iterator_cf(cf, mode)
            .expect("Cannot open cf iterator.");

        let iter = iter.map(|(k, v)| {
            let k = Hash::try_from_bytes(&k).expect("couldn't deserialize entry.");
            let v = OutputValue::from_buffer(&*v).expect("couldn't deserialize entry.");
            (k, v)
        });
        // filter-out utxos that was removed in epoch.
        let iter_filtered = iter
            .filter(move |(hash, _)| self.utxos.get(hash).is_none())
            .inspect(|(k, _)| trace!("Iter UTXO from db = {}", k));
        // add utxos that was not finalized.
        let iter_chained = iter_filtered.chain(
            self.utxos
                .iter()
                .filter_map(|(k, v)| match v {
                    UnspentOutput::Add(v) => Some((k.clone(), v.clone())),
                    UnspentOutput::Removed => None,
                })
                .inspect(|(k, _)| trace!("Iter UTXO from mem = {}", k)),
        );
        // map info about change.
        iter_chained.map(move |(h, mut utxo)| {
            match &mut utxo {
                OutputValue::Payment(ref mut p) => p.is_change = self.known_changes.contains(&h),
                _ => (),
            }
            (h, utxo)
        })
    }

    pub fn insert_unspent(&mut self, utxo: OutputValue) -> Result<(), Error> {
        let key = Hash::digest(&utxo.to_output());
        let utxo = UnspentOutput::Add(utxo);
        self.utxos.insert(key, utxo);
        Ok(())
    }

    pub fn remove_unspent(&mut self, key: &Hash) -> Result<(), Error> {
        trace!("Removed UTXO = {}", key);
        let utxo = UnspentOutput::Removed;
        self.utxos.insert(*key, utxo);
        Ok(())
    }

    pub fn get_unspent(&self, hash: &Hash) -> Result<Option<OutputValue>, Error> {
        trace!("Get UTXO = {}", hash);
        let cf = self.database.cf_handle(UNSPENT).expect("cf created");
        match self.utxos.get(hash) {
            Some(UnspentOutput::Removed) => Ok(None),
            Some(UnspentOutput::Add(t)) => Ok(Some(t.clone())),
            None => {
                trace!("Get UTXO from db = {}", hash);
                self.database
                    .get_cf(cf, hash.base_vector())
                    .map(|v| {
                        v.map(|b| OutputValue::from_buffer(&b).expect("Deserialization error."))
                    })
                    .map_err(Into::into)
            }
        }
    }

    fn update_tx_indexes(&mut self, tx_hash: Hash, status: TransactionStatus) {
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
            }
            _ => {
                trace!("Found status that is final, didn't add transaction to pending list.");
                let _ = self.pending_txs.remove(&tx_hash);
            }
        }
    }

    /// Return iterator over transactions
    pub fn pending_txs<'a>(&'a self) -> impl Iterator<Item = Result<TransactionValue, Error>> + 'a {
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
                LogEntry::Outgoing { tx } => tx,
                _ => panic!("Found link to incomming entry, in transaaction list."),
            })
        })
    }

    /// Returns exact timestamp of created transaction, if tx found.
    pub fn tx_entry(&self, tx_hash: Hash) -> Option<Timestamp> {
        self.created_txs.get(&tx_hash).cloned()
    }

    /// Insert log entry as last entry in log.
    pub fn push_incomming(
        &mut self,
        timestamp: Timestamp,
        incoming: OutputValue,
    ) -> Result<Timestamp, Error> {
        let output_hash = Hash::digest(&incoming.to_output());
        if let Some(time) = self.utxos_list.get(&output_hash) {
            trace!("Skip adding, log already contain output = {}", output_hash);
            return Ok(*time);
        }

        let entry = LogEntry::Incoming { output: incoming };
        let timestamp = self.push_entry(timestamp, entry)?;
        assert!(self.utxos_list.insert(output_hash, timestamp).is_none());
        Ok(timestamp)
    }

    /// Insert log entry as last entry in log.
    pub fn push_outgoing(
        &mut self,
        timestamp: Timestamp,
        tx: TransactionValue,
    ) -> Result<Timestamp, Error> {
        let tx_hash = Hash::digest(&tx.tx);
        let status = tx.status.clone();
        let entry = LogEntry::Outgoing { tx: tx.clone() };
        let timestamp = self.push_entry(timestamp, entry)?;
        assert!(self.created_txs.insert(tx_hash, timestamp).is_none());
        self.update_tx_indexes(tx_hash, status);
        for utxo in tx.outputs.iter() {
            if utxo.is_change() {
                let utxo_hash = Hash::digest(&utxo.to_output());
                self.known_changes.insert(utxo_hash);
            }
        }
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
        tx_hash: Hash,
        timestamp: Timestamp,
        status: TransactionStatus,
    ) -> Result<(), Error> {
        self.update_log_entry(timestamp, |mut e| {
            match &mut e {
                LogEntry::Outgoing { ref mut tx } => {
                    tx.status = status.clone();
                }
                LogEntry::Incoming { .. } => bail!("Expected outgoing transaction."),
            };
            Ok(e)
        })?;

        self.update_tx_indexes(tx_hash, status);
        Ok(())
    }

    /// Finalize Prepare status for transaction, return list of updated transactions
    pub fn finalize_epoch(
        &mut self,
        epoch: u64,
    ) -> Result<HashMap<Hash, TransactionStatus>, Error> {
        debug!("Finalizing unspent utxos");

        let unspent = self.database.cf_handle(UNSPENT).expect("cf created");
        let meta_cf = self.database.cf_handle(META).expect("cf created");

        let our_epoch = self
            .database
            .get_cf(meta_cf, EPOCH_KEY)?
            .and_then(|b| Self::u64_from_bytes(&b))
            .unwrap_or(0);
        let mut batch = WriteBatch::default();
        let utxos = mem::replace(&mut self.utxos, HashMap::new());
        for (hash, utxo) in utxos {
            match utxo {
                UnspentOutput::Removed => {
                    trace!("Found removed utxo = {}", hash);
                    batch.delete_cf(unspent, hash.base_vector())?;
                }
                UnspentOutput::Add(v) => {
                    trace!("Found added utxo = {}", hash);
                    let data = v.into_buffer()?;
                    batch.put_cf(unspent, hash.base_vector(), &data)?;
                }
            }
        }

        batch.put_cf(meta_cf, EPOCH_KEY, &Self::bytes_from_u64(epoch))?;
        self.database.write(batch)?;
        if our_epoch == epoch {
            debug!("Skipping epoch txs finalization");
            return Ok(HashMap::new());
        }
        debug!("Finalize epoch txs");
        let mut result = HashMap::new();
        let txs = std::mem::replace(&mut self.epoch_transactions, Default::default());
        for tx_hash in txs {
            let timestamp = self
                .tx_entry(tx_hash)
                .expect("Transaction should be found in tx list");

            let mut changed_to_status = None;
            self.update_log_entry(timestamp, |mut e| {
                match &mut e {
                    LogEntry::Outgoing { ref mut tx } => match tx.status {
                        TransactionStatus::Prepared { epoch, .. } => {
                            trace!("Finalize tx={}", tx_hash);
                            let status = TransactionStatus::Committed { epoch };
                            tx.status = status.clone();
                            changed_to_status = Some(status);
                        }
                        _ => {}
                    },
                    LogEntry::Incoming { .. } => bail!("Expected outgoing transaction."),
                };
                Ok(e)
            })?;

            if let Some(status) = changed_to_status {
                result.insert(tx_hash, status.clone());
                self.update_tx_indexes(tx_hash, status);
            }
        }
        Ok(result)
    }

    /// List log entries starting from `offset`, limited by `limit`.
    pub fn iter_range(
        &self,
        starting_from: Timestamp,
        limit: u64,
    ) -> impl Iterator<Item = (Timestamp, LogEntry)> {
        let log_cf = self.database.cf_handle(HISTORY).expect("cf created");
        let key = Self::bytes_from_timestamp(starting_from);
        let mode = IteratorMode::From(&key, Direction::Forward);
        self.database
            .iterator_cf(log_cf, mode)
            .expect("cannot open cf")
            .map(|(k, v)| {
                let k = Self::timestamp_from_bytes(&k).expect("parsable time");
                let v = LogEntry::from_buffer(&*v).expect("couldn't deserialize entry.");
                (k, v)
            })
            .take(limit as usize)
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

        trace!("Entry before = {:?}", entry);
        let entry = func(entry)?;

        trace!("Entry after = {:?}", entry);
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

    /// Convert timestamp to bytearray.
    fn bytes_from_u64(len: u64) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        BigEndian::write_u64(&mut bytes[0..8], len);
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

    /// Convert bytearray to timestamp.
    fn u64_from_bytes(bytes: &[u8]) -> Option<u64> {
        if bytes.len() == 8 {
            let idx = BigEndian::read_u64(&bytes[0..8]);
            Some(idx)
        } else {
            None
        }
    }
}

pub struct PendingOutput {
    pub time: Instant,
}

#[derive(Clone, Debug)]
pub enum UnspentOutput {
    Removed,
    Add(OutputValue),
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
    PublicPayment(PublicPaymentOutput),
    Stake(StakeValue),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentValue {
    pub output: PaymentOutput,
    pub amount: i64,
    /// Uncloaked public key of the owner
    pub recipient: PublicKey,
    pub data: PaymentPayloadData,
    pub rvalue: Option<Fr>,
    pub is_change: bool,
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

    pub fn new_snowball(tx: PaymentTransaction, outputs: Vec<OutputValue>) -> TransactionValue {
        assert!(tx.txouts.len() >= 2);
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

    // We didn't track restake transaction, and wont store them on disk.
    // But we still able to give info about this transaction, to api.
    // This method was created to split api serialisation logic from main logic.
    pub fn restake_tx_info(
        tx: RestakeTransaction,
        outputs: Vec<OutputValue>,
        current_epoch: u64,
    ) -> TransactionInfo {
        let tx_hash = Hash::digest(&tx);

        // merge output with extended info.
        let outputs = outputs.iter().map(|e| e.to_info(current_epoch)).collect();

        TransactionInfo {
            tx_hash,
            outputs,
            fee: 0,
            inputs: tx.txins.clone(),
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

    pub fn public_payment(self) -> Option<PublicPaymentOutput> {
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

impl PaymentValue {
    pub fn to_info(&self, pending: Option<&PendingOutput>) -> PaymentInfo {
        // Convert Time from instant to timestamp, for visualise in API.
        let pending_timestamp = pending.and_then(|p| {
            let now = tokio_timer::clock::now();
            if p.time + super::PENDING_UTXO_TIME < now {
                return None;
            }
            let duration_to_end = p.time + super::PENDING_UTXO_TIME - now;
            Some(Timestamp::now() + duration_to_end)
        });

        PaymentInfo {
            utxo: Hash::digest(&self.output),
            amount: self.amount,
            data: self.data.clone(),
            locked_timestamp: self.output.locked_timestamp,
            pending_timestamp,
            recipient: self.recipient,
            rvalue: self.rvalue.clone(),
            is_change: self.is_change,
        }
    }
}

pub fn public_payment_info(output: &PublicPaymentOutput) -> PublicPaymentInfo {
    PublicPaymentInfo {
        utxo: Hash::digest(&output),
        amount: output.amount,
        locked_timestamp: output.locked_timestamp,
    }
}

impl StakeValue {
    pub fn to_info(&self, epoch: u64) -> StakeInfo {
        let is_active = self
            .active_until_epoch
            .map(|active_until_epoch| active_until_epoch >= epoch);
        StakeInfo {
            account_pkey: self.output.recipient,
            utxo: Hash::digest(&self.output),
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
            OutputValue::PublicPayment(o) => public_payment_info(&o).into(),
            OutputValue::Stake(o) => o.to_info(epoch).into(),
        }
    }

    pub fn to_output(&self) -> Output {
        match self {
            OutputValue::Payment(o) => o.output.clone().into(),
            OutputValue::PublicPayment(o) => o.clone().into(),
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

impl From<PublicPaymentOutput> for OutputValue {
    fn from(value: PublicPaymentOutput) -> OutputValue {
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

impl Hashable for StakeValue {
    fn hash(&self, hasher: &mut Hasher) {
        self.output.hash(hasher);
        self.active_until_epoch.hash(hasher);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use stegos_crypto::scc::make_random_keys;
    impl LogEntry {
        #[allow(unused)]
        fn testing_stub(id: usize) -> LogEntry {
            let (_s, p) = make_random_keys();
            let public = PublicPaymentOutput::new(&p, id as i64);

            LogEntry::Incoming {
                output: OutputValue::PublicPayment(public),
            }
        }

        #[allow(unused)]
        fn is_testing_stub(&self, id: usize) -> bool {
            match self {
                LogEntry::Incoming {
                    output: OutputValue::PublicPayment(output),
                    ..
                } => output.amount == id as i64,
                _ => false,
            }
        }
    }

    fn create_entry(id: usize) -> (Timestamp, LogEntry) {
        let time = Timestamp::UNIX_EPOCH + Duration::from_millis(id as u64 + 1);
        let entry = LogEntry::testing_stub(id);
        (time, entry)
    }

    fn create_output(id: usize) -> OutputValue {
        OutputValue::PublicPayment(PublicPaymentOutput {
            serno: id as i64,
            amount: 10,
            locked_timestamp: None,
            recipient: PublicKey::zero(),
        })
    }

    #[test]
    fn smoke_test() {
        let _ = simple_logger::init();

        let entries: Vec<_> = (0..5).map(create_entry).collect();

        let mut db = AccountDatabase::testing();
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

        let mut db = AccountDatabase::testing();
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
        let mut db = AccountDatabase::testing();
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
    fn push_output_get_iter() {
        let _ = simple_logger::init();

        let outputs: Vec<_> = (0..2).map(create_output).collect();
        let mut db = AccountDatabase::testing();
        for output in outputs.iter() {
            db.insert_unspent(output.clone()).unwrap();
        }

        for (t, ref saved) in db.iter_unspent() {
            debug!("saved = {:?}", saved);
            assert_eq!(t, Hash::digest(&saved.to_output()));
        }
        let _ = db.finalize_epoch(1).unwrap();

        for (t, ref saved) in db.iter_unspent() {
            debug!("saved = {:?}", saved);
            assert_eq!(t, Hash::digest(&saved.to_output()));
        }
    }
}

//! Blockchain definition.

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

use crate::block::*;
use crate::config::*;
use crate::election::ElectionInfo;
use crate::election::{self, mix, ElectionResult};
use crate::error::*;
use crate::escrow::*;
use crate::merkle::*;
use crate::metrics;
use crate::multisignature::create_multi_signature;
use crate::mvcc::MultiVersionedMap;
use crate::output::*;
use crate::storage::ListDb;
use crate::transaction::{CoinbaseTransaction, PaymentTransaction, Transaction};
use crate::view_changes::ViewChangeProof;
use failure::Error;
use log::*;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use stegos_crypto::bulletproofs::fee_a;
use stegos_crypto::curve1174::{ECp, Fr, PublicKey, SecretKey, G};
use stegos_crypto::hash::*;
use stegos_crypto::pbc;
use stegos_keychain::KeyChain;

pub type ViewCounter = u32;
pub type ValidatorId = u32;

/// Information of current chain, that is used as proof of viewchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainInfo {
    pub height: u64,
    pub view_change: ViewCounter,
    pub last_block: Hash,
}

impl ChainInfo {
    /// Create ChainInfo from micro block.
    /// ## Panics
    /// if view_change is equal to 0
    pub fn from_micro_block(micro_block: &MicroBlock) -> Self {
        assert_ne!(micro_block.base.view_change, 0);
        ChainInfo {
            height: micro_block.base.height,
            view_change: micro_block.base.view_change - 1,
            last_block: micro_block.base.previous,
        }
    }

    /// Create ChainInfo from blockchain.
    pub fn from_blockchain(blockchain: &Blockchain) -> Self {
        ChainInfo {
            height: blockchain.height(),
            view_change: blockchain.view_change(),
            last_block: blockchain.last_block_hash(),
        }
    }
}

impl Hashable for ChainInfo {
    fn hash(&self, hasher: &mut Hasher) {
        self.height.hash(hasher);
        self.view_change.hash(hasher);
        self.last_block.hash(hasher);
    }
}

/// A helper to find UTXO in this blockchain.
#[derive(Debug, Clone)]
enum OutputKey {
    MacroBlock {
        /// Block Height.
        height: u64,
        /// Merkle Tree path inside block.
        path: MerklePath,
    },
    MicroBlock {
        /// Block Height.
        height: u64,
        /// Transaction number.
        tx_id: u32,
        /// Output number.
        txout_id: u32,
    },
}

/// A helper to store the global monetary balance in MultiVersionedMap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Balance {
    /// The total sum of money created.
    pub created: ECp,
    /// The total sum of money burned.
    pub burned: ECp,
    /// The total sum of gamma adjustments.
    pub gamma: Fr,
    /// The total sum of block rewards.
    pub block_reward: i64,
}

type BlockByHashMap = MultiVersionedMap<Hash, u64, u64>;
type OutputByHashMap = MultiVersionedMap<Hash, OutputKey, u64>;
type BalanceMap = MultiVersionedMap<(), Balance, u64>;

/// The blockchain database.
pub struct Blockchain {
    //
    // Configuration.
    //
    cfg: BlockchainConfig,

    //
    // Storage.
    //
    /// Persistent storage for blocks.
    database: ListDb,
    /// In-memory index to lookup blocks by its hash.
    block_by_hash: BlockByHashMap,
    /// In-memory index to lookup UTXO by its hash.
    output_by_hash: OutputByHashMap,
    /// Global monetary balance.
    balance: BalanceMap,
    /// In-memory storage of stakes.
    escrow: Escrow,

    //
    // Epoch Information.
    //
    /// Monotonically increasing 1-indexed identifier of the current epoch.
    /// Equals to the number of macro blocks in the blockchain.
    /// 1-based indexed - the genetic macro block starts epoch #1.
    epoch: u64,
    /// Zero-indexed identifier of the last macro block.
    last_macro_block_height: u64,
    /// A timestamp from the last macro block.
    last_macro_block_timestamp: SystemTime,
    /// Last election result.
    election_result: ElectionResult,
    //
    // Consensus information.
    //
    /// Last saved view change, if view change was happen at current height,
    /// and we was not leader.
    view_change_proof: Option<ViewChangeProof>,

    //
    // Height Information.
    //
    /// The number of blocks in this blockchain.
    height: u64,
    /// Copy of a block hash from the latest registered block.
    last_block_hash: Hash,
}

impl Blockchain {
    //----------------------------------------------------------------------------------------------
    // Constructors.
    //----------------------------------------------------------------------------------------------

    pub fn new(
        cfg: BlockchainConfig,
        storage_cfg: StorageConfig,
        genesis: Vec<Block>,
        timestamp: SystemTime,
    ) -> Result<Blockchain, Error> {
        let database = ListDb::new(&storage_cfg.database_path);
        Self::with_db(cfg, database, genesis, timestamp)
    }

    pub fn testing(
        cfg: BlockchainConfig,
        genesis: Vec<Block>,
        timestamp: SystemTime,
    ) -> Result<Blockchain, Error> {
        let database = ListDb::testing();
        Self::with_db(cfg, database, genesis, timestamp)
    }

    fn with_db(
        cfg: BlockchainConfig,
        database: ListDb,
        genesis: Vec<Block>,
        timestamp: SystemTime,
    ) -> Result<Blockchain, Error> {
        //
        // Storage.
        //
        let block_by_hash: BlockByHashMap = BlockByHashMap::new();
        let output_by_hash: OutputByHashMap = OutputByHashMap::new();
        let mut balance: BalanceMap = BalanceMap::new();
        let initial_balance = Balance {
            created: ECp::inf(),
            burned: ECp::inf(),
            gamma: Fr::zero(),
            block_reward: 0,
        };
        balance.insert(0, (), initial_balance);
        let escrow = Escrow::new();

        //
        // Epoch Information.
        //
        let epoch: u64 = 0;
        let last_macro_block_height: u64 = 0;
        let last_macro_block_timestamp = UNIX_EPOCH;
        let election_result = ElectionResult::default();

        //
        // Consensus information.
        //
        let view_change_proof = None;
        //
        // Height Information.
        //
        let height: u64 = 0;
        let last_block_hash = Hash::digest("genesis");

        let mut blockchain = Blockchain {
            cfg,
            database,
            block_by_hash,
            output_by_hash,
            balance,
            escrow,
            epoch,
            last_macro_block_height,
            last_macro_block_timestamp,
            election_result,
            view_change_proof,
            height,
            last_block_hash,
        };

        blockchain.recover(genesis, timestamp)?;
        Ok(blockchain)
    }

    //----------------------------------------------------------------------------------------------
    // Recovery.
    //----------------------------------------------------------------------------------------------

    fn recover(&mut self, genesis: Vec<Block>, timestamp: SystemTime) -> Result<(), Error> {
        let mut blocks = self.database.iter();

        let block = blocks.next();
        let block = if let Some(block) = block {
            block
        } else {
            debug!("Creating a new blockchain...");
            for block in genesis {
                match block {
                    Block::MicroBlock(micro_block) => {
                        self.push_micro_block(micro_block, timestamp)?;
                    }
                    Block::MacroBlock(macro_block) => {
                        self.push_macro_block(macro_block, timestamp)?
                    }
                }
            }
            info!(
                "Initialized a new blockchain: height={}, last_block={}",
                self.height, self.last_block_hash
            );
            return Ok(());
        };

        info!("Recovering blockchain from the disk...");

        // Recover genesis.
        self.recover_block(block, timestamp)?;

        // Check genesis.
        let genesis_hash = Hash::digest(&genesis[0]);
        if genesis_hash != self.last_block_hash() {
            return Err(BlockchainError::IncompatibleChain(
                genesis[0].base_header().height,
                genesis_hash,
                self.last_block_hash(),
            )
            .into());
        }

        // Recover remaining blocks.
        for block in blocks {
            self.recover_block(block, timestamp)?;
        }

        info!(
            "Recovered blockchain from the disk: height={}, last_block={}",
            self.height, self.last_block_hash
        );

        Ok(())
    }

    fn recover_block(&mut self, block: Block, timestamp: SystemTime) -> Result<(), Error> {
        debug!(
            "Recovering a block from the disk: height={}, block={}",
            block.base_header().height,
            Hash::digest(&block)
        );
        // Skip validate_macro_block()/validate_micro_block().
        match block {
            Block::MicroBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_micro_block(&block, timestamp)?
                }
                let _ = self.register_micro_block(block, timestamp);
            }
            Block::MacroBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_macro_block(&block, timestamp)?
                }
                let _ = self.register_macro_block(block, timestamp);
            }
        }
        Ok(())
    }

    /// Helper for recover_wallet()
    fn check_wallet_output(&self, skey: &SecretKey, pkey: &PublicKey, output: &Output) -> bool {
        let output_hash = Hash::digest(&output);
        if !self.contains_output(&output_hash) {
            return false; // Spent.
        }
        output.is_my_utxo(skey, pkey)
    }

    ///
    /// Recovery wallet state from the blockchain.
    /// TODO: this method is a temporary solution until persistence is implemented in wallet.
    /// https://github.com/stegos/stegos/issues/812
    ///
    pub fn recover_wallet(
        &self,
        skey: &SecretKey,
        pkey: &PublicKey,
    ) -> Result<Vec<(Output, u64)>, Error> {
        let mut wallet_state: Vec<(Output, u64)> = Vec::new();
        let mut epoch: u64 = 0;
        for block in self.database.iter_starting(0) {
            match block {
                Block::MacroBlock(block) => {
                    for (output, _) in block.body.outputs.leafs() {
                        if self.check_wallet_output(skey, pkey, &output) {
                            wallet_state.push((output.as_ref().clone(), epoch));
                        }
                    }
                    epoch += 1;
                }
                Block::MicroBlock(block) => {
                    for tx in block.transactions {
                        for output in tx.txouts() {
                            if self.check_wallet_output(skey, pkey, &output) {
                                wallet_state.push((output.clone(), epoch));
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(epoch, self.epoch);
        Ok(wallet_state)
    }

    //
    // Info
    //
    pub fn election_info(&self) -> ElectionInfo {
        ElectionInfo {
            height: self.height,
            view_change: self.view_change(),
            slots_count: self.cfg.max_slot_count as i64,
            current_leader: self.select_leader(self.view_change()),
            next_leader: self.select_leader(self.view_change() + 1),
        }
    }
    //----------------------------------------------------------------------------------------------
    // Database API.
    //----------------------------------------------------------------------------------------------

    /// Returns the number of blocks in the current epoch.
    pub fn blocks_in_epoch(&self) -> u64 {
        // Include the macro block itself.
        self.height - self.last_macro_block_height
    }

    /// Returns an iterator over UTXO hashes.
    pub fn unspent(&self) -> impl Iterator<Item = &Hash> {
        self.output_by_hash.keys()
    }

    /// Returns true if blockchain contains unspent output.
    pub fn contains_output(&self, output_hash: &Hash) -> bool {
        self.output_by_hash.get(output_hash).is_some()
    }

    /// Resolve UTXO by hash.
    pub fn output_by_hash(&self, output_hash: &Hash) -> Result<Option<Output>, Error> {
        match self.output_by_hash.get(output_hash) {
            Some(OutputKey::MacroBlock { height, path }) => {
                let block = &self.block_by_height(*height)?;
                match block {
                    Block::MacroBlock(MacroBlock { ref body, .. }) => {
                        if let Some(output) = body.outputs.lookup(path) {
                            Ok(Some(output.as_ref().clone()))
                        } else {
                            Ok(None) // Pruned.
                        }
                    }
                    Block::MicroBlock(_) => panic!("Corrupted outputs_by_hash (Macro-0)"),
                }
            }
            Some(OutputKey::MicroBlock {
                height,
                tx_id,
                txout_id,
            }) => {
                let block = &self.block_by_height(*height)?;
                match block {
                    Block::MacroBlock(_) => panic!("Corrupted outputs_by_hash (Micro-0)"),
                    Block::MicroBlock(MicroBlock {
                        ref transactions, ..
                    }) => {
                        let tx = transactions
                            .get(*tx_id as usize)
                            .expect("Corrupted outputs_by_hash (Micro-2)");
                        let output = tx
                            .txouts()
                            .get(*txout_id as usize)
                            .expect("Corrupted outputs_by_hash (Micro-3)");
                        Ok(Some(output.clone()))
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Checks whether a block exists or not.
    pub fn contains_block(&self, block_hash: &Hash) -> bool {
        if let Some(_height) = self.block_by_hash.get(block_hash) {
            return true;
        }
        return false;
    }

    /// Get a block by height.
    pub fn block_by_height(&self, height: u64) -> Result<Block, Error> {
        assert!(height < self.height);
        Ok((self.database.get(height)?).expect("block exists"))
    }

    /// Return iterator over saved blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Block> {
        self.database.iter()
    }

    /// Returns blocks history starting from block_hash + 1, limited by count.
    pub fn blocks_range(&self, starting_height: u64, count: u64) -> Vec<Block> {
        self.database
            .iter_starting(starting_height)
            .take(count as usize)
            .collect()
    }

    /// Return the last block.
    pub fn last_block(&self) -> Result<Block, Error> {
        assert!(self.height > 0);
        Ok(self.database.get(self.height - 1)?.expect("block exists"))
    }

    /// Return leader public key for specific view_change number.
    pub fn select_leader(&self, view_change: ViewCounter) -> pbc::PublicKey {
        self.election_result.select_leader(view_change)
    }

    /// Returns public key of the active leader.
    pub fn leader(&self) -> pbc::PublicKey {
        self.select_leader(self.view_change())
    }

    /// Return the current epoch facilitator.
    #[inline]
    pub fn facilitator(&self) -> &pbc::PublicKey {
        &self.election_result.facilitator
    }

    /// Return the current epoch validators with their stakes.
    #[inline]
    pub fn validators(&self) -> &Vec<(pbc::PublicKey, i64)> {
        &self.election_result.validators
    }

    /// Returns true if peer is validator in current epoch.
    #[inline]
    pub fn is_validator(&self, peer: &pbc::PublicKey) -> bool {
        self.validators()
            .iter()
            .find(|item| item.0 == *peer)
            .is_some()
    }

    /// Returns the last block height.
    #[inline]
    pub fn last_macro_block_height(&self) -> u64 {
        self.last_macro_block_height
    }

    /// Return the timestamp from the last macro block.
    #[inline]
    pub fn last_macro_block_timestamp(&self) -> SystemTime {
        self.last_macro_block_timestamp
    }

    /// Return the last random value.
    #[inline]
    pub fn last_random(&self) -> Hash {
        self.election_result.random.rand
    }

    /// Return the last block hash.
    #[inline(always)]
    pub fn last_block_hash(&self) -> Hash {
        assert!(self.height > 0);
        self.last_block_hash
    }

    /// Return the current blockchain height.
    #[inline(always)]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Return the current blockchain epoch.
    #[inline(always)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    ///
    /// Get staked value for validator.
    ///
    /// Returns (active_balance, expired_balance) stake.
    ///
    #[inline]
    pub(crate) fn get_stake(&self, validator_pkey: &pbc::PublicKey) -> (i64, i64) {
        self.escrow.get(validator_pkey, self.epoch)
    }

    ///
    /// Get staked value for validator.
    ///
    /// Returns (active_balance, expired_balance) stake.
    ///
    #[inline]
    pub(crate) fn staker_outputs(&self, validator_pkey: &pbc::PublicKey) -> (Vec<Hash>, i64) {
        self.escrow.staker_outputs(validator_pkey, self.epoch)
    }
    /// Return information about escrow.
    #[inline]
    pub fn escrow_info(&self) -> EscrowInfo {
        self.escrow.info(self.epoch)
    }

    /// Returns balance.
    #[inline]
    pub(crate) fn balance(&self) -> &Balance {
        &self.balance.get(&()).unwrap()
    }

    /// Returns number of leader changes since last epoch creation.
    #[inline]
    pub fn view_change(&self) -> u32 {
        self.election_result.view_change
    }

    /// Returns proof of last view change, if it happen on current height.
    pub fn view_change_proof(&self) -> &Option<ViewChangeProof> {
        &self.view_change_proof
    }

    /// Returns number of total slots in current epoch.
    /// Internally always return cfg.max_slot_count
    pub fn total_slots(&self) -> i64 {
        self.cfg.max_slot_count
    }
    /// Sets new blockchain view_change.
    /// ## Panics
    /// if new_view_change not greater than current.
    #[inline]
    pub fn set_view_change(&mut self, new_view_change: u32, proof: ViewChangeProof) {
        assert!(self.view_change() < new_view_change);
        self.election_result.view_change = new_view_change;
        self.view_change_proof = Some(proof);
    }

    /// Resets current view change counter.
    pub fn reset_view_change(&mut self) {
        self.election_result.view_change = 0;
        self.view_change_proof = None;
    }

    ///
    /// Check if some of validator was caught on cheating in current epoch.
    /// Returns proof of cheating.
    ///
    pub fn validator_wallet(&self, peer: &pbc::PublicKey) -> Option<PublicKey> {
        self.escrow
            .get_first_output(peer)
            .map(|hash| match self.output_by_hash(&hash) {
                Ok(Some(Output::StakeOutput(s))) => s.recipient,
                e => panic!("Expected stake output, found = {:?}", e),
            })
    }

    pub fn election_result(&self) -> ElectionResult {
        self.election_result.clone()
    }

    /// Return election result, for specific moment of history, in past.
    pub fn election_result_by_height(
        &self,
        height: u64,
    ) -> Result<ElectionResult, BlockchainError> {
        assert!(
            height > self.last_macro_block_height(),
            "Election info for past epoch."
        );
        assert!(height < self.height(), "Election info from future height.");
        let mut election = self.election_result();
        let block = self.block_by_height(height - 1)?;
        election.random = block.base_header().random;
        Ok(election)
    }

    //----------------------------------------------------------------------------------------------
    // Macro Blocks
    //----------------------------------------------------------------------------------------------

    ///
    /// Add a new block into blockchain.
    ///
    pub fn push_macro_block(
        &mut self,
        block: MacroBlock,
        timestamp: SystemTime,
    ) -> Result<(), BlockchainError> {
        //
        // Validate the macro block.
        //
        self.validate_macro_block(&block, timestamp)?;

        //
        // Write the macro block to the disk.
        //
        self.database
            .insert(self.height, Block::MacroBlock(block.clone()))?;

        //
        // Update in-memory indexes and metadata.
        //
        self.register_macro_block(block, timestamp)?;

        Ok(())
    }

    ///
    /// Update indexes and metadata.
    ///
    fn register_macro_block(
        &mut self,
        block: MacroBlock,
        timestamp: SystemTime,
    ) -> Result<(Vec<Output>, Vec<Output>), BlockchainError> {
        let block_hash = Hash::digest(&block);
        assert_eq!(self.height, block.header.base.height);
        let height = self.height;

        //
        // Prepare inputs.
        //
        let input_hashes = block.body.inputs;
        let mut inputs: Vec<Output> = Vec::with_capacity(input_hashes.len());
        for input_hash in &input_hashes {
            let input = self.output_by_hash(input_hash)?.expect("Missing output");
            inputs.push(input);
        }

        //
        // Prepare outputs.
        //
        let mut outputs: Vec<Output> = Vec::new();
        let mut output_keys: Vec<OutputKey> = Vec::new();
        for (output, path) in block.body.outputs.leafs() {
            let output = output.as_ref().clone();
            outputs.push(output);
            let output_key = OutputKey::MacroBlock {
                height: self.height,
                path,
            };
            output_keys.push(output_key);
        }

        //
        // Register block.
        //
        self.register_block(
            block_hash,
            input_hashes,
            &inputs,
            output_keys,
            &outputs,
            block.header.gamma,
            block.header.block_reward,
            block.header.base.random,
            timestamp,
        );

        //
        // Update metadata.
        //
        self.epoch += 1;
        self.last_macro_block_height = height;
        self.last_macro_block_timestamp = block.header.base.timestamp;
        self.election_result = election::select_validators_slots(
            self.escrow
                .get_stakers_majority(self.epoch, self.cfg.min_stake_amount),
            block.header.base.random,
            self.cfg.max_slot_count,
        );
        metrics::EPOCH.inc();

        info!(
            "Registered a macro block: height={}, block={}",
            height, block_hash
        );
        debug!("Validators: {:?}", &self.validators());
        for (key, stake) in self.validators().iter() {
            let key_str = key.to_string();
            metrics::VALIDATOR_STAKE_GAUGEVEC
                .with_label_values(&[key_str.as_str()])
                .set(*stake);
        }

        //
        // Finalize storage.
        //
        self.block_by_hash.checkpoint();
        self.output_by_hash.checkpoint();
        self.balance.checkpoint();
        self.escrow.checkpoint();

        Ok((inputs, outputs))
    }

    // ---------------------------------------------------------------------------------------------
    // Micro Blocks
    // ---------------------------------------------------------------------------------------------

    ///
    /// Add a new micro block into blockchain.
    ///
    pub fn push_micro_block(
        &mut self,
        block: MicroBlock,
        timestamp: SystemTime,
    ) -> Result<(Vec<Output>, Vec<Output>), BlockchainError> {
        //
        // Validate the micro block.
        //
        self.validate_micro_block(&block, timestamp)?;

        //
        // Write the micro block to the disk.
        //
        self.database
            .insert(self.height, Block::MicroBlock(block.clone()))?;

        //
        // Update in-memory indexes and metadata.
        //
        let (inputs, outputs) = self.register_micro_block(block, timestamp)?;

        Ok((inputs, outputs))
    }

    ///
    /// Common part of register_macro_block()/register_micro_block().
    ///
    fn register_block(
        &mut self,
        block_hash: Hash,
        input_hashes: Vec<Hash>,
        inputs: &[Output],
        output_keys: Vec<OutputKey>,
        outputs: &[Output],
        gamma: Fr,
        block_reward: i64,
        random: pbc::VRF,
        _timestamp: SystemTime,
    ) {
        let version = self.height + 1;
        let height = self.height;

        //
        // Update block_by_hash index.
        //
        if let Some(_) = self.block_by_hash.insert(version, block_hash, height) {
            panic!(
                "Block hash collision: height={}, block={}",
                height, block_hash
            );
        }
        assert_eq!(self.block_by_hash.current_version(), version);

        let mut burned = ECp::inf();
        let mut created = ECp::inf();

        //
        // Process inputs.
        //
        for (input_hash, input) in input_hashes.iter().zip(inputs) {
            debug_assert_eq!(input_hash, &Hash::digest(input));
            if self.output_by_hash.remove(version, input_hash).is_none() {
                panic!(
                    "Missing input UTXO: height={}, block={}, utxo={}",
                    height, block_hash, &input_hash
                );
            }

            input.validate().expect("valid UTXO");
            burned += input
                .pedersen_commitment()
                .expect("valid Pedersen commitment");

            match input {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    self.escrow
                        .unstake(version, o.validator, input_hash.clone(), self.epoch);
                    assert_eq!(self.escrow.current_version(), version);
                }
            }

            debug!(
                "Pruned UXTO: height={}, block={}, utxo={}",
                height, block_hash, input_hash
            );
        }

        //
        // Process outputs.
        //
        for (output_key, output) in output_keys.into_iter().zip(outputs) {
            let output_hash = Hash::digest(output);

            // Update indexes.
            if let Some(_) = self
                .output_by_hash
                .insert(version, output_hash.clone(), output_key)
            {
                panic!(
                    "UTXO hash collision: height={}, block={}, utxo={}",
                    height, &block_hash, &output_hash
                );
            }
            assert_eq!(self.output_by_hash.current_version(), version);

            output.validate().expect("valid UTXO");
            created += output
                .pedersen_commitment()
                .expect("valid Pedersen commitment");

            match output {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    self.escrow.stake(
                        version,
                        o.validator,
                        output_hash,
                        self.epoch,
                        self.cfg.stake_epochs,
                        o.amount,
                    );
                    assert_eq!(self.escrow.current_version(), version);
                }
            }

            debug!(
                "Registered UXTO: height={}, block={}, utxo={}",
                height, &block_hash, &output_hash
            );
        }

        //
        // Update monetary balance.
        //

        // Check the block monetary balance.
        if fee_a(block_reward) + burned - created != &gamma * (*G) {
            panic!(
                "Invalid block monetary balance: height={}, block={}",
                height, &block_hash
            )
        }

        // Global monetary balance.
        let orig_balance = self.balance();
        let balance = Balance {
            created: orig_balance.created + created,
            burned: orig_balance.burned + burned,
            gamma: &orig_balance.gamma + gamma,
            block_reward: orig_balance.block_reward + block_reward,
        };
        if fee_a(balance.block_reward) + balance.burned - balance.created != &balance.gamma * (*G) {
            panic!(
                "Invalid global monetary balance: height={}, block={}",
                height, &block_hash
            );
        }
        self.balance.insert(version, (), balance);
        assert_eq!(self.balance.current_version(), version);

        //
        // Update metadata.
        //
        self.last_block_hash = block_hash;
        self.reset_view_change();
        self.election_result.random = random;
        self.height += 1;
        assert_eq!(self.height, version);
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);
    }

    ///
    /// Register a new micro block.
    ///
    fn register_micro_block(
        &mut self,
        block: MicroBlock,
        timestamp: SystemTime,
    ) -> Result<(Vec<Output>, Vec<Output>), BlockchainError> {
        assert_eq!(self.height, block.base.height);
        let height = self.height;
        let block_hash = Hash::digest(&block);

        //
        // Prepare inputs && outputs.
        //
        let mut input_hashes = Vec::new();
        let mut inputs: Vec<Output> = Vec::new();
        let mut output_keys: Vec<OutputKey> = Vec::new();
        let mut outputs: Vec<Output> = Vec::new();
        let mut gamma = Fr::zero();
        let mut block_reward: i64 = 0;
        // Regular transactions.
        for (tx_id, tx) in block.transactions.into_iter().enumerate() {
            assert!(tx_id < std::u32::MAX as usize);
            for input_hash in tx.txins() {
                let input = self.output_by_hash(input_hash)?.expect("Missing output");
                inputs.push(input);
                input_hashes.push(input_hash.clone());
            }
            for (txout_id, output) in tx.txouts().iter().enumerate() {
                assert!(txout_id < std::u32::MAX as usize);
                let output_key = OutputKey::MicroBlock {
                    height,
                    tx_id: tx_id as u32,
                    txout_id: txout_id as u32,
                };
                outputs.push(output.clone());
                output_keys.push(output_key);
            }
            match tx {
                Transaction::CoinbaseTransaction(tx) => {
                    block_reward += tx.block_reward;
                    gamma += tx.gamma;
                }
                Transaction::PaymentTransaction(tx) => {
                    gamma += tx.gamma;
                }
                Transaction::RestakeTransaction(_tx) => {}
                Transaction::SlashingTransaction(tx) => {
                    info!(
                        "Found slashing transaction, removing validator, from list: cheater={}",
                        tx.cheater()
                    );
                    let validators =
                        std::mem::replace(&mut self.election_result.validators, Vec::new());
                    // remove cheater for current epoch.
                    self.election_result.validators = validators
                        .into_iter()
                        .filter(|(k, _)| k != &tx.cheater())
                        .collect();
                }
            }
        }

        //
        // Register block.
        //
        self.register_block(
            block_hash,
            input_hashes,
            &inputs,
            output_keys,
            &outputs,
            gamma,
            block_reward,
            block.base.random,
            timestamp,
        );

        //
        // Update metadata.
        //
        self.election_result.view_change = 0;
        self.election_result.random = block.base.random;

        info!(
            "Registered a micro block: height={}, block={}, inputs={}, outputs={}",
            height,
            block_hash,
            inputs.len(),
            outputs.len()
        );

        Ok((inputs, outputs))
    }

    pub fn pop_micro_block(&mut self) -> Result<(Vec<Output>, Vec<Output>), BlockchainError> {
        assert!(self.height > 1);
        let height = self.height - 1;
        assert_ne!(
            height, self.last_macro_block_height,
            "attempt to revert the macro block"
        );
        let version = height;

        //
        // Remove from the disk.
        //
        let block = self.block_by_height(height)?;
        let block = if let Block::MicroBlock(block) = block {
            block
        } else {
            panic!("Expected micro block");
        };
        let previous = self.block_by_height(height - 1)?;
        self.database.remove(height)?;
        let block_hash = Hash::digest(&block);

        //
        // Revert metadata.
        //
        self.block_by_hash.rollback_to_version(version);
        self.output_by_hash.rollback_to_version(version);
        self.balance.rollback_to_version(version);
        self.escrow.rollback_to_version(version);
        assert_eq!(self.block_by_hash.current_version(), version);
        assert!(self.output_by_hash.current_version() <= version);
        assert!(self.balance.current_version() <= version);
        assert!(self.escrow.current_version() <= version);
        self.height = self.height - 1;
        assert_eq!(self.height, height);
        assert_eq!(self.height, version);
        self.last_block_hash = Hash::digest(&previous);
        self.election_result.random = previous.base_header().random;
        self.reset_view_change();
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        let mut created: Vec<Output> = Vec::new();
        let mut pruned: Vec<Output> = Vec::new();
        for tx in block.transactions {
            for input_hash in tx.txins() {
                let input = self.output_by_hash(input_hash)?.expect("exists");
                created.push(input);
                debug!(
                    "Restored UXTO: height={}, block={}, utxo={}",
                    height, &block_hash, &input_hash
                );
            }
            for output in tx.txouts() {
                pruned.push(output.clone());
                let output_hash = Hash::digest(output);
                debug!(
                    "Reverted UTXO: height={}, block={}, utxo={}",
                    height, &block_hash, &output_hash
                );
            }
        }

        info!(
            "Reverted a micro block: height={}, block={}, inputs={}, outputs={}",
            self.height,
            &block_hash,
            created.len(),
            pruned.len()
        );

        Ok((pruned, created))
    }
}

pub fn sign_fake_macro_block(block: &mut MacroBlock, chain: &Blockchain, keychains: &[KeyChain]) {
    let block_hash = Hash::digest(block);
    let validators = chain.validators();
    let mut signatures: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
    for keychain in keychains {
        let sig = pbc::sign_hash(&block_hash, &keychain.network_skey);
        signatures.insert(keychain.network_pkey.clone(), sig);
    }
    let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
    block.body.multisig = multisig;
    block.body.multisigmap = multisigmap;
}

pub fn create_fake_macro_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: SystemTime,
) -> MacroBlock {
    let version = VERSION;
    let previous = chain.last_block_hash().clone();
    let height = chain.height();
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let keys = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&keys.network_skey, &seed);
    let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
    let mut block = MacroBlock::empty(base, keys.network_pkey);
    sign_fake_macro_block(&mut block, chain, keychains);
    block
}

pub fn create_fake_micro_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: SystemTime,
    block_reward: i64,
) -> (MicroBlock, Vec<Hash>, Vec<Hash>) {
    let version: u64 = VERSION;
    let height = chain.height();
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let keys = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let previous = chain.last_block_hash().clone();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&keys.network_skey, &seed);

    let mut input_hashes: Vec<Hash> = Vec::new();
    let mut inputs: Vec<Output> = Vec::new();
    let mut monetary_balance: i64 = 0;
    let mut staking_balance: i64 = 0;
    for input_hash in chain.unspent() {
        let input = chain
            .output_by_hash(&input_hash)
            .expect("no disk errors")
            .expect("exists");
        input.validate().expect("Valid input");
        match input {
            Output::PaymentOutput(ref o) => {
                let payload = o.decrypt_payload(&keys.wallet_skey).unwrap();
                monetary_balance += payload.amount;
            }
            Output::PublicPaymentOutput(ref o) => {
                monetary_balance += o.amount;
            }
            Output::StakeOutput(ref o) => {
                staking_balance += o.amount;
            }
        }
        input_hashes.push(input_hash.clone());
        inputs.push(input);
    }

    let mut outputs: Vec<Output> = Vec::new();
    let mut outputs_gamma = Fr::zero();
    // Payments.
    if monetary_balance > 0 {
        let (output, output_gamma) =
            PaymentOutput::new(&keys.wallet_pkey, monetary_balance).expect("keys are valid");
        outputs.push(Output::PaymentOutput(output));
        outputs_gamma += output_gamma;
    }

    // Stakes.
    if staking_balance > 0 {
        let output = StakeOutput::new(
            &keys.wallet_pkey,
            &keys.network_skey,
            &keys.network_pkey,
            staking_balance,
        )
        .expect("keys are valid");
        outputs.push(Output::StakeOutput(output));
    }

    let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
    let block_fee: i64 = 0;
    let tx = PaymentTransaction::new(
        &keys.wallet_skey,
        &inputs,
        &outputs,
        &outputs_gamma,
        block_fee,
    )
    .expect("Invalid keys");
    tx.validate(&inputs).expect("Invalid transaction");

    let coinbase_tx = {
        let data = PaymentPayloadData::Comment(format!("Block reward"));
        let (output, gamma) = PaymentOutput::with_payload(&keys.wallet_pkey, block_reward, data)
            .expect("invalid keys");
        CoinbaseTransaction {
            block_reward,
            block_fee,
            gamma: -gamma,
            txouts: vec![Output::PaymentOutput(output)],
        }
    };
    coinbase_tx.validate().expect("Invalid transaction");

    let transactions: Vec<Transaction> = vec![coinbase_tx.into(), tx.into()];

    let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
    let mut block = MicroBlock::new(base, None, transactions, keys.network_pkey);
    block.sign(&keys.network_skey, &keys.network_pkey);
    (block, input_hashes, output_hashes)
}

pub fn create_empty_micro_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: SystemTime,
) -> MicroBlock {
    let version = VERSION;
    let previous = chain.last_block_hash().clone();
    let height = chain.height();
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let keys = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&keys.network_skey, &seed);
    let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
    let mut block = MicroBlock::empty(base, None, keys.network_pkey);
    block.sign(&keys.network_skey, &keys.network_pkey);
    block
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::genesis::genesis;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use simple_logger;
    use std::time::{Duration, SystemTime};
    use tempdir::TempDir;

    #[test]
    fn basic() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let timestamp = SystemTime::now();
        let cfg: BlockchainConfig = Default::default();
        let blocks = genesis(
            &keychains,
            cfg.min_stake_amount,
            cfg.min_stake_amount,
            timestamp,
        );
        assert_eq!(blocks.len(), 1);
        let block1 = match &blocks[..] {
            [Block::MacroBlock(block1)] => block1,
            _ => panic!(),
        };
        let blockchain = Blockchain::testing(cfg, blocks.clone(), timestamp)
            .expect("Failed to create blockchain");
        let outputs: Vec<Output> = block1
            .body
            .outputs
            .leafs()
            .iter()
            .map(|(o, _p)| o.as_ref().clone())
            .collect();
        let mut unspent: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
        unspent.sort();
        let mut unspent2: Vec<Hash> = blockchain.unspent().cloned().collect();
        unspent2.sort();
        assert_eq!(unspent, unspent2);

        let validators = blockchain
            .escrow
            .get_stakers_majority(blockchain.epoch, blockchain.cfg.min_stake_amount);
        assert_eq!(validators.len(), keychains.len());
        let validators_map: BTreeMap<_, _> = validators.iter().cloned().collect();
        for keychain in &keychains {
            let stake = validators_map.get(&keychain.network_pkey).expect("exists");
            assert_eq!(*stake, blockchain.cfg.min_stake_amount);
        }
        assert_eq!(blockchain.last_block_hash(), Hash::digest(&block1));
        assert_eq!(
            Hash::digest(&blockchain.last_block().unwrap()),
            Hash::digest(&block1)
        );

        let blocks2: Vec<Block> = blockchain.blocks().collect();
        assert_eq!(blocks2.len(), 1);
        assert_eq!(Hash::digest(&blocks2[0]), Hash::digest(&block1));

        assert!(blockchain.contains_block(&Hash::digest(&block1)));
        assert!(!blockchain.contains_block(&Hash::digest("test")));

        assert_eq!(
            Hash::digest(&blockchain.block_by_height(0).unwrap()),
            Hash::digest(&block1)
        );

        assert!(!blockchain.contains_output(&Hash::digest("test")));
        assert!(blockchain
            .output_by_hash(&Hash::digest("test"))
            .expect("no disk errors")
            .is_none());
        for (output, _path) in block1.body.outputs.leafs() {
            let output_hash = Hash::digest(&output);
            let output2 = blockchain
                .output_by_hash(&output_hash)
                .expect("no disk errors")
                .expect("exists");
            assert_eq!(Hash::digest(&output2), output_hash);
            assert!(blockchain.contains_output(&output_hash));
        }
    }

    #[test]
    fn iterate() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let mut timestamp = SystemTime::now();
        let mut cfg: BlockchainConfig = Default::default();
        cfg.stake_epochs = 1;
        let genesis = genesis(
            &keychains,
            cfg.min_stake_amount,
            10 * cfg.min_stake_amount,
            timestamp,
        );
        let temp_prefix: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let temp_dir = TempDir::new(&temp_prefix).expect("couldn't create temp dir");
        let database = ListDb::new(&temp_dir.path());
        let mut chain = Blockchain::with_db(cfg.clone(), database, genesis.clone(), timestamp)
            .expect("Failed to create blockchain");

        for epoch in 0..2 {
            //
            // Non-empty block.
            //
            timestamp += Duration::from_millis(1);
            let block_reward = if epoch % 2 == 0 { 60i64 } else { 0i64 };
            let (block, input_hashes, output_hashes) =
                create_fake_micro_block(&mut chain, &keychains, timestamp, block_reward);
            let hash = Hash::digest(&block);
            let height = chain.height();
            chain
                .push_micro_block(block, timestamp)
                .expect("block is valid");
            assert_eq!(hash, chain.last_block_hash());
            assert_eq!(height + 1, chain.height());
            for input_hash in input_hashes {
                assert!(!chain.contains_output(&input_hash));
            }
            for output_hash in output_hashes {
                assert!(chain.contains_output(&output_hash));
            }

            //
            // Empty block.
            //
            timestamp += Duration::from_millis(1);
            let block = create_empty_micro_block(&mut chain, &keychains, timestamp);
            let hash = Hash::digest(&block);
            let height = chain.height();
            chain
                .push_micro_block(block, timestamp)
                .expect("block is valid");
            assert_eq!(hash, chain.last_block_hash());
            assert_eq!(height + 1, chain.height());

            //
            // Key block.
            //
            timestamp += Duration::from_millis(1);
            let block = create_fake_macro_block(&chain, &keychains, timestamp);
            let hash = Hash::digest(&block);
            let height = chain.height();
            chain
                .push_macro_block(block, timestamp)
                .expect("Invalid block");
            assert_eq!(hash, chain.last_block_hash());
            assert_eq!(height + 1, chain.height());
        }

        //
        // Recovery.
        //
        let height = chain.height();
        let block_hash = chain.last_block_hash();
        let balance = chain.balance().clone();
        drop(chain);
        let database = ListDb::new(&temp_dir.path());
        let chain = Blockchain::with_db(cfg, database, genesis, timestamp)
            .expect("Failed to create blockchain");
        assert_eq!(height, chain.height());
        assert_eq!(block_hash, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_eq!(&balance, chain.balance());
    }

    #[test]
    fn rollback() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let mut timestamp = SystemTime::now();
        let cfg: BlockchainConfig = Default::default();
        let genesis = genesis(
            &keychains,
            cfg.min_stake_amount,
            10 * cfg.min_stake_amount,
            timestamp,
        );
        let temp_prefix: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let temp_dir = TempDir::new(&temp_prefix).expect("couldn't create temp dir");
        let database = ListDb::new(&temp_dir.path());
        let mut chain = Blockchain::with_db(cfg.clone(), database, genesis.clone(), timestamp)
            .expect("Failed to create blockchain");

        let height0 = chain.height();
        let view_change0 = 0;
        let block_hash0 = chain.last_block_hash();
        let balance0 = chain.balance().clone();
        let escrow0 = chain.escrow_info().clone();

        // Register a micro block.
        timestamp += Duration::from_millis(1);
        let (block1, input_hashes1, output_hashes1) =
            create_fake_micro_block(&mut chain, &keychains, timestamp, 60);
        chain
            .push_micro_block(block1, timestamp)
            .expect("block is valid");
        assert_eq!(height0 + 1, chain.height());
        assert_eq!(view_change0, chain.view_change());
        assert_ne!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_ne!(&balance0, chain.balance());
        for input_hash in &input_hashes1 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes1 {
            assert!(chain.contains_output(output_hash));
        }
        let height1 = chain.height();
        let block_hash1 = chain.last_block_hash();
        let balance1 = chain.balance().clone();
        let escrow1 = chain.escrow_info().clone();

        // Register one more micro block.
        timestamp += Duration::from_millis(1);
        let (block2, input_hashes2, output_hashes2) =
            create_fake_micro_block(&mut chain, &keychains, timestamp, 0);
        chain
            .push_micro_block(block2, timestamp)
            .expect("block is valid");
        assert_eq!(height1 + 1, chain.height());
        assert_eq!(view_change0, chain.view_change());
        assert_ne!(block_hash1, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_ne!(&balance1, chain.balance());
        for input_hash in &input_hashes2 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes2 {
            assert!(chain.contains_output(output_hash));
        }

        // Pop the last micro block.
        chain.pop_micro_block().expect("no disk errors");
        assert_eq!(height1, chain.height());
        assert_eq!(view_change0, chain.view_change());
        assert_eq!(block_hash1, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_eq!(&balance1, chain.balance());
        assert_eq!(escrow1, chain.escrow_info());
        for input_hash in &input_hashes2 {
            assert!(chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes2 {
            assert!(!chain.contains_output(output_hash));
        }

        // Pop the previous micro block.
        chain.pop_micro_block().expect("no disk errors");
        assert_eq!(height0, chain.height());
        assert_eq!(view_change0, chain.view_change());
        assert_eq!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_eq!(&balance0, chain.balance());
        assert_eq!(escrow0, chain.escrow_info());
        for input_hash in &input_hashes1 {
            assert!(chain.contains_output(&input_hash));
        }
        for output_hash in &output_hashes1 {
            assert!(!chain.contains_output(&output_hash));
        }

        //
        // Recovery.
        //
        drop(chain);
        let database = ListDb::new(&temp_dir.path());
        let chain = Blockchain::with_db(cfg, database, genesis, timestamp)
            .expect("Failed to create blockchain");
        assert_eq!(height0, chain.height());
        assert_eq!(view_change0, chain.view_change());
        assert_eq!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_eq!(&balance0, chain.balance());
    }

    #[test]
    fn block_range_limit() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keychains = [KeyChain::new_mem()];

        let mut timestamp = SystemTime::now();
        let cfg: BlockchainConfig = Default::default();
        let stake = cfg.min_stake_amount;
        let blocks = genesis(&keychains, stake, 10 * cfg.min_stake_amount, timestamp);
        let mut blockchain =
            Blockchain::testing(cfg, blocks, timestamp).expect("Failed to create blockchain");
        let starting_height = blockchain.height();
        // len of genesis
        assert!(blockchain.height() > 0);
        for _height in 2..12 {
            timestamp += Duration::from_millis(1);
            let block = create_empty_micro_block(&blockchain, &keychains, timestamp);
            blockchain
                .push_micro_block(block, timestamp)
                .expect("Invalid block");
        }

        assert_eq!(blockchain.blocks_range(starting_height, 1).len(), 1);

        assert_eq!(blockchain.blocks_range(starting_height, 4).len(), 4);
        // limit
        assert_eq!(blockchain.blocks_range(starting_height, 20).len(), 10);
        // empty
        assert_eq!(blockchain.blocks_range(blockchain.height(), 1).len(), 0);
    }
}

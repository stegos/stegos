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
use crate::check_multi_signature;
use crate::config::*;
use crate::election::ElectionInfo;
use crate::election::{self, mix, ElectionResult};
use crate::error::*;
use crate::escrow::*;
use crate::merkle::*;
use crate::metrics;
use crate::mvcc::MultiVersionedMap;
use crate::output::*;
use crate::storage::ListDb;
use crate::view_changes::ChainInfo;
use failure::{ensure, Error};
use log::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use stegos_crypto::bulletproofs::fee_a;
use stegos_crypto::bulletproofs::validate_range_proof;
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
use stegos_crypto::hash::*;
use stegos_crypto::pbc::secure;
use tokio_timer::clock;

/// A helper to find UTXO in this blockchain.
#[derive(Debug, Clone)]
struct OutputKey {
    /// Block Height.
    pub height: u64,
    /// Merkle Tree path inside block.
    pub path: MerklePath,
}

/// A helper to store the global monetary balance in MultiVersionedMap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Balance {
    /// The total sum of money created.
    created: ECp,
    /// The total sum of money burned.
    burned: ECp,
    /// The total sum of gamma adjustments.
    gamma: Fr,
    /// The total sum of monetary adjustments.
    monetary_adjustment: i64,
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
    /// Equals to the number of key blocks in the blockchain.
    /// 1-based indexed - the genetic key block starts epoch #1.
    epoch: u64,
    /// Zero-indexed identifier of the last key block.
    last_key_block_height: u64,
    /// Last election result.
    election_result: ElectionResult,

    //
    // Height Information.
    //
    /// The number of blocks in this blockchain.
    height: u64,
    /// Timestamp when the latest block was registered.
    last_block_timestamp: Instant,
    /// Copy of a block hash from the latest registered block.
    last_block_hash: Hash,

    //
    // Consensus information.
    //
    /// Number of leader changes since last epoch.
    view_change: u32,
}

impl Blockchain {
    //----------------------------------------------------------------------------------------------
    // Constructors.
    //----------------------------------------------------------------------------------------------

    pub fn new(
        cfg: BlockchainConfig,
        storage_cfg: StorageConfig,
        genesis: Vec<Block>,
        current_timestamp: u64,
    ) -> Blockchain {
        let database = ListDb::new(&storage_cfg.database_path);
        Self::with_db(cfg, database, genesis, current_timestamp)
    }

    pub fn testing(
        cfg: BlockchainConfig,
        genesis: Vec<Block>,
        current_timestamp: u64,
    ) -> Blockchain {
        let database = ListDb::testing();
        Self::with_db(cfg, database, genesis, current_timestamp)
    }

    fn with_db(
        cfg: BlockchainConfig,
        database: ListDb,
        genesis: Vec<Block>,
        current_timestamp: u64,
    ) -> Blockchain {
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
            monetary_adjustment: 0,
        };
        balance.insert(0, (), initial_balance);
        let escrow = Escrow::new();

        //
        // Epoch Information.
        //
        let epoch: u64 = 0;
        let last_key_block_height: u64 = 0;
        let election_result = ElectionResult::default();

        //
        // Height Information.
        //
        let height: u64 = 0;
        let last_block_timestamp = clock::now();
        let last_block_hash = Hash::digest("genesis");

        //
        // Consensus information.
        //
        let view_change = 0;

        let mut blockchain = Blockchain {
            cfg,
            database,
            block_by_hash,
            output_by_hash,
            balance,
            escrow,
            epoch,
            last_key_block_height,
            election_result,
            height,
            last_block_timestamp,
            last_block_hash,
            view_change,
        };

        blockchain.recover(genesis, current_timestamp);
        blockchain
    }

    //----------------------------------------------------------------------------------------------
    // Recovery.
    //----------------------------------------------------------------------------------------------

    fn recover(&mut self, genesis: Vec<Block>, current_timestamp: u64) {
        let mut blocks = self.database.iter();

        let block = blocks.next();
        let block = if let Some(block) = block {
            block
        } else {
            debug!("Creating a new blockchain...");
            for block in genesis {
                match block {
                    Block::MonetaryBlock(monetary_block) => {
                        self.push_monetary_block(monetary_block, current_timestamp)
                            .expect("genesis is valid");
                    }
                    Block::KeyBlock(key_block) => {
                        self.push_key_block(key_block).expect("genesis is valid");
                    }
                }
            }
            info!(
                "Initialized a new blockchain: height={}, hash={}",
                self.height, self.last_block_hash
            );
            return;
        };

        info!("Loading blockchain from database.");
        self.recover_block(block, current_timestamp);
        for block in blocks {
            self.recover_block(block, current_timestamp);
        }

        for ((height, genesis), chain) in genesis.iter().enumerate().zip(self.blocks()) {
            let genesis_hash = Hash::digest(genesis);
            let chain_hash = Hash::digest(&chain);
            if genesis_hash != chain_hash {
                error!(
                    "Found a saved chain that is not compatible to our genesis at height = {}, \
                     genesis_block = {:?}, database_block = {:?}",
                    height + 1,
                    genesis_hash,
                    chain_hash
                );
                std::process::exit(1);
            }
        }

        info!(
            "Recovered blockchain from the disk: height={}, hash={}",
            self.height, self.last_block_hash
        );
    }

    fn recover_block(&mut self, block: Block, current_timestamp: u64) {
        debug!(
            "Loading a block from the disk: hash={}",
            Hash::digest(&block)
        );
        // Skip validate_key_block()/validate_monetary_block().
        match block {
            Block::MonetaryBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_monetary_block(&block, current_timestamp)
                        .expect("a monetary block from the disk is valid")
                }
                let _ = self.register_monetary_block(block, current_timestamp);
            }
            Block::KeyBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_key_block(&block, false)
                        .expect("a key block from the disk is valid")
                }
                self.register_key_block(block);
            }
        }
    }

    //
    // Info
    //
    pub fn election_info(&self) -> ElectionInfo {
        let last_leader = if self.view_change > 1 {
            self.select_leader(self.view_change - 1).to_string()
        } else {
            "no_leader".to_owned()
        };

        ElectionInfo {
            height: self.height,
            view_change: self.view_change,
            slots_count: self.cfg.max_slot_count as i64,
            last_leader,
            current_leader: self.select_leader(self.view_change).to_string(),
            next_leader: self.select_leader(self.view_change + 1).to_string(),
        }
    }
    //----------------------------------------------------------------------------------------------
    // Database API.
    //----------------------------------------------------------------------------------------------

    /// Returns the number of blocks in the current epoch.
    pub fn blocks_in_epoch(&self) -> u64 {
        // Include the key block itself.
        self.height - self.last_key_block_height
    }

    /// Returns an iterator over UTXO hashes.
    pub fn unspent(&self) -> impl Iterator<Item = &Hash> {
        self.output_by_hash.keys()
    }

    /// Returns true if blockchain contains unspent output.
    pub fn contains_output(&self, output_hash: &Hash) -> bool {
        if let Some(OutputKey { .. }) = self.output_by_hash.get(output_hash) {
            return true;
        }
        return false;
    }

    /// Resolve UTXO by hash.
    pub fn output_by_hash(&self, output_hash: &Hash) -> Result<Output, Error> {
        if let Some(OutputKey { height, path }) = self.output_by_hash.get(output_hash) {
            let block = self.block_by_height(*height)?;
            if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                if let Some(output) = body.outputs.lookup(path) {
                    return Ok(output.as_ref().clone());
                } else {
                    return Err(BlockchainError::MissingUTXO(output_hash.clone()).into());
                }
            } else {
                unreachable!(); // Non-monetary block
            }
        }
        return Err(BlockchainError::MissingUTXO(output_hash.clone()).into());
    }

    /// Resolve the list of UTXOs by its hashes.
    pub fn outputs_by_hashes(&self, output_hashes: &[Hash]) -> Result<Vec<Output>, Error> {
        // TODO: optimize this function for batch processing.
        let mut outputs: Vec<Output> = Vec::new();
        for output_hash in output_hashes {
            let input = self.output_by_hash(output_hash)?;
            outputs.push(input);
        }
        Ok(outputs)
    }

    /// Checks whether a block exists or not.
    pub fn contains_block(&self, block_hash: &Hash) -> bool {
        if let Some(_height) = self.block_by_hash.get(block_hash) {
            return true;
        }
        return false;
    }

    /// Get a block by height.
    fn block_by_height(&self, height: u64) -> Result<Block, Error> {
        assert!(height < self.height);
        Ok((self.database.get(height)?).expect("block exists"))
    }

    /// Return iterator over saved blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Block> {
        self.database.iter()
    }

    /// Returns blocks history starting from block_hash, limited by count.
    pub fn blocks_range(&self, starting_hash: &Hash, count: u64) -> Option<Vec<Block>> {
        if let Some(&height) = self.block_by_hash.get(starting_hash) {
            let height = height + 1;
            return Some(
                self.database
                    .iter_starting(height)
                    .take(count as usize)
                    .collect(),
            );
        }
        return None;
    }

    /// Return the last block.
    pub fn last_block(&self) -> Result<Block, Error> {
        assert!(self.height > 0);
        match self.database.get(self.height - 1) {
            Ok(block) => Ok(block.expect("block exists")),
            Err(e) => Err(e),
        }
    }

    /// Return leader public key for specific view_change number.
    pub fn select_leader(&self, view_change: u32) -> secure::PublicKey {
        self.election_result.select_leader(view_change)
    }

    /// Returns public key of the active leader.
    pub fn leader(&self) -> secure::PublicKey {
        self.select_leader(self.view_change())
    }

    /// Return the current epoch facilitator.
    #[inline]
    pub fn facilitator(&self) -> &secure::PublicKey {
        &self.election_result.facilitator
    }

    /// Return the current epoch validators with their stakes.
    #[inline]
    pub fn validators(&self) -> &Vec<(secure::PublicKey, i64)> {
        &self.election_result.validators
    }

    /// Return the last block timestamp.
    #[inline]
    pub fn last_block_timestamp(&self) -> Instant {
        self.last_block_timestamp
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

    /// Returns escrow.
    #[inline]
    pub fn escrow(&self) -> &Escrow {
        &self.escrow
    }

    /// Returns balance.
    #[inline]
    fn balance(&self) -> &Balance {
        &self.balance.get(&()).unwrap()
    }

    /// Returns number of leader changes since last epoch creation.
    #[inline]
    pub fn view_change(&self) -> u32 {
        self.view_change
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
    pub fn set_view_change(&mut self, new_view_change: u32) {
        assert!(self.view_change < new_view_change);
        self.view_change = new_view_change;
    }

    //----------------------------------------------------------------------------------------------
    // Key Blocks
    //----------------------------------------------------------------------------------------------

    ///
    /// Add a new block into blockchain.
    ///
    pub fn push_key_block(&mut self, block: KeyBlock) -> Result<(), Error> {
        //
        // Validate the key block.
        //
        self.validate_key_block(&block, false)?;

        //
        // Write the key block to the disk.
        //
        self.database
            .insert(self.height, Block::KeyBlock(block.clone()))?;

        //
        // Update in-memory indexes and metadata.
        //
        self.register_key_block(block);

        Ok(())
    }

    ///
    /// Validate sealed key block.
    ///
    /// # Arguments
    ///
    /// * `block` - block to validate.
    /// * `is_proposal` - don't check for the supermajority of votes.
    ///                          Used to validating block proposals.
    ///
    pub fn validate_key_block(&self, block: &KeyBlock, is_proposal: bool) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a key block: height={}, hash={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockchainError::InvalidBlockVersion(
                height,
                block_hash,
                VERSION,
                block.header.base.version,
            )
            .into());
        }

        // Check height.
        if block.header.base.height != self.height {
            return Err(BlockchainError::OutOfOrderBlock(
                block_hash,
                self.height,
                block.header.base.height,
            )
            .into());
        }

        // Check previous hash.
        if self.height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::InvalidPreviousHash(
                    height,
                    block_hash,
                    previous_hash,
                    block.header.base.previous,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockchainError::BlockHashCollision(height, block_hash).into());
        }

        // Check the view change.
        if block.header.base.view_change != self.view_change() {
            return Err(BlockchainError::InvalidViewChange(
                height,
                block_hash,
                self.view_change,
                block.header.base.view_change,
            )
            .into());
        }

        // skip leader selection and signature checking for genesis block.
        if self.epoch > 0 {
            let leader = self.select_leader(block.header.base.view_change);
            let seed = mix(self.last_random(), block.header.base.view_change);
            if !secure::validate_VRF_source(&block.header.random, &leader, &seed) {
                return Err(BlockchainError::IncorrectRandom(height, block_hash).into());
            }

            // Currently macro block consensus uses public key as peer id.
            // This adaptor allows converting PublicKey into integer identifier.
            let validators_map: HashMap<secure::PublicKey, u32> = self
                .validators()
                .iter()
                .enumerate()
                .map(|(id, (pk, _))| (*pk, id as u32))
                .collect();

            if let Some(leader_id) = validators_map.get(&leader) {
                // bit of leader should be always set.
                ensure!(
                    block.body.multisigmap.contains(*leader_id as usize),
                    BlockchainError::NoLeaderSignatureFound
                );
            } else {
                return Err(BlockchainError::LeaderIsNotValidator.into());
            }

            // checks that proposal is signed only by leader.
            if is_proposal {
                ensure!(
                    block.body.multisigmap.len() == 1,
                    BlockchainError::MoreThanOneSignatureAtPropose(height, block_hash)
                );
                ensure!(
                    secure::check_hash(&block_hash, &block.body.multisig, &leader),
                    BlockchainError::InvalidLeaderSignature(height, block_hash)
                );
            } else {
                check_multi_signature(
                    &block_hash,
                    &block.body.multisig,
                    &block.body.multisigmap,
                    self.validators(),
                    self.total_slots(),
                )
                .map_err(|e| BlockchainError::InvalidBlockSignature(e, height, block_hash))?;
            }
        }

        debug!(
            "The key block is valid: height={}, hash={}",
            height, &block_hash
        );
        Ok(())
    }

    ///
    /// Update indexes and metadata.
    ///
    fn register_key_block(&mut self, block: KeyBlock) {
        let version = self.height + 1;
        let height = self.height;
        assert_eq!(height, block.header.base.height);
        let block_hash = Hash::digest(&block);

        //
        // Update indexes.
        //
        if let Some(_) = self
            .block_by_hash
            .insert(version, block_hash.clone(), height)
        {
            panic!(
                "Block hash collision: height={}, hash={}",
                height, block_hash
            );
        }
        assert_eq!(self.block_by_hash.current_version(), version);

        //
        // Update metadata.
        //

        self.last_block_timestamp = clock::now();
        self.last_block_hash = block_hash.clone();
        self.height += 1;
        self.epoch += 1;
        self.last_key_block_height = height;
        self.election_result = election::select_validators_slots(
            self.escrow.get_stakers_majority(self.cfg.min_stake_amount),
            block.header.random,
            self.cfg.max_slot_count,
        );
        self.view_change = 0;
        assert_eq!(self.height, version);
        metrics::HEIGHT.set(self.height as i64);
        metrics::EPOCH.inc();

        info!(
            "Registered key block: height={}, hash={}",
            height, block_hash
        );
        debug!("Validators: {:?}", &self.validators());
        for (key, stake) in self.validators().iter() {
            let key_str = key.to_string();
            metrics::VALIDATOR_STAKE_GAUGEVEC
                .with_label_values(&[key_str.as_str()])
                .set(*stake);
        }

        // Finalize storage.
        self.block_by_hash.checkpoint();
        self.output_by_hash.checkpoint();
        self.balance.checkpoint();
        self.escrow.checkpoint();
    }

    // ---------------------------------------------------------------------------------------------
    // Monetary blocks
    // ---------------------------------------------------------------------------------------------

    ///
    /// Add a new monetary block into blockchain.
    ///
    pub fn push_monetary_block(
        &mut self,
        block: MonetaryBlock,
        current_timestamp: u64,
    ) -> Result<(Vec<Output>, Vec<Output>), Error> {
        //
        // Validate the monetary block.
        //
        self.validate_monetary_block(&block, current_timestamp)?;

        //
        // Write the monetary block to the disk.
        //
        self.database
            .insert(self.height, Block::MonetaryBlock(block.clone()))?;

        //
        // Update in-memory indexes and metadata.
        //
        let (inputs, outputs) = self.register_monetary_block(block, current_timestamp)?;

        Ok((inputs, outputs))
    }

    ///
    /// Validate sealed monetary block.
    ///
    /// # Arguments
    ///
    /// * `block` - block to validate.
    /// * `is_proposal` - don't check for the supermajority of votes.
    ///                          Used to validating block proposals.
    /// * `current_timestamp` - current time.
    ///                         Used to validating escrow.
    ///
    pub fn validate_monetary_block(
        &self,
        block: &MonetaryBlock,
        current_timestamp: u64,
    ) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a monetary block: height={}, hash={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockchainError::InvalidBlockVersion(
                height,
                block_hash,
                VERSION,
                block.header.base.version,
            )
            .into());
        }

        // Check height.
        if block.header.base.height != self.height {
            return Err(BlockchainError::OutOfOrderBlock(block_hash, self.height, height).into());
        }

        // Check previous hash.
        if self.height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::InvalidPreviousHash(
                    height,
                    block_hash,
                    previous_hash,
                    block.header.base.previous,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockchainError::BlockHashCollision(height, block_hash).into());
        }

        //TODO: remove multisig?

        // Check signature (exclude epoch == 0 for genesis).
        if self.epoch > 0 {
            let leader = match block.header.base.view_change.cmp(&self.view_change) {
                Ordering::Equal => self.leader(),
                Ordering::Greater => {
                    let chain = ChainInfo::from_monetary_block(&block, self.height());
                    match block.header.proof {
                        Some(ref proof) => {
                            proof.validate(&chain, &self)?;
                            self.select_leader(block.header.base.view_change)
                        }
                        _ => {
                            return Err(BlockchainError::NoProofWasFound(
                                height,
                                block_hash,
                                self.view_change,
                                block.header.base.view_change,
                            )
                            .into());
                        }
                    }
                }
                Ordering::Less => {
                    return Err(BlockchainError::InvalidViewChange(
                        height,
                        block_hash,
                        self.view_change,
                        block.header.base.view_change,
                    )
                    .into());
                }
            };
            ensure!(
                secure::check_hash(&block_hash, &block.body.sig, &leader),
                BlockchainError::InvalidLeaderSignature(height, block_hash)
            );
        }

        let mut burned = ECp::inf();
        let mut created = ECp::inf();

        //
        // Validate inputs.
        //
        let mut hasher = Hasher::new();
        let inputs_count: u64 = block.body.inputs.len() as u64;
        inputs_count.hash(&mut hasher);
        let mut input_set: HashSet<Hash> = HashSet::new();
        let inputs = self.outputs_by_hashes(&block.body.inputs)?;
        for (input_hash, input) in block.body.inputs.iter().zip(inputs.iter()) {
            debug_assert_eq!(Hash::digest(input), *input_hash);
            // Check for the duplicate input.
            if !input_set.insert(*input_hash) {
                return Err(BlockchainError::DuplicateBlockInput(*input_hash).into());
            }
            // Check UTXO.
            match input {
                Output::PaymentOutput(o) => {
                    burned += Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    o.validate_pkey()?;
                    burned += fee_a(o.amount);
                    self.escrow
                        .validate_unstake(&o.validator, input_hash, current_timestamp)?;
                }
            }
            input_hash.hash(&mut hasher);
        }
        drop(input_set);
        let inputs_range_hash = hasher.result();
        if block.header.inputs_range_hash != inputs_range_hash {
            let expected = block.header.inputs_range_hash.clone();
            let got = inputs_range_hash;
            return Err(BlockchainError::InvalidBlockInputsHash(expected, got).into());
        }
        //
        // Validate outputs.
        //
        let mut output_set: HashSet<Hash> = HashSet::new();
        for (output, _path) in block.body.outputs.leafs() {
            // Check that hash is unique.
            let output_hash = Hash::digest(output.as_ref());
            if let Some(_) = self.output_by_hash.get(&output_hash) {
                return Err(BlockchainError::OutputHashCollision(output_hash).into());
            }
            // Check for the duplicate output.
            if !output_set.insert(output_hash) {
                return Err(BlockchainError::DuplicateBlockOutput(output_hash).into());
            }
            // Check UTXO.
            match output.as_ref() {
                Output::PaymentOutput(o) => {
                    // Validate bullet proofs.
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof.into());
                    }
                    // Validate payload.
                    if o.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            PAYMENT_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    // Update balance.
                    created += Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    // Check for valid signature on network pkey.
                    o.validate_pkey()?;
                    // Validate amount.
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake.into());
                    }
                    // Validate payload.
                    if o.payload.ctxt.len() != STAKE_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            STAKE_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                    // Update balance.
                    created += fee_a(o.amount);
                }
            }
        }
        drop(output_set);
        if block.header.outputs_range_hash != *block.body.outputs.roothash() {
            let expected = block.header.outputs_range_hash.clone();
            let got = block.body.outputs.roothash().clone();
            return Err(BlockchainError::InvalidBlockOutputsHash(expected, got).into());
        }

        //
        // Validate block monetary balance.
        //
        if fee_a(block.header.monetary_adjustment) + burned - created != block.header.gamma * (*G) {
            return Err(BlockchainError::InvalidBlockBalance.into());
        }

        //
        // Validate the global monetary balance.
        //
        let orig_balance = self.balance();
        let balance = Balance {
            created: orig_balance.created + created,
            burned: orig_balance.burned + burned,
            gamma: orig_balance.gamma + block.header.gamma,
            monetary_adjustment: orig_balance.monetary_adjustment
                + block.header.monetary_adjustment,
        };
        if fee_a(balance.monetary_adjustment) + balance.burned - balance.created
            != balance.gamma * (*G)
        {
            panic!("Invalid global monetary balance");
        }

        debug!("The monetary block is valid: hash={}", &block_hash);
        Ok(())
    }

    //
    fn register_monetary_block(
        &mut self,
        mut block: MonetaryBlock,
        current_timestamp: u64,
    ) -> Result<(Vec<Output>, Vec<Output>), Error> {
        let version = self.height + 1;
        let height = self.height;
        assert_eq!(height, block.header.base.height);
        let block_hash = Hash::digest(&block);
        let block_timestamp = block.header.base.timestamp;

        //
        // Update indexes.
        //
        if let Some(_) = self
            .block_by_hash
            .insert(version, block_hash.clone(), height)
        {
            panic!(
                "Block hash collision: height={}, hash={}",
                height, block_hash
            );
        }
        assert_eq!(self.block_by_hash.current_version(), version);

        let mut burned = ECp::inf();
        let mut created = ECp::inf();

        //
        // Process inputs.
        //
        let mut inputs: Vec<Output> = Vec::with_capacity(block.body.inputs.len());
        for input_hash in &block.body.inputs {
            if let Some(OutputKey { height, path }) =
                self.output_by_hash.remove(version, input_hash)
            {
                assert_eq!(self.output_by_hash.current_version(), version);
                let block = self.block_by_height(height)?;
                let block_hash = Hash::digest(&block);
                if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                    // Remove from the block.
                    match body.outputs.lookup(&path) {
                        Some(o) => {
                            match o.as_ref() {
                                Output::PaymentOutput(o) => {
                                    burned += Pt::decompress(o.proof.vcmt)
                                        .expect("pedersen commitment is valid");
                                }
                                Output::StakeOutput(o) => {
                                    o.validate_pkey().expect("valid network pkey");
                                    self.escrow.unstake(
                                        version,
                                        o.validator,
                                        input_hash.clone(),
                                        current_timestamp,
                                    );
                                    assert_eq!(self.escrow.current_version(), version);
                                    burned += fee_a(o.amount);
                                }
                            }
                            inputs.push(o.as_ref().clone());
                        }
                        None => {
                            panic!(
                                "Corrupted 'output_by_hash' index or block: utxo={}, block={}",
                                &input_hash, block_hash,
                            );
                        }
                    }
                } else {
                    panic!("Corrupted 'output_by_hash' index: utxo={}", &input_hash);
                }
            } else {
                panic!(
                    "Missing input UTXO: block={}, hash={}",
                    &block_hash, &input_hash
                );
            }

            info!("Pruned UXTO: hash={}", &input_hash);
        }

        //
        // Process outputs.
        //
        let mut outputs: Vec<Output> = Vec::new();
        for (output, path) in block.body.outputs.leafs() {
            let output_hash = Hash::digest(output.as_ref());

            // Update indexes.
            let output_key = OutputKey { height, path };
            if let Some(_) = self
                .output_by_hash
                .insert(version, output_hash.clone(), output_key)
            {
                panic!("UTXO hash collision: hash={}", output_hash);
            }
            assert_eq!(self.output_by_hash.current_version(), version);

            match output.as_ref() {
                Output::PaymentOutput(o) => {
                    created += Pt::decompress(o.proof.vcmt).expect("pedersen commitment is valid");
                }
                Output::StakeOutput(o) => {
                    o.validate_pkey().expect("valid network pkey signature");
                    created += fee_a(o.amount);

                    let bonding_timestamp = block_timestamp + self.cfg.bonding_time;
                    self.escrow.stake(
                        version,
                        o.validator,
                        output_hash,
                        bonding_timestamp,
                        o.amount,
                    );
                    assert_eq!(self.escrow.current_version(), version);
                }
            }

            outputs.push(output.as_ref().clone());
            info!("Registered UXTO: hash={}", &output_hash);
        }

        // Check the block monetary balance.
        if fee_a(block.header.monetary_adjustment) + burned - created != block.header.gamma * (*G) {
            panic!("Invalid block balance")
        }

        //
        // Prune inputs.
        //
        block.body.inputs.clear();

        //
        // Update metadata.
        //

        // Global monetary balance.
        let orig_balance = self.balance();
        let balance = Balance {
            created: orig_balance.created + created,
            burned: orig_balance.burned + burned,
            gamma: orig_balance.gamma + block.header.gamma,
            monetary_adjustment: orig_balance.monetary_adjustment
                + block.header.monetary_adjustment,
        };
        if fee_a(balance.monetary_adjustment) + balance.burned - balance.created
            != balance.gamma * (*G)
        {
            panic!("Invalid global monetary balance");
        }
        self.balance.insert(version, (), balance);
        assert_eq!(self.balance.current_version(), version);
        self.last_block_timestamp = clock::now();
        self.last_block_hash = block_hash.clone();
        self.view_change = block.header.base.view_change + 1;
        self.height += 1;
        assert_eq!(self.height, version);
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        info!(
            "Registered monetary block: height={}, hash={}, inputs={}, outputs={}",
            height,
            block_hash,
            inputs.len(),
            outputs.len()
        );

        Ok((inputs, outputs))
    }

    pub fn pop_monetary_block(&mut self) -> Result<(), Error> {
        assert!(self.height > 1);
        let height = self.height - 1;
        assert_ne!(
            height, self.last_key_block_height,
            "attempt to rollback the key block"
        );
        let version = height;

        //
        // Remove from the disk.
        //
        let block = self.block_by_height(height)?;
        let block = if let Block::MonetaryBlock(block) = block {
            block
        } else {
            panic!("Expected monetary block");
        };
        self.database.remove(height)?;

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
        self.last_block_timestamp = clock::now();
        self.last_block_hash = Hash::digest(&self.last_block()?);
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        let mut outputs_count: usize = 0;
        for (output, _path) in block.body.outputs.leafs() {
            let output_hash = Hash::digest(output.as_ref());
            info!("Reverted UTXO: hash={}", &output_hash);
            outputs_count += 1;
        }

        for input_hash in &block.body.inputs {
            info!("Restored UXTO: hash={}", &input_hash);
        }

        info!(
            "Reverted monetary block: height={}, hash={}, inputs={}, outputs={}",
            self.height,
            Hash::digest(&block),
            block.body.inputs.len(),
            outputs_count
        );

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::genesis::genesis;
    use crate::multisignature::create_multi_signature;
    use chrono::prelude::Utc;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use simple_logger;
    use std::collections::BTreeMap;
    use stegos_keychain::KeyChain;
    use tempdir::TempDir;

    #[test]
    fn basic() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let current_timestamp = Utc::now().timestamp() as u64;
        let cfg: BlockchainConfig = Default::default();
        let blocks = genesis(
            &keychains,
            cfg.min_stake_amount,
            1_000_000,
            current_timestamp,
        );
        assert_eq!(blocks.len(), 2);
        let (block1, block2) = match &blocks[..] {
            [Block::MonetaryBlock(block1), Block::KeyBlock(block2)] => (block1, block2),
            _ => panic!(),
        };
        let blockchain = Blockchain::testing(cfg, blocks.clone(), current_timestamp);
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

        assert_eq!(blockchain.height(), 2);
        assert_eq!(blockchain.height, block2.header.base.height + 1);
        assert_eq!(blockchain.blocks_in_epoch(), 1);
        let validators = blockchain
            .escrow
            .get_stakers_majority(blockchain.cfg.min_stake_amount);
        assert_eq!(validators.len(), keychains.len());
        let validators_map: BTreeMap<_, _> = validators.iter().cloned().collect();
        for keychain in &keychains {
            let stake = validators_map.get(&keychain.network_pkey).expect("exists");
            assert_eq!(*stake, blockchain.cfg.min_stake_amount);
        }
        assert_eq!(blockchain.validators(), &validators);
        assert_eq!(blockchain.last_block_hash(), Hash::digest(&block2));
        assert_eq!(
            Hash::digest(&blockchain.last_block().unwrap()),
            Hash::digest(&block2)
        );

        let blocks2: Vec<Block> = blockchain.blocks().collect();
        assert_eq!(blocks2.len(), 2);
        assert_eq!(Hash::digest(&blocks2[0]), Hash::digest(&block1));
        assert_eq!(Hash::digest(&blocks2[1]), Hash::digest(&block2));

        assert!(blockchain.contains_block(&Hash::digest(&block1)));
        assert!(blockchain.contains_block(&Hash::digest(&block2)));
        assert!(!blockchain.contains_block(&Hash::digest("test")));

        assert_eq!(
            Hash::digest(&blockchain.block_by_height(0).unwrap()),
            Hash::digest(&block1)
        );
        assert_eq!(
            Hash::digest(&blockchain.block_by_height(1).unwrap()),
            Hash::digest(&block2)
        );

        assert!(!blockchain.contains_output(&Hash::digest("test")));
        assert!(blockchain.output_by_hash(&Hash::digest("test")).is_err());
        for (output, _path) in block1.body.outputs.leafs() {
            let output_hash = Hash::digest(&output);
            let output2 = blockchain.output_by_hash(&output_hash).expect("exists");
            assert_eq!(Hash::digest(&output2), output_hash);
            assert!(blockchain.contains_output(&output_hash));
        }
    }

    fn create_monetary_block(
        chain: &mut Blockchain,
        keys: &KeyChain,
        current_timestamp: u64,
        view_change: u32,
    ) -> (MonetaryBlock, Vec<Hash>, Vec<Hash>) {
        let mut input_hashes: Vec<Hash> = Vec::new();
        let mut gamma: Fr = Fr::zero();
        let mut amount: i64 = 0;
        for input_hash in chain.unspent() {
            let input = chain
                .output_by_hash(&input_hash)
                .expect("exists and no disk errors");
            match input {
                Output::PaymentOutput(ref o) => {
                    let payload = o.decrypt_payload(&keys.wallet_skey).unwrap();
                    gamma += payload.gamma;
                    amount += payload.amount;
                    input_hashes.push(input_hash.clone());
                }
                Output::StakeOutput(ref o) => {
                    o.validate_pkey().expect("valid network pkey signature");
                    o.decrypt_payload(&keys.wallet_skey).unwrap();
                    amount += o.amount;
                    input_hashes.push(input_hash.clone());
                }
            }
        }

        let mut outputs: Vec<Output> = Vec::new();
        let stake = chain.cfg.min_stake_amount;
        let (output, output_gamma) = PaymentOutput::new(
            current_timestamp,
            &keys.wallet_skey,
            &keys.wallet_pkey,
            amount - stake,
        )
        .expect("keys are valid");
        outputs.push(Output::PaymentOutput(output));
        gamma -= output_gamma;
        let output = StakeOutput::new(
            current_timestamp,
            &keys.wallet_skey,
            &keys.wallet_pkey,
            &keys.network_pkey,
            &keys.network_skey,
            stake,
        )
        .expect("keys are valid");
        outputs.push(Output::StakeOutput(output));

        let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
        let version = VERSION;
        let previous = chain.last_block_hash().clone();
        let height = chain.height();
        let base = BaseBlockHeader::new(version, previous, height, view_change, current_timestamp);
        let mut block = MonetaryBlock::new(base, gamma, 0, &input_hashes, &outputs, None);
        let block_hash = Hash::digest(&block);
        block.body.sig = secure::sign_hash(&block_hash, &keys.network_skey);
        (block, input_hashes, output_hashes)
    }

    fn create_empty_monetary_block(
        chain: &mut Blockchain,
        keys: &KeyChain,
        current_timestamp: u64,
        view_change: u32,
    ) -> MonetaryBlock {
        let input_hashes: Vec<Hash> = Vec::new();
        let outputs: Vec<Output> = Vec::new();
        let gamma = Fr::zero();
        let version = VERSION;
        let previous = chain.last_block_hash().clone();
        let height = chain.height();
        let base = BaseBlockHeader::new(version, previous, height, view_change, current_timestamp);
        let mut block = MonetaryBlock::new(base, gamma, 0, &input_hashes, &outputs, None);
        let block_hash = Hash::digest(&block);
        block.body.sig = secure::sign_hash(&block_hash, &keys.network_skey);
        block
    }

    #[test]
    fn iterate() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let mut current_timestamp = Utc::now().timestamp() as u64;
        let cfg: BlockchainConfig = Default::default();
        let genesis = genesis(
            &keychains,
            cfg.min_stake_amount,
            1_000_000,
            current_timestamp,
        );
        let temp_prefix: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let temp_dir = TempDir::new(&temp_prefix).expect("couldn't create temp dir");
        let database = ListDb::new(&temp_dir.path());
        let mut chain =
            Blockchain::with_db(cfg.clone(), database, genesis.clone(), current_timestamp);

        let height = chain.height();
        for i in 1..4 {
            current_timestamp += cfg.bonding_time + 1;
            let block_hash = if i % 2 == 0 {
                // Non-empty block.
                let (block, input_hashes, output_hashes) =
                    create_monetary_block(&mut chain, &keychains[0], current_timestamp, i - 1);
                let block_hash = Hash::digest(&block);
                chain
                    .push_monetary_block(block, current_timestamp)
                    .expect("block is valid");
                for input_hash in input_hashes {
                    assert!(!chain.contains_output(&input_hash));
                }
                for output_hash in output_hashes {
                    assert!(chain.contains_output(&output_hash));
                }
                block_hash
            } else {
                // Empty block.
                let block = create_empty_monetary_block(
                    &mut chain,
                    &keychains[0],
                    current_timestamp,
                    i - 1,
                );
                let block_hash = Hash::digest(&block);
                chain
                    .push_monetary_block(block, current_timestamp)
                    .expect("block is valid");
                block_hash
            };
            assert_eq!(block_hash, chain.last_block_hash());
            assert_eq!(height + i as u64, chain.height());
            assert!(chain.last_block_timestamp <= clock::now());
        }

        //
        // Recovery.
        //
        let height = chain.height();
        let block_hash = chain.last_block_hash();
        let balance = chain.balance().clone();
        drop(chain);
        let database = ListDb::new(&temp_dir.path());
        let chain = Blockchain::with_db(cfg, database, genesis, current_timestamp);
        assert_eq!(height, chain.height());
        assert_eq!(block_hash, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_eq!(&balance, chain.balance());
    }

    #[test]
    fn rollback() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let mut current_timestamp = Utc::now().timestamp() as u64;
        let cfg: BlockchainConfig = Default::default();
        let genesis = genesis(
            &keychains,
            cfg.min_stake_amount,
            1_000_000,
            current_timestamp,
        );

        let temp_prefix: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let temp_dir = TempDir::new(&temp_prefix).expect("couldn't create temp dir");
        let database = ListDb::new(&temp_dir.path());
        let mut chain =
            Blockchain::with_db(cfg.clone(), database, genesis.clone(), current_timestamp);

        let height0 = chain.height();
        let block_hash0 = chain.last_block_hash();
        let balance0 = chain.balance().clone();
        let escrow0 = chain.escrow().info().clone();

        // Register a monetary block.
        current_timestamp += chain.cfg.bonding_time + 1;
        let (block1, input_hashes1, output_hashes1) =
            create_monetary_block(&mut chain, &keychains[0], current_timestamp, 0);
        chain
            .push_monetary_block(block1, current_timestamp)
            .expect("block is valid");
        assert_eq!(height0 + 1, chain.height());
        assert_ne!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_ne!(&balance0, chain.balance());
        assert_ne!(escrow0, chain.escrow().info());
        for input_hash in &input_hashes1 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes1 {
            assert!(chain.contains_output(output_hash));
        }
        let height1 = chain.height();
        let block_hash1 = chain.last_block_hash();
        let balance1 = chain.balance().clone();
        let escrow1 = chain.escrow().info().clone();

        // Register one more monetary block.
        current_timestamp += chain.cfg.bonding_time + 1;
        let (block2, input_hashes2, output_hashes2) =
            create_monetary_block(&mut chain, &keychains[0], current_timestamp, 1);
        chain
            .push_monetary_block(block2, current_timestamp)
            .expect("block is valid");
        assert_eq!(height1 + 1, chain.height());
        assert_ne!(block_hash1, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_ne!(&balance1, chain.balance());
        assert_ne!(escrow1, chain.escrow().info());
        for input_hash in &input_hashes2 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes2 {
            assert!(chain.contains_output(output_hash));
        }

        // Pop the last monetary block.
        chain.pop_monetary_block().expect("no disk errors");
        assert_eq!(height1, chain.height());
        assert_eq!(block_hash1, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_eq!(&balance1, chain.balance());
        assert_eq!(escrow1, chain.escrow().info());
        for input_hash in &input_hashes2 {
            assert!(chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes2 {
            assert!(!chain.contains_output(output_hash));
        }

        // Pop the previous monetary block.
        chain.pop_monetary_block().expect("no disk errors");
        assert_eq!(height0, chain.height());
        assert_eq!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_eq!(&balance0, chain.balance());
        assert_eq!(escrow0, chain.escrow().info());
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
        let chain = Blockchain::with_db(cfg, database, genesis, current_timestamp);
        assert_eq!(height0, chain.height());
        assert_eq!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert!(chain.last_block_timestamp <= clock::now());
        assert_eq!(&balance0, chain.balance());
    }

    #[test]
    fn block_range_limit() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keychains = [
            KeyChain::new_mem(),
            KeyChain::new_mem(),
            KeyChain::new_mem(),
        ];

        let current_timestamp = Utc::now().timestamp() as u64;
        let cfg: BlockchainConfig = Default::default();
        let stake = cfg.min_stake_amount;
        let blocks = genesis(&keychains, stake, 1_000_000, current_timestamp);
        let mut blockchain = Blockchain::testing(cfg, blocks, current_timestamp);
        let start = blockchain.last_block_hash();
        // len of genesis
        assert!(blockchain.height() > 0);
        let version: u64 = 1;
        for height in 2..12 {
            let view_change = blockchain.view_change();;
            let key = blockchain.select_leader(view_change);
            let keychain = keychains.iter().find(|p| p.network_pkey == key).unwrap();
            let mut block = {
                let previous = blockchain.last_block_hash();
                let base =
                    BaseBlockHeader::new(version, previous, height, view_change, current_timestamp);
                let seed = mix(blockchain.last_random(), view_change);
                let random = secure::make_VRF(&keychain.network_skey, &seed);
                KeyBlock::new(base, random)
            };
            let block_hash = Hash::digest(&block);
            let validators: Vec<(secure::PublicKey, i64)> = keychains
                .iter()
                .map(|p| (p.network_pkey.clone(), stake))
                .collect();
            let mut signatures: BTreeMap<secure::PublicKey, secure::Signature> = BTreeMap::new();
            for keychain in &keychains {
                let sig = secure::sign_hash(&block_hash, &keychain.network_skey);
                signatures.insert(keychain.network_pkey.clone(), sig);
            }
            let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
            block.body.multisig = multisig;
            block.body.multisigmap = multisigmap;
            blockchain.push_key_block(block).expect("block is valid");
        }

        assert_eq!(blockchain.blocks_range(&start, 1).unwrap().len(), 1);

        assert_eq!(blockchain.blocks_range(&start, 4).unwrap().len(), 4);
        // limit
        assert_eq!(blockchain.blocks_range(&start, 20).unwrap().len(), 10);
    }
}

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
use crate::multisignature::create_multi_signature;
use crate::mvcc::MultiVersionedMap;
use crate::output::*;
use crate::storage::ListDb;
use crate::view_changes::ChainInfo;
use failure::Error;
use log::*;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use stegos_crypto::bulletproofs::fee_a;
use stegos_crypto::bulletproofs::validate_range_proof;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
use stegos_crypto::hash::*;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;

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
    /// A timestamp from the last key block.
    last_key_block_timestamp: SystemTime,
    /// Last election result.
    election_result: ElectionResult,

    //
    // Height Information.
    //
    /// The number of blocks in this blockchain.
    height: u64,
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
            monetary_adjustment: 0,
        };
        balance.insert(0, (), initial_balance);
        let escrow = Escrow::new();

        //
        // Epoch Information.
        //
        let epoch: u64 = 0;
        let last_key_block_height: u64 = 0;
        let last_key_block_timestamp = UNIX_EPOCH;
        let election_result = ElectionResult::default();

        //
        // Height Information.
        //
        let height: u64 = 0;
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
            last_key_block_timestamp,
            election_result,
            height,
            last_block_hash,
            view_change,
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
                    Block::KeyBlock(key_block) => self.push_key_block(key_block)?,
                }
            }
            info!(
                "Initialized a new blockchain: height={}, last_block={}",
                self.height, self.last_block_hash
            );
            return Ok(());
        };

        info!("Recovering blockchain from the disk...");
        self.recover_block(block, timestamp)?;
        for block in blocks {
            self.recover_block(block, timestamp)?;
        }

        // Check genesis.
        for (genesis, chain) in genesis.iter().zip(self.blocks()) {
            let genesis_hash = Hash::digest(genesis);
            let chain_hash = Hash::digest(&chain);
            if genesis_hash != chain_hash {
                return Err(BlockchainError::IncompatibleChain(
                    chain.base_header().height,
                    genesis_hash,
                    chain_hash,
                )
                .into());
            }
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
        // Skip validate_key_block()/validate_micro_block().
        match block {
            Block::MicroBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_micro_block(&block, timestamp)?
                }
                let _ = self.register_micro_block(block, timestamp);
            }
            Block::KeyBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_key_block(&block, false)?
                }
                self.register_key_block(block);
            }
        }
        Ok(())
    }

    ///
    /// Recovery wallet state from the blockchain.
    /// TODO: this method is a temporary solution until persistence is implemented in wallet.
    /// https://github.com/stegos/stegos/issues/812
    ///
    pub fn recover_wallet(&self, skey: &SecretKey) -> Result<Vec<(Output, u64)>, Error> {
        let mut wallet_state: Vec<(Output, u64)> = Vec::new();
        let mut epoch: u64 = 0;
        for block in self.database.iter_starting(0) {
            match block {
                Block::KeyBlock(_block) => {
                    epoch += 1;
                }
                Block::MicroBlock(block) => {
                    for (output, _) in block.body.outputs.leafs() {
                        let output_hash = Hash::digest(&output);
                        if !self.contains_output(&output_hash) {
                            continue; // Spent.
                        }
                        match output.as_ref() {
                            Output::PaymentOutput(o) => {
                                if let Ok(_payload) = o.decrypt_payload(skey) {
                                    wallet_state.push((output.as_ref().clone(), epoch));
                                }
                            }
                            Output::StakeOutput(o) => {
                                if let Ok(_payload) = o.decrypt_payload(skey) {
                                    wallet_state.push((output.as_ref().clone(), epoch));
                                }
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
        let last_leader = if self.view_change > 1 {
            Some(self.select_leader(self.view_change - 1))
        } else {
            None
        };

        ElectionInfo {
            height: self.height,
            view_change: self.view_change,
            slots_count: self.cfg.max_slot_count as i64,
            last_leader,
            current_leader: self.select_leader(self.view_change),
            next_leader: self.select_leader(self.view_change + 1),
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
    pub fn output_by_hash(&self, output_hash: &Hash) -> Result<Option<Output>, Error> {
        if let Some(OutputKey { height, path }) = self.output_by_hash.get(output_hash) {
            let block = self.block_by_height(*height)?;
            if let Block::MicroBlock(MicroBlock { header: _, body }) = block {
                if let Some(output) = body.outputs.lookup(path) {
                    return Ok(Some(output.as_ref().clone()));
                } else {
                    return Ok(None);
                }
            } else {
                unreachable!(); // Non-micro block
            }
        }
        return Ok(None);
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

    /// Returns the last block height.
    #[inline]
    pub fn last_key_block_height(&self) -> u64 {
        self.last_key_block_height
    }

    /// Return the timestamp from the last key block.
    #[inline]
    pub fn last_key_block_timestamp(&self) -> SystemTime {
        self.last_key_block_timestamp
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

    /// Check that the stake can be unstaked.
    #[inline]
    pub fn validate_unstake(
        &self,
        validator_pkey: &secure::PublicKey,
        output_hash: &Hash,
    ) -> Result<(), OutputError> {
        self.escrow
            .validate_unstake(validator_pkey, output_hash, self.epoch)
    }

    /// Return information about escrow.
    #[inline]
    pub fn escrow_info(&self) -> EscrowInfo {
        self.escrow.info(self.epoch)
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

    pub fn election_result(&self) -> ElectionResult {
        self.election_result.clone()
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
            "Validating a key block: height={}, block={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                block_hash,
                VERSION,
                block.header.base.version,
            )
            .into());
        }

        // Check height.
        if block.header.base.height != self.height {
            return Err(BlockError::OutOfOrderBlock(
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
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    block_hash,
                    block.header.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, block_hash).into());
        }

        // skip leader selection and signature checking for genesis block.
        if self.epoch > 0 {
            // Skip view change check, just check supermajority.
            let leader = self.select_leader(block.header.base.view_change);
            debug!(
                "Validating VRF: leader={}, round={}",
                leader, block.header.base.view_change
            );
            let seed = mix(self.last_random(), block.header.base.view_change);
            if !secure::validate_VRF_source(&block.header.random, &leader, &seed) {
                return Err(BlockError::IncorrectRandom(height, block_hash).into());
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
                if !block.body.multisigmap.contains(*leader_id as usize) {
                    return Err(BlockError::NoLeaderSignatureFound(height, block_hash).into());
                }
            } else {
                return Err(BlockError::LeaderIsNotValidator(height, block_hash).into());
            }

            // checks that proposal is signed only by leader.
            if is_proposal {
                if block.body.multisigmap.len() != 1 {
                    return Err(
                        BlockError::MoreThanOneSignatureAtPropose(height, block_hash).into(),
                    );
                }
                if let Err(_e) = secure::check_hash(&block_hash, &block.body.multisig, &leader) {
                    return Err(BlockError::InvalidLeaderSignature(height, block_hash).into());
                }
            } else {
                check_multi_signature(
                    &block_hash,
                    &block.body.multisig,
                    &block.body.multisigmap,
                    self.validators(),
                    self.total_slots(),
                )
                .map_err(|e| BlockError::InvalidBlockSignature(e, height, block_hash))?;
            }
        }

        debug!(
            "The key block is valid: height={}, block={}",
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
                "A block hash collision: height={}, block={}",
                height, block_hash
            );
        }
        assert_eq!(self.block_by_hash.current_version(), version);

        //
        // Update metadata.
        //

        self.last_block_hash = block_hash.clone();
        self.height += 1;
        self.epoch += 1;
        self.last_key_block_height = height;
        self.last_key_block_timestamp = block.header.base.timestamp;
        self.election_result = election::select_validators_slots(
            self.escrow
                .get_stakers_majority(self.epoch, self.cfg.min_stake_amount),
            block.header.random,
            self.cfg.max_slot_count,
        );
        self.view_change = 0;
        assert_eq!(self.height, version);
        metrics::HEIGHT.set(self.height as i64);
        metrics::EPOCH.inc();

        info!(
            "Registered a key block: height={}, block={}",
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
    /// Add a new micro block into blockchain.
    ///
    pub fn push_micro_block(
        &mut self,
        block: MicroBlock,
        timestamp: SystemTime,
    ) -> Result<(Vec<Output>, Vec<Output>), Error> {
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
    /// Validate sealed micro block.
    ///
    /// # Arguments
    ///
    /// * `block` - block to validate.
    /// * `is_proposal` - don't check for the supermajority of votes.
    ///                          Used to validating block proposals.
    /// * `timestamp` - current time.
    ///                         Used to validating escrow.
    ///
    pub fn validate_micro_block(
        &self,
        block: &MicroBlock,
        _timestamp: SystemTime,
    ) -> Result<(), Error> {
        let height = block.header.base.height;
        let block_hash = Hash::digest(&block);
        debug!(
            "Validating a micro block: height={}, block={}",
            height, &block_hash
        );

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockError::InvalidBlockVersion(
                height,
                block_hash,
                block.header.base.version,
                VERSION,
            )
            .into());
        }

        // Check height.
        if height != self.height {
            return Err(BlockError::OutOfOrderBlock(block_hash, height, self.height).into());
        }

        // Check previous hash.
        if self.height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockError::InvalidPreviousHash(
                    height,
                    block_hash,
                    block.header.base.previous,
                    previous_hash,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockError::BlockHashCollision(height, block_hash).into());
        }

        // Check signature (exclude epoch == 0 for genesis).
        if self.epoch > 0 {
            let leader = match block.header.base.view_change.cmp(&self.view_change) {
                Ordering::Equal => self.leader(),
                Ordering::Greater => {
                    let chain = ChainInfo::from_micro_block(&block);
                    match block.header.proof {
                        Some(ref proof) => {
                            if let Err(e) = proof.validate(&chain, &self) {
                                return Err(BlockError::InvalidViewChangeProof(
                                    height,
                                    block_hash,
                                    proof.clone(),
                                    e,
                                )
                                .into());
                            }
                            self.select_leader(block.header.base.view_change)
                        }
                        _ => {
                            return Err(BlockError::NoProofWasFound(
                                height,
                                block_hash,
                                block.header.base.view_change,
                                self.view_change,
                            )
                            .into());
                        }
                    }
                }
                Ordering::Less => {
                    return Err(BlockError::InvalidViewChange(
                        height,
                        block_hash,
                        block.header.base.view_change,
                        self.view_change,
                    )
                    .into());
                }
            };
            if let Err(_e) = secure::check_hash(&block_hash, &block.body.sig, &leader) {
                return Err(BlockError::InvalidLeaderSignature(height, block_hash).into());
            }
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
        for input_hash in block.body.inputs.iter() {
            let input = match self.output_by_hash(input_hash)? {
                Some(input) => input,
                None => {
                    return Err(
                        BlockError::MissingBlockInput(height, block_hash, *input_hash).into(),
                    );
                }
            };
            // Check for the duplicate input.
            if !input_set.insert(*input_hash) {
                return Err(
                    BlockError::DuplicateBlockInput(height, block_hash, *input_hash).into(),
                );
            }

            // Update balance
            burned += input.commitment()?;

            // Check UTXO.
            match input {
                Output::StakeOutput(o) => {
                    o.validate_pkey()?;
                    self.escrow
                        .validate_unstake(&o.validator, input_hash, self.epoch)
                        .expect("Valid unstake");
                }
                _ => {}
            }
            input_hash.hash(&mut hasher);
        }
        drop(input_set);
        let inputs_range_hash = hasher.result();
        if block.header.inputs_range_hash != inputs_range_hash {
            let expected = block.header.inputs_range_hash.clone();
            let got = inputs_range_hash;
            return Err(
                BlockError::InvalidBlockInputsHash(height, block_hash, expected, got).into(),
            );
        }
        //
        // Validate outputs.
        //
        let mut output_set: HashSet<Hash> = HashSet::new();
        for (output, _path) in block.body.outputs.leafs() {
            // Check that hash is unique.
            let output_hash = Hash::digest(output.as_ref());
            if let Some(_) = self.output_by_hash.get(&output_hash) {
                return Err(
                    BlockError::OutputHashCollision(height, block_hash, output_hash).into(),
                );
            }
            // Check for the duplicate output.
            if !output_set.insert(output_hash) {
                return Err(
                    BlockError::DuplicateBlockOutput(height, block_hash, output_hash).into(),
                );
            }

            // Update balance.
            created += output.commitment()?;

            // Check UTXO.
            match output.as_ref() {
                Output::PaymentOutput(o) => {
                    // Validate bullet proofs.
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof(output_hash).into());
                    }
                    // Validate payload.
                    if o.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            output_hash,
                            PAYMENT_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                }
                Output::StakeOutput(o) => {
                    // Check for valid signature on network pkey.
                    o.validate_pkey()?;
                    // Validate amount.
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake(output_hash).into());
                    }
                    // Validate payload.
                    if o.payload.ctxt.len() != STAKE_PAYLOAD_LEN {
                        return Err(OutputError::InvalidPayloadLength(
                            output_hash,
                            STAKE_PAYLOAD_LEN,
                            o.payload.ctxt.len(),
                        )
                        .into());
                    }
                }
            }
        }
        drop(output_set);
        if block.header.outputs_range_hash != *block.body.outputs.roothash() {
            let expected = block.header.outputs_range_hash.clone();
            let got = block.body.outputs.roothash().clone();
            return Err(
                BlockError::InvalidBlockOutputsHash(height, block_hash, expected, got).into(),
            );
        }

        //
        // Validate block monetary balance.
        //
        if fee_a(block.header.monetary_adjustment) + burned - created != block.header.gamma * (*G) {
            return Err(BlockError::InvalidBlockBalance(height, block_hash).into());
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
            panic!(
                "Invalid global monetary balance: height={}, block={}",
                height, &block_hash
            );
        }

        debug!(
            "The micro block is valid: height={}, block={}",
            height, &block_hash
        );
        Ok(())
    }

    //
    fn register_micro_block(
        &mut self,
        mut block: MicroBlock,
        _timestamp: SystemTime,
    ) -> Result<(Vec<Output>, Vec<Output>), Error> {
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
        let mut inputs: Vec<Output> = Vec::with_capacity(block.body.inputs.len());
        for input_hash in &block.body.inputs {
            if let Some(OutputKey { height, path }) =
                self.output_by_hash.remove(version, input_hash)
            {
                assert_eq!(self.output_by_hash.current_version(), version);
                let block = self.block_by_height(height)?;
                let block_hash = Hash::digest(&block);
                if let Block::MicroBlock(MicroBlock { header: _, body }) = block {
                    // Remove from the block.
                    match body.outputs.lookup(&path) {
                        Some(o) => {
                            burned += o.commitment()?;
                            match o.as_ref() {
                                Output::StakeOutput(o) => {
                                    o.validate_pkey().expect("valid network pkey");
                                    self.escrow.unstake(
                                        version,
                                        o.validator,
                                        input_hash.clone(),
                                        self.epoch,
                                    );
                                    assert_eq!(self.escrow.current_version(), version);
                                    // burned += Pt::decompress(o.commitment)?;
                                }
                                _ => {}
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
                    "Missing input UTXO: height={}, block={}, utxo={}",
                    height, &block_hash, &input_hash
                );
            }

            debug!(
                "Pruned UXTO: height={}, block={}, utxo={}",
                height, &block_hash, &input_hash
            );
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
                panic!(
                    "UTXO hash collision: height={}, block={}, utxo={}",
                    height, &block_hash, &output_hash
                );
            }
            assert_eq!(self.output_by_hash.current_version(), version);

            created += output.commitment()?;
            match output.as_ref() {
                Output::StakeOutput(o) => {
                    o.validate_pkey().expect("valid network pkey signature");
                    let active_until_epoch = self.epoch + self.cfg.stake_epochs;
                    self.escrow.stake(
                        version,
                        o.validator,
                        output_hash,
                        active_until_epoch,
                        o.amount,
                    );
                    assert_eq!(self.escrow.current_version(), version);
                }
                _ => {}
            }

            outputs.push(output.as_ref().clone());
            debug!(
                "Registered UXTO: height={}, block={}, utxo={}",
                height, &block_hash, &output_hash
            );
        }

        // Check the block monetary balance.
        if fee_a(block.header.monetary_adjustment) + burned - created != block.header.gamma * (*G) {
            panic!(
                "Invalid block monetary balance: height={}, block={}",
                height, &block_hash
            )
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
            panic!(
                "Invalid global monetary balance: height={}, block={}",
                height, &block_hash
            );
        }
        self.balance.insert(version, (), balance);
        assert_eq!(self.balance.current_version(), version);
        self.last_block_hash = block_hash.clone();
        self.view_change = block.header.base.view_change + 1;
        self.height += 1;
        assert_eq!(self.height, version);
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        info!(
            "Registered a micro block: height={}, block={}, inputs={}, outputs={}",
            height,
            block_hash,
            inputs.len(),
            outputs.len()
        );

        Ok((inputs, outputs))
    }

    pub fn pop_micro_block(&mut self) -> Result<(Vec<Output>, Vec<Output>), Error> {
        assert!(self.height > 1);
        let height = self.height - 1;
        assert_ne!(
            height, self.last_key_block_height,
            "attempt to revert the key block"
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
        self.view_change = match previous {
            Block::KeyBlock(ref _previous) => 0,
            Block::MicroBlock(ref previous) => previous.header.base.view_change + 1,
        };
        metrics::HEIGHT.set(self.height as i64);
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        let mut pruned: Vec<Output> = Vec::new();
        for (output, _path) in block.body.outputs.leafs() {
            pruned.push(output.as_ref().clone());
            let output_hash = Hash::digest(output.as_ref());
            debug!(
                "Reverted UTXO: height={}, block={}, utxo={}",
                height, &block_hash, &output_hash
            );
        }

        let mut created: Vec<Output> = Vec::new();
        for input_hash in &block.body.inputs {
            let input = self.output_by_hash(input_hash)?.expect("exists");
            created.push(input);
            debug!(
                "Restored UXTO: height={}, block={}, utxo={}",
                height, &block_hash, &input_hash
            );
        }

        info!(
            "Reverted a micro block: height={}, block={}, inputs={}, outputs={}",
            self.height,
            Hash::digest(&block),
            created.len(),
            pruned.len()
        );

        Ok((pruned, created))
    }
}

pub fn create_fake_key_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: SystemTime,
) -> KeyBlock {
    let version: u64 = VERSION;
    let height = chain.height();
    let view_change = chain.view_change();;
    let key = chain.select_leader(view_change);
    let keychain = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let mut block = {
        let previous = chain.last_block_hash();
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
        let seed = mix(chain.last_random(), view_change);
        let random = secure::make_VRF(&keychain.network_skey, &seed);
        KeyBlock::new(base, random)
    };
    let block_hash = Hash::digest(&block);
    let validators = chain.validators();
    let mut signatures: BTreeMap<secure::PublicKey, secure::Signature> = BTreeMap::new();
    for keychain in keychains {
        let sig = secure::sign_hash(&block_hash, &keychain.network_skey);
        signatures.insert(keychain.network_pkey.clone(), sig);
    }
    let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
    block.body.multisig = multisig;
    block.body.multisigmap = multisigmap;
    block
}

pub fn create_fake_micro_block(
    chain: &mut Blockchain,
    keys: &KeyChain,
    timestamp: SystemTime,
    with_stakes: bool,
) -> (MicroBlock, Vec<Hash>, Vec<Hash>) {
    let mut input_hashes: Vec<Hash> = Vec::new();
    let mut gamma: Fr = Fr::zero();
    let mut amount: i64 = 0;
    for input_hash in chain.unspent() {
        let input = chain
            .output_by_hash(&input_hash)
            .expect("no disk errors")
            .expect("exists");
        match input {
            Output::PaymentOutput(ref o) => {
                let payload = o.decrypt_payload(&keys.wallet_skey).unwrap();
                gamma += payload.gamma;
                amount += payload.amount;
                input_hashes.push(input_hash.clone());
            }
            Output::StakeOutput(ref o) => {
                if !with_stakes {
                    continue;
                }
                o.validate_pkey().expect("valid network pkey signature");
                let payload = o.decrypt_payload(&keys.wallet_skey).unwrap();
                gamma += payload.gamma;
                amount += o.amount;
                input_hashes.push(input_hash.clone());
            }
        }
    }

    let mut outputs: Vec<Output> = Vec::new();
    let stake = chain.cfg.min_stake_amount;
    let (output, output_gamma) = PaymentOutput::new(
        timestamp,
        &keys.wallet_skey,
        &keys.wallet_pkey,
        amount - stake,
    )
    .expect("keys are valid");
    outputs.push(Output::PaymentOutput(output));
    gamma -= output_gamma;
    let (output, output_gamma) = StakeOutput::new(
        timestamp,
        &keys.wallet_skey,
        &keys.wallet_pkey,
        &keys.network_pkey,
        &keys.network_skey,
        stake,
    )
    .expect("keys are valid");
    outputs.push(Output::StakeOutput(output));
    gamma -= output_gamma;

    let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();

    let version: u64 = VERSION;
    let height = chain.height();
    let view_change = chain.view_change();;
    let previous = chain.last_block_hash().clone();
    let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
    let mut block = MicroBlock::new(base, gamma, 0, &input_hashes, &outputs, None);
    let block_hash = Hash::digest(&block);
    block.body.sig = secure::sign_hash(&block_hash, &keys.network_skey);
    (block, input_hashes, output_hashes)
}

pub fn create_empty_micro_block(
    chain: &mut Blockchain,
    keys: &KeyChain,
    timestamp: SystemTime,
) -> MicroBlock {
    let input_hashes: Vec<Hash> = Vec::new();
    let outputs: Vec<Output> = Vec::new();
    let gamma = Fr::zero();
    let version = VERSION;
    let previous = chain.last_block_hash().clone();
    let height = chain.height();
    let view_change = chain.view_change();;
    let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
    let mut block = MicroBlock::new(base, gamma, 0, &input_hashes, &outputs, None);
    let block_hash = Hash::digest(&block);
    block.body.sig = secure::sign_hash(&block_hash, &keys.network_skey);
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
        assert_eq!(blocks.len(), 2);
        let (block1, block2) = match &blocks[..] {
            [Block::MicroBlock(block1), Block::KeyBlock(block2)] => (block1, block2),
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

        assert_eq!(blockchain.height(), 2);
        assert_eq!(blockchain.height, block2.header.base.height + 1);
        assert_eq!(blockchain.blocks_in_epoch(), 1);
        let validators = blockchain
            .escrow
            .get_stakers_majority(blockchain.epoch, blockchain.cfg.min_stake_amount);
        assert_eq!(validators.len(), keychains.len());
        let validators_map: BTreeMap<_, _> = validators.iter().cloned().collect();
        for keychain in &keychains {
            let stake = validators_map.get(&keychain.network_pkey).expect("exists");
            assert_eq!(*stake, blockchain.cfg.min_stake_amount);
        }
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
        cfg.stake_epochs = 0;
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

        for _epoch in 0..2 {
            //
            // Non-empty block.
            //
            timestamp += Duration::from_millis(1);
            let (block, input_hashes, output_hashes) =
                create_fake_micro_block(&mut chain, &keychains[0], timestamp, true);
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
            let block = create_empty_micro_block(&mut chain, &keychains[0], timestamp);
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
            let block = create_fake_key_block(&chain, &keychains, timestamp);
            let hash = Hash::digest(&block);
            let height = chain.height();
            chain.push_key_block(block).expect("Invalid block");
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
        let mut cfg: BlockchainConfig = Default::default();
        cfg.stake_epochs = 0;
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
            create_fake_micro_block(&mut chain, &keychains[0], timestamp, true);
        chain
            .push_micro_block(block1, timestamp)
            .expect("block is valid");
        assert_eq!(height0 + 1, chain.height());
        assert_eq!(view_change0 + 1, chain.view_change());
        assert_ne!(block_hash0, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_ne!(&balance0, chain.balance());
        assert_ne!(escrow0, chain.escrow_info());
        for input_hash in &input_hashes1 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes1 {
            assert!(chain.contains_output(output_hash));
        }
        let height1 = chain.height();
        let view_change1 = 1;
        let block_hash1 = chain.last_block_hash();
        let balance1 = chain.balance().clone();
        let escrow1 = chain.escrow_info().clone();

        // Register one more micro block.
        timestamp += Duration::from_millis(1);
        let (block2, input_hashes2, output_hashes2) =
            create_fake_micro_block(&mut chain, &keychains[0], timestamp, false);
        chain
            .push_micro_block(block2, timestamp)
            .expect("block is valid");
        assert_eq!(height1 + 1, chain.height());
        assert_eq!(view_change1 + 1, chain.view_change());
        assert_ne!(block_hash1, chain.last_block_hash());
        assert_eq!(chain.blocks().count() as u64, chain.height());
        assert_ne!(&balance1, chain.balance());
        assert_ne!(escrow1, chain.escrow_info());
        for input_hash in &input_hashes2 {
            assert!(!chain.contains_output(input_hash));
        }
        for output_hash in &output_hashes2 {
            assert!(chain.contains_output(output_hash));
        }

        // Pop the last micro block.
        chain.pop_micro_block().expect("no disk errors");
        assert_eq!(height1, chain.height());
        assert_eq!(view_change1, chain.view_change());
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
        let keychains = [
            KeyChain::new_mem(),
            KeyChain::new_mem(),
            KeyChain::new_mem(),
        ];

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
            let block = create_fake_key_block(&blockchain, &keychains[..], timestamp);
            blockchain.push_key_block(block).expect("block is valid");
        }

        assert_eq!(blockchain.blocks_range(starting_height, 1).len(), 1);

        assert_eq!(blockchain.blocks_range(starting_height, 4).len(), 4);
        // limit
        assert_eq!(blockchain.blocks_range(starting_height, 20).len(), 10);
        // empty
        assert_eq!(blockchain.blocks_range(blockchain.height(), 1).len(), 0);
    }
}

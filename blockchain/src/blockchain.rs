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
use crate::output::*;
use crate::storage::ListDb;
use failure::ensure;
use failure::Error;
use log::*;
use std::collections::HashMap;
use std::collections::HashSet;
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

pub const MAX_SLOTS_COUNT: usize = 1000;

/// A help to find UTXO in this blockchain.
struct OutputKey {
    /// The short block identifier.
    pub block_id: u64,
    /// Merkle Tree path inside block.
    pub path: MerklePath,
}

/// The blockchain database.
pub struct Blockchain {
    //
    // Storage.
    //
    /// Persistent storage for blocks.
    database: ListDb,
    /// In-memory index to lookup blocks by its hash.
    block_by_hash: HashMap<Hash, u64>,
    /// In-memory index to lookup UTXO by its hash.
    output_by_hash: HashMap<Hash, OutputKey>,
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
    last_key_block_id: u64,
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

    //
    // Global Monetary Balance.
    //
    /// The total sum of money created.
    created: ECp,
    /// The total sum of money burned.
    burned: ECp,
    /// The total sum of gamma adjustments.
    gamma: Fr,
    /// The total sum of monetary adjustments.
    monetary_adjustment: i64,
}

impl Blockchain {
    //----------------------------------------------------------------------------------------------
    // Constructors.
    //----------------------------------------------------------------------------------------------

    pub fn new(config: &StorageConfig, genesis: Vec<Block>, current_timestamp: u64) -> Blockchain {
        let database = ListDb::new(&config.database_path);
        Self::with_db(database, genesis, current_timestamp)
    }

    pub fn testing(genesis: Vec<Block>, current_timestamp: u64) -> Blockchain {
        let database = ListDb::testing();
        Self::with_db(database, genesis, current_timestamp)
    }

    fn with_db(database: ListDb, genesis: Vec<Block>, current_timestamp: u64) -> Blockchain {
        //
        // Storage.
        //
        let block_by_hash = HashMap::<Hash, u64>::new();
        let output_by_hash = HashMap::<Hash, OutputKey>::new();
        let escrow = Escrow::new();

        //
        // Epoch Information.
        //
        let epoch: u64 = 0;
        let last_key_block_id: u64 = 0;
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

        //
        // Global Monetary Balance.
        //
        let created = ECp::inf();
        let burned = ECp::inf();
        let gamma = Fr::zero();
        let monetary_adjustment: i64 = 0;

        let mut blockchain = Blockchain {
            database,
            block_by_hash,
            output_by_hash,
            escrow,
            epoch,
            last_key_block_id,
            election_result,
            height,
            last_block_timestamp,
            last_block_hash,
            view_change,
            created,
            burned,
            gamma,
            monetary_adjustment,
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
        self.height - self.last_key_block_id
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
        if let Some(OutputKey { block_id, path }) = self.output_by_hash.get(output_hash) {
            let block = self.block_by_id(*block_id)?;
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
        if let Some(_block_id) = self.block_by_hash.get(block_hash) {
            return true;
        }
        return false;
    }

    /// Get a block by id.
    fn block_by_id(&self, block_id: u64) -> Result<Block, Error> {
        assert!(block_id < self.height);
        Ok((self.database.get(block_id)?).expect("block exists"))
    }

    /// Return iterator over saved blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Block> {
        self.database.iter()
    }

    /// Returns blocks history starting from block_hash, limited by count.
    pub fn blocks_range(&self, starting_hash: &Hash, count: u64) -> Option<Vec<Block>> {
        if let Some(&block_id) = self.block_by_hash.get(starting_hash) {
            let block_id = block_id + 1;
            return Some(
                self.database
                    .iter_starting(block_id as u64)
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

    /// Returns number of leader changes since last epoch creation.
    pub fn view_change(&self) -> u32 {
        self.view_change
    }

    //----------------------------------------------------------------------------------------------
    // Key Blocks
    //----------------------------------------------------------------------------------------------

    ///
    /// Add a new block into blockchain.
    ///
    pub fn push_key_block(&mut self, block: KeyBlock) -> Result<(), Error> {
        let block_id = self.height;

        //
        // Validate the key block.
        //
        self.validate_key_block(&block, false)?;

        //
        // Write the key block to the disk.
        //
        self.database
            .insert(block_id as u64, Block::KeyBlock(block.clone()))?;

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
        let block_hash = Hash::digest(&block);
        debug!("Validating a key block: hash={}", &block_hash);

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockchainError::InvalidBlockVersion(
                block_hash,
                VERSION,
                block.header.base.version,
            )
            .into());
        }

        // Check epoch.
        if block.header.base.epoch != self.epoch + 1 {
            return Err(BlockchainError::OutOfOrderBlockEpoch(
                block_hash,
                self.epoch + 1,
                block.header.base.epoch,
            )
            .into());
        }

        // Check previous hash.
        if self.height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::PreviousHashMismatch(
                    previous_hash,
                    block.header.base.previous,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockchainError::BlockHashCollision(block_hash).into());
        }

        // Check validators.
        if block.header.validators.is_empty() {
            return Err(BlockchainError::MissingValidators.into());
        }
        if !block.header.validators.contains(&block.header.leader) {
            return Err(BlockchainError::LeaderIsNotValidator.into());
        }

        let seed = mix(self.last_random(), block.header.view_change);
        if !secure::validate_VRF_source(&block.header.random, &block.header.leader, &seed) {
            return Err(BlockchainError::IncorrectRandom.into());
        }

        //Try to tmp elect according to random
        let election_result = election::select_validators_slots(
            self.escrow.get_stakers_majority().into_iter().collect(),
            block.header.random,
            MAX_SLOTS_COUNT,
        );

        //TODO: Remove validators list from keyblock.
        //TODO: Remove facilitator, leader from keyblock.

        let validators = &election_result.validators;

        // select leader work only with inited blockchain
        // view_change is equal to 0 at genesis
        // facilitator is equal to leader at genesis
        if self.epoch > 0 {
            ensure!(block.header.leader == self.leader(), "Wrong leader");
            // TODO: Use real view_change
            ensure!(
                block.header.view_change == self.view_change(),
                "Wrong view_change"
            );
            ensure!(
                block.header.facilitator == election_result.facilitator,
                "Wrong facilitator"
            );
            for (election, key_block) in validators
                .iter()
                .map(|(k, _)| k)
                .zip(&block.header.validators)
            {
                ensure!(
                    election == key_block,
                    BlockchainError::ValidatorsNotEqualToOurStakers
                );
            }
        }

        // Check multisignature.
        if !check_multi_signature(
            &block_hash,
            &block.header.base.multisig,
            &block.header.base.multisigmap,
            &validators,
            &block.header.leader,
            is_proposal,
        ) {
            return Err(BlockchainError::InvalidBlockSignature(block_hash).into());
        }

        debug!("The key block is valid: hash={}", &block_hash);
        Ok(())
    }

    ///
    /// Update indexes and metadata.
    ///
    fn register_key_block(&mut self, block: KeyBlock) {
        let block_id = self.height;
        let block_hash = Hash::digest(&block);

        //
        // Update indexes.
        //
        if let Some(_) = self.block_by_hash.insert(block_hash.clone(), block_id) {
            panic!("Block hash collision");
        }

        //
        // Update metadata.
        //

        self.last_block_timestamp = clock::now();
        self.last_block_hash = block_hash.clone();
        self.height += 1;
        self.epoch += 1;
        self.last_key_block_id = block_id;
        self.election_result = election::select_validators_slots(
            self.escrow.get_stakers_majority().into_iter().collect(),
            block.header.random,
            MAX_SLOTS_COUNT,
        );
        self.view_change = 0;

        metrics::HEIGHT.inc();
        metrics::EPOCH.inc();

        info!(
            "Registered key block: height={}, hash={}",
            self.height, block_hash
        );
        debug!("Validators: {:?}", &self.validators());
        for (key, stake) in self.validators().iter() {
            let key_str = key.to_string();
            metrics::VALIDATOR_STAKE_GAUGEVEC
                .with_label_values(&[key_str.as_str()])
                .set(*stake);
        }
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
        let block_id = self.height;

        //
        // Validate the monetary block.
        //
        self.validate_monetary_block(&block, current_timestamp)?;

        //
        // Write the monetary block to the disk.
        //
        self.database
            .insert(block_id as u64, Block::MonetaryBlock(block.clone()))?;

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
        let block_hash = Hash::digest(&block);
        debug!("Validating a monetary block: hash={}", &block_hash);

        // Check block version.
        if block.header.base.version != VERSION {
            return Err(BlockchainError::InvalidBlockVersion(
                block_hash,
                VERSION,
                block.header.base.version,
            )
            .into());
        }

        // Check epoch.
        if block.header.base.epoch != self.epoch {
            return Err(BlockchainError::OutOfOrderBlockEpoch(
                block_hash,
                self.epoch,
                block.header.base.epoch,
            )
            .into());
        }

        // Check previous hash.
        if self.height > 0 {
            let previous_hash = self.last_block_hash();
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::PreviousHashMismatch(
                    previous_hash,
                    block.header.base.previous,
                )
                .into());
            }
        }

        // Check new hash.
        if let Some(_) = self.block_by_hash.get(&block_hash) {
            return Err(BlockchainError::BlockHashCollision(block_hash).into());
        }

        //TODO: remove multisig?

        // Check multisignature (exclude epoch == 0 for genesis).
        if self.epoch > 0
            && !check_multi_signature(
                &block_hash,
                &block.header.base.multisig,
                &block.header.base.multisigmap,
                self.validators(),
                &self.leader(),
                true,
            )
        {
            return Err(BlockchainError::InvalidBlockSignature(block_hash).into());
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
        let created: ECp = self.created + created;
        let burned: ECp = self.burned + burned;
        let gamma: Fr = self.gamma + block.header.gamma;
        let monetary_adjustment: i64 = self.monetary_adjustment + block.header.monetary_adjustment;
        if fee_a(monetary_adjustment) + burned - created != gamma * (*G) {
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
        let block_id = self.height;
        let block_hash = Hash::digest(&block);
        let block_timestamp = block.header.base.timestamp;

        //
        // Update indexes.
        //
        if let Some(_) = self.block_by_hash.insert(block_hash.clone(), block_id) {
            panic!("Block hash collision");
        }

        let mut burned = ECp::inf();
        let mut created = ECp::inf();

        //
        // Process inputs.
        //
        let mut inputs: Vec<Output> = Vec::with_capacity(block.body.inputs.len());
        for input_hash in &block.body.inputs {
            if let Some(OutputKey { block_id, path }) = self.output_by_hash.remove(input_hash) {
                let block = self.block_by_id(block_id)?;
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
                                    self.escrow.unstake(
                                        o.validator,
                                        input_hash.clone(),
                                        current_timestamp,
                                    );
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
            let output_key = OutputKey { block_id, path };
            if let Some(_) = self.output_by_hash.insert(output_hash.clone(), output_key) {
                panic!("UTXO hash collision: hash={}", output_hash);
            }

            match output.as_ref() {
                Output::PaymentOutput(o) => {
                    created += Pt::decompress(o.proof.vcmt).expect("pedersen commitment is valid");
                }
                Output::StakeOutput(o) => {
                    created += fee_a(o.amount);
                    let bonding_timestamp = block_timestamp + crate::escrow::BONDING_TIME;
                    self.escrow
                        .stake(o.validator, output_hash, bonding_timestamp, o.amount);
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
        let created: ECp = self.created + created;
        let burned: ECp = self.burned + burned;
        let gamma: Fr = self.gamma + block.header.gamma;
        let monetary_adjustment: i64 = self.monetary_adjustment + block.header.monetary_adjustment;
        if fee_a(monetary_adjustment) + burned - created != gamma * (*G) {
            panic!("Invalid global monetary balance");
        }
        self.created = created;
        self.burned = burned;
        self.gamma = gamma;
        self.monetary_adjustment = monetary_adjustment;
        self.last_block_timestamp = clock::now();
        self.last_block_hash = block_hash.clone();
        self.height += 1;
        self.view_change += 1;
        metrics::HEIGHT.inc();
        metrics::UTXO_LEN.set(self.output_by_hash.len() as i64);

        info!(
            "Registered monetary block: height={}, hash={}, inputs={}, outputs={}",
            self.height,
            block_hash,
            inputs.len(),
            outputs.len()
        );

        Ok((inputs, outputs))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::election::select_validators_slots;
    use crate::genesis::genesis;
    use crate::multisignature::create_multi_signature;
    use chrono::prelude::Utc;
    use simple_logger;
    use std::collections::BTreeMap;
    use stegos_keychain::KeyChain;

    #[test]
    fn basic() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [KeyChain::new_mem()];
        let current_timestamp = Utc::now().timestamp() as u64;
        let blocks = genesis(&keychains, MIN_STAKE_AMOUNT, 1_000_000, current_timestamp);
        assert_eq!(blocks.len(), 2);
        let (block1, block2) = match &blocks[..] {
            [Block::MonetaryBlock(block1), Block::KeyBlock(block2)] => (block1, block2),
            _ => panic!(),
        };
        let blockchain = Blockchain::testing(blocks.clone(), current_timestamp);
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
        assert_eq!(blockchain.epoch, block2.header.base.epoch);
        assert_eq!(blockchain.blocks_in_epoch(), 1);
        assert_eq!(blockchain.leader(), block2.header.leader);
        assert_eq!(*blockchain.facilitator(), block2.header.facilitator);
        let validators = blockchain.escrow.get_stakers_majority();
        assert_eq!(validators.len(), keychains.len());
        let validators_map: BTreeMap<_, _> = validators.iter().cloned().collect();
        for keychain in &keychains {
            let stake = validators_map.get(&keychain.network_pkey).expect("exists");
            assert_eq!(*stake, MIN_STAKE_AMOUNT);
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
            Hash::digest(&blockchain.block_by_id(0).unwrap()),
            Hash::digest(&block1)
        );
        assert_eq!(
            Hash::digest(&blockchain.block_by_id(1).unwrap()),
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

    #[test]
    fn block_range_limit() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let keychains = [
            KeyChain::new_mem(),
            KeyChain::new_mem(),
            KeyChain::new_mem(),
        ];

        let stake = MIN_STAKE_AMOUNT;
        let current_timestamp = Utc::now().timestamp() as u64;
        let blocks = genesis(&keychains, stake, 1_000_000, current_timestamp);
        let mut blockchain = Blockchain::testing(blocks, current_timestamp);
        let start = blockchain.last_block_hash();
        // len of genesis
        assert!(blockchain.height() > 0);
        let version: u64 = 1;
        for epoch in 2..12 {
            let view_change = blockchain.view_change();;
            let key = blockchain.select_leader(view_change);
            let keychain = keychains.iter().find(|p| p.network_pkey == key).unwrap();
            let mut block = {
                let previous = blockchain.last_block_hash();
                let base = BaseBlockHeader::new(version, previous, epoch, 0);

                let leader = keychain.network_pkey.clone();
                let seed = mix(blockchain.last_random(), view_change);
                let random = secure::make_VRF(&keychain.network_skey, &seed);
                let election = select_validators_slots(
                    blockchain
                        .escrow
                        .get_stakers_majority()
                        .into_iter()
                        .collect(),
                    random,
                    MAX_SLOTS_COUNT,
                );

                let facilitator = election.facilitator;
                let validators = election.validators.into_iter().map(|(k, _)| k).collect();
                KeyBlock::new(base, leader, facilitator, random, view_change, validators)
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
            block.header.base.multisig = multisig;
            block.header.base.multisigmap = multisigmap;
            blockchain.push_key_block(block).expect("block is valid");
        }

        assert_eq!(blockchain.blocks_range(&start, 1).unwrap().len(), 1);

        assert_eq!(blockchain.blocks_range(&start, 4).unwrap().len(), 4);
        // limit
        assert_eq!(blockchain.blocks_range(&start, 20).unwrap().len(), 10);
    }
}

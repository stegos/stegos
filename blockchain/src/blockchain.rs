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
use crate::error::*;
use crate::escrow::*;
use crate::merkle::*;
use crate::metrics;
use crate::output::*;
use crate::storage::ListDb;
use chrono::Utc;
use failure::Error;
use log::*;
use std::collections::BTreeMap;
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

/// A help to find UTXO in this blockchain.
struct OutputKey {
    /// The short block identifier.
    pub block_id: u64,
    /// Merkle Tree path inside block.
    pub path: MerklePath,
}

/// The Blockchain.
pub struct Blockchain {
    /// Database.
    database: ListDb,

    /// Block by hash mapping.
    block_by_hash: HashMap<Hash, u64>,
    /// Unspent outputs by hash.
    output_by_hash: HashMap<Hash, OutputKey>,

    //TODO: most of this fields is just duplication of keyblock. Save keyblock rather then copy of fields.
    //
    // Last blockchain info:
    // 1) Stake
    // 2) consensus group
    // 3) last block time
    // 4) epoch
    //
    /// Escrow
    pub escrow: Escrow,
    /// Snapshot of selected leader from the latest key block.
    pub leader: secure::PublicKey,
    /// Snapshot of selected facilitator from the latest key block.
    pub facilitator: secure::PublicKey,
    /// Snapshot of validators with stakes from the latest key block.
    pub validators: BTreeMap<secure::PublicKey, i64>,
    /// A timestamp when the last sealed block was received.
    pub last_block_timestamp: Instant,
    /// The hash of the last block.
    pub last_block_hash: Hash,

    /// Copy of rnadom from last keyblock.
    pub last_random: Hash,
    /// The number of blocks.
    pub height: u64,
    /// A monotonically increasing value that represents the epoch of the blockchain,
    /// starting from genesis block (=0).
    pub epoch: u64,
    /// Last height where epoch was changed.
    pub last_epoch_change: u64,

    // Monetary info
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
    // Public API
    //----------------------------------------------------------------------------------------------

    pub fn new(config: &StorageConfig) -> Blockchain {
        let database = ListDb::new(&config.database_path);
        Self::with_db(database)
    }

    pub fn testing() -> Blockchain {
        let database = ListDb::testing();
        Self::with_db(database)
    }

    fn with_db(database: ListDb) -> Blockchain {
        let block_by_hash = HashMap::<Hash, u64>::new();
        let output_by_hash = HashMap::<Hash, OutputKey>::new();
        let height: u64 = 0;
        let epoch: u64 = 0;
        let escrow = Escrow::new();
        let leader: secure::PublicKey = secure::G2::generator().into(); // some fake key
        let facilitator: secure::PublicKey = secure::G2::generator().into(); // some fake key
        let validators = BTreeMap::<secure::PublicKey, i64>::new();
        let last_block_timestamp = clock::now();
        let last_block_hash = Hash::digest("genesis");
        let last_random = Hash::digest("random");
        let created = ECp::inf();
        let burned = ECp::inf();
        let gamma = Fr::zero();
        let monetary_adjustment: i64 = 0;
        let last_epoch_change = 0;
        let mut blockchain = Blockchain {
            database,
            block_by_hash,
            output_by_hash,
            escrow,
            leader,
            facilitator,
            validators,
            height,
            epoch,
            last_epoch_change,
            last_block_timestamp,
            last_block_hash,
            last_random,
            created,
            burned,
            gamma,
            monetary_adjustment,
        };
        let current_timestamp = Utc::now().timestamp() as u64;
        blockchain.load_blockchain(current_timestamp);
        blockchain
    }

    fn load_blockchain(&mut self, current_timestamp: u64) {
        let mut blocks = self.database.iter();

        let block = blocks.next();
        let block = if let Some(block) = block {
            block
        } else {
            debug!("Creating a new blockchain.");
            return;
        };

        info!("Loading blockchain from database.");

        self.handle_block(block, current_timestamp);
        for block in blocks {
            self.handle_block(block, current_timestamp);
        }
    }

    fn handle_block(&mut self, block: Block, current_timestamp: u64) {
        debug!(
            "Loading a block from the disk: hash={}",
            Hash::digest(&block)
        );
        // Skip validate_key_block()/validate_monetary_block().
        match block {
            Block::MonetaryBlock(block) => {
                if cfg!(debug_assertions) {
                    self.validate_monetary_block(&block, false, current_timestamp)
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

    /// Returns count of blocks in current epoch.
    pub fn blocks_in_epoch(&self) -> u64 {
        self.height - self.last_epoch_change
    }

    /// Returns an iterator over UTXO hashes.
    pub fn unspent(&self) -> Vec<Hash> {
        // TODO: return iterator instead.
        self.output_by_hash.keys().cloned().collect()
    }

    /// Returns true if blockchain contains unspent output.
    pub fn contains_output(&self, output_hash: &Hash) -> bool {
        if let Some(OutputKey { .. }) = self.output_by_hash.get(output_hash) {
            return true;
        }
        return false;
    }

    /// Find UTXO by its hash.
    pub fn output_by_hash(&self, output_hash: &Hash) -> Result<Option<Output>, Error> {
        if let Some(OutputKey { block_id, path }) = self.output_by_hash.get(output_hash) {
            let block = self.block_by_id(*block_id)?;
            if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                if let Some(output) = body.outputs.lookup(path) {
                    return Ok(Some(output.as_ref().clone()));
                } else {
                    return Ok(None);
                }
            } else {
                unreachable!(); // Non-monetary block
            }
        }
        return Ok(None);
    }

    /// Resolve UTXOs by its hashes.
    pub fn outputs_by_hashes(&self, output_hashes: &[Hash]) -> Result<Vec<Output>, Error> {
        // Find appropriate UTXO in the database.
        // TODO: optimize this function for batch processing.
        let mut outputs = Vec::<Output>::new();
        for output_hash in output_hashes {
            let input = match self.output_by_hash(output_hash)? {
                Some(o) => o.clone(),
                None => return Err(BlockchainError::MissingUTXO(output_hash.clone()).into()),
            };
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

    /// Get block by id.
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

    /// Return the last random value.
    pub fn last_random(&self) -> Hash {
        self.last_random
    }

    /// Return the last block hash.
    pub fn last_block_hash(&self) -> Hash {
        assert!(self.height > 0);
        self.last_block_hash.clone()
    }

    /// Return the current blockchain height.
    pub fn height(&self) -> u64 {
        self.height
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
        let validators = self.escrow.multiget(&block.header.validators);
        let stakers = self.escrow.get_stakers_majority();
        // We didn't allows fork, this is done by forcing group to be the same as stakers count.
        if stakers != validators {
            return Err(BlockchainError::ValidatorsNotEqualToOurStakers.into());
        }

        let seed = mix(self.last_random, block.header.view_change);
        if !secure::validate_VRF_source(&block.header.random, &block.header.leader, &seed) {
            return Err(BlockchainError::IncorrectRandom.into());
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
        self.height = self.height + 1;
        self.epoch = self.epoch + 1;
        self.last_epoch_change = block_id;
        self.last_random = block.header.random.rand.clone();
        self.leader = block.header.leader.clone();
        self.facilitator = block.header.facilitator.clone();
        self.validators = self.escrow.multiget(&block.header.validators);
        metrics::HEIGHT.inc();
        metrics::EPOCH.inc();

        info!(
            "Registered key block: height={}, hash={}",
            self.height, block_hash
        );
        debug!("Validators: {:?}", &self.validators);
        for (key, stake) in self.validators.iter() {
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
        self.validate_monetary_block(&block, false, current_timestamp)?;

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
        is_proposal: bool,
        current_timestamp: u64,
    ) -> Result<(), Error> {
        let block_hash = Hash::digest(&block);
        debug!("Validating a monetary block: hash={}", &block_hash);

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

        // Check multisignature (exclude epoch == 0 for genesis).
        if self.epoch > 0
            && !check_multi_signature(
                &block_hash,
                &block.header.base.multisig,
                &block.header.base.multisigmap,
                &self.validators,
                &self.leader,
                is_proposal,
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
        self.height = self.height + 1;
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

/// Mix seed hash with round value to produce new hash.
pub(crate) fn mix(random: Hash, round: u32) -> Hash {
    let mut hasher = Hasher::new();
    random.hash(&mut hasher);
    round.hash(&mut hasher);
    hasher.result()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::genesis::genesis;
    use crate::multisignature::create_multi_signature;
    use chrono::prelude::Utc;
    use simple_logger;
    use std::collections::BTreeSet;
    use stegos_keychain::KeyChain;

    #[test]
    fn basic() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let mut blockchain = Blockchain::testing();

        assert_eq!(blockchain.height(), 0);
        assert_eq!(blockchain.epoch, 0);
        assert_eq!(blockchain.blocks_in_epoch(), 0);

        let keychains = [KeyChain::new_mem()];
        let current_timestamp = Utc::now().timestamp() as u64;
        let blocks = genesis(&keychains, MIN_STAKE_AMOUNT, 1_000_000, current_timestamp);
        assert_eq!(blocks.len(), 2);
        let (block1, block2) = match &blocks[..] {
            [Block::MonetaryBlock(block1), Block::KeyBlock(block2)] => (block1, block2),
            _ => panic!(),
        };
        let (inputs2, outputs2) = blockchain
            .push_monetary_block(block1.clone(), current_timestamp)
            .unwrap();
        blockchain.push_key_block(block2.clone()).unwrap();

        let outputs: Vec<Output> = block1
            .body
            .outputs
            .leafs()
            .iter()
            .map(|(o, _p)| o.as_ref().clone())
            .collect();
        assert_eq!(inputs2.len(), 0);
        assert!(outputs2
            .iter()
            .map(|o| Hash::digest(o))
            .eq(outputs.iter().map(|o| Hash::digest(o))));

        let mut unspent: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
        unspent.sort();
        let mut unspent2: Vec<Hash> = blockchain.unspent();
        unspent2.sort();
        assert_eq!(unspent, unspent2);

        assert_eq!(blockchain.height(), 2);
        assert_eq!(blockchain.epoch, block2.header.base.epoch);
        assert_eq!(blockchain.blocks_in_epoch(), 1);
        assert_eq!(blockchain.leader, block2.header.leader);
        assert_eq!(blockchain.facilitator, block2.header.facilitator);
        let validators = blockchain.escrow.get_stakers_majority();
        assert_eq!(validators.len(), keychains.len());
        for keychain in &keychains {
            let stake = validators.get(&keychain.network_pkey).expect("exists");
            assert_eq!(*stake, MIN_STAKE_AMOUNT);
        }
        assert_eq!(blockchain.validators, validators);
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
        assert!(blockchain
            .output_by_hash(&Hash::digest("test"))
            .unwrap()
            .is_none());
        for (output, _path) in block1.body.outputs.leafs() {
            let output_hash = Hash::digest(&output);
            let output2 = blockchain
                .output_by_hash(&output_hash)
                .unwrap()
                .expect("exists");
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
        let mut blockchain = Blockchain::testing();
        for block in blocks {
            match block {
                Block::KeyBlock(block) => blockchain.register_key_block(block),
                Block::MonetaryBlock(block) => {
                    blockchain
                        .push_monetary_block(block, current_timestamp)
                        .expect("block is valid");
                }
            }
        }

        let start = blockchain.last_block_hash();
        // len of genesis
        assert!(blockchain.height() > 0);
        let version: u64 = 1;
        for epoch in 2..12 {
            let mut block = {
                let previous = blockchain.last_block_hash();
                let base = BaseBlockHeader::new(version, previous, epoch, 0);

                let validators: BTreeSet<secure::PublicKey> =
                    keychains.iter().map(|p| p.network_pkey.clone()).collect();
                let leader = keychains[0].network_pkey.clone();
                let facilitator = keychains[0].network_pkey.clone();
                let seed = mix(blockchain.last_random, 0);
                let random = secure::make_VRF(&keychains[0].network_skey, &seed);
                KeyBlock::new(base, leader, facilitator, random, 0, validators)
            };
            let block_hash = Hash::digest(&block);
            let validators: BTreeMap<secure::PublicKey, i64> = keychains
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

//! Blockchain definition.

//
// Copyright (c) 2018 Stegos
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

use std::collections::HashMap;
use std::vec::Vec;

use crate::block::*;
use crate::genesis::*;
use crate::merkle::*;
use crate::output::*;
use stegos_crypto::hash::*;

type BlockId = usize;

/// A help to find UTXO in this blockchain.
struct OutputKey {
    /// The short block identifier.
    pub block_id: BlockId,
    /// Merkle Tree path inside block.
    pub path: MerklePath,
}

#[derive(Debug, Fail)]
pub enum BlockchainError {
    #[fail(
        display = "Previous hash mismatch: expected={}, got={}.",
        _0,
        _1
    )]
    PreviousHashMismatch(Hash, Hash),
    #[fail(display = "Block hash collision: {}.", _0)]
    BlockHashCollision(Hash),
    #[fail(display = "UXTO hash collision: {}.", _0)]
    OutputHashCollision(Hash),
    #[fail(display = "Missing UXTO {}.", _0)]
    MissingUTXO(Hash),
}

/// The Blockchain.
pub struct Blockchain {
    /// Blockchain blocks stored in-memory.
    /// Position in this vector is short BlockId = usize.
    blocks: Vec<Block>,
    /// Block by hash mapping.
    block_by_hash: HashMap<Hash, BlockId>,
    /// Unspent outputs by hash.
    output_by_hash: HashMap<Hash, OutputKey>,
}

impl Blockchain {
    //----------------------------------------------------------------------------------------------
    // Public API
    //----------------------------------------------------------------------------------------------

    pub fn new() -> Blockchain {
        let blocks = Vec::new();
        let block_by_hash = HashMap::<Hash, BlockId>::new();
        let output_by_hash = HashMap::<Hash, OutputKey>::new();
        let blockchain = Blockchain {
            blocks,
            block_by_hash,
            output_by_hash,
        };
        blockchain
    }

    pub fn bootstrap(&mut self) -> Result<(), BlockchainError> {
        assert_eq!(self.blocks().len(), 0);
        info!("Generating genesis blocks...");
        let (block1, block2, inputs2, output2) = genesis_dev();
        info!("Genesis key block hash: {}", Hash::digest(&block1));
        info!("Genesis monetary block hash: {}", Hash::digest(&block2));
        info!("Done");

        info!("Registering genesis blocks...");
        self.register_key_block(block1)?;
        self.register_monetary_block(block2, &inputs2, &output2)?;
        info!("Done");

        Ok(())
    }

    /// Returns an iterator over UTXO hashes.
    pub fn unspent(&self) -> Vec<Hash> {
        // TODO: return iterator instead.
        self.output_by_hash.keys().cloned().collect()
    }

    /// Find UTXO by its hash.
    pub fn output_by_hash(&self, output_hash: &Hash) -> Option<&Output> {
        if let Some(OutputKey { block_id, path }) = self.output_by_hash.get(output_hash) {
            let block = &self.blocks[*block_id];
            if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                if let Some(output) = body.outputs.lookup(path) {
                    return Some(&output);
                } else {
                    return None;
                }
            } else {
                unreachable!(); // Non-monetary block
            }
        }
        return None;
    }

    /// Find block by its hash
    pub fn block_by_hash(&self, block_hash: &Hash) -> Option<&Block> {
        if let Some(block_id) = self.block_by_hash.get(block_hash) {
            return Some(&self.blocks[*block_id]);
        }
        return None;
    }

    /// Return all blocks.
    pub fn blocks(&self) -> &[Block] {
        self.blocks.as_slice()
    }

    /// Return the last block.
    pub fn last_block(&self) -> &Block {
        assert!(self.blocks.len() > 0);
        self.blocks.last().unwrap()
    }

    //----------------------------------------------------------------------------------------------

    fn register_key_block(&mut self, block: KeyBlock) -> Result<(), BlockchainError> {
        let block_id = self.blocks.len();

        // Check previous hash.
        if let Some(previous_block) = self.blocks.last() {
            let previous_hash = Hash::digest(previous_block);
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::PreviousHashMismatch(
                    previous_hash,
                    block.header.base.previous,
                ));
            }
        }

        // Check new hash.
        let this_hash = Hash::digest(&block);
        if let Some(_) = self.block_by_hash.get(&this_hash) {
            return Err(BlockchainError::BlockHashCollision(this_hash));
        }

        // -----------------------------------------------------------------------------------------
        // Alright, starting transaction.
        // -----------------------------------------------------------------------------------------

        info!("Register Key Block: {}", this_hash);

        if let Some(_) = self.block_by_hash.insert(this_hash.clone(), block_id) {
            panic!("Block hash collision");
        }

        self.blocks.push(Block::KeyBlock(block));

        Ok(())
    }

    fn register_monetary_block(
        &mut self,
        block: MonetaryBlock,
        inputs: &[Hash],
        outputs: &[(Hash, MerklePath)],
    ) -> Result<(Vec<Output>), BlockchainError> {
        let block_id = self.blocks.len();

        // Check previous hash.
        if let Some(previous_block) = self.blocks.last() {
            let previous_hash = Hash::digest(previous_block);
            if previous_hash != block.header.base.previous {
                return Err(BlockchainError::PreviousHashMismatch(
                    previous_hash,
                    block.header.base.previous,
                ));
            }
        }

        // Check new hash.
        let this_hash = Hash::digest(&block);
        if let Some(_) = self.block_by_hash.get(&this_hash) {
            return Err(BlockchainError::BlockHashCollision(this_hash));
        }

        // Check all inputs.
        for output_hash in inputs {
            if let Some(OutputKey { block_id, path }) = self.output_by_hash.get(output_hash) {
                assert!(*block_id < self.blocks.len());
                let block = &self.blocks[*block_id];
                if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                    if let Some(output) = body.outputs.lookup(&path) {
                        // Check that hash is the same.
                        assert_eq!(Hash::digest(output), *output_hash);
                    } else {
                        // Internal database inconsistency - missing UTXO in block.
                        unreachable!();
                    }
                } else {
                    // Internal database inconsistency - invalid block type.
                    unreachable!();
                }
            } else {
                // Cannot find UTXO referred by block.
                return Err(BlockchainError::MissingUTXO(*output_hash));
            }
        }

        // Check all outputs.
        for (hash, _path) in outputs {
            if let Some(_) = self.output_by_hash.get(hash) {
                return Err(BlockchainError::OutputHashCollision(*hash));
            }
        }

        // -----------------------------------------------------------------------------------------
        // Alright, starting transaction.
        // -----------------------------------------------------------------------------------------
        info!("Register Monetary Block block: {}", this_hash);

        let mut pruned: Vec<Output> = Vec::with_capacity(inputs.len());

        // Remove spent outputs.
        for output_hash in inputs {
            info!("Prune UXTO({})", output_hash);
            // Remove from the set of unspent outputs.
            if let Some(OutputKey { block_id, path }) = self.output_by_hash.remove(output_hash) {
                let block = &mut self.blocks[block_id];
                if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                    // Remove from the block.
                    if let Some(output) = body.outputs.prune(&path) {
                        pruned.push(*output);
                    } else {
                        unreachable!();
                    }
                } else {
                    unreachable!();
                }
            } else {
                unreachable!();
            }
        }

        // Register create unspent outputs.
        for (hash, path) in outputs {
            info!("Register UXTO({})", hash);

            // Create the new unspent output
            let output_key = OutputKey {
                block_id,
                path: path.clone(),
            };
            if let Some(_) = self.output_by_hash.insert(hash.clone(), output_key) {
                unreachable!();
            }
        }

        // Register block
        if let Some(_) = self.block_by_hash.insert(this_hash.clone(), block_id) {
            unreachable!();
        }

        // Must be the last line to make Rust happy.
        self.blocks.push(Block::MonetaryBlock(block));

        Ok(pruned)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use chrono::prelude::Utc;

    use stegos_crypto::curve1174::cpt::make_random_keys;

    pub fn iterate(blockchain: &mut Blockchain) -> Result<(), BlockchainError> {
        let version = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let (epoch, previous) = {
            let last = blockchain.last_block();
            let base_header = last.base_header();
            let epoch = base_header.epoch + 1;
            let previous = Hash::digest(last);
            (epoch, previous)
        };

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

        let (skey, pkey, _sig) = make_random_keys();

        let output_hash = blockchain.output_by_hash.keys().next().unwrap().clone();
        let input = output_hash.clone();
        let inputs = [input];

        let amount: i64 = 112;
        let (output, delta) = Output::new(timestamp, skey.clone(), pkey.clone(), amount)
            .expect("tests have valid keys");
        let outputs = [output];

        // Adjustment is the sum of all gamma found in UTXOs.
        let adjustment = delta;

        let (block, outputs) = MonetaryBlock::new(base, adjustment, &inputs, &outputs);

        blockchain.register_monetary_block(block, &inputs, &outputs)?;

        Ok(())
    }

    #[test]
    fn basic() {
        extern crate simple_logger;
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let mut blockchain = Blockchain::new();
        blockchain.bootstrap().unwrap();
        assert!(blockchain.blocks().len() > 0);
        iterate(&mut blockchain).unwrap();
        iterate(&mut blockchain).unwrap();
        iterate(&mut blockchain).unwrap();
    }
}

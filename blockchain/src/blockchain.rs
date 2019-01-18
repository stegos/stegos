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

use crate::block::*;
use crate::error::*;
use crate::merkle::*;
use crate::output::*;
use log::*;
use std::collections::HashMap;
use std::vec::Vec;
use stegos_crypto::hash::*;

type BlockId = usize;

/// A help to find UTXO in this blockchain.
struct OutputKey {
    /// The short block identifier.
    pub block_id: BlockId,
    /// Merkle Tree path inside block.
    pub path: MerklePath,
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

    /// Resolve UTXOs by its hashes.
    pub fn outputs_by_hashes(
        &self,
        output_hashes: &[Hash],
    ) -> Result<Vec<Output>, BlockchainError> {
        // Find appropriate UTXO in the database.
        let mut outputs = Vec::<Output>::new();
        for output_hash in output_hashes {
            let input = match self.output_by_hash(output_hash) {
                Some(o) => o.clone(),
                None => return Err(BlockchainError::MissingUTXO(output_hash.clone()).into()),
            };
            outputs.push(input);
        }

        Ok(outputs)
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

    /// Return the current blockchain height.
    pub fn height(&self) -> usize {
        self.blocks().len()
    }

    //----------------------------------------------------------------------------------------------

    pub fn register_key_block(&mut self, block: KeyBlock) -> Result<(), BlockchainError> {
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

        info!(
            "Registered key block: height={}, hash={}",
            self.blocks.len() + 1,
            this_hash
        );

        if let Some(_) = self.block_by_hash.insert(this_hash.clone(), block_id) {
            panic!("Block hash collision");
        }
        self.blocks.push(Block::KeyBlock(block));

        Ok(())
    }

    pub fn register_monetary_block(
        &mut self,
        block: MonetaryBlock,
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
        for output_hash in &block.body.inputs {
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
        let outputs_pathes = block
            .body
            .outputs
            .leafs()
            .iter()
            .map(|(o, path)| (Hash::digest(*o), *path))
            .collect::<Vec<(Hash, MerklePath)>>();
        for (hash, _path) in &outputs_pathes {
            if let Some(_) = self.output_by_hash.get(hash) {
                return Err(BlockchainError::OutputHashCollision(*hash));
            }
        }

        // -----------------------------------------------------------------------------------------
        // Alright, starting transaction.
        // -----------------------------------------------------------------------------------------
        info!(
            "Registered monetary block: height={}, hash={}, inputs={}, outputs={}",
            self.blocks.len() + 1,
            this_hash,
            block.body.inputs.len(),
            outputs_pathes.len()
        );

        let mut pruned: Vec<Output> = Vec::with_capacity(block.body.inputs.len());

        // Remove spent outputs.
        for output_hash in &block.body.inputs {
            info!("Pruned UXTO: hash={}", output_hash);
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
        for (hash, path) in outputs_pathes {
            info!("Registered UXTO: hash={}", &hash);

            // Create the new unspent output
            let output_key = OutputKey { block_id, path };
            if let Some(_) = self.output_by_hash.insert(hash, output_key) {
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

    use crate::genesis::genesis;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_keychain::KeyChain;

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
        let (output, gamma) =
            Output::new_payment(timestamp, &skey, &pkey, amount).expect("tests have valid keys");
        let outputs = [output];

        let block = MonetaryBlock::new(base, gamma, &inputs, &outputs);

        blockchain.register_monetary_block(block)?;

        Ok(())
    }

    #[test]
    fn basic() {
        use simple_logger;
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let keychains = [
            KeyChain::new_mem(),
            KeyChain::new_mem(),
            KeyChain::new_mem(),
        ];

        let blocks = genesis(&keychains, 1_000_000);

        let mut blockchain = Blockchain::new();
        for block in blocks {
            match block {
                Block::KeyBlock(block) => blockchain.register_key_block(block).unwrap(),
                Block::MonetaryBlock(block) => {
                    blockchain.register_monetary_block(block).unwrap();
                }
            }
        }

        assert!(blockchain.blocks().len() > 0);
        iterate(&mut blockchain).unwrap();
        iterate(&mut blockchain).unwrap();
        iterate(&mut blockchain).unwrap();
    }
}

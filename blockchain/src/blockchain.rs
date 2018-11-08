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

use block::*;
use genesis::*;
use merkle::*;
use output::*;
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
        let mut blockchain = Blockchain {
            blocks,
            block_by_hash,
            output_by_hash,
        };

        let (block1, block2, inputs2, output2) = genesis_dev();

        info!("Genesis key block hash: {}", Hash::digest(&block1));
        info!("Genesis monetary block hash: {}", Hash::digest(&block2));

        blockchain.register_key_block(block1);
        blockchain.register_monetary_block(block2, &inputs2, &output2);

        blockchain
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

    fn register_key_block(&mut self, block: KeyBlock) {
        let block_id = self.blocks.len();

        let this_hash = Hash::digest(&block);

        info!("Registering a new key block: {}", this_hash);

        if let Some(previous_block) = self.blocks.last() {
            let previous_hash = Hash::digest(previous_block);
            assert_eq!(previous_hash, block.header.base.previous);
        }

        if let Some(_) = self.block_by_hash.insert(this_hash.clone(), block_id) {
            panic!("Block hash collision");
        }

        self.blocks.push(Block::KeyBlock(block));
    }

    fn register_monetary_block(
        &mut self,
        block: MonetaryBlock,
        inputs: &[Hash],
        outputs: &[(Hash, MerklePath)],
    ) {
        let block_id = self.blocks.len();

        let this_hash = Hash::digest(&block);

        info!("Registering a new monetary block: {}", this_hash);

        if let Some(previous_block) = self.blocks.last() {
            let previous_hash = Hash::digest(previous_block);
            assert_eq!(previous_hash, block.header.base.previous);
        }

        if let Some(_) = self.block_by_hash.insert(this_hash.clone(), block_id) {
            panic!("Block hash collision");
        }

        // Remove spent outputs.
        for output_hash in inputs {
            debug!("Prune UXTO({})", output_hash);
            // Remove from the set of unspent outputs.
            if let Some(OutputKey { block_id, path }) = self.output_by_hash.remove(output_hash) {
                let block = &mut self.blocks[block_id];
                if let Block::MonetaryBlock(MonetaryBlock { header: _, body }) = block {
                    // Remove from the block.
                    if let Some(output) = body.outputs.prune(&path) {
                        assert_eq!(output.hash, *output_hash);
                    } else {
                        panic!("Missing output with id {}", output_hash);
                    }
                } else {
                    unreachable!(); // Non-monetary block.
                }
            } else {
                panic!("Can't find input with id {}", output_hash);
            }
        }

        // Register create unspent outputs.
        for (hash, path) in outputs {
            debug!("Register UXTO({})", hash);

            // Create the new unspent output
            let output_key = OutputKey {
                block_id,
                path: path.clone(),
            };
            if let Some(_) = self.output_by_hash.insert(hash.clone(), output_key) {
                panic!("The output hash collision");
            }
        }

        // Must be the last line to make Rust happy.
        self.blocks.push(Block::MonetaryBlock(block));
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use chrono::prelude::Utc;

    use stegos_crypto::bulletproofs;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::curve1174::fields::Fr;

    use payload::*;

    pub fn iterate(blockchain: &mut Blockchain) {
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

        let (_skey, pkey, _sig) = make_random_keys();

        let output_hash = blockchain.output_by_hash.keys().next().unwrap().clone();
        let input = output_hash.clone();
        let inputs = [input];

        let delta: Fr = Fr::random();

        let amount: i64 = 112;
        let (proof, gamma) = bulletproofs::make_range_proof(amount);

        let payload = new_monetary(delta, gamma, amount, pkey).expect("tests have valid keys");

        let output = Output::new(pkey.clone(), proof, payload);
        let outputs = [output];

        // Adjustment is the sum of all gamma found in UTXOs.
        let adjustment = delta;

        let (block, outputs) = MonetaryBlock::new(base, adjustment, &inputs, &outputs);

        blockchain.register_monetary_block(block, &inputs, &outputs);
    }

    #[test]
    fn basic() {
        extern crate simple_logger;
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let mut blockchain = Blockchain::new();
        assert!(blockchain.blocks().len() > 0);
        iterate(&mut blockchain);
        iterate(&mut blockchain);
        iterate(&mut blockchain);
    }
}

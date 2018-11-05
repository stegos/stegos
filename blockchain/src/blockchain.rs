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

        let (genesis, paths) = genesis_dev();
        blockchain.register_block(genesis, paths);

        blockchain
    }

    /// Find UTXO by its hash.
    pub fn output_by_hash(&self, output_hash: &Hash) -> Option<&Output> {
        if let Some(OutputKey { block_id, path }) = self.output_by_hash.get(output_hash) {
            let block = &self.blocks[*block_id];
            if let Some(output) = block.outputs.lookup(path) {
                return Some(&output);
            } else {
                return None;
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
    #[allow(dead_code)]
    fn register_block(&mut self, block: Block, paths: Vec<MerklePath>) {
        let block_id = self.blocks.len();
        assert!(block_id == 0 || self.blocks[block_id - 1].header.hash == block.header.previous);

        if let Some(_) = self
            .block_by_hash
            .insert(block.header.hash.clone(), block_id)
        {
            panic!("Block hash collision");
        }

        // Remove spent outputs.
        for input in &block.inputs {
            let output_hash = &input.source_id;
            // Remove from the set of unspent outputs.
            if let Some(OutputKey { block_id, path }) = self.output_by_hash.remove(output_hash) {
                let block = &mut self.blocks[block_id];
                // Remove from the block.
                if let Some(output) = block.outputs.prune(&path) {
                    assert_eq!(output.hash, *output_hash);
                } else {
                    panic!("Missing output with id {}", output_hash);
                }
            } else {
                panic!("Can't find input with id {}", output_hash);
            }
        }

        // Register create unspent outputs.
        for path in paths {
            // TODO: this algorithm is efficient and has O(nlogn) complexity because of lookup().
            // Vec<&Output> should be passed as an argument in order to fix it.
            // I tried to do so, Rust is not happy with &Output lifetime.
            let output: &Output = block.outputs.lookup(&path).unwrap();

            // Create the new unspent output
            let output_key = OutputKey { block_id, path };
            if let Some(_) = self.output_by_hash.insert(output.hash, output_key) {
                panic!("The output hash collision");
            }
        }

        // Must be the last line to make Rust happy.
        self.blocks.push(block);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use block::tests::fake;
    use input::*;
    use stegos_crypto::pbc::secure::*;

    pub fn iterate(blockchain: &mut Blockchain) {
        let (epoch, previous) = {
            let last = blockchain.last_block();
            let epoch = last.header.epoch + 1;
            let previous = last.header.hash.clone();
            (epoch, previous)
        };

        let seed: [u8; 4] = [1, 2, 3, 4];
        let (_skey, _pubkey, signature) = make_deterministic_keys(&seed);

        let output_hash = blockchain.output_by_hash.keys().next().unwrap().clone();
        let input = Input::new(output_hash.clone(), signature);
        let inputs = [input];
        let (block, paths) = fake(1, epoch, &inputs, &previous);
        blockchain.register_block(block, paths);
    }

    #[test]
    fn basic() {
        let mut blockchain = Blockchain::new();
        assert!(blockchain.blocks().len() > 0);
        iterate(&mut blockchain);
        iterate(&mut blockchain);
        iterate(&mut blockchain);
    }
}

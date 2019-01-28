//! Blockchain Integration.

//
// Copyright (c) 2019 Stegos
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

use crate::{Consensus, ConsensusMessage};
use stegos_blockchain::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
/// A proof for monetary block.
#[derive(Clone, Debug)]
pub struct MonetaryBlockProof {
    pub fee_output: Option<Output>,
    pub tx_hashes: Vec<Hash>,
}

/// A proof for gblock.
#[derive(Clone, Debug)]
pub enum BlockProof {
    KeyBlockProof,
    MonetaryBlockProof(MonetaryBlockProof),
}

impl Hashable for MonetaryBlockProof {
    fn hash(&self, state: &mut Hasher) {
        "MonetaryBlockProof".hash(state);
        self.fee_output.hash(state);
        let txs_count: u64 = self.tx_hashes.len() as u64;
        txs_count.hash(state);
        for tx_hashes in &self.tx_hashes {
            tx_hashes.hash(state);
        }
    }
}

impl Hashable for BlockProof {
    fn hash(&self, state: &mut Hasher) {
        match self {
            BlockProof::KeyBlockProof => "KeyBlockProof".hash(state),
            BlockProof::MonetaryBlockProof(proof) => proof.hash(state),
        }
    }
}

pub type BlockConsensus = Consensus<Block, BlockProof>;
pub type BlockConsensusMessage = ConsensusMessage<Block, BlockProof>;

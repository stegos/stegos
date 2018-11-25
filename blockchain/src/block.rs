//! Block Definition.

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

use crate::merkle::*;
use crate::output::Output;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::PublicKey as WitnessPublicKey;

/// General Block Header.
#[derive(Debug, PartialEq, Eq)]
pub struct BaseBlockHeader {
    /// Version number.
    pub version: u64,

    /// Hash of the block previous to this in the chain.
    pub previous: Hash,

    /// A monotonically increasing value that represents the heights of the blockchain,
    /// starting from genesis block (=0).
    pub epoch: u64,

    /// Timestamp at which the block was built.
    pub timestamp: u64,
    // TODO: BLS Multi-signature.
    // pub sig: BlsSignature,

    // TODO: Bitmap of signers in the multi-signature.
    // pub signers: u64,
}

impl BaseBlockHeader {
    pub fn new(version: u64, previous: Hash, epoch: u64, timestamp: u64) -> Self {
        BaseBlockHeader {
            version,
            previous,
            epoch,
            timestamp,
        }
    }
}

impl Hashable for BaseBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.version.hash(state);
        self.previous.hash(state);
        self.epoch.hash(state);
        self.timestamp.hash(state);
    }
}

/// Header for Key Blocks.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Leader public key.
    pub leader: WitnessPublicKey,

    /// Ordered list of witnesses public keys.
    pub witnesses: Vec<WitnessPublicKey>,
    // TODO: pooled transactions facilitator public key (which kind?).
    // pub facilitator: WitnessPublicKey,
}

impl Hashable for KeyBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.base.hash(state);
        self.leader.hash(state);
        // self.witnesses[..].hash(state);
        // self.facilitator.hash(state);
    }
}

/// Monetary Block Header.
#[derive(Debug, PartialEq, Eq)]
pub struct MonetaryBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub adjustment: Fr,

    /// Merklish root of all range proofs for inputs.
    pub inputs_range_hash: Hash,

    /// Merklish root of all range proofs for output.
    pub outputs_range_hash: Hash,
}

impl Hashable for MonetaryBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.base.hash(state);
        self.adjustment.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_range_hash.hash(state);
    }
}

/// Monetary Block.
#[derive(Debug)]
pub struct MonetaryBlockBody {
    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Merkle<Box<Output>>,
}

impl PartialEq for MonetaryBlockBody {
    fn eq(&self, _other: &MonetaryBlockBody) -> bool {
        // Required by enum Block.
        unreachable!();
    }
}

impl Eq for MonetaryBlockBody {}

/// Carries all cryptocurrency transactions.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyBlock {
    /// Header.
    pub header: KeyBlockHeader,
}

impl KeyBlock {
    pub fn new(
        base: BaseBlockHeader,
        leader: WitnessPublicKey,
        mut witnesses: Vec<WitnessPublicKey>,
    ) -> Self {
        // Witnesses list must be sorted.
        witnesses.sort();

        // Leader must present in witnesses array.
        //assert_eq!(witnesses.binary_search(leader), Ok((_, _)));

        // Create header
        let header = KeyBlockHeader {
            base,
            leader,
            witnesses,
        };

        // Create the block
        KeyBlock { header }
    }
}

impl Hashable for KeyBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Carries administrative information to blockchain participants.
#[derive(Debug, PartialEq, Eq)]
pub struct MonetaryBlock {
    /// Header.
    pub header: MonetaryBlockHeader,
    /// Body
    pub body: MonetaryBlockBody,
}

impl MonetaryBlock {
    pub fn new(
        base: BaseBlockHeader,
        adjustment: Fr,
        inputs: &[Hash],
        outputs: &[Output],
    ) -> MonetaryBlock {
        // Create inputs array
        let mut hasher = Hasher::new();
        let inputs_count: u64 = inputs.len() as u64;
        inputs_count.hash(&mut hasher);
        for input in inputs {
            input.hash(&mut hasher);
        }
        let inputs_range_hash = hasher.result();
        let inputs = inputs.iter().map(|o| o.clone()).collect::<Vec<Hash>>();

        // Create outputs tree
        let mut hasher = Hasher::new();
        let outputs_count: u64 = outputs.len() as u64;
        outputs_count.hash(&mut hasher);
        for output in outputs {
            output.hash(&mut hasher);
        }
        let outputs_range_hash = hasher.result();
        let outputs = outputs
            .iter()
            .map(|o| Box::<Output>::new(o.clone()))
            .collect::<Vec<Box<Output>>>();

        let outputs = Merkle::from_array(&outputs);

        // Create header
        let header = MonetaryBlockHeader {
            base,
            adjustment,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create the block
        let body = MonetaryBlockBody { inputs, outputs };

        let block = MonetaryBlock { header, body };
        block
    }
}

impl Hashable for MonetaryBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Types of blocks supported by this blockchain.
#[derive(Debug, PartialEq, Eq)]
pub enum Block {
    KeyBlock(KeyBlock),
    MonetaryBlock(MonetaryBlock),
}

impl Block {
    pub fn base_header(&self) -> &BaseBlockHeader {
        match self {
            Block::KeyBlock(KeyBlock { header }) => &header.base,
            Block::MonetaryBlock(MonetaryBlock { header, body: _ }) => &header.base,
        }
    }
}

impl Hashable for Block {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Block::KeyBlock(key_block) => key_block.hash(state),
            Block::MonetaryBlock(monetary_block) => monetary_block.hash(state),
        }
    }
}

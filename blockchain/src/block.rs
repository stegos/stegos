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

use input::Input;
use merkle::*;
use output::Output;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
// use stegos_crypto::pbc::secure::BlsSignature;

/// Block Header.
#[derive(Debug)]
pub struct BlockHeader {
    /// Hash of the current block (except Merkle trees):
    /// H(BNO | HPREV | SGA | RH_TXINS | RH_TXOUT) (HCURR)
    pub hash: Hash,

    /// Version number.
    pub version: u64,

    /// A monotonically increasing value that represents the heights of the blockchain,
    /// starting from genesis block (=0).
    pub epoch: u64,

    /// Hash of the block previous to this in the chain.
    pub previous: Hash,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub adjustment: Fr,

    /// Timestamp at which the block was built.
    pub timestamp: u64,

    /// Merklish root of all range proofs for inputs.
    pub inputs_range_hash: Hash,

    /// Merklish root of all range proofs for output.
    pub outputs_range_hash: Hash,
}

/// Block.
pub struct Block {
    /// Block Header.
    pub header: BlockHeader,

    /// The list of transaction inputs.
    pub inputs: Vec<Input>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Merkle<Box<Output>>,
    // TODO: BLS Multi-signature.
    // pub sig: BlsSignature,

    // TODO: Bitmap of signers in the multi-signature.
    // pub signers: u64,
}

impl Block {
    pub fn sign(
        version: u64,
        epoch: u64,
        previous: Hash,
        timestamp: u64,
        adjustment: Fr,
        inputs: &[Input],
        outputs: &[Output],
    ) -> (Block, Vec<MerklePath>) {
        // Create inputs array
        let mut hasher = Hasher::new();
        let inputs_count: u64 = inputs.len() as u64;
        inputs_count.hash(&mut hasher);
        for input in inputs {
            input.hash(&mut hasher);
        }
        let inputs_range_hash = hasher.result();
        let inputs = inputs.to_vec();

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

        let (outputs, paths) = Merkle::from_array(&outputs);

        // Calculate block hash
        let mut hasher = Hasher::new();
        version.hash(&mut hasher);
        epoch.hash(&mut hasher);
        previous.hash(&mut hasher);
        adjustment.hash(&mut hasher);
        timestamp.hash(&mut hasher);
        inputs_range_hash.hash(&mut hasher);
        outputs_range_hash.hash(&mut hasher);

        // Finalize the block hash
        let hash = hasher.result();

        // Create header
        let header = BlockHeader {
            hash,
            version,
            epoch,
            previous,
            adjustment,
            timestamp,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create the block
        let block = Block {
            header,
            inputs,
            outputs,
        };

        (block, paths)
    }
}

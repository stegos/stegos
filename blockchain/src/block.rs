//! Block Definition.

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

use crate::merkle::*;
use crate::output::*;
use crate::view_changes::ViewChangeProof;
use bitvector::BitVector;
use std::time::SystemTime;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_crypto::pbc::secure::VRF;

/// Blockchain version.
pub const VERSION: u64 = 1;
/// The maximum number of nodes in multi-signature.
pub const VALIDATORS_MAX: usize = 512;

/// General Block Header.
#[derive(Debug, Clone)]
pub struct BaseBlockHeader {
    /// Version number.
    pub version: u64,

    /// Hash of the block previous to this in the chain.
    pub previous: Hash,

    /// Block height.
    pub height: u64,

    /// Number of leader changes in current validator groups.
    pub view_change: u32,

    /// Timestamp at which the block was built.
    pub timestamp: SystemTime,

    /// Latest random of the leader.
    pub random: VRF,
}

impl BaseBlockHeader {
    pub fn new(
        version: u64,
        previous: Hash,
        height: u64,
        view_change: u32,
        timestamp: SystemTime,
        random: VRF,
    ) -> Self {
        debug_assert!(
            secure::validate_VRF_randomness(&random),
            "Cannot verify VRF."
        );

        BaseBlockHeader {
            version,
            previous,
            height,
            view_change,
            timestamp,
            random,
        }
    }
}

impl Hashable for BaseBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.version.hash(state);
        self.previous.hash(state);
        self.height.hash(state);
        self.view_change.hash(state);
        self.timestamp.hash(state);
        self.random.hash(state);
    }
}

/// Header for Key Blocks.
#[derive(Debug, Clone)]
pub struct KeyBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,
}

impl Hashable for KeyBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Key".hash(state);
        self.base.hash(state);
    }
}

/// Key Block Body.
#[derive(Debug, Clone)]
pub struct KeyBlockBody {
    /// BLS multi-signature
    pub multisig: secure::Signature,

    /// Bitmap of signers in the multi-signature.
    pub multisigmap: BitVector,
}

impl PartialEq for KeyBlockBody {
    fn eq(&self, _other: &KeyBlockBody) -> bool {
        // Required by enum Block.
        unreachable!();
    }
}

impl Eq for KeyBlockBody {}

/// Monetary Block Header.
#[derive(Debug, Clone)]
pub struct MicroBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub gamma: Fr,

    /// Adjustment of the global monetary balance.
    /// Positive value means that money has been created.
    /// Negative value means that money has been burned.
    pub monetary_adjustment: i64,

    /// Merklish root of all range proofs for inputs.
    pub inputs_range_hash: Hash,

    /// Merklish root of all range proofs for output.
    pub outputs_range_hash: Hash,

    /// Proof of the happen view_change.
    pub proof: Option<ViewChangeProof>,
}

impl Hashable for MicroBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Monetary".hash(state);
        self.base.hash(state);
        self.gamma.hash(state);
        self.monetary_adjustment.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_range_hash.hash(state);
        if let Some(proof) = &self.proof {
            proof.hash(state);
        }
    }
}

/// Monetary Block.
#[derive(Debug, Clone)]
pub struct MicroBlockBody {
    /// Public key of leader.
    pub pkey: secure::PublicKey,

    /// BLS signature.
    pub sig: secure::Signature,

    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Merkle<Box<Output>>,
}

impl PartialEq for MicroBlockBody {
    fn eq(&self, _other: &MicroBlockBody) -> bool {
        // Required by enum Block.
        unreachable!();
    }
}

impl Eq for MicroBlockBody {}

/// Carries all cryptocurrency transactions.
#[derive(Debug, Clone)]
pub struct KeyBlock {
    /// Header.
    pub header: KeyBlockHeader,

    /// Body.
    pub body: KeyBlockBody,
}

impl KeyBlock {
    pub fn new(base: BaseBlockHeader) -> Self {
        // Create header
        let header = KeyBlockHeader { base };

        // Create body
        let multisig = secure::Signature::zero();
        let multisigmap = BitVector::new(VALIDATORS_MAX);
        let body = KeyBlockBody {
            multisig,
            multisigmap,
        };

        // Create the block
        KeyBlock { header, body }
    }
}

impl Hashable for KeyBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

impl PartialEq for KeyBlock {
    fn eq(&self, other: &KeyBlock) -> bool {
        Hash::digest(self) == Hash::digest(other)
    }
}

impl Eq for KeyBlock {}

/// Carries administrative information to blockchain participants.
#[derive(Debug, Clone)]
pub struct MicroBlock {
    /// Header.
    pub header: MicroBlockHeader,
    /// Body
    pub body: MicroBlockBody,
}

impl MicroBlock {
    pub fn new(
        base: BaseBlockHeader,
        gamma: Fr,
        monetary_adjustment: i64,
        inputs: &[Hash],
        outputs: &[Output],
        proof: Option<ViewChangeProof>,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> MicroBlock {
        // Re-order all inputs to blur transaction boundaries.
        // Current algorithm just sorts this list.
        // Since Hash is random, it has the same effect as shuffling.
        let inputs_len = inputs.len();
        let mut inputs: Vec<Hash> = inputs.iter().cloned().collect();
        inputs.sort();
        inputs.dedup(); // should do nothing
        assert_eq!(inputs.len(), inputs_len, "inputs must be unique");

        // Calculate input_range_hash.
        let inputs_range_hash: Hash = {
            let mut hasher = Hasher::new();
            let inputs_count: u64 = inputs.len() as u64;
            inputs_count.hash(&mut hasher);
            for input in &inputs {
                input.hash(&mut hasher);
            }
            hasher.result()
        };

        // Re-order all outputs to blur transaction boundaries.
        let outputs_len = outputs.len();
        let mut outputs: Vec<(Hash, Box<Output>)> = outputs
            .iter()
            .map(|o| (Hash::digest(o), Box::<Output>::new(o.clone())))
            .collect();
        outputs.sort_by(|(h1, _o1), (h2, _o2)| h1.cmp(h2));
        outputs.dedup_by(|(h1, _o1), (h2, _o2)| h1 == h2); // should do nothing
        assert_eq!(outputs.len(), outputs_len, "outputs must be unique");
        let outputs: Vec<Box<Output>> = outputs.into_iter().map(|(_h, o)| o).collect();

        // Create Merkle Tree and calculate outputs_range_hash.
        let outputs = Merkle::from_array(&outputs);
        let outputs_range_hash = outputs.roothash().clone();

        // Create header
        let header = MicroBlockHeader {
            proof,
            base,
            gamma,
            monetary_adjustment,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create body
        let sig = secure::Signature::zero();
        let body = MicroBlockBody {
            pkey,
            sig,
            inputs,
            outputs,
        };

        // Create the block.
        let mut block = MicroBlock { header, body };
        let h = Hash::digest(&block);
        let sig = secure::sign_hash(&h, &skey);
        block.body.sig = sig;

        block
    }
}

impl Hashable for MicroBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Types of blocks supported by this blockchain.
#[derive(Clone, Debug)]
pub enum Block {
    KeyBlock(KeyBlock),
    MicroBlock(MicroBlock),
}

impl Block {
    pub fn base_header(&self) -> &BaseBlockHeader {
        match self {
            Block::KeyBlock(KeyBlock { header, .. }) => &header.base,
            Block::MicroBlock(MicroBlock { header, .. }) => &header.base,
        }
    }
}

impl Hashable for Block {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Block::KeyBlock(key_block) => key_block.hash(state),
            Block::MicroBlock(micro_block) => micro_block.hash(state),
        }
    }
}

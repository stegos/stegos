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

use crate::error::TransactionError;
use crate::merkle::*;
use crate::output::*;
use crate::transaction::Transaction;
use crate::view_changes::ViewChangeProof;
use bitvector::BitVector;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::SystemTime;
use stegos_crypto::curve1174::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

/// Blockchain version.
pub const VERSION: u64 = 1;
/// The maximum number of nodes in multi-signature.
pub const VALIDATORS_MAX: usize = 512;

//--------------------------------------------------------------------------------------------------
// Base Header.
//--------------------------------------------------------------------------------------------------

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
    pub random: pbc::VRF,
}

impl BaseBlockHeader {
    pub fn new(
        version: u64,
        previous: Hash,
        height: u64,
        view_change: u32,
        timestamp: SystemTime,
        random: pbc::VRF,
    ) -> Self {
        debug_assert!(pbc::validate_VRF_randomness(&random), "Cannot verify VRF.");

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

//--------------------------------------------------------------------------------------------------
// Micro Blocks.
//--------------------------------------------------------------------------------------------------

/// Monetary Block Header.
#[derive(Debug, Clone)]
pub struct MicroBlock {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Proof of the happen view_change.
    pub view_change_proof: Option<ViewChangeProof>,

    /// Transactions.
    pub transactions: Vec<Transaction>,

    // TODO: slashing
    /// PBC public key of slot owner.
    pub pkey: pbc::PublicKey,

    /// BLS signature by slot owner.
    pub sig: pbc::Signature,
}

impl Hashable for MicroBlock {
    fn hash(&self, state: &mut Hasher) {
        "Micro".hash(state);
        self.base.hash(state);
        if let Some(proof) = &self.view_change_proof {
            proof.hash(state);
        }
        let tx_count: u64 = self.transactions.len() as u64;
        tx_count.hash(state);
        for tx in &self.transactions {
            tx.fullhash(state);
        }
        self.pkey.hash(state);
    }
}

impl PartialEq for MicroBlock {
    fn eq(&self, _other: &MicroBlock) -> bool {
        // Required by enum Block.
        unreachable!();
    }
}

impl Eq for MicroBlock {}

impl MicroBlock {
    pub fn new(
        base: BaseBlockHeader,
        view_change_proof: Option<ViewChangeProof>,
        transactions: Vec<Transaction>,
        pkey: pbc::PublicKey,
    ) -> MicroBlock {
        let sig = pbc::Signature::zero();
        let block = MicroBlock {
            base,
            view_change_proof,
            transactions,
            pkey,
            sig,
        };
        block
    }

    pub fn empty(
        base: BaseBlockHeader,
        view_change_proof: Option<ViewChangeProof>,
        pkey: pbc::PublicKey,
    ) -> MicroBlock {
        let transactions = Vec::new();
        MicroBlock::new(base, view_change_proof, transactions, pkey)
    }

    /// Sign block using leader's signature.
    pub fn sign(&mut self, skey: &pbc::SecretKey, pkey: &pbc::PublicKey) {
        assert_eq!(&self.pkey, pkey);
        let hash = Hash::digest(self);
        let sig = pbc::sign_hash(&hash, &skey);
        self.sig = sig;
    }
}

//--------------------------------------------------------------------------------------------------
// Macro Blocks.
//--------------------------------------------------------------------------------------------------

/// Monetary Block Header.
#[derive(Debug, Clone)]
pub struct MacroBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub gamma: Fr,

    /// Block Reward.
    pub block_reward: i64,

    /// Merklish root of all range proofs for inputs.
    pub inputs_range_hash: Hash,

    /// Merklish root of all range proofs for output.
    pub outputs_range_hash: Hash,
}

impl Hashable for MacroBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Monetary".hash(state);
        self.base.hash(state);
        self.gamma.hash(state);
        self.block_reward.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_range_hash.hash(state);
    }
}

/// Monetary Block.
#[derive(Debug, Clone)]
pub struct MacroBlockBody {
    /// Public key of leader.
    pub pkey: pbc::PublicKey,

    /// BLS (multi-)signature.
    pub multisig: pbc::Signature,

    /// Bitmap of signers in the multi-signature.
    pub multisigmap: BitVector,

    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Merkle<Box<Output>>,
}

impl PartialEq for MacroBlockBody {
    fn eq(&self, _other: &MacroBlockBody) -> bool {
        // Required by enum Block.
        unreachable!();
    }
}

impl Eq for MacroBlockBody {}

/// Carries all cryptocurrency transactions.
#[derive(Debug, Clone)]
pub struct MacroBlock {
    /// Header.
    pub header: MacroBlockHeader,
    /// Body
    pub body: MacroBlockBody,
}

impl MacroBlock {
    pub fn empty(base: BaseBlockHeader, pkey: pbc::PublicKey) -> MacroBlock {
        Self::new(base, Fr::zero(), 0, &[], &[], pkey)
    }

    ///
    /// Create a new macro block from the list of transactions.
    ///
    pub fn from_transactions(
        base: BaseBlockHeader,
        transactions: &[Transaction],
        block_reward: i64,
        pkey: pbc::PublicKey,
    ) -> Result<MacroBlock, TransactionError> {
        //
        // Collect transactions.
        //
        let mut inputs: BTreeSet<Hash> = BTreeSet::new();
        let mut outputs: BTreeMap<Hash, Output> = BTreeMap::new();
        let mut gamma = Fr::zero();
        for tx in transactions {
            gamma += tx.gamma();
            for input_hash in tx.txins() {
                // Prune output if exists.outputs.
                if let Some(_) = outputs.remove(input_hash) {
                    continue;
                }
                if !inputs.insert(input_hash.clone()) {
                    // Can happen due to double-spending in micro-blocks.
                    return Err(TransactionError::DuplicateInput(
                        Hash::digest(tx),
                        input_hash.clone(),
                    )
                    .into());
                }
            }
            for output in tx.txouts() {
                let output_hash = Hash::digest(output);
                if let Some(_) = outputs.insert(output_hash, output.clone()) {
                    return Err(TransactionError::DuplicateOutput(
                        Hash::digest(tx),
                        output_hash.clone(),
                    )
                    .into());
                }
            }
        }

        //
        // Create block.
        //
        let inputs: Vec<Hash> = inputs.into_iter().collect();
        let outputs: Vec<Output> = outputs.into_iter().map(|(_, o)| o).collect();
        let block = MacroBlock::new(base, gamma, block_reward, &inputs, &outputs, pkey);
        Ok(block)
    }

    pub fn new(
        base: BaseBlockHeader,
        gamma: Fr,
        block_reward: i64,
        inputs: &[Hash],
        outputs: &[Output],
        pkey: pbc::PublicKey,
    ) -> MacroBlock {
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
        let header = MacroBlockHeader {
            base,
            gamma,
            block_reward,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create body
        let multisig = pbc::Signature::zero();
        let multisigmap = BitVector::new(VALIDATORS_MAX);
        let body = MacroBlockBody {
            pkey,
            multisig,
            multisigmap,
            inputs,
            outputs,
        };

        // Create the block.
        MacroBlock { header, body }
    }
}

impl Hashable for MacroBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

impl PartialEq for MacroBlock {
    fn eq(&self, other: &MacroBlock) -> bool {
        Hash::digest(self) == Hash::digest(other)
    }
}

impl Eq for MacroBlock {}

//--------------------------------------------------------------------------------------------------
// Block (enum).
//--------------------------------------------------------------------------------------------------

/// Types of blocks supported by this blockchain.
#[derive(Clone, Debug)]
pub enum Block {
    MacroBlock(MacroBlock),
    MicroBlock(MicroBlock),
}

impl Block {
    pub fn base_header(&self) -> &BaseBlockHeader {
        match self {
            Block::MacroBlock(MacroBlock { header, .. }) => &header.base,
            Block::MicroBlock(MicroBlock { base, .. }) => &base,
        }
    }

    ///
    /// Unwrap a Micro Block.
    ///
    /// # Panics
    ///
    /// Panics if the block is not Micro Block.
    ///
    pub fn unwrap_micro(self) -> MicroBlock {
        match self {
            Block::MicroBlock(micro_block) => micro_block,
            Block::MacroBlock(macro_block) => {
                panic!(
                    "Expected a micro block: height={}, block={}",
                    macro_block.header.base.height,
                    Hash::digest(&macro_block)
                );
            }
        }
    }

    ///
    /// Unwrap a Micro Block.
    ///
    /// # Panics
    ///
    /// Panics if the block is not Macro Block.
    ///
    pub fn unwrap_macro(self) -> MacroBlock {
        match self {
            Block::MacroBlock(macro_block) => macro_block,
            Block::MicroBlock(micro_block) => {
                panic!(
                    "Expected a micro block: height={}, block={}",
                    micro_block.base.height,
                    Hash::digest(&micro_block)
                );
            }
        }
    }
}

impl Hashable for Block {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Block::MacroBlock(macro_block) => macro_block.hash(state),
            Block::MicroBlock(micro_block) => micro_block.hash(state),
        }
    }
}

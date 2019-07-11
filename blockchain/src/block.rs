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
use crate::timestamp::Timestamp;
use crate::transaction::Transaction;
use crate::view_changes::ViewChangeProof;
use bitvector::BitVector;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_crypto::scc::Fr;

/// Blockchain version.
pub const VERSION: u64 = 1;
/// The maximum number of nodes in multi-signature.
pub const VALIDATORS_MAX: usize = 512;

//--------------------------------------------------------------------------------------------------
// Micro Blocks.
//--------------------------------------------------------------------------------------------------

/// Micro Block Header.
#[derive(Debug, Clone)]
pub struct MicroBlockHeader {
    /// Version number.
    pub version: u64,

    /// The hash of the previous block header.
    pub previous: Hash,

    /// The epoch number.
    pub epoch: u64,

    /// The block number within the epoch.
    pub offset: u32,

    /// The number of changed leaders for this block.
    pub view_change: u32,

    /// The proof of performed view_change.
    pub view_change_proof: Option<ViewChangeProof>,

    /// The public PBC key of selected leader.
    pub pkey: pbc::PublicKey,

    /// Generated random value by leader.
    pub random: pbc::VRF,

    /// Solution for VDF.
    pub solution: Vec<u8>,

    /// UNIX timestamp of block creation.
    pub timestamp: Timestamp,

    /// Merklish root of all transactions.
    pub transactions_range_hash: Hash,
}

/// Micro Block.
#[derive(Debug, Clone)]
pub struct MicroBlock {
    /// Header.
    pub header: MicroBlockHeader,

    /// BLS signature by leader.
    pub sig: pbc::Signature,

    /// Transactions.
    pub transactions: Vec<Transaction>,
}

impl Hashable for MicroBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Micro".hash(state);
        self.version.hash(state);
        self.previous.hash(state);
        self.epoch.hash(state);
        self.offset.hash(state);
        self.view_change.hash(state);
        if let Some(proof) = &self.view_change_proof {
            proof.hash(state);
        }
        self.pkey.hash(state);
        self.random.hash(state);
        self.solution.hash(state);
        self.timestamp.hash(state);
        self.transactions_range_hash.hash(state);
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
        previous: Hash,
        epoch: u64,
        offset: u32,
        view_change: u32,
        view_change_proof: Option<ViewChangeProof>,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        solution: Vec<u8>,
        timestamp: Timestamp,
        transactions: Vec<Transaction>,
    ) -> MicroBlock {
        let transactions_range_hash: Hash = Self::calculate_transactions_range_hash(&transactions);
        let header = MicroBlockHeader {
            version: VERSION,
            previous,
            epoch,
            offset,
            view_change,
            view_change_proof,
            pkey,
            random,
            solution,
            timestamp,
            transactions_range_hash,
        };

        let sig = pbc::Signature::zero();
        MicroBlock {
            header,
            sig,
            transactions,
        }
    }

    pub fn empty(
        previous: Hash,
        epoch: u64,
        offset: u32,
        view_change: u32,
        view_change_proof: Option<ViewChangeProof>,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        solution: Vec<u8>,
        timestamp: Timestamp,
    ) -> MicroBlock {
        let transactions = Vec::new();
        MicroBlock::new(
            previous,
            epoch,
            offset,
            view_change,
            view_change_proof,
            pkey,
            random,
            solution,
            timestamp,
            transactions,
        )
    }

    /// Sign block using leader's signature.
    pub fn sign(&mut self, skey: &pbc::SecretKey, pkey: &pbc::PublicKey) {
        assert_eq!(&self.header.pkey, pkey);
        let hash = Hash::digest(&self.header);
        let sig = pbc::sign_hash(&hash, &skey);
        self.sig = sig;
    }

    pub fn calculate_transactions_range_hash(transactions: &[Transaction]) -> Hash {
        let tx_hashes: Vec<Hash> = transactions
            .iter()
            .map(|tx| {
                let mut hasher = Hasher::new();
                tx.fullhash(&mut hasher);
                hasher.result()
            })
            .collect();
        let transactions_tree = Merkle::from_array(&tx_hashes);
        transactions_tree.roothash().clone()
    }
}

impl Hashable for MicroBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

//--------------------------------------------------------------------------------------------------
// Macro Blocks.
//--------------------------------------------------------------------------------------------------

/// Macro Block Header.
#[derive(Debug, Clone)]
pub struct MacroBlockHeader {
    /// Version number.
    pub version: u64,

    /// The hash of the previous block header.
    pub previous: Hash,

    /// The epoch number.
    pub epoch: u64,

    /// Number of rounds performed by consensus.
    pub view_change: u32,

    /// The public PBC key of selected leader.
    pub pkey: pbc::PublicKey,

    /// Latest random of the leader.
    pub random: pbc::VRF,

    /// Difficulty of Verifiable Delay Function.
    pub difficulty: u64,

    /// UNIX timestamp of block creation.
    pub timestamp: Timestamp,

    /// The block reward.
    pub block_reward: i64,

    /// Bitmap of active validators in epoch.
    pub activity_map: BitVector,

    /// The sum of all gamma adjustments.
    pub gamma: Fr,

    /// Merklish root of all input hashes.
    pub inputs_range_hash: Hash,
    /// The number of inputs in Merkle Tree to prevent potential attacks.
    pub inputs_len: u32,

    /// Merklish root of all output hashes.
    pub outputs_range_hash: Hash,
    /// The number of outputs in Merkle Tree to prevent potential attacks.
    pub outputs_len: u32,
}

impl Hashable for MacroBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Macro".hash(state);
        self.version.hash(state);
        self.previous.hash(state);
        self.epoch.hash(state);
        self.view_change.hash(state);
        self.pkey.hash(state);
        self.random.hash(state);
        self.difficulty.hash(state);
        self.timestamp.hash(state);
        self.block_reward.hash(state);
        for bit in self.activity_map.iter() {
            (bit as u32).hash(state);
        }
        self.gamma.hash(state);
        self.inputs_len.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_len.hash(state);
        self.outputs_range_hash.hash(state);
    }
}

/// Macro Block.
#[derive(Debug, Clone)]
pub struct MacroBlock {
    /// Header.
    pub header: MacroBlockHeader,

    /// BLS (multi-)signature.
    pub multisig: pbc::Signature,

    /// Bitmap of signers in the multi-signature.
    pub multisigmap: BitVector,

    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Vec<Output>,
}

impl MacroBlock {
    pub fn empty(
        previous: Hash,
        epoch: u64,
        view_change: u32,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        difficulty: u64,
        timestamp: Timestamp,
        block_reward: i64,
        activity_map: BitVector,
    ) -> MacroBlock {
        let gamma = Fr::zero();
        let inputs: Vec<Hash> = Vec::new();
        let outputs: Vec<Output> = Vec::new();
        Self::new(
            previous,
            epoch,
            view_change,
            pkey,
            random,
            difficulty,
            timestamp,
            block_reward,
            activity_map,
            gamma,
            inputs,
            outputs,
        )
    }

    ///
    /// Create a new macro block from the list of transactions.
    ///
    pub fn from_transactions(
        previous: Hash,
        epoch: u64,
        view_change: u32,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        difficulty: u64,
        timestamp: Timestamp,
        block_reward: i64,
        activity_map: BitVector,
        transactions: &[Transaction],
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
        let block = Self::new(
            previous,
            epoch,
            view_change,
            pkey,
            random,
            difficulty,
            timestamp,
            block_reward,
            activity_map,
            gamma,
            inputs,
            outputs,
        );
        Ok(block)
    }

    pub fn new(
        previous: Hash,
        epoch: u64,
        view_change: u32,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        difficulty: u64,
        timestamp: Timestamp,
        block_reward: i64,
        activity_map: BitVector,
        gamma: Fr,
        mut inputs: Vec<Hash>,
        mut outputs: Vec<Output>,
    ) -> MacroBlock {
        // Re-order all inputs to blur transaction boundaries.
        // Current algorithm just sorts this list.
        // Since Hash is random, it has the same effect as shuffling.
        assert!(inputs.len() <= std::u32::MAX as usize);
        let inputs_len = inputs.len() as u32;
        inputs.sort();

        // Calculate input_range_hash.
        let inputs_range_hash = Self::calculate_range_hash(&inputs);

        // Re-order all outputs to blur transaction boundaries.
        assert!(outputs.len() <= std::u32::MAX as usize);
        let outputs_len = outputs.len() as u32;
        outputs.sort_by_cached_key(Hash::digest);

        // Calculate outputs_range_hash.
        let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
        let outputs_range_hash = Self::calculate_range_hash(&output_hashes);

        // Create header
        let header = MacroBlockHeader {
            version: VERSION,
            previous,
            epoch,
            view_change,
            pkey,
            random,
            difficulty,
            timestamp,
            block_reward,
            activity_map,
            gamma,
            inputs_len,
            inputs_range_hash,
            outputs_len,
            outputs_range_hash,
        };

        // Create the block.
        let multisig = pbc::Signature::zero();
        let multisigmap = BitVector::new(VALIDATORS_MAX);
        MacroBlock {
            header,
            multisig,
            multisigmap,
            inputs,
            outputs,
        }
    }

    pub(crate) fn calculate_range_hash(hashes: &[Hash]) -> Hash {
        let tree = Merkle::from_array(hashes);
        tree.roothash().clone()
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
                    "Expected a micro block: epoch={}, block={}",
                    macro_block.header.epoch,
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
                    "Expected a micro block: epoch={}, offset={}, block={}",
                    micro_block.header.epoch,
                    micro_block.header.offset,
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

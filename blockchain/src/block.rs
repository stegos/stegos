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

use std::fmt::{Display, Error, Formatter};
use std::iter::{FromIterator, Iterator};

use crate::error::TransactionError;
use crate::merkle::*;
use crate::output::*;
use crate::timestamp::Timestamp;
use crate::transaction::Transaction;
use crate::view_changes::ViewChangeProof;
use bit_vec::BitVec;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_crypto::scc::Fr;

/// Blockchain version.
pub const VERSION: u64 = 1;

//--------------------------------------------------------------------------------------------------
// Micro Blocks.
//--------------------------------------------------------------------------------------------------

/// Micro Block Header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockHeader {
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
    #[serde(deserialize_with = "stegos_crypto::utils::vec_deserialize_from_hex")]
    #[serde(serialize_with = "stegos_crypto::utils::vec_serialize_to_hex")]
    pub solution: Vec<u8>,

    /// UNIX timestamp of block creation.
    pub timestamp: Timestamp,

    /// The number of transactions in this block.
    pub transactions_len: u32,

    /// Merklish root of all transactions.
    pub transactions_range_hash: Hash,

    /// The total number of inputs in all transactions in this block.
    pub inputs_len: u32,

    /// Merklish root of all input hashes.
    pub inputs_range_hash: Hash,

    /// The total number of outputs in all transactions in this block.
    pub outputs_len: u32,

    /// Merklish root of all output hashes.
    pub outputs_range_hash: Hash,

    /// Merklish root of all canary canaries.
    pub canaries_range_hash: Hash,
}

/// Micro Block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "crate::api::MicroblockInfo")]
#[serde(into = "crate::api::MicroblockInfo")]
pub struct Microblock {
    /// Header.
    pub header: MicroblockHeader,

    /// BLS signature by leader.
    pub sig: pbc::Signature,

    /// Transactions.
    pub transactions: Vec<Transaction>,
}

/// Micro Block for the light node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightMicroblock {
    /// Header.
    pub header: MicroblockHeader,
    /// BLS signature by leader.
    pub sig: pbc::Signature,
    /// Input hashes.
    pub input_hashes: Vec<Hash>,
    /// Output hashes.
    pub output_hashes: Vec<Hash>,
    /// Output canaries.
    pub canaries: Vec<Canary>,
}

impl Hashable for MicroblockHeader {
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
        self.transactions_len.hash(state);
        self.transactions_range_hash.hash(state);
        self.inputs_len.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_len.hash(state);
        self.outputs_range_hash.hash(state);
        self.canaries_range_hash.hash(state);
    }
}

impl Microblock {
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
    ) -> Microblock {
        assert!(transactions.len() <= std::u32::MAX as usize);
        let (
            transactions_range_hash,
            inputs_range_hash,
            outputs_range_hash,
            canaries_range_hash,
            transaction_hashes,
            input_hashes,
            output_hashes,
            canary_hashes,
        ) = Self::calculate_range_hashes(&transactions);
        assert_eq!(transaction_hashes.len(), transactions.len());
        assert!(input_hashes.len() <= std::u32::MAX as usize);
        assert!(output_hashes.len() <= std::u32::MAX as usize);
        assert_eq!(output_hashes.len(), canary_hashes.len());
        let transactions_len = transactions.len() as u32;
        let inputs_len = input_hashes.len() as u32;
        let outputs_len = output_hashes.len() as u32;
        let header = MicroblockHeader {
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
            transactions_len,
            transactions_range_hash,
            inputs_len,
            inputs_range_hash,
            outputs_len,
            outputs_range_hash,
            canaries_range_hash,
        };
        let sig = pbc::Signature::zero();
        Microblock {
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
    ) -> Microblock {
        let transactions = Vec::new();
        Microblock::new(
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

    pub(crate) fn calculate_range_hashes(
        transactions: &[Transaction],
    ) -> (
        Hash,
        Hash,
        Hash,
        Hash,
        Vec<Hash>,
        Vec<Hash>,
        Vec<Hash>,
        Vec<Hash>,
    ) {
        let mut transaction_hashes = Vec::with_capacity(transactions.len());
        let mut input_hashes = Vec::with_capacity(2 * transactions.len());
        let mut output_hashes = Vec::with_capacity(2 * transactions.len());
        let mut canary_hashes = Vec::with_capacity(2 * transactions.len());
        for tx in transactions {
            let mut hasher = Hasher::new();
            tx.fullhash(&mut hasher);
            transaction_hashes.push(hasher.result());
            input_hashes.extend(tx.txins().iter().cloned());
            output_hashes.extend(tx.txouts().iter().map(Hash::digest));
            canary_hashes.extend(tx.txouts().iter().map(|o| Hash::digest(&o.canary())));
        }
        assert_eq!(output_hashes.len(), canary_hashes.len());
        let transactions_range_hash = Merkle::root_hash_from_array(&transaction_hashes);
        let inputs_range_hash = Merkle::root_hash_from_array(&input_hashes);
        let outputs_range_hash = Merkle::root_hash_from_array(&output_hashes);
        let canaries_range_hash = Merkle::root_hash_from_array(&canary_hashes);
        (
            transactions_range_hash,
            inputs_range_hash,
            outputs_range_hash,
            canaries_range_hash,
            transaction_hashes,
            input_hashes,
            output_hashes,
            canary_hashes,
        )
    }

    pub fn inputs(&self) -> impl Iterator<Item = &Hash> {
        self.transactions.iter().flat_map(|tx| tx.txins())
    }

    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.transactions.iter().flat_map(|tx| tx.txouts())
    }
}

impl Hashable for Microblock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

impl Hashable for LightMicroblock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

impl Microblock {
    pub fn into_light_ublock(self) -> LightMicroblock {
        let input_hashes: Vec<Hash> = self.inputs().cloned().collect();
        let canaries: Vec<Canary> = self.outputs().map(|o| o.canary()).collect();
        let output_hashes: Vec<Hash> = self.outputs().map(Hash::digest).collect();
        LightMicroblock {
            header: self.header,
            sig: self.sig,
            input_hashes,
            output_hashes,
            canaries,
        }
    }
}

impl From<Microblock> for LightMicroblock {
    fn from(block: Microblock) -> LightMicroblock {
        block.into_light_ublock()
    }
}

//--------------------------------------------------------------------------------------------------
// Macro Blocks.
//--------------------------------------------------------------------------------------------------

/// Group of validators, should be ordered and unique by pbc::PublicKey.
pub type Validator = (pbc::PublicKey, i64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validators(pub Vec<Validator>);

impl Validators {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }
}

impl FromIterator<Validator> for Validators {
    fn from_iter<I: IntoIterator<Item = Validator>>(iter: I) -> Self {
        let mut vec = Vec::new();
        for v in iter {
            vec.push(v)
        }
        Validators(vec)
    }
}

impl Display for Validators {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "[")?;
        for v in &self.0[0..self.0.len() - 1] {
            write!(f, "({}, {}), ", v.0, v.1)?;
        }

        let v = &self.0[self.0.len() - 1];
        write!(f, "({}, {})]", v.0, v.1)
    }
}

/// Macro Block Header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacroblockHeader {
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

    /// The sum of all gamma adjustments.
    pub gamma: Fr,

    /// Bitmap of active validators in epoch.
    #[serde(deserialize_with = "stegos_crypto::utils::deserialize_bitvec")]
    #[serde(serialize_with = "stegos_crypto::utils::serialize_bitvec")]
    pub activity_map: BitVec,

    /// The number of validators for the next epoch.
    pub validators_len: u32,

    /// Merklish root of validators for the next epoch (pkey, slots).
    pub validators_range_hash: Hash,

    /// The number of inputs in this block.
    pub inputs_len: u32,

    /// Merklish root of all input hashes.
    pub inputs_range_hash: Hash,

    /// The number of outputs in this block.
    pub outputs_len: u32,

    /// Merklish root of all output hashes.
    pub outputs_range_hash: Hash,

    /// Merklish root of all canary hashes.
    pub canaries_range_hash: Hash,
}

impl Hashable for MacroblockHeader {
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
        self.gamma.hash(state);
        (self.activity_map.len() as u32).hash(state);
        for val in self.activity_map.iter() {
            val.hash(state);
        }
        self.validators_len.hash(state);
        self.validators_range_hash.hash(state);
        self.inputs_len.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_len.hash(state);
        self.outputs_range_hash.hash(state);
        self.canaries_range_hash.hash(state);
    }
}

/// Macro Block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "crate::api::MacroblockInfo")]
#[serde(into = "crate::api::MacroblockInfo")]
pub struct Macroblock {
    /// Header.
    pub header: MacroblockHeader,

    /// BLS multi-signature.
    pub multisig: pbc::Signature,

    /// Bitmap of signers in the multi-signature.
    pub multisigmap: BitVec,

    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Vec<Output>,
}

/// Macro Block for the light node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightMacroblock {
    /// Header.
    pub header: MacroblockHeader,
    /// BLS multi-signature.
    pub multisig: pbc::Signature,
    /// Bitmap of signers in the multi-signature.
    #[serde(deserialize_with = "stegos_crypto::utils::deserialize_bitvec")]
    #[serde(serialize_with = "stegos_crypto::utils::serialize_bitvec")]
    pub multisigmap: BitVec,
    /// Validators for the new epoch.
    pub validators: Validators,
    /// Input hashes.
    pub input_hashes: Vec<Hash>,
    /// Output hashes.
    pub output_hashes: Vec<Hash>,
    /// Output canaries.
    pub canaries: Vec<Canary>,
}

impl Macroblock {
    pub fn empty(
        previous: Hash,
        epoch: u64,
        view_change: u32,
        pkey: pbc::PublicKey,
        random: pbc::VRF,
        difficulty: u64,
        timestamp: Timestamp,
        block_reward: i64,
        activity_map: BitVec,
        validators: Validators,
    ) -> Macroblock {
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
            gamma,
            activity_map,
            validators,
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
        activity_map: BitVec,
        validators: Validators,
        transactions: &[Transaction],
    ) -> Result<Macroblock, TransactionError> {
        //
        // Collect transactions.
        //
        let mut inputs: BTreeSet<Hash> = BTreeSet::new();
        let mut outputs: BTreeMap<Hash, Output> = BTreeMap::new();
        let mut gamma = Fr::zero();
        for tx in transactions {
            gamma += tx.gamma();
            for input_hash in tx.txins() {
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
            gamma,
            activity_map,
            validators,
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
        gamma: Fr,
        activity_map: BitVec,
        validators: Validators,
        mut inputs: Vec<Hash>,
        mut outputs: Vec<Output>,
    ) -> Macroblock {
        // Validators are already sorted.
        assert!(validators.0.len() < std::u32::MAX as usize);
        let validators_len = validators.0.len() as u32;
        // Calculate validators_range_hash.
        let validators_range_hash = Merkle::root_hash_from_array(&validators.0);

        // Re-order all inputs to blur transaction boundaries.
        // Current algorithm just sorts this list.
        // Since Hash is random, it has the same effect as shuffling.
        assert!(inputs.len() <= std::u32::MAX as usize);
        let inputs_len = inputs.len() as u32;
        inputs.sort();

        // Calculate input_range_hash.
        let inputs_range_hash = Merkle::root_hash_from_array(&inputs);

        // Re-order all outputs to blur transaction boundaries.
        assert!(outputs.len() <= std::u32::MAX as usize);
        let outputs_len = outputs.len() as u32;
        outputs.sort_by_cached_key(Hash::digest);

        // Calculate outputs_range_hash.
        let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
        let outputs_range_hash = Merkle::root_hash_from_array(&output_hashes);

        // Calculate canaries_range_hash.
        let canary_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(&o.canary())).collect();
        let canaries_range_hash = Merkle::root_hash_from_array(&canary_hashes);

        // Create header
        let header = MacroblockHeader {
            version: VERSION,
            previous,
            epoch,
            view_change,
            pkey,
            random,
            difficulty,
            timestamp,
            block_reward,
            gamma,
            activity_map,
            validators_len,
            validators_range_hash,
            inputs_len,
            inputs_range_hash,
            outputs_len,
            outputs_range_hash,
            canaries_range_hash,
        };

        // Create the block.
        let multisig = pbc::Signature::zero();
        let multisigmap = BitVec::new();
        Macroblock {
            header,
            multisig,
            multisigmap,
            inputs,
            outputs,
        }
    }

    pub fn into_light_mblock(self, validators: Validators) -> LightMacroblock {
        let input_hashes: Vec<Hash> = self.inputs;
        let outputs: Vec<Output> = self.outputs;
        let canaries: Vec<Canary> = outputs.iter().map(|o| o.canary()).collect();
        let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
        LightMacroblock {
            header: self.header,
            multisig: self.multisig,
            multisigmap: self.multisigmap,
            validators,
            input_hashes,
            output_hashes,
            canaries,
        }
    }
}

impl Hashable for Macroblock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

impl Hashable for LightMacroblock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

//--------------------------------------------------------------------------------------------------
// Block (enum).
//--------------------------------------------------------------------------------------------------

/// Types of blocks supported by this blockchain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "block")]
pub enum Block {
    Macroblock(Macroblock),
    Microblock(Microblock),
}

impl From<Macroblock> for Block {
    fn from(block: Macroblock) -> Block {
        Block::Macroblock(block)
    }
}

impl From<Microblock> for Block {
    fn from(block: Microblock) -> Block {
        Block::Microblock(block)
    }
}

impl Block {
    ///
    /// Unwrap a Micro Block.
    ///
    /// # Panics
    ///
    /// Panics if the block is not Micro Block.
    ///
    pub fn unwrap_micro(self) -> Microblock {
        match self {
            Block::Microblock(ub) => ub,
            Block::Macroblock(mb) => {
                panic!(
                    "Expected a micro block: epoch={}, block={}",
                    mb.header.epoch,
                    Hash::digest(&mb)
                );
            }
        }
    }

    ///
    /// Unwrap a Micro Block by ref.
    ///
    /// # Panics
    ///
    /// Panics if the block is not Micro Block.
    ///
    pub fn unwrap_micro_ref(&self) -> &Microblock {
        match self {
            Block::Microblock(ref ub) => ub,
            Block::Macroblock(ref mb) => {
                panic!(
                    "Expected a micro block: epoch={}, block={}",
                    mb.header.epoch,
                    Hash::digest(&mb)
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
    pub fn unwrap_macro(self) -> Macroblock {
        match self {
            Block::Macroblock(mb) => mb,
            Block::Microblock(ub) => {
                panic!(
                    "Expected a micro block: epoch={}, offset={}, block={}",
                    ub.header.epoch,
                    ub.header.offset,
                    Hash::digest(&ub)
                );
            }
        }
    }

    ///
    /// Unwrap a Micro Block by ref.
    ///
    /// # Panics
    ///
    /// Panics if the block is not Macro Block.
    ///
    pub fn unwrap_macro_ref(&self) -> &Macroblock {
        match self {
            Block::Macroblock(ref mb) => mb,
            Block::Microblock(ref ub) => {
                panic!(
                    "Expected a micro block: epoch={}, offset={}, block={}",
                    ub.header.epoch,
                    ub.header.offset,
                    Hash::digest(&ub)
                );
            }
        }
    }
}

impl Hashable for Block {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Block::Macroblock(mb) => mb.hash(state),
            Block::Microblock(ub) => ub.hash(state),
        }
    }
}

/// A container for light-node blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LightBlock {
    LightMacroblock(LightMacroblock),
    LightMicroblock(LightMicroblock),
}

impl From<LightMacroblock> for LightBlock {
    fn from(block: LightMacroblock) -> LightBlock {
        LightBlock::LightMacroblock(block)
    }
}

impl From<LightMicroblock> for LightBlock {
    fn from(block: LightMicroblock) -> LightBlock {
        LightBlock::LightMicroblock(block)
    }
}

impl Hashable for LightBlock {
    fn hash(&self, state: &mut Hasher) {
        match self {
            LightBlock::LightMacroblock(mb) => mb.header.hash(state),
            LightBlock::LightMicroblock(ub) => ub.header.hash(state),
        }
    }
}

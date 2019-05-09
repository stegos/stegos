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
use crate::transaction::Transaction;
use crate::view_changes::ViewChangeProof;
use bitvector::BitVector;
use std::time::SystemTime;
use stegos_crypto::curve1174::cpt;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_crypto::pbc::secure::VRF;

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

//--------------------------------------------------------------------------------------------------
// Micro Blocks.
//--------------------------------------------------------------------------------------------------

/// Coinbase Transaction.
#[derive(Debug, Clone)]
pub struct Coinbase {
    /// Block reward.
    pub block_reward: i64,

    /// Sum of fees from all block transactions.
    pub block_fee: i64,

    /// Minus sum of gamma adjustments in outputs.
    pub gamma: Fr,

    /// Coinbase UTXOs.
    pub outputs: Vec<Output>,
}

/// Monetary Block Header.
#[derive(Debug, Clone)]
pub struct MicroBlock {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Proof of the happen view_change.
    pub view_change_proof: Option<ViewChangeProof>,

    /// Coinbase transaction.
    pub coinbase: Coinbase,

    /// Transactions.
    pub transactions: Vec<Transaction>,

    // TODO: slashing
    /// PBC public key of slot owner.
    pub pkey: secure::PublicKey,

    /// BLS signature by slot owner.
    pub sig: secure::Signature,
}

impl Hashable for Coinbase {
    fn hash(&self, state: &mut Hasher) {
        self.block_reward.hash(state);
        self.block_fee.hash(state);
        self.gamma.hash(state);
        let outputs_count: u64 = self.outputs.len() as u64;
        outputs_count.hash(state);
        for output in &self.outputs {
            let output_hash = Hash::digest(&output);
            output_hash.hash(state);
        }
    }
}

impl Hashable for MicroBlock {
    fn hash(&self, state: &mut Hasher) {
        "Micro".hash(state);
        self.base.hash(state);
        if let Some(proof) = &self.view_change_proof {
            proof.hash(state);
        }
        self.coinbase.hash(state);
        let tx_count: u64 = self.transactions.len() as u64;
        tx_count.hash(state);
        for tx in &self.transactions {
            tx.body.hash(state);
            tx.sig.hash(state);
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
        coinbase: Coinbase,
        transactions: Vec<Transaction>,
        pkey: secure::PublicKey,
    ) -> MicroBlock {
        let sig = secure::Signature::zero();
        let block = MicroBlock {
            base,
            view_change_proof,
            coinbase,
            transactions,
            pkey,
            sig,
        };
        block
    }

    pub fn empty(
        base: BaseBlockHeader,
        view_change_proof: Option<ViewChangeProof>,
        pkey: secure::PublicKey,
    ) -> MicroBlock {
        let coinbase = Coinbase {
            block_reward: 0,
            block_fee: 0,
            gamma: Fr::zero(),
            outputs: Vec::new(),
        };
        let transactions = Vec::new();
        MicroBlock::new(base, view_change_proof, coinbase, transactions, pkey)
    }

    pub fn with_reward(
        base: BaseBlockHeader,
        view_change_proof: Option<ViewChangeProof>,
        transactions: Vec<Transaction>,
        timestamp: SystemTime,
        sender_skey: &cpt::SecretKey,
        recipient_pkey: &cpt::PublicKey,
        pkey: secure::PublicKey,
        block_reward: i64,
    ) -> MicroBlock {
        let block_fee = transactions.iter().map(|tx| tx.body.fee).sum();

        //
        // Coinbase.
        //

        let mut outputs: Vec<Output> = Vec::new();
        let mut gamma = Fr::zero();

        // Create outputs for fee and rewards.
        for (amount, comment) in vec![(block_fee, "fee"), (block_reward, "reward")] {
            if amount <= 0 {
                continue;
            }

            let data = PaymentPayloadData::Comment(format!("Block {}", comment));
            let (output_fee, gamma_fee) =
                PaymentOutput::with_payload(timestamp, sender_skey, recipient_pkey, amount, data)
                    .expect("invalid keys");
            gamma -= gamma_fee;
            outputs.push(Output::PaymentOutput(output_fee));
        }

        let coinbase = Coinbase {
            block_reward,
            block_fee,
            gamma,
            outputs,
        };

        MicroBlock::new(base, view_change_proof, coinbase, transactions, pkey)
    }

    /// Sign block using leader's signature.
    pub fn sign(&mut self, skey: &secure::SecretKey, pkey: &secure::PublicKey) {
        assert_eq!(&self.pkey, pkey);
        let hash = Hash::digest(self);
        let sig = secure::sign_hash(&hash, &skey);
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

impl Hashable for MacroBlockHeader {
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
pub struct MacroBlockBody {
    /// Public key of leader.
    pub pkey: secure::PublicKey,

    /// BLS (multi-)signature.
    pub multisig: secure::Signature,

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
    pub fn empty(base: BaseBlockHeader, pkey: secure::PublicKey) -> MacroBlock {
        Self::new(base, Fr::zero(), 0, &[], &[], None, pkey)
    }

    pub fn new(
        base: BaseBlockHeader,
        gamma: Fr,
        monetary_adjustment: i64,
        inputs: &[Hash],
        outputs: &[Output],
        proof: Option<ViewChangeProof>,
        pkey: secure::PublicKey,
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
            proof,
            base,
            gamma,
            monetary_adjustment,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create body
        let multisig = secure::Signature::zero();
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
}

impl Hashable for Block {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Block::MacroBlock(macro_block) => macro_block.hash(state),
            Block::MicroBlock(micro_block) => micro_block.hash(state),
        }
    }
}

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

use crate::error::*;
use crate::merkle::*;
use crate::output::*;
use bitvector::BitVector;
use failure::Error;
use std::collections::BTreeSet;
use std::collections::HashSet;
use stegos_crypto::bulletproofs::validate_range_proof;
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

pub const WITNESSES_MAX: usize = 128;

/// General Block Header.
#[derive(Debug, Clone, PartialEq)]
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

    /// BLS multi-signature
    pub sig: SecureSignature,

    /// Bitmap of signers in the multi-signature.
    pub sigmap: BitVector,
}

impl BaseBlockHeader {
    pub fn new(version: u64, previous: Hash, epoch: u64, timestamp: u64) -> Self {
        let sig = SecureSignature::null();
        let sigbitmap = BitVector::new(WITNESSES_MAX);
        BaseBlockHeader {
            version,
            previous,
            epoch,
            timestamp,
            sig,
            sigmap: sigbitmap,
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

impl Eq for BaseBlockHeader {}

/// Header for Key Blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Leader public key.
    pub leader: SecurePublicKey,

    /// Ordered list of witnesses public keys.
    pub witnesses: BTreeSet<SecurePublicKey>,
    // TODO: pooled transactions facilitator public key (which kind?).
    // pub facilitator: SecurePublicKey,
}

impl Hashable for KeyBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.base.hash(state);
        self.leader.hash(state);
        for witness in self.witnesses.iter() {
            witness.hash(state);
        }
    }
}

/// Monetary Block Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub gamma: Fr,

    /// Merklish root of all range proofs for inputs.
    pub inputs_range_hash: Hash,

    /// Merklish root of all range proofs for output.
    pub outputs_range_hash: Hash,
}

impl Hashable for MonetaryBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        self.base.hash(state);
        self.gamma.hash(state);
        self.inputs_range_hash.hash(state);
        self.outputs_range_hash.hash(state);
    }
}

/// Monetary Block.
#[derive(Debug, Clone)]
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

impl Hashable for MonetaryBlockBody {
    fn hash(&self, state: &mut Hasher) {
        let inputs_count: u64 = self.inputs.len() as u64;
        inputs_count.hash(state);
        for input in &self.inputs {
            input.hash(state);
        }
        self.outputs.roothash().hash(state)
    }
}

/// Carries all cryptocurrency transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// Header.
    pub header: KeyBlockHeader,
}

impl KeyBlock {
    pub fn new(
        base: BaseBlockHeader,
        leader: SecurePublicKey,
        witnesses: BTreeSet<SecurePublicKey>,
    ) -> Self {
        assert!(!witnesses.is_empty(), "witnesses is not empty");
        assert!(
            witnesses.contains(&leader),
            "leader must present in witnesses array"
        );
        assert!(witnesses.len() <= WITNESSES_MAX, "max number of witnesses");

        // Create header
        let header = KeyBlockHeader {
            base,
            leader,
            witnesses,
        };

        // Create the block
        KeyBlock { header }
    }

    /// Validate basic properties of KeyBlock.
    pub fn validate(&self) -> Result<(), Error> {
        if self.header.witnesses.is_empty() {
            return Err(BlockchainError::MissingWitnesses.into());
        }

        if !self.header.witnesses.contains(&self.header.leader) {
            return Err(BlockchainError::InvalidLeaderIsNotWitness.into());
        }
        Ok(())
    }
}

impl Hashable for KeyBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Carries administrative information to blockchain participants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryBlock {
    /// Header.
    pub header: MonetaryBlockHeader,
    /// Body
    pub body: MonetaryBlockBody,
}

impl MonetaryBlock {
    pub fn new(
        base: BaseBlockHeader,
        gamma: Fr,
        inputs: &[Hash],
        outputs: &[Output],
    ) -> MonetaryBlock {
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
        let header = MonetaryBlockHeader {
            base,
            gamma,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create the block
        let body = MonetaryBlockBody { inputs, outputs };

        let block = MonetaryBlock { header, body };
        block
    }

    /// Validate block.
    ///
    /// This functions validates monetary balance, bulletproofs, inputs and outputs.
    /// Sic: only full untrimmed blocks are currently supported.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.inputs, in the same order as in self.body.inputs.
    ///
    pub fn validate(&self, inputs: &[Output]) -> Result<(), Error> {
        // Validate inputs.
        let inputs_range_hash = {
            let mut hasher = Hasher::new();
            let inputs_count: u64 = self.body.inputs.len() as u64;
            inputs_count.hash(&mut hasher);
            for input in &self.body.inputs {
                input.hash(&mut hasher);
            }
            hasher.result()
        };
        if self.header.inputs_range_hash != inputs_range_hash {
            let expected = self.header.inputs_range_hash.clone();
            let got = inputs_range_hash;
            return Err(BlockchainError::InvalidBlockInputsHash(expected, got).into());
        }

        // Validate outputs.
        if self.header.outputs_range_hash != *self.body.outputs.roothash() {
            let expected = self.header.outputs_range_hash.clone();
            let got = self.body.outputs.roothash().clone();
            return Err(BlockchainError::InvalidBlockOutputsHash(expected, got).into());
        }

        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = \sum C_i - \sum C_o
        //

        let mut pedersen_commitment_diff = ECp::inf();

        // +\sum{C_i} for i in txins
        let mut txins_set: HashSet<Hash> = HashSet::new();
        for (txin_hash, txin) in self.body.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            if !txins_set.insert(*txin_hash) {
                return Err(BlockchainError::DuplicateBlockInput(*txin_hash).into());
            }
            let pedersen_commitment = match txin {
                Output::MonetaryOutput(o) => o.proof.vcmt,
                Output::DataOutput(o) => o.vcmt,
            };
            let pedersen_commitment: ECp = Pt::decompress(pedersen_commitment)?;
            pedersen_commitment_diff += pedersen_commitment;
        }
        drop(txins_set);

        // -\sum{C_o} for o in txouts
        let mut txouts_set: HashSet<Hash> = HashSet::new();
        for (txout, _) in self.body.outputs.leafs() {
            let txout_hash = Hash::digest(txout);
            if !txouts_set.insert(txout_hash) {
                return Err(BlockchainError::DuplicateBlockOutput(txout_hash).into());
            }
            let pedersen_commitment = match **txout {
                Output::MonetaryOutput(ref o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(BlockchainError::InvalidBulletProof.into());
                    }
                    o.proof.vcmt
                }
                Output::DataOutput(ref o) => o.vcmt,
            };
            let pedersen_commitment: ECp = Pt::decompress(pedersen_commitment)?;
            pedersen_commitment_diff -= pedersen_commitment;
        }
        drop(txouts_set);

        // Check the monetary balance
        if pedersen_commitment_diff != self.header.gamma * (*G) {
            return Err(BlockchainError::InvalidBlockBalance.into());
        }

        Ok(())
    }
}

impl Hashable for MonetaryBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Types of blocks supported by this blockchain.
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use chrono::Utc;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::pbc::secure::make_random_keys as make_secure_random_keys;

    #[test]
    fn create_validate_key_block() {
        let (_skey0, pkey0, _sig0) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

        let witnesses: BTreeSet<SecurePublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();

        let mut block = KeyBlock::new(base, leader, witnesses);
        block.validate().expect("block is valid");

        // Missing witnesses.
        let mut witnesses = BTreeSet::new();
        std::mem::swap(&mut block.header.witnesses, &mut witnesses);
        match block.validate() {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::MissingWitnesses => {}
                _ => panic!(),
            },
            _ => panic!(),
        }
        std::mem::swap(&mut block.header.witnesses, &mut witnesses);

        // Leader is not included to the list of witnesses.
        let (_skey0, mut pkey1, _sig0) = make_secure_random_keys();
        std::mem::swap(&mut block.header.leader, &mut pkey1);
        match block.validate() {
            Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::InvalidLeaderIsNotWitness => {}
                _ => panic!(),
            },
            _ => panic!(),
        }
        std::mem::swap(&mut block.header.leader, &mut pkey1);
    }

    #[test]
    fn create_validate_monetary_block() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        //
        // Valid block with transaction from 1 to 2
        //
        {
            let (output0, gamma0) =
                Output::new_monetary(timestamp, &skey0, &pkey1, amount).unwrap();
            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) =
                Output::new_monetary(timestamp, &skey1, &pkey2, amount).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MonetaryBlock::new(base, gamma, &inputs1, &outputs1);
            block.validate(&[output0]).expect("block is valid");
        }

        //
        // Block with invalid monetary balance
        //
        {
            let (output0, gamma0) =
                Output::new_monetary(timestamp, &skey0, &pkey1, amount).unwrap();
            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) =
                Output::new_monetary(timestamp, &skey1, &pkey2, amount - 1).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MonetaryBlock::new(base, gamma, &inputs1, &outputs1);
            match block.validate(&[output0]) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockBalance => {}
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }

        //
        // Valid block with invalid inputs/outputs.
        //
        {
            let (output0, gamma0) =
                Output::new_monetary(timestamp, &skey0, &pkey1, amount).unwrap();
            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) =
                Output::new_monetary(timestamp, &skey1, &pkey2, amount).unwrap();
            let outputs1 = [output1.clone()];
            let gamma = gamma0 - gamma1;
            let mut block = MonetaryBlock::new(base, gamma, &inputs1, &outputs1);
            let inputs = [output0.clone()];

            // Invalid inputs_range_hash.
            let inputs_range_hash = block.header.inputs_range_hash.clone();
            block.header.inputs_range_hash = Hash::digest(&"invalid".to_string());
            match block.validate(&inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockInputsHash(expected, got) => {
                        assert_eq!(block.header.inputs_range_hash, expected);
                        assert_eq!(inputs_range_hash, got);
                    }
                    _ => panic!(),
                },
                _ => panic!(),
            }
            block.header.inputs_range_hash = inputs_range_hash;

            // Invalid outputs_range_hash.
            let outputs_range_hash = block.header.outputs_range_hash.clone();
            block.header.outputs_range_hash = Hash::digest(&"invalid".to_string());
            match block.validate(&inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockOutputsHash(expected, got) => {
                        assert_eq!(block.header.outputs_range_hash, expected);
                        assert_eq!(outputs_range_hash, got);
                    }
                    _ => panic!(),
                },
                _ => panic!(),
            }
            block.header.outputs_range_hash = outputs_range_hash;

            // Duplicate input.
            let bad_inputs = vec![output0.clone(), output0.clone()];
            let mut bad_input_hashes = vec![Hash::digest(&output0), Hash::digest(&output0)];
            let mut bad_inputs_range_hash: Hash = {
                let mut hasher = Hasher::new();
                let inputs_count: u64 = bad_inputs.len() as u64;
                inputs_count.hash(&mut hasher);
                for input in &bad_input_hashes {
                    input.hash(&mut hasher);
                }
                hasher.result()
            };
            std::mem::swap(&mut block.body.inputs, &mut bad_input_hashes);
            std::mem::swap(
                &mut block.header.inputs_range_hash,
                &mut bad_inputs_range_hash,
            );
            match block.validate(&bad_inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::DuplicateBlockInput(txin_hash) => {
                        assert_eq!(txin_hash, bad_input_hashes[0]);
                    }
                    _ => panic!(),
                },
                _ => panic!(),
            };
            block.body.inputs = bad_input_hashes;
            block.header.inputs_range_hash = bad_inputs_range_hash;

            // Duplicate output.
            let bad_outputs = vec![Box::new(output1.clone()), Box::new(output1.clone())];
            let mut bad_outputs = Merkle::from_array(&bad_outputs);
            let mut bad_outputs_range_hash = bad_outputs.roothash().clone();
            std::mem::swap(&mut block.body.outputs, &mut bad_outputs);
            std::mem::swap(
                &mut block.header.outputs_range_hash,
                &mut bad_outputs_range_hash,
            );
            match block.validate(&inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::DuplicateBlockOutput(hash) => {
                        assert_eq!(hash, Hash::digest(&output1));
                    }
                    _ => panic!(),
                },
                _ => panic!(),
            };
            block.body.outputs = bad_outputs;
            block.header.outputs_range_hash = bad_outputs_range_hash;
        }
    }
}

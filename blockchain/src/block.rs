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
use failure::Error;
use stegos_crypto::bulletproofs::validate_range_proof;
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

/// General Block Header.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Leader public key.
    pub leader: SecurePublicKey,

    /// Ordered list of witnesses public keys.
    pub witnesses: Vec<SecurePublicKey>,
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
        witnesses: &[SecurePublicKey],
    ) -> Self {
        let mut witnesses = witnesses.to_vec();

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
        let outputs = outputs
            .iter()
            .map(|o| Box::<Output>::new(o.clone()))
            .collect::<Vec<Box<Output>>>();
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
        for (txin_hash, txin) in self.body.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            let pedersen_commitment = match txin {
                Output::MonetaryOutput(o) => o.proof.vcmt,
                Output::DataOutput(o) => o.vcmt,
            };
            let pedersen_commitment: ECp = Pt::decompress(pedersen_commitment)?;
            pedersen_commitment_diff += pedersen_commitment;
        }

        // -\sum{C_o} for o in txouts
        for (txout, _) in self.body.outputs.leafs() {
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

    #[test]
    fn create_validate() {
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
        // Valid block with invalid inputs/outputs hash
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
            let mut block = MonetaryBlock::new(base, gamma, &inputs1, &outputs1);

            // Invalid inputs_range_hash.
            let inputs = [output0];
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
        }
    }
}

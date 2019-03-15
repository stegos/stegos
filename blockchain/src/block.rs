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

use crate::error::*;
use crate::merkle::*;
use crate::output::*;
use bitvector::BitVector;
use failure::Error;
use std::collections::BTreeSet;
use stegos_crypto::bulletproofs::{fee_a, validate_range_proof};
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
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

    /// A monotonically increasing value that represents the heights of the blockchain,
    /// starting from genesis block (=0).
    pub epoch: u64,

    /// Timestamp at which the block was built.
    pub timestamp: u64,

    /// BLS multi-signature
    pub multisig: secure::Signature,

    /// Bitmap of signers in the multi-signature.
    pub multisigmap: BitVector,
}

impl BaseBlockHeader {
    pub fn new(version: u64, previous: Hash, epoch: u64, timestamp: u64) -> Self {
        let multisig = secure::Signature::zero();
        let multisigmap = BitVector::new(VALIDATORS_MAX);
        BaseBlockHeader {
            version,
            previous,
            epoch,
            timestamp,
            multisig,
            multisigmap,
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
#[derive(Debug, Clone)]
pub struct KeyBlockHeader {
    /// Common header.
    pub base: BaseBlockHeader,

    /// Leader public key.
    pub leader: secure::PublicKey,

    /// Facilitator of Transaction Pool.
    pub facilitator: secure::PublicKey,

    /// Initial seed of epoch.
    pub random: VRF,

    /// Number of retries during creating a block.
    pub view_change: u32,

    /// Ordered list of validators public keys.
    pub validators: BTreeSet<secure::PublicKey>,
}

impl Hashable for KeyBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Key".hash(state);
        self.base.hash(state);
        self.leader.hash(state);
        self.facilitator.hash(state);
        for validator in self.validators.iter() {
            validator.hash(state);
        }
    }
}

/// Monetary Block Header.
#[derive(Debug, Clone)]
pub struct MonetaryBlockHeader {
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
}

impl Hashable for MonetaryBlockHeader {
    fn hash(&self, state: &mut Hasher) {
        "Monetary".hash(state);
        self.base.hash(state);
        self.gamma.hash(state);
        self.monetary_adjustment.hash(state);
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
        "Monetary".hash(state);
        let inputs_count: u64 = self.inputs.len() as u64;
        inputs_count.hash(state);
        for input in &self.inputs {
            input.hash(state);
        }
        self.outputs.roothash().hash(state)
    }
}

/// Carries all cryptocurrency transactions.
#[derive(Debug, Clone)]
pub struct KeyBlock {
    /// Header.
    pub header: KeyBlockHeader,
}

impl KeyBlock {
    pub fn new(
        base: BaseBlockHeader,
        leader: secure::PublicKey,
        facilitator: secure::PublicKey,
        random: VRF,
        view_change: u32,
        validators: BTreeSet<secure::PublicKey>,
    ) -> Self {
        debug_assert!(
            secure::validate_VRF_randomness(&random),
            "Cannot verify VRF."
        );
        assert!(!validators.is_empty(), "validators is not empty");
        assert!(
            validators.contains(&leader),
            "leader must present in validators array"
        );
        assert!(
            validators.len() <= VALIDATORS_MAX,
            "max number of validators"
        );

        // Create header
        let header = KeyBlockHeader {
            base,
            leader,
            facilitator,
            random,
            view_change,
            validators,
        };

        // Create the block
        KeyBlock { header }
    }

    /// Create block from known header.
    pub fn new_from_header(header: KeyBlockHeader) -> Self {
        KeyBlock { header }
    }
}

impl Hashable for KeyBlock {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state)
    }
}

/// Carries administrative information to blockchain participants.
#[derive(Debug, Clone)]
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
        monetary_adjustment: i64,
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
            monetary_adjustment,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Create the block
        let body = MonetaryBlockBody { inputs, outputs };

        let block = MonetaryBlock { header, body };
        block
    }

    ///
    /// Validate the block monetary balance.
    ///
    /// This function is a lightweight version of Blockchain.validate_monetary_block().
    /// The only monetary balance is validated. For test purposes only.
    ///
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.body.inputs, in the same order as in self.body.inputs.
    ///
    pub fn validate_balance(&self, inputs: &[Output]) -> Result<(), Error> {
        //
        // Calculate the pedersen commitment difference in order to check the monetary balance:
        //
        //     pedersen_commitment_diff = monetary_adjustment + \sum C_i - \sum C_o
        //

        let mut pedersen_commitment_diff: ECp = fee_a(self.header.monetary_adjustment);

        // +\sum{C_i} for i in txins
        for (txin_hash, txin) in self.body.inputs.iter().zip(inputs) {
            assert_eq!(Hash::digest(txin), *txin_hash);
            match txin {
                Output::PaymentOutput(o) => {
                    pedersen_commitment_diff += Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(o) => {
                    pedersen_commitment_diff += fee_a(o.amount);
                }
            };
        }

        // -\sum{C_o} for o in txouts
        for (txout, _) in self.body.outputs.leafs() {
            match **txout {
                Output::PaymentOutput(ref o) => {
                    // Check bulletproofs of created outputs
                    if !validate_range_proof(&o.proof) {
                        return Err(OutputError::InvalidBulletProof.into());
                    }
                    pedersen_commitment_diff -= Pt::decompress(o.proof.vcmt)?;
                }
                Output::StakeOutput(ref o) => {
                    if o.amount <= 0 {
                        return Err(OutputError::InvalidStake.into());
                    }
                    pedersen_commitment_diff -= fee_a(o.amount);
                }
            };
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
#[derive(Clone, Debug)]
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
    fn create_validate_monetary_block() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest("test");

        //
        // Valid block with transaction from 1 to 2
        //
        {
            let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();
            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) = Output::new_payment(timestamp, &skey1, &pkey2, amount).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MonetaryBlock::new(base, gamma, 0, &inputs1, &outputs1);
            block.validate_balance(&[output0]).expect("block is valid");
        }

        //
        // Block with invalid monetary balance
        //
        {
            let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();
            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let inputs1 = [Hash::digest(&output0)];
            let (output1, gamma1) =
                Output::new_payment(timestamp, &skey1, &pkey2, amount - 1).unwrap();
            let outputs1 = [output1];
            let gamma = gamma0 - gamma1;
            let block = MonetaryBlock::new(base, gamma, 0, &inputs1, &outputs1);
            match block.validate_balance(&[output0]) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockBalance => {}
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }
    }

    #[test]
    fn validate_pruned_monetary_block() {
        let (skey, pkey, _sig) = make_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        let (input, gamma0) = Output::new_payment(timestamp, &skey, &pkey, amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, gamma1) = Output::new_payment(timestamp, &skey, &pkey, amount).unwrap();
        let outputs = [output];
        let gamma = gamma0 - gamma1;
        let block = MonetaryBlock::new(base, gamma, 0, &input_hashes, &outputs);
        block.validate_balance(&inputs).expect("block is valid");

        {
            // Prune an output.
            let mut block2 = block.clone();
            let (_output, path) = block2.body.outputs.leafs()[0];
            block2.body.outputs.prune(&path).expect("output exists");
            match block2.validate_balance(&inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockBalance => {}
                    _ => panic!(),
                },
                _ => panic!(),
            }
        }
    }

    #[test]
    fn create_validate_monetary_block_with_escrow() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_secure_skey1, secure_pkey1, _secure_sig1) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        //
        // Escrow as an input.
        //
        {
            let input = Output::new_stake(timestamp, &skey0, &pkey1, &secure_pkey1, amount)
                .expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let inputs_gamma = Fr::zero();
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey1, &pkey1, amount).expect("keys are valid");
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let block = MonetaryBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..]);
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Escrow as an output.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let output = Output::new_stake(timestamp, &skey1, &pkey1, &secure_pkey1, amount)
                .expect("keys are valid");
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let block = MonetaryBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..]);
            block.validate_balance(&inputs).expect("block is valid");
        }

        //
        // Invalid monetary balance.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let mut output = StakeOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount)
                .expect("keys are valid");
            output.amount = amount - 1;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let block = MonetaryBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..]);
            match block.validate_balance(&inputs) {
                Err(e) => match e.downcast::<BlockchainError>().unwrap() {
                    BlockchainError::InvalidBlockBalance => {}
                    _ => panic!(),
                },
                _ => panic!(),
            };
        }

        //
        // Invalid stake.
        //
        {
            let (input, inputs_gamma) =
                Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
            let input_hashes = [Hash::digest(&input)];
            let inputs = [input];
            let mut output = StakeOutput::new(timestamp, &skey1, &pkey1, &secure_pkey1, amount)
                .expect("keys are valid");
            output.amount = 0;
            let output = Output::StakeOutput(output);
            let outputs_gamma = Fr::zero();
            let outputs = [output];
            let gamma = inputs_gamma - outputs_gamma;

            let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
            let block = MonetaryBlock::new(base, gamma, 0, &input_hashes[..], &outputs[..]);
            match block.validate_balance(&inputs) {
                Err(e) => match e.downcast::<OutputError>().unwrap() {
                    OutputError::InvalidStake => {}
                    _ => panic!(),
                },
                _ => panic!(),
            };
        }
    }

    fn create_burn_money(input_amount: i64, output_amount: i64) {
        let (skey, pkey, _sig) = make_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());

        let monetary_adjustment: i64 = output_amount - input_amount;

        let (input, input_gamma) =
            Output::new_payment(timestamp, &skey, &pkey, input_amount).unwrap();
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let input_hashes = [Hash::digest(&input)];
        let inputs = [input];
        let (output, output_gamma) =
            Output::new_payment(timestamp, &skey, &pkey, output_amount).unwrap();
        let outputs = [output];
        let gamma = input_gamma - output_gamma;
        let block = MonetaryBlock::new(base, gamma, monetary_adjustment, &input_hashes, &outputs);
        block.validate_balance(&inputs).expect("block is valid");
    }

    #[test]
    fn create_money() {
        create_burn_money(100, 200);
    }

    #[test]
    fn burn_money() {
        create_burn_money(200, 100);
    }

}

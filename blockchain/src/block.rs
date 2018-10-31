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

use chrono::prelude::Utc;
use input::Input;
use output::Output;
use merkle::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::fast::Zr;
use stegos_crypto::pbc::secure::*;

// The default file name for configuration
#[allow(dead_code)]
const GENESIS_BLOCK_HASH_STRING: &'static str = "genesis";

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

    /// Leader public key
    pub leader: PublicKey,

    /// The sum of all gamma adjustments found in the block transactions (∑ γ_adj).
    /// Includes the γ_adj from the leader's fee distribution transaction.
    pub adjustment: Zr,

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
    // TODO: replace with Merkle tree
    pub outputs: Merkle<Box<Output>>,

    /// Ordered list of witness public keys for current epoch.
    /// The leader node is also considered a witness during the current epoch.
    pub witnesses: Vec<PublicKey>,

    /// CoSi multisignature on HCURR
    // TODO: which kind
    pub sig: Signature,
}

impl Block {
    pub fn sign(
        skey: &SecretKey,
        version: u64,
        epoch: u64,
        previous: Hash,
        leader: PublicKey,
        adjustment: Zr,
        witnesses: &[PublicKey],
        inputs: &[Input],
        outputs: &[Output],
    ) -> (Block, Vec<MerklePath>) {
        // Get current time
        let timestamp = Utc::now().timestamp() as u64;

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
        // TODO: replace with actual Merkle tree
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

        // Create witnesses array
        let witnesses = witnesses.to_vec();

        // Calculate block hash
        let mut hasher = Hasher::new();
        version.hash(&mut hasher);
        epoch.hash(&mut hasher);
        previous.hash(&mut hasher);
        leader.hash(&mut hasher);
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
            leader,
            adjustment,
            timestamp,
            inputs_range_hash,
            outputs_range_hash,
        };

        // Sign header
        let sig = sign_hash(&hash, skey);

        // hash the number of witnesses first
        let witnesses_count: u64 = witnesses.len() as u64;
        witnesses_count.hash(&mut hasher);
        for witness in witnesses.iter() {
            witness.hash(&mut hasher);
        }
        sig.hash(&mut hasher);

        // Create the block
        let block = Block {
            header,
            inputs,
            outputs,
            witnesses,
            sig,
        };

        (block, paths)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use stegos_crypto::pbc::init_pairings;
    use stegos_crypto::*;
    use payload::EncryptedPayload;

    pub fn fake(
        version: u64,
        epoch: u64,
        inputs: &[Input],
        previous: &Hash,
    ) -> (Block, Vec<MerklePath>) {
        let seed: [u8; 4] = [1, 2, 3, 4];

        let (skey, pubkey, _sig) = make_deterministic_keys(&seed);
        let leader = pubkey;

        let adjustment: Zr = Zr::new();
        let witnesses = [leader.clone()];

        // But have one hard-coded output
        let (proof, _gamma) = bulletproofs::make_range_proof(1234567890);
        let payload = EncryptedPayload::garbage();
        let output = Output::new(leader.clone(), proof, payload);
        let outputs = [output];

        Block::sign(
            &skey,
            version,
            epoch,
            previous.clone(),
            leader,
            adjustment,
            &witnesses,
            &inputs,
            &outputs,
        )
    }

    pub fn genesis() -> (Block, Vec<MerklePath>) {
        let previous = Hash::from_str(GENESIS_BLOCK_HASH_STRING);
        fake(1, 1, &[], &previous)
    }

    #[test]
    fn test_genesis() {
        init_pairings().expect("pbc initialization");

        let (genesis, _) = genesis();
        let header = genesis.header;

        assert_eq!(header.previous, Hash::from_str(GENESIS_BLOCK_HASH_STRING));
        assert_eq!(header.epoch, 1);
        assert_eq!(header.version, 1);
    }
}

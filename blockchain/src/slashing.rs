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

use crate::error::SlashingError;
use crate::transaction::SlashingTransaction;
use crate::{Blockchain, BlockchainError, MicroBlock, PublicPaymentOutput};
use log::debug;
use rand::{thread_rng, Rng};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

#[derive(Clone, Debug)]
pub struct SlashingProof {
    pub block1: MicroBlock,
    pub block2: MicroBlock,
}

impl SlashingProof {
    pub fn new_unchecked(block1: MicroBlock, block2: MicroBlock) -> SlashingProof {
        let proof = SlashingProof { block1, block2 };
        proof
    }

    pub fn validate(&self, blockchain: &Blockchain) -> Result<(), BlockchainError> {
        let height = self.block1.base.height;

        if self.block1.base.height != self.block2.base.height {
            return Err(SlashingError::DifferentHeight(
                self.block1.base.height,
                self.block2.base.height,
            )
            .into());
        }

        if height > blockchain.height() {
            return Err(SlashingError::InvalidProofHeight(height, blockchain.height()).into());
        }
        if height <= blockchain.last_macro_block_height() {
            return Err(SlashingError::InvalidProofEpoch(
                height,
                blockchain.last_macro_block_height(),
            )
            .into());
        }

        if self.block1.base.previous != self.block2.base.previous {
            return Err(SlashingError::DifferentHistory(
                self.block1.base.previous,
                self.block2.base.previous,
            )
            .into());
        }

        if self.block1.base.view_change != self.block2.base.view_change {
            return Err(SlashingError::DifferentLeader(
                self.block1.base.view_change,
                self.block2.base.view_change,
            )
            .into());
        }

        let block1_hash = Hash::digest(&self.block1);

        let block2_hash = Hash::digest(&self.block2);
        if block1_hash == block2_hash {
            return Err(SlashingError::BlockWithoutConflicts(height).into());
        }

        let election_result = blockchain.election_result_by_height(height)?;

        let ref leader_pk = election_result.select_leader(self.block1.base.view_change);

        pbc::check_hash(&block1_hash, &self.block1.sig, leader_pk)?;
        pbc::check_hash(&block2_hash, &self.block2.sig, leader_pk)?;
        Ok(())
    }
}

pub fn confiscate_tx(
    chain: &Blockchain,
    our_key: &pbc::PublicKey, // our key, used to add change to payment utxo.
    proof: SlashingProof,
) -> Result<SlashingTransaction, BlockchainError> {
    assert_eq!(proof.block1.pkey, proof.block2.pkey);
    let ref cheater = proof.block1.pkey;
    let (inputs, stake) = chain.staker_outputs(cheater);
    let validators: Vec<_> = chain
        .validators()
        .iter()
        .map(|(k, _v)| *k)
        .filter(|k| k != cheater)
        .collect();

    if validators.is_empty() {
        return Err(SlashingError::LastValidator(*cheater).into());
    }

    if inputs.is_empty() {
        return Err(SlashingError::NotValidator(*cheater).into());
    }

    proof.validate(&chain)?;
    assert!(stake > 0);
    let piece = stake / validators.len() as i64;
    let change = stake % validators.len() as i64;

    let mut rng = thread_rng();

    let mut outputs = Vec::new();
    for validator in &validators {
        let key = chain
            .validator_wallet(validator)
            .expect("validator has wallet key");
        let mut output = PublicPaymentOutput {
            recipient: key,
            serno: rng.gen(),
            amount: piece,
        };
        if validator == our_key {
            output.amount += change
        }
        outputs.push(output.into());
    }
    debug!("Creating confiscate transaction: cheater = {}, piece = {}, change = {}, num_validators = {}", cheater, piece, change, outputs.len());

    Ok(SlashingTransaction {
        proof,
        txins: inputs,
        txouts: outputs,
    })
}

impl Hashable for SlashingProof {
    fn hash(&self, state: &mut Hasher) {
        self.block1.hash(state);
        self.block2.hash(state);
    }
}

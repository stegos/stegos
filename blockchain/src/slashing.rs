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
use serde_derive::{Deserialize, Serialize};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        let epoch = self.block1.header.epoch;
        let offset = self.block1.header.offset;

        if self.block1.header.epoch != self.block2.header.epoch {
            return Err(SlashingError::DifferentEpoch(
                self.block1.header.epoch,
                self.block2.header.epoch,
            )
            .into());
        }

        if self.block1.header.offset != self.block2.header.offset {
            return Err(SlashingError::DifferentOffset(
                self.block1.header.offset,
                self.block2.header.offset,
            )
            .into());
        }

        if epoch != blockchain.epoch() {
            return Err(SlashingError::InvalidProofEpoch(epoch, blockchain.epoch()).into());
        }

        if self.block1.header.previous != self.block2.header.previous {
            return Err(SlashingError::DifferentHistory(
                self.block1.header.previous,
                self.block2.header.previous,
            )
            .into());
        }

        if self.block1.header.view_change != self.block2.header.view_change {
            return Err(SlashingError::DifferentLeader(
                self.block1.header.view_change,
                self.block2.header.view_change,
            )
            .into());
        }

        let block1_hash = Hash::digest(&self.block1);

        let block2_hash = Hash::digest(&self.block2);
        if block1_hash == block2_hash {
            return Err(SlashingError::BlockWithoutConflicts(epoch, offset, block1_hash).into());
        }

        let election_result = blockchain.election_result_by_offset(offset)?;

        let ref leader_pk = election_result.select_leader(self.block1.header.view_change);

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
    assert_eq!(proof.block1.header.pkey, proof.block2.header.pkey);
    let ref cheater = proof.block1.header.pkey;
    let epoch = chain.epoch();
    let (inputs, stake) = chain.iter_validator_stakes(cheater).fold(
        (Vec::<Hash>::new(), 0i64),
        |(mut result, mut stake), (hash, amount, _, active_until_epoch)| {
            if active_until_epoch >= epoch {
                stake += amount;
                result.push(hash.clone());
            }
            (result, stake)
        },
    );
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

    let mut outputs = Vec::new();
    for validator in &validators {
        let key = chain
            .account_by_network_key(validator)
            .expect("validator has account key");
        let mut output = PublicPaymentOutput::new(&key, piece);
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

//
// Copyright (c) 2019 Stegos AG
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

//!
//! View Changes implementation.
//!

use crate::error::ConsensusError;
use log::*;
use std::collections::HashMap;
use stegos_blockchain::view_changes::*;
use stegos_blockchain::{check_supermajority, Blockchain, ChainInfo, ValidatorId};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewChangeMessage {
    pub chain: ChainInfo,
    pub validator_id: ValidatorId,
    pub signature: pbc::Signature,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SealedViewChangeProof {
    pub chain: ChainInfo,
    pub proof: ViewChangeProof,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddressedViewChangeProof {
    pub view_change_proof: SealedViewChangeProof,
    pub pkey: pbc::PublicKey,
}

impl Hashable for ViewChangeMessage {
    fn hash(&self, state: &mut Hasher) {
        self.chain.hash(state);
        self.validator_id.hash(state);
        self.signature.hash(state);
    }
}

impl ViewChangeMessage {
    pub fn new(chain: ChainInfo, validator_id: ValidatorId, skey: &pbc::SecretKey) -> Self {
        let hash = Hash::digest(&chain);
        let signature = pbc::sign_hash(&hash, skey);
        ViewChangeMessage {
            chain,
            validator_id,
            signature,
        }
    }
}

#[derive(Debug)]
pub struct ViewChangeCollector {
    /// Keeps `ViewChangeMessage` for each validator,
    /// when message.view_change strict equal to our view_change.
    actual_view_changes: HashMap<ValidatorId, ViewChangeMessage>,
    collected_slots: i64,
    /// validator_id of current node.
    validator_id: ValidatorId,
    pkey: pbc::PublicKey,
    skey: pbc::SecretKey,
}

impl ViewChangeCollector {
    pub fn new(
        blockchain: &Blockchain,
        pkey: pbc::PublicKey,
        skey: pbc::SecretKey,
    ) -> ViewChangeCollector {
        // get validator id, by public_key
        let validator_id = blockchain
            .validators()
            .iter()
            .enumerate()
            .find(|(_id, validator)| validator.0 == pkey)
            .map(|(id, _)| id as ValidatorId)
            .expect("Node is not validator");
        ViewChangeCollector {
            pkey,
            skey,
            collected_slots: 0,
            validator_id,
            actual_view_changes: Default::default(),
        }
    }
    //
    // External events
    //
    pub fn handle_message(
        &mut self,
        blockchain: &Blockchain,
        message: ViewChangeMessage,
    ) -> Result<Option<ViewChangeProof>, ConsensusError> {
        // Check epoch.
        if message.chain.epoch != blockchain.epoch() {
            return Err(ConsensusError::InvalidViewChangeEpoch(
                message.chain.epoch,
                blockchain.epoch(),
            ));
        }

        // Check validator_id.
        let validator_id = message.validator_id;
        let validator_pkey = blockchain
            .validator_key_by_id(validator_id as usize)
            .ok_or(ConsensusError::InvalidValidatorId(validator_id))?;

        // Check signature.
        let hash = Hash::digest(&message.chain);
        if let Err(_e) = pbc::check_hash(&hash, &message.signature, &validator_pkey) {
            return Err(ConsensusError::InvalidViewChangeSignature);
        }

        // Check offset.
        if message.chain.offset < blockchain.offset() {
            return Err(ConsensusError::ViewChangeOffsetFromThePast(
                message.chain.offset,
                blockchain.offset(),
            ));
        } else if message.chain.offset > blockchain.offset() {
            return Err(ConsensusError::ViewChangeOffsetFromTheFuture(
                message.chain.offset,
                blockchain.offset(),
            ));
        }

        // Check the last block hash.
        if message.chain.last_block != blockchain.last_block_hash() {
            return Err(ConsensusError::InvalidLastBlockHash(
                message.chain.last_block,
                blockchain.last_block_hash(),
            ));
        }

        // Check the view change number.
        if message.chain.view_change < blockchain.view_change() {
            return Err(ConsensusError::ViewChangeNumberFromThePast(
                message.chain.view_change,
                blockchain.view_change(),
            ));
        } else if message.chain.view_change > blockchain.view_change() {
            return Err(ConsensusError::ViewChangeNumberFromTheFuture(
                message.chain.view_change,
                blockchain.view_change(),
            ));
        }

        info!(
            "Received a valid view_change message: view_change={}, validator={},",
            message.chain.view_change, validator_pkey
        );
        if self.actual_view_changes.get(&validator_id).is_none() {
            self.actual_view_changes
                .insert(validator_id, message.clone());
            self.collected_slots += blockchain.validators()[validator_id as usize].1;
        }
        info!(
            "Collected view_changes: collected={}, total={},",
            self.collected_slots,
            blockchain.total_slots()
        );
        // return proof only about first 2/3rd of validators
        if check_supermajority(self.collected_slots, blockchain.total_slots()) {
            let signatures = self
                .actual_view_changes
                .iter()
                .map(|(k, v)| (*k, &v.signature));
            let proof = ViewChangeProof::new(signatures, blockchain.validators().len());
            self.actual_view_changes.clear();
            self.collected_slots = 0;
            return Ok(Some(proof));
        }
        Ok(None)
    }

    /// Handle block timeout, starting mooving to the next view change.
    pub fn handle_timeout(&self, chain_info: ChainInfo) -> ViewChangeMessage {
        // on timeout, create view change message.
        ViewChangeMessage::new(chain_info, self.validator_id, &self.skey)
    }
}

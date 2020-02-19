//! Protobuf Definitions.

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

#![allow(bare_trait_objects)]

use stegos_blockchain::protos::*;
use stegos_consensus::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use crate::optimistic::{AddressedViewChangeProof, SealedViewChangeProof, ViewChangeMessage};
use crate::storage::{
    Awards, AwardsInfo, Balance, ChainInfo, EpochInfo, EscrowKey, EscrowValue, OutputKey,
    PayoutInfo, ValidatorAwardState, ValidatorKeyInfo, LSN,
};
use failure::{format_err, Error};
use protobuf::RepeatedField;
use std::collections::BTreeMap;
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_blockchain::{Block, ElectionResult};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_serialization::traits::ProtoConvert;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RequestBlocks {
    pub epoch: u64,
}

impl Hashable for RequestBlocks {
    fn hash(&self, state: &mut Hasher) {
        self.epoch.hash(state);
    }
}

impl RequestBlocks {
    pub fn new(epoch: u64) -> RequestBlocks {
        Self { epoch }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseBlocks {
    pub blocks: Vec<Block>,
}

impl Hashable for ResponseBlocks {
    fn hash(&self, state: &mut Hasher) {
        for block in &self.blocks {
            block.hash(state);
        }
    }
}

impl ResponseBlocks {
    pub fn new(blocks: Vec<Block>) -> ResponseBlocks {
        Self { blocks }
    }
}

#[derive(Debug, Clone)]
pub enum ChainLoaderMessage {
    Request(RequestBlocks),
    Response(ResponseBlocks),
}

impl Hashable for ChainLoaderMessage {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ChainLoaderMessage::Request(r) => {
                "request".hash(state);
                r.hash(state)
            }
            ChainLoaderMessage::Response(r) => {
                "response".hash(state);
                r.hash(state)
            }
        }
    }
}

impl ProtoConvert for RequestBlocks {
    type Proto = loader::RequestBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::RequestBlocks::new();
        proto.set_epoch(self.epoch);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        Ok(RequestBlocks { epoch })
    }
}

impl ProtoConvert for ResponseBlocks {
    type Proto = loader::ResponseBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ResponseBlocks::new();
        let blocks: Vec<_> = self.blocks.iter().map(ProtoConvert::into_proto).collect();
        proto.set_blocks(RepeatedField::from_vec(blocks));
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let blocks: Result<Vec<_>, _> = proto
            .get_blocks()
            .iter()
            .map(ProtoConvert::from_proto)
            .collect();
        let blocks = blocks?;
        Ok(ResponseBlocks { blocks })
    }
}

impl ProtoConvert for ChainLoaderMessage {
    type Proto = loader::ChainLoaderMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ChainLoaderMessage::new();
        match self {
            ChainLoaderMessage::Request(r) => proto.set_request(r.into_proto()),
            ChainLoaderMessage::Response(r) => proto.set_response(r.into_proto()),
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let ref body = proto
            .body
            .as_ref()
            .ok_or_else(|| format_err!("No variants in ChainLoaderMessage found"))?;
        let chain_message = match body {
            loader::ChainLoaderMessage_oneof_body::request(ref r) => {
                ChainLoaderMessage::Request(RequestBlocks::from_proto(r)?)
            }
            loader::ChainLoaderMessage_oneof_body::response(ref r) => {
                ChainLoaderMessage::Response(ResponseBlocks::from_proto(r)?)
            }
        };
        Ok(chain_message)
    }
}

impl ProtoConvert for LSN {
    type Proto = storage::LSN;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = storage::LSN::new();
        msg.set_epoch(self.0);
        msg.set_offset(self.1);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        let offset = proto.get_offset();
        Ok(LSN(epoch, offset))
    }
}

impl ProtoConvert for OutputKey {
    type Proto = storage::OutputKey;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        match self {
            OutputKey::MacroBlock { epoch, output_id } => {
                let mut sub = storage::MacroBlockOutputKey::new();
                sub.set_epoch(*epoch);
                sub.set_output_id(*output_id);
                msg.set_macro_block(sub);
            }
            OutputKey::MicroBlock {
                epoch,
                offset,
                tx_id,
                txout_id,
            } => {
                let mut sub = storage::MicroBlockOutputKey::new();
                sub.set_epoch(*epoch);
                sub.set_offset(*offset);
                sub.set_tx_id(*tx_id);
                sub.set_txout_id(*txout_id);
                msg.set_micro_block(sub);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let data = match proto.key {
            Some(storage::OutputKey_oneof_key::macro_block(ref msg)) => {
                let epoch = msg.get_epoch();
                let output_id = msg.get_output_id();

                OutputKey::MacroBlock { epoch, output_id }
            }
            Some(storage::OutputKey_oneof_key::micro_block(ref msg)) => {
                let epoch = msg.get_epoch();
                let offset = msg.get_offset();
                let tx_id = msg.get_tx_id();
                let txout_id = msg.get_txout_id();
                OutputKey::MicroBlock {
                    epoch,
                    offset,
                    tx_id,
                    txout_id,
                }
            }
            None => {
                return Err(ProtoError::MissingField("key".to_string(), "key".to_string()).into());
            }
        };
        Ok(data)
    }
}

impl ProtoConvert for EscrowKey {
    type Proto = storage::EscrowKey;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_validator_pkey(self.validator_pkey.into_proto());
        msg.set_output_hash(self.output_hash.into_proto());
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let validator_pkey = ProtoConvert::from_proto(proto.get_validator_pkey())?;
        let output_hash = ProtoConvert::from_proto(proto.get_output_hash())?;

        Ok(Self {
            validator_pkey,
            output_hash,
        })
    }
}

impl ProtoConvert for EscrowValue {
    type Proto = storage::EscrowValue;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_account_pkey(self.account_pkey.into_proto());
        msg.set_active_until_epoch(self.active_until_epoch);
        msg.set_amount(self.amount);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let account_pkey = ProtoConvert::from_proto(proto.get_account_pkey())?;
        let active_until_epoch = proto.get_active_until_epoch();
        let amount = proto.get_amount();

        Ok(Self {
            account_pkey,
            active_until_epoch,
            amount,
        })
    }
}

impl ProtoConvert for ElectionResult {
    type Proto = storage::ElectionResult;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_random(self.random.into_proto());
        msg.set_view_change(self.view_change);
        for validator in &self.validators {
            let mut staker = blockchain::Staker::new();
            staker.set_network_pkey(validator.0.into_proto());
            staker.set_amount(validator.1);
            msg.stakers.push(staker)
        }
        msg.set_facilitator(self.facilitator.into_proto());
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let random = ProtoConvert::from_proto(proto.get_random())?;
        let view_change = proto.get_view_change();
        let facilitator = ProtoConvert::from_proto(proto.get_facilitator())?;

        let mut validators = Vec::new();
        for staker in &proto.stakers {
            validators.push((
                ProtoConvert::from_proto(staker.get_network_pkey())?,
                staker.get_amount(),
            ))
        }

        Ok(Self {
            random,
            view_change,
            facilitator,
            validators,
        })
    }
}

impl ProtoConvert for Balance {
    type Proto = storage::Balance;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_created(self.created.into_proto());
        msg.set_burned(self.burned.into_proto());
        msg.set_gamma(self.gamma.into_proto());
        msg.set_block_reward(self.block_reward);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let created = ProtoConvert::from_proto(proto.get_created())?;
        let burned = ProtoConvert::from_proto(proto.get_burned())?;
        let gamma = ProtoConvert::from_proto(proto.get_gamma())?;
        let block_reward = proto.get_block_reward();

        Ok(Self {
            created,
            burned,
            gamma,
            block_reward,
        })
    }
}

impl ProtoConvert for ValidatorKeyInfo {
    type Proto = storage::ValidatorKeyInfo;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_network_pkey(self.network_pkey.into_proto());
        msg.set_account_pkey(self.account_pkey.into_proto());
        msg.set_slots(self.slots);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let network_pkey = ProtoConvert::from_proto(proto.get_network_pkey())?;
        let account_pkey = ProtoConvert::from_proto(proto.get_account_pkey())?;
        let slots = proto.get_slots();

        Ok(Self {
            network_pkey,
            account_pkey,
            slots,
        })
    }
}

impl ProtoConvert for PayoutInfo {
    type Proto = storage::PayoutInfo;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_recipient(self.recipient.into_proto());
        msg.set_amount(self.amount);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = ProtoConvert::from_proto(proto.get_recipient())?;
        let amount = proto.get_amount();

        Ok(Self { recipient, amount })
    }
}

impl ProtoConvert for Awards {
    type Proto = storage::Awards;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_budget(self.budget);
        msg.set_difficulty(self.difficulty as u64);

        for (pk, s) in &self.validators_activity {
            match s {
                ValidatorAwardState::Active => {
                    let en = storage::Active::new();
                    let mut sub = storage::ValidatorAwardState::new();
                    sub.set_key(pk.into_proto());
                    sub.set_active(en);
                    msg.validators_activity.push(sub)
                }
                ValidatorAwardState::Failed { epoch, offset } => {
                    let mut en = storage::Failed::new();
                    en.set_epoch(*epoch);
                    en.set_offset(*offset);

                    let mut sub = storage::ValidatorAwardState::new();
                    sub.set_key(pk.into_proto());
                    sub.set_failed(en);
                    msg.validators_activity.push(sub)
                }
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let budget = proto.get_budget();
        let difficulty = proto.get_difficulty() as usize;

        let mut validators_activity = BTreeMap::new();

        for validator in &proto.validators_activity {
            let key = ProtoConvert::from_proto(validator.get_key())?;
            let data = match validator.enum_value {
                Some(storage::ValidatorAwardState_oneof_enum_value::active(ref _msg)) => {
                    ValidatorAwardState::Active
                }
                Some(storage::ValidatorAwardState_oneof_enum_value::failed(ref msg)) => {
                    let epoch = msg.get_epoch();
                    let offset = msg.get_offset();
                    ValidatorAwardState::Failed { epoch, offset }
                }
                None => {
                    return Err(ProtoError::MissingField(
                        "payload".to_string(),
                        "payload".to_string(),
                    )
                    .into());
                }
            };
            let _ = validators_activity.insert(key, data);
        }

        Ok(Self {
            budget,
            difficulty,
            validators_activity,
        })
    }
}

impl ProtoConvert for AwardsInfo {
    type Proto = storage::AwardsInfo;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_service_award_state(self.service_award_state.into_proto());
        if let Some(payout) = &self.payout {
            msg.set_payout(payout.into_proto());
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let service_award_state = ProtoConvert::from_proto(proto.get_service_award_state())?;
        let payout = if proto.has_payout() {
            Some(ProtoConvert::from_proto(proto.get_payout())?)
        } else {
            None
        };

        Ok(Self {
            payout,
            service_award_state,
        })
    }
}

impl ProtoConvert for EpochInfo {
    type Proto = storage::EpochInfo;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_facilitator(self.facilitator.into_proto());
        for validator in &self.validators {
            let validator = validator.into_proto();
            msg.validators.push(validator)
        }
        msg.set_awards(self.awards.into_proto());
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let facilitator = ProtoConvert::from_proto(proto.get_facilitator())?;
        let awards = ProtoConvert::from_proto(proto.get_awards())?;

        let mut validators = Vec::new();
        for validator in &proto.validators {
            let validator = ProtoConvert::from_proto(validator)?;
            validators.push(validator)
        }

        Ok(Self {
            facilitator,
            awards,
            validators,
        })
    }
}

impl ProtoConvert for ChainInfo {
    type Proto = view_changes::ChainInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_changes::ChainInfo::new();
        proto.set_epoch(self.epoch);
        proto.set_offset(self.offset);
        proto.set_last_block(self.last_block.into_proto());
        proto.set_view_change(self.view_change);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        let offset = proto.get_offset();
        let view_change = proto.get_view_change();
        let last_block = Hash::from_proto(proto.get_last_block())?;
        Ok(ChainInfo {
            epoch,
            offset,
            view_change,
            last_block,
        })
    }
}

impl ProtoConvert for ViewChangeMessage {
    type Proto = view_change::ViewChangeMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_change::ViewChangeMessage::new();
        proto.set_chain(self.chain.into_proto());
        proto.set_validator_id(self.validator_id);
        proto.set_signature(self.signature.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let chain = ChainInfo::from_proto(proto.get_chain())?;
        let validator_id = proto.get_validator_id();
        let signature = pbc::Signature::from_proto(proto.get_signature())?;

        Ok(ViewChangeMessage {
            chain,
            validator_id,
            signature,
        })
    }
}

impl ProtoConvert for SealedViewChangeProof {
    type Proto = view_change::SealedViewChangeProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_change::SealedViewChangeProof::new();
        proto.set_chain(self.chain.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let chain = ChainInfo::from_proto(proto.get_chain())?;
        let proof = ViewChangeProof::from_proto(proto.get_proof())?;

        Ok(SealedViewChangeProof { chain, proof })
    }
}

impl ProtoConvert for AddressedViewChangeProof {
    type Proto = view_change::AddressedViewChangeProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_change::AddressedViewChangeProof::new();
        proto.set_view_change_proof(self.view_change_proof.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let view_change_proof = SealedViewChangeProof::from_proto(proto.get_view_change_proof())?;
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;

        Ok(AddressedViewChangeProof {
            view_change_proof,
            pkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::escrow::EscrowValue;
    use crate::storage::{Balance, ChainInfo};
    use stegos_blockchain::ElectionResult;
    use stegos_crypto::hash::Hash;
    use stegos_crypto::scc;
    use stegos_crypto::scc::{Fr, Pt};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    /*
    #[test]
    fn message() {
        let message = PoolJoin { txins: Vec::<TXIN>::new(),
        ownsig: SchnorrSig::new() };
        roundtrip(&message);
    }

    #[test]
    fn pool_info() {
        let (_, pkey) = pbc::make_random_keys();
        let (_, pkey1) = pbc::make_random_keys();

        let session_id = Hash::digest(&1u64);
        let mut participants: Vec<pbc::PublicKey> = Vec::new();
        participants.push((pkey.clone(), Vec::new(), scc::SchnorrSig::new()));
        participants.push(pkey1);
        let pool = PoolInfo {
            participants,
            session_id,
        };
        roundtrip(&pool);
    }
    */

    #[test]
    fn chain_loader() {
        let request = ChainLoaderMessage::Request(RequestBlocks::new(1));
        roundtrip(&request);
    }

    #[test]
    fn roundtrip_lsn() {
        let lsn = LSN(23, 15);
        roundtrip_eq(&lsn);
    }

    #[test]
    fn roundtrip_output_key() {
        let key = OutputKey::MacroBlock {
            epoch: 12,
            output_id: 43,
        };
        roundtrip_eq(&key);
    }

    #[test]
    fn roundtrip_escrow_key() {
        let key = EscrowKey {
            validator_pkey: pbc::PublicKey::dum(),
            output_hash: Hash::digest("test"),
        };
        roundtrip_eq(&key);
    }

    #[test]
    fn roundtrip_escrow_value() {
        let value = EscrowValue {
            account_pkey: scc::PublicKey::from(scc::Pt::random()),
            active_until_epoch: 324,
            amount: 55,
        };
        roundtrip_eq(&value);
    }

    #[test]
    fn roundtrip_election_result() {
        let value = ElectionResult {
            random: pbc::VRF {
                rand: Hash::digest("bla"),
                proof: pbc::G1::generator(),
            },
            view_change: 43,
            validators: vec![(pbc::PublicKey::dum(), 1), (pbc::PublicKey::dum(), 15)],
            facilitator: pbc::PublicKey::dum(),
        };
        roundtrip_eq(&value);
    }
    #[test]
    fn roundtrip_balance() {
        let balance = Balance {
            created: Pt::random(),
            burned: Pt::random(),
            gamma: Fr::random(),
            block_reward: 6123,
        };
        roundtrip_eq(&balance);
    }

    #[test]
    fn roundtrip_epoch_info() {
        let key = ValidatorKeyInfo {
            network_pkey: pbc::PublicKey::dum(),
            account_pkey: scc::PublicKey::from(scc::Pt::random()),
            slots: 455,
        };
        roundtrip_eq(&key);

        let key2 = ValidatorKeyInfo {
            network_pkey: pbc::PublicKey::dum(),
            account_pkey: scc::PublicKey::from(scc::Pt::random()),
            slots: 56455,
        };
        roundtrip_eq(&key2);

        let info = PayoutInfo {
            amount: 756,
            recipient: scc::PublicKey::from(scc::Pt::random()),
        };
        roundtrip_eq(&info);

        let mut validators_activity = BTreeMap::new();
        validators_activity.insert(
            scc::PublicKey::from(scc::Pt::random()),
            ValidatorAwardState::Active,
        );
        validators_activity.insert(
            scc::PublicKey::from(scc::Pt::random()),
            ValidatorAwardState::Failed {
                epoch: 3,
                offset: 66,
            },
        );
        let awards = Awards {
            budget: 656,
            difficulty: 65,
            validators_activity,
        };
        roundtrip_eq(&awards);

        let awards_info = AwardsInfo {
            service_award_state: awards,
            payout: Some(info),
        };
        roundtrip_eq(&awards_info);
        let epoch_info = EpochInfo {
            validators: vec![key, key2],
            facilitator: pbc::PublicKey::dum(),
            awards: awards_info,
        };
        roundtrip_eq(&epoch_info);
    }

    #[test]
    fn view_change() {
        let (skey0, _pkey0) = pbc::make_random_keys();

        let chain = ChainInfo {
            epoch: 41,
            offset: 48,
            view_change: 12,
            last_block: Hash::digest("test"),
        };
        let view_change_vote = ViewChangeMessage::new(chain, 1, &skey0);
        roundtrip(&view_change_vote);
    }
}

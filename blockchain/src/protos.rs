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

use crate::transaction::PaymentTransaction;
use crate::view_changes::*;
use crate::*;
use failure::{Error, Fail};
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::{Fr, Pt, PublicKey, SchnorrSig};
use stegos_serialization::traits::*;

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Missing field '{}' in packet '{}'.", _1, _0)]
    MissingField(String, String),
    #[fail(display = "Duplicate value in field '{}'.", _0)]
    DuplicateValue(String),
    #[fail(display = "Invalid canary length: expected={}, got={}", _0, _1)]
    InvalidCanaryLength(usize, usize),
}

// link protobuf dependencies
use crate::awards::Awards;
use bit_vec::BitVec;
use std::collections::BTreeMap;
use std::iter::FromIterator;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for LSN {
    type Proto = blockchain::LSN;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = blockchain::LSN::new();
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
    type Proto = blockchain::OutputKey;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        match self {
            OutputKey::MacroBlock { epoch, output_id } => {
                let mut sub = blockchain::MacroBlockOutputKey::new();
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
                let mut sub = blockchain::MicroBlockOutputKey::new();
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
            Some(blockchain::OutputKey_oneof_key::macro_block(ref msg)) => {
                let epoch = msg.get_epoch();
                let output_id = msg.get_output_id();

                OutputKey::MacroBlock { epoch, output_id }
            }
            Some(blockchain::OutputKey_oneof_key::micro_block(ref msg)) => {
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
    type Proto = blockchain::EscrowKey;

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
    type Proto = blockchain::EscrowValue;

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
    type Proto = blockchain::ElectionResult;

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
    type Proto = blockchain::Balance;

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
    type Proto = blockchain::ValidatorKeyInfo;

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
    type Proto = blockchain::PayoutInfo;

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
    type Proto = blockchain::Awards;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_budget(self.budget);
        msg.set_difficulty(self.difficulty as u64);

        for (pk, s) in &self.validators_activity {
            match s {
                ValidatorAwardState::Active => {
                    let en = blockchain::Active::new();
                    let mut sub = blockchain::ValidatorAwardState::new();
                    sub.set_key(pk.into_proto());
                    sub.set_active(en);
                    msg.validators_activity.push(sub)
                }
                ValidatorAwardState::Failed { epoch, offset } => {
                    let mut en = blockchain::Failed::new();
                    en.set_epoch(*epoch);
                    en.set_offset(*offset);

                    let mut sub = blockchain::ValidatorAwardState::new();
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
                Some(blockchain::ValidatorAwardState_oneof_enum_value::active(ref _msg)) => {
                    ValidatorAwardState::Active
                }
                Some(blockchain::ValidatorAwardState_oneof_enum_value::failed(ref msg)) => {
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
    type Proto = blockchain::AwardsInfo;

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
    type Proto = blockchain::EpochInfo;

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

impl ProtoConvert for LightEpochInfo {
    type Proto = blockchain::LightEpochInfo;

    fn into_proto(&self) -> Self::Proto {
        let mut msg = Self::Proto::new();
        msg.set_header(self.header.into_proto());
        msg.set_facilitator(self.facilitator.into_proto());
        for validator in &self.validators {
            let mut validator_proto = blockchain::Staker::new();
            validator_proto.set_network_pkey(validator.0.into_proto());
            validator_proto.set_amount(validator.1);
            msg.validators.push(validator_proto)
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MacroBlockHeader::from_proto(proto.get_header())?;
        let facilitator = ProtoConvert::from_proto(proto.get_facilitator())?;
        let mut validators = Vec::new();
        for validator in &proto.validators {
            validators.push((
                ProtoConvert::from_proto(validator.get_network_pkey())?,
                validator.get_amount(),
            ))
        }

        Ok(Self {
            header,
            facilitator,
            validators,
        })
    }
}

impl ProtoConvert for PaymentPayloadData {
    type Proto = blockchain::PaymentPayloadData;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = blockchain::PaymentPayloadData::new();
        match self {
            PaymentPayloadData::Comment(ref s) => {
                msg.set_comment(s.clone());
            }
            PaymentPayloadData::ContentHash(ref h) => {
                msg.set_hash(h.into_proto());
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let data = match proto.data {
            Some(blockchain::PaymentPayloadData_oneof_data::comment(ref msg)) => {
                PaymentPayloadData::Comment(msg.clone())
            }
            Some(blockchain::PaymentPayloadData_oneof_data::hash(ref msg)) => {
                let hash = Hash::from_proto(msg)?;
                PaymentPayloadData::ContentHash(hash)
            }
            None => {
                return Err(
                    ProtoError::MissingField("payload".to_string(), "payload".to_string()).into(),
                );
            }
        };
        Ok(data)
    }
}

impl ProtoConvert for PaymentOutput {
    type Proto = blockchain::PaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_ag(self.ag.into_proto());
        proto.set_payload(self.payload.clone());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let ag = Pt::from_proto(proto.get_ag())?;
        let payload = proto.get_payload().to_vec();
        Ok(PaymentOutput {
            recipient,
            proof,
            ag,
            payload,
        })
    }
}

impl ProtoConvert for PaymentCanary {
    type Proto = blockchain::PaymentCanary;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentCanary::new();
        proto.set_ag(self.ag.into_proto());
        proto.set_canary(self.canary.to_vec());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let ag = Pt::from_proto(proto.get_ag())?;
        let canary_vec = proto.get_canary().to_vec();
        if canary_vec.len() != PAYMENT_PAYLOAD_CANARY_LEN {
            return Err(ProtoError::InvalidCanaryLength(
                PAYMENT_PAYLOAD_CANARY_LEN,
                canary_vec.len(),
            )
            .into());
        }
        let mut canary = [0u8; PAYMENT_PAYLOAD_CANARY_LEN];
        canary.copy_from_slice(&canary_vec);
        Ok(PaymentCanary { ag, canary })
    }
}

impl ProtoConvert for PublicPaymentOutput {
    type Proto = blockchain::PublicPaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PublicPaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_amount(self.amount);
        proto.set_serno(self.serno);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let amount = proto.get_amount();
        let serno = proto.get_serno();
        Ok(PublicPaymentOutput {
            recipient,
            amount,
            serno,
        })
    }
}

impl ProtoConvert for PublicPaymentCanary {
    type Proto = blockchain::PublicPaymentCanary;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PublicPaymentCanary::new();
        proto.set_recipient(self.recipient.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        Ok(PublicPaymentCanary { recipient })
    }
}

impl ProtoConvert for StakeOutput {
    type Proto = blockchain::StakeOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::StakeOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_validator(self.validator.into_proto());
        proto.set_amount(self.amount);
        proto.set_serno(self.serno);
        proto.set_signature(self.signature.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let validator = pbc::PublicKey::from_proto(proto.get_validator())?;
        let amount = proto.get_amount();
        let serno = proto.get_serno();
        let signature = pbc::Signature::from_proto(proto.get_signature())?;
        Ok(StakeOutput {
            recipient,
            validator,
            amount,
            serno,
            signature,
        })
    }
}

impl ProtoConvert for StakeCanary {
    type Proto = blockchain::StakeCanary;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::StakeCanary::new();
        proto.set_recipient(self.recipient.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        Ok(StakeCanary { recipient })
    }
}

impl ProtoConvert for Output {
    type Proto = blockchain::Output;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Output::new();
        match self {
            Output::PaymentOutput(output) => proto.set_payment_output(output.into_proto()),
            Output::PublicPaymentOutput(output) => {
                proto.set_public_payment_output(output.into_proto())
            }
            Output::StakeOutput(output) => proto.set_stake_output(output.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.output {
            Some(blockchain::Output_oneof_output::payment_output(ref output)) => {
                let output = PaymentOutput::from_proto(output)?;
                Ok(Output::PaymentOutput(output))
            }
            Some(blockchain::Output_oneof_output::public_payment_output(ref output)) => {
                let output = PublicPaymentOutput::from_proto(output)?;
                Ok(Output::PublicPaymentOutput(output))
            }
            Some(blockchain::Output_oneof_output::stake_output(ref output)) => {
                let output = StakeOutput::from_proto(output)?;
                Ok(Output::StakeOutput(output))
            }
            None => {
                Err(ProtoError::MissingField("output".to_string(), "output".to_string()).into())
            }
        }
    }
}

impl ProtoConvert for Canary {
    type Proto = blockchain::Canary;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Canary::new();
        match self {
            Canary::PaymentCanary(canary) => proto.set_payment_canary(canary.into_proto()),
            Canary::PublicPaymentCanary(canary) => {
                proto.set_public_payment_canary(canary.into_proto())
            }
            Canary::StakeCanary(canary) => proto.set_stake_canary(canary.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.canary {
            Some(blockchain::Canary_oneof_canary::payment_canary(ref canary)) => {
                let canary = PaymentCanary::from_proto(canary)?;
                Ok(Canary::PaymentCanary(canary))
            }
            Some(blockchain::Canary_oneof_canary::public_payment_canary(ref canary)) => {
                let canary = PublicPaymentCanary::from_proto(canary)?;
                Ok(Canary::PublicPaymentCanary(canary))
            }
            Some(blockchain::Canary_oneof_canary::stake_canary(ref canary)) => {
                let canary = StakeCanary::from_proto(canary)?;
                Ok(Canary::StakeCanary(canary))
            }
            None => {
                Err(ProtoError::MissingField("canary".to_string(), "canary".to_string()).into())
            }
        }
    }
}

impl ProtoConvert for CoinbaseTransaction {
    type Proto = blockchain::CoinbaseTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::CoinbaseTransaction::new();
        proto.set_block_reward(self.block_reward);
        proto.set_block_fee(self.block_fee);
        proto.set_gamma(self.gamma.into_proto());
        for output in &self.txouts {
            proto.txouts.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block_reward = proto.get_block_reward();
        let block_fee = proto.get_block_fee();
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for output in proto.txouts.iter() {
            txouts.push(Output::from_proto(output)?);
        }
        Ok(CoinbaseTransaction {
            block_reward,
            block_fee,
            gamma,
            txouts,
        })
    }
}

impl ProtoConvert for PaymentTransaction {
    type Proto = blockchain::PaymentTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentTransaction::new();

        for txin in &self.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_gamma(self.gamma.into_proto());
        proto.set_fee(self.fee);
        proto.set_sig(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let fee = proto.get_fee();
        let sig = SchnorrSig::from_proto(proto.get_sig())?;

        Ok(PaymentTransaction {
            txins,
            txouts,
            gamma,
            fee,
            sig,
        })
    }
}

impl ProtoConvert for RestakeTransaction {
    type Proto = blockchain::RestakeTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::RestakeTransaction::new();

        for txin in &self.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_signature(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let sig = pbc::Signature::from_proto(proto.get_signature())?;

        Ok(RestakeTransaction { txins, txouts, sig })
    }
}

impl ProtoConvert for ServiceAwardTransaction {
    type Proto = blockchain::ServiceAwardTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::ServiceAwardTransaction::new();
        for txout in &self.winner_reward {
            proto.winner_reward.push(txout.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut winner_reward = Vec::<Output>::with_capacity(proto.winner_reward.len());
        for txout in proto.winner_reward.iter() {
            winner_reward.push(Output::from_proto(txout)?);
        }
        Ok(ServiceAwardTransaction { winner_reward })
    }
}

impl ProtoConvert for SlashingTransaction {
    type Proto = blockchain::SlashingTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::SlashingTransaction::new();
        proto.set_proof(self.proof.into_proto());
        for txin in &self.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let proof = SlashingProof::from_proto(proto.get_proof())?;
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }

        Ok(SlashingTransaction {
            proof,
            txins,
            txouts,
        })
    }
}
impl ProtoConvert for Transaction {
    type Proto = blockchain::Transaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Transaction::new();
        match self {
            Transaction::CoinbaseTransaction(coinbase_transaction) => {
                proto.set_coinbase_transaction(coinbase_transaction.into_proto())
            }
            Transaction::PaymentTransaction(payment_transaction) => {
                proto.set_payment_transaction(payment_transaction.into_proto())
            }
            Transaction::RestakeTransaction(restake_transaction) => {
                proto.set_restake_transaction(restake_transaction.into_proto())
            }
            Transaction::SlashingTransaction(slashing_transaction) => {
                proto.set_slashing_transaction(slashing_transaction.into_proto())
            }
            Transaction::ServiceAwardTransaction(service_reward_transaction) => {
                proto.set_service_reward_transaction(service_reward_transaction.into_proto())
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let transaction = match proto.transaction {
            Some(blockchain::Transaction_oneof_transaction::coinbase_transaction(
                ref coinbase_transaction,
            )) => {
                let coinbase_transaction = CoinbaseTransaction::from_proto(coinbase_transaction)?;
                Transaction::CoinbaseTransaction(coinbase_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::payment_transaction(
                ref payment_transaction,
            )) => {
                let payment_transaction = PaymentTransaction::from_proto(payment_transaction)?;
                Transaction::PaymentTransaction(payment_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::restake_transaction(
                ref restake_transaction,
            )) => {
                let restake_transaction = RestakeTransaction::from_proto(restake_transaction)?;
                Transaction::RestakeTransaction(restake_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::slashing_transaction(
                ref slashing_transaction,
            )) => {
                let slashing_transaction = SlashingTransaction::from_proto(slashing_transaction)?;
                Transaction::SlashingTransaction(slashing_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::service_reward_transaction(
                ref service_reward_transaction,
            )) => {
                let service_reward_transaction =
                    ServiceAwardTransaction::from_proto(service_reward_transaction)?;
                Transaction::ServiceAwardTransaction(service_reward_transaction)
            }
            None => {
                return Err(ProtoError::MissingField(
                    "transaction".to_string(),
                    "transaction".to_string(),
                )
                .into());
            }
        };
        Ok(transaction)
    }
}

impl ProtoConvert for MicroBlockHeader {
    type Proto = blockchain::MicroBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlockHeader::new();
        proto.set_version(self.version);
        proto.set_previous(self.previous.into_proto());
        proto.set_epoch(self.epoch);
        proto.set_offset(self.offset);
        proto.set_view_change(self.view_change);
        if let Some(view_change_proof) = &self.view_change_proof {
            proto.set_view_change_proof(view_change_proof.into_proto())
        }
        proto.set_pkey(self.pkey.into_proto());
        proto.set_random(self.random.into_proto());
        proto.set_solution(self.solution.clone());
        let timestamp: u64 = self.timestamp.into();
        proto.set_timestamp(timestamp);
        proto.set_transactions_len(self.transactions_len);
        proto.set_transactions_range_hash(self.transactions_range_hash.into_proto());
        proto.set_inputs_len(self.inputs_len);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_len(self.outputs_len);
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        proto.set_canaries_range_hash(self.canaries_range_hash.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let epoch = proto.get_epoch();
        let offset = proto.get_offset();
        let view_change = proto.get_view_change();
        let view_change_proof = if proto.has_view_change_proof() {
            Some(ViewChangeProof::from_proto(proto.get_view_change_proof())?)
        } else {
            None
        };
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        let random = pbc::VRF::from_proto(proto.get_random())?;
        let solution = proto.get_solution().to_vec();
        let timestamp: Timestamp = proto.get_timestamp().into();
        let transactions_len = proto.get_transactions_len();
        let transactions_range_hash = Hash::from_proto(proto.get_transactions_range_hash())?;
        let inputs_len = proto.get_inputs_len();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_len = proto.get_outputs_len();
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;
        let canaries_range_hash = Hash::from_proto(proto.get_canaries_range_hash())?;
        Ok(MicroBlockHeader {
            version,
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
        })
    }
}

impl ProtoConvert for MicroBlock {
    type Proto = blockchain::MicroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_sig(self.sig.into_proto());
        for transaction in &self.transactions {
            proto.transactions.push(transaction.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MicroBlockHeader::from_proto(proto.get_header())?;
        let sig = if proto.has_sig() {
            pbc::Signature::from_proto(proto.get_sig())?
        } else {
            pbc::Signature::zero()
        };
        let mut transactions = Vec::<Transaction>::with_capacity(proto.transactions.len());
        for transaction in proto.transactions.iter() {
            transactions.push(Transaction::from_proto(transaction)?);
        }
        Ok(MicroBlock {
            header,
            sig,
            transactions,
        })
    }
}

impl ProtoConvert for LightMicroBlock {
    type Proto = blockchain::LightMicroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::LightMicroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_sig(self.sig.into_proto());
        for input_hash in &self.input_hashes {
            proto.input_hashes.push(input_hash.into_proto());
        }
        for output_hash in &self.output_hashes {
            proto.output_hashes.push(output_hash.into_proto());
        }
        for canary in &self.canaries {
            proto.canaries.push(canary.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MicroBlockHeader::from_proto(proto.get_header())?;
        let sig = pbc::Signature::from_proto(proto.get_sig())?;
        let mut input_hashes = Vec::<Hash>::with_capacity(proto.input_hashes.len());
        for input_hash in proto.input_hashes.iter() {
            input_hashes.push(Hash::from_proto(input_hash)?);
        }
        let mut output_hashes = Vec::<Hash>::with_capacity(proto.output_hashes.len());
        for output in proto.output_hashes.iter() {
            output_hashes.push(Hash::from_proto(output)?);
        }
        let mut canaries = Vec::with_capacity(proto.canaries.len());
        for canary in proto.canaries.iter() {
            canaries.push(Canary::from_proto(canary)?);
        }
        Ok(LightMicroBlock {
            header,
            sig,
            input_hashes,
            output_hashes,
            canaries,
        })
    }
}

impl ProtoConvert for MacroBlockHeader {
    type Proto = blockchain::MacroBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlockHeader::new();
        proto.set_version(self.version);
        proto.set_previous(self.previous.into_proto());
        proto.set_epoch(self.epoch);
        proto.set_view_change(self.view_change);
        proto.set_pkey(self.pkey.into_proto());
        proto.set_random(self.random.into_proto());
        proto.set_difficulty(self.difficulty);
        proto.set_timestamp(self.timestamp.into());
        proto.set_block_reward(self.block_reward);
        proto.set_gamma(self.gamma.into_proto());
        proto.activity_map.extend(self.activity_map.iter());
        proto.set_validators_len(self.validators_len);
        proto.set_validators_range_hash(self.validators_range_hash.into_proto());
        proto.set_inputs_len(self.inputs_len);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_len(self.outputs_len);
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        proto.set_canaries_range_hash(self.canaries_range_hash.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let epoch = proto.get_epoch();
        let view_change = proto.get_view_change();
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        let random = pbc::VRF::from_proto(proto.get_random())?;
        let difficulty = proto.get_difficulty();
        let timestamp = proto.get_timestamp().into();
        let block_reward = proto.get_block_reward();
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let activity_map = BitVec::from_iter(proto.activity_map.iter().map(|x| *x));
        let validators_len = proto.get_validators_len();
        let validators_range_hash = Hash::from_proto(proto.get_validators_range_hash())?;
        let inputs_len = proto.get_inputs_len();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_len = proto.get_outputs_len();
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;
        let canaries_range_hash = Hash::from_proto(proto.get_canaries_range_hash())?;
        Ok(MacroBlockHeader {
            version,
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
        })
    }
}

impl ProtoConvert for MacroBlock {
    type Proto = blockchain::MacroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_multisig(self.multisig.into_proto());
        proto.multisigmap.extend(self.multisigmap.iter());
        for input in &self.inputs {
            proto.inputs.push(input.into_proto());
        }
        for output in &self.outputs {
            proto.outputs.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MacroBlockHeader::from_proto(proto.get_header())?;
        let multisig = if proto.has_multisig() {
            pbc::Signature::from_proto(proto.get_multisig())?
        } else {
            pbc::Signature::zero()
        };
        let multisigmap = BitVec::from_iter(proto.multisigmap.iter().map(|x| *x));

        let mut inputs = Vec::<Hash>::with_capacity(proto.inputs.len());
        for input in proto.inputs.iter() {
            inputs.push(Hash::from_proto(input)?);
        }

        let mut outputs = Vec::with_capacity(proto.outputs.len());
        for output in proto.outputs.iter() {
            outputs.push(Output::from_proto(output)?);
        }

        Ok(MacroBlock {
            header,
            multisig,
            multisigmap,
            inputs,
            outputs,
        })
    }
}

impl ProtoConvert for LightMacroBlock {
    type Proto = blockchain::LightMacroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::LightMacroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_multisig(self.multisig.into_proto());
        proto.multisigmap.extend(self.multisigmap.iter());
        for validator in &self.validators {
            let mut staker = blockchain::Staker::new();
            staker.set_network_pkey(validator.0.into_proto());
            staker.set_amount(validator.1);
            proto.validators.push(staker)
        }
        for input_hash in &self.input_hashes {
            proto.input_hashes.push(input_hash.into_proto());
        }
        for output_hash in &self.output_hashes {
            proto.output_hashes.push(output_hash.into_proto());
        }
        for canary in &self.canaries {
            proto.canaries.push(canary.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MacroBlockHeader::from_proto(proto.get_header())?;
        let multisig = if proto.has_multisig() {
            pbc::Signature::from_proto(proto.get_multisig())?
        } else {
            pbc::Signature::zero()
        };
        let multisigmap = BitVec::from_iter(proto.multisigmap.iter().map(|x| *x));
        let mut validators = Vec::new();
        for staker in &proto.validators {
            validators.push((
                ProtoConvert::from_proto(staker.get_network_pkey())?,
                staker.get_amount(),
            ))
        }
        let mut input_hashes = Vec::<Hash>::with_capacity(proto.input_hashes.len());
        for input_hash in proto.input_hashes.iter() {
            input_hashes.push(Hash::from_proto(input_hash)?);
        }
        let mut output_hashes = Vec::<Hash>::with_capacity(proto.output_hashes.len());
        for output in proto.output_hashes.iter() {
            output_hashes.push(Hash::from_proto(output)?);
        }
        let mut canaries = Vec::with_capacity(proto.canaries.len());
        for canary in proto.canaries.iter() {
            canaries.push(Canary::from_proto(canary)?);
        }
        Ok(LightMacroBlock {
            header,
            multisig,
            multisigmap,
            validators,
            input_hashes,
            output_hashes,
            canaries,
        })
    }
}

impl ProtoConvert for Block {
    type Proto = blockchain::Block;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Block::new();
        match self {
            Block::MacroBlock(macro_block) => proto.set_macro_block(macro_block.into_proto()),
            Block::MicroBlock(micro_block) => proto.set_micro_block(micro_block.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = match proto.block {
            Some(blockchain::Block_oneof_block::macro_block(ref macro_block)) => {
                let macro_block = MacroBlock::from_proto(macro_block)?;
                Block::MacroBlock(macro_block)
            }
            Some(blockchain::Block_oneof_block::micro_block(ref micro_block)) => {
                let micro_block = MicroBlock::from_proto(micro_block)?;
                Block::MicroBlock(micro_block)
            }
            None => {
                return Err(
                    ProtoError::MissingField("block".to_string(), "block".to_string()).into(),
                );
            }
        };
        Ok(block)
    }
}

impl ProtoConvert for LightBlock {
    type Proto = blockchain::LightBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::LightBlock::new();
        match self {
            LightBlock::LightMacroBlock(macro_block) => {
                proto.set_light_macro_block(macro_block.into_proto())
            }
            LightBlock::LightMicroBlock(micro_block) => {
                proto.set_light_micro_block(micro_block.into_proto())
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = match proto.block {
            Some(blockchain::LightBlock_oneof_block::light_macro_block(ref macro_block)) => {
                let macro_block = LightMacroBlock::from_proto(macro_block)?;
                LightBlock::LightMacroBlock(macro_block)
            }
            Some(blockchain::LightBlock_oneof_block::light_micro_block(ref micro_block)) => {
                let micro_block = LightMicroBlock::from_proto(micro_block)?;
                LightBlock::LightMicroBlock(micro_block)
            }
            None => {
                return Err(
                    ProtoError::MissingField("block".to_string(), "block".to_string()).into(),
                );
            }
        };
        Ok(block)
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

impl ProtoConvert for ViewChangeProof {
    type Proto = view_changes::ViewChangeProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_changes::ViewChangeProof::new();
        if !self.multisig.is_zero() {
            proto.set_multisig(self.multisig.into_proto());
        }
        proto.multimap.extend(self.multimap.iter());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let multisig = if proto.has_multisig() {
            pbc::Signature::from_proto(proto.get_multisig())?
        } else {
            pbc::Signature::zero()
        };
        let multimap = BitVec::from_iter(proto.multimap.iter().map(|x| *x));
        Ok(ViewChangeProof { multisig, multimap })
    }
}

impl ProtoConvert for SlashingProof {
    type Proto = blockchain::SlashingProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::SlashingProof::new();
        proto.set_block1(self.block1.into_proto());
        proto.set_block2(self.block2.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block1 = MicroBlock::from_proto(proto.get_block1())?;
        let block2 = MicroBlock::from_proto(proto.get_block2())?;
        Ok(SlashingProof { block1, block2 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::Timestamp;
    use stegos_crypto::hash::{Hash, Hashable};
    use stegos_crypto::scc;
    use stegos_crypto::{init_test_network_prefix, pbc};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    fn roundtrip_eq<T>(x: &T) -> T
    where
        T: ProtoConvert + Eq + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(x, &r);
        r
    }

    #[test]
    fn outputs() {
        let (_skey1, pkey1) = scc::make_random_keys();
        let (network_skey1, network_pkey1) = pbc::make_random_keys();

        let amount = 1_000_000;

        let (output, _gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        roundtrip(&output);
        roundtrip(&output.canary());

        let output: Output = PublicPaymentOutput::new(&pkey1, amount).into();
        roundtrip(&output);
        roundtrip(&output.canary());

        let output = Output::new_stake(&pkey1, &network_skey1, &network_pkey1, amount)
            .expect("keys are valid");
        roundtrip(&output);
        roundtrip(&output.canary());

        let mut buf = output.into_buffer().unwrap();
        buf.pop();
        Output::from_buffer(&buf).expect_err("error");
    }

    fn mktransaction() -> PaymentTransaction {
        let (skey1, pkey1) = scc::make_random_keys();
        let (_skey2, pkey2) = scc::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _gamma0) = Output::new_payment(&pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) = Output::new_payment(&pkey2, amount).expect("keys are valid");

        roundtrip(&output11);
        roundtrip(&gamma11);

        let outputs_gamma = gamma11;

        let tx = PaymentTransaction::new(&skey1, &inputs1, &[output11], &outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs1).unwrap();

        let tx2 = roundtrip(&tx);
        tx2.validate(&inputs1).unwrap();

        tx
    }

    #[test]
    fn coinbase_transaction() {
        let (_skey, pkey) = scc::make_random_keys();

        let (output, gamma) = Output::new_payment(&pkey, 100).expect("Invalid keys");
        let coinbase = CoinbaseTransaction {
            block_reward: 15,
            block_fee: 100,
            gamma: -gamma,
            txouts: vec![output],
        };
        roundtrip(&coinbase);
    }

    #[test]
    fn public_payment_utxo() {
        let (_skey, pkey) = scc::make_random_keys();
        let output = PublicPaymentOutput::new(&pkey, 100);

        roundtrip(&output);
        let output: Output = output.into();
        roundtrip(&output);

        let output = PublicPaymentOutput::new_locked(&pkey, 100);

        roundtrip(&output);
        let output: Output = output.into();
        roundtrip(&output);
    }

    #[test]
    fn payment_transaction() {
        let tx = mktransaction();
        roundtrip(&tx);
        let tx: Transaction = tx.into();
        roundtrip(&tx);

        let mut buf = tx.into_buffer().unwrap();
        buf.pop();
        PaymentTransaction::from_buffer(&buf).expect_err("error");
    }

    #[test]
    fn micro_blocks() {
        init_test_network_prefix();
        let (skey, pkey) = scc::make_random_keys();
        let (skeypbc, pkeypbc) = pbc::make_random_keys();

        let epoch: u64 = 10;
        let timestamp = Timestamp::now();
        let view_change = 15;
        let previous = Hash::digest(&"test".to_string());
        let offset = 20;
        let seed = mix(Hash::digest("random"), view_change);
        let random = pbc::make_VRF(&skeypbc, &seed);
        let solution = vec![1u8, 2, 3, 4];

        // View Changes Proof.
        let sig = pbc::sign_hash(&previous, &skeypbc);
        let signatures = vec![(0u32, &sig)];
        let view_change_proof = Some(ViewChangeProof::new(signatures.into_iter(), 1));

        // Transactions.
        let (tx, _inputs, _outputs) =
            PaymentTransaction::new_test(&skey, &pkey, 300, 2, 100, 1, 100)
                .expect("Invalid transaction");
        let transactions: Vec<Transaction> = vec![tx.into()];

        let mut block = MicroBlock::new(
            previous,
            epoch,
            offset,
            view_change,
            view_change_proof,
            pkeypbc,
            random,
            solution,
            timestamp,
            transactions,
        );
        roundtrip(&block.header);
        block.sign(&skeypbc, &pkeypbc);
        let block2 = roundtrip(&block);
        assert_eq!(block, block2);

        let light_block = block.clone().into_light_micro_block();
        let light_block2 = roundtrip(&light_block);
        assert_eq!(light_block2, light_block);

        let block = Block::MicroBlock(block);
        let block2 = roundtrip(&block);
        assert_eq!(block, block2);

        let block_json = serde_json::to_string(&block).unwrap();
        let block3: Block = serde_json::from_str(&block_json).unwrap();
        assert_eq!(block, block3);

        let light_block = LightBlock::LightMicroBlock(light_block);
        let light_block2 = roundtrip(&light_block);
        assert_eq!(light_block, light_block2);

        let light_block_json = serde_json::to_string(&light_block).unwrap();
        let light_block3: LightBlock = serde_json::from_str(&light_block_json).unwrap();
        assert_eq!(light_block, light_block3);
    }

    #[test]
    fn macro_blocks() {
        init_test_network_prefix();
        let (_skey1, pkey1) = scc::make_random_keys();
        let (_skey2, pkey2) = scc::make_random_keys();
        let (skeypbc, pkeypbc) = pbc::make_random_keys();

        let epoch: u64 = 10;
        let timestamp = Timestamp::now();
        let view_change = 15;
        let amount: i64 = 1_000_000;
        let block_reward = 1000;
        let activity_map = BitVec::new();
        let previous = Hash::digest(&"test".to_string());

        // "genesis" output by 0
        let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();

        // Transaction from 1 to 2
        let inputs1 = vec![Hash::digest(&output0)];
        let (output1, gamma1) = Output::new_payment(&pkey2, amount).unwrap();
        let outputs1 = vec![output1];
        let gamma = gamma0 - gamma1;

        let seed = mix(Hash::digest("random"), view_change);
        let random = pbc::make_VRF(&skeypbc, &seed);
        let difficulty = 100500u64;
        let validators = vec![(pkeypbc.clone(), 100500i64)];

        let block = MacroBlock::new(
            previous,
            epoch,
            view_change,
            pkeypbc,
            random,
            difficulty,
            timestamp,
            block_reward,
            gamma,
            activity_map,
            validators.clone(),
            inputs1,
            outputs1,
        );
        roundtrip(&block.header);
        roundtrip(&block);
        let block2 = roundtrip(&block);
        assert_eq!(block, block2);

        let light_block = block.clone().into_light_macro_block(validators);
        let light_block2 = roundtrip(&light_block);
        assert_eq!(light_block, light_block2);

        let block = Block::MacroBlock(block);
        let block2 = roundtrip(&block);
        assert_eq!(block, block2);

        let block_json = serde_json::to_string(&block).unwrap();
        let block3: Block = serde_json::from_str(&block_json).unwrap();
        assert_eq!(block, block3);

        let light_block = LightBlock::LightMacroBlock(light_block);
        let light_block2 = roundtrip(&light_block);
        assert_eq!(light_block, light_block2);

        let light_block_json = serde_json::to_string(&light_block).unwrap();
        let light_block3: LightBlock = serde_json::from_str(&light_block_json).unwrap();
        assert_eq!(light_block, light_block3);
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
}

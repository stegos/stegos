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
use failure::{ensure, format_err, Error, Fail};
use stegos_serialization::traits::*;

use bitvector::BitVector;

use crate::view_changes::*;
use crate::*;
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::{EncryptedPayload, Fr, Pt, PublicKey, SchnorrSig};

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Missing field '{}' in packet '{}'.", _1, _0)]
    MissingField(String, String),
    #[fail(display = "Duplicate value in field '{}'.", _0)]
    DuplicateValue(String),
}

// link protobuf dependencies
use stegos_crypto::protos::*;
use stegos_crypto::CryptoError;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for PaymentOutput {
    type Proto = blockchain::PaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_cloaking_hint(self.cloaking_hint.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        let timestamp: u64 = if let Some(locked_timestamp) = self.locked_timestamp {
            locked_timestamp.into()
        } else {
            0u64
        };
        proto.set_locked_timestamp(timestamp);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let cloaking_hint = Pt::from_proto(proto.get_cloaking_hint())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        let locked_timestamp: Option<Timestamp> = match proto.get_locked_timestamp() {
            0 => None,
            n => Some(n.into()),
        };
        Ok(PaymentOutput {
            recipient,
            cloaking_hint,
            proof,
            locked_timestamp,
            payload,
        })
    }
}

impl ProtoConvert for PublicPaymentOutput {
    type Proto = blockchain::PublicPaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PublicPaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_amount(self.amount);
        proto.set_serno(self.serno);
        let timestamp: u64 = if let Some(locked_timestamp) = self.locked_timestamp {
            locked_timestamp.into()
        } else {
            0u64
        };

        proto.set_locked_timestamp(timestamp);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let amount = proto.get_amount();
        let serno = proto.get_serno();
        let locked_timestamp: Option<Timestamp> = match proto.get_locked_timestamp() {
            0 => None,
            n => Some(n.into()),
        };
        Ok(PublicPaymentOutput {
            recipient,
            amount,
            serno,
            locked_timestamp,
        })
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
        proto.set_transactions_range_hash(self.transactions_range_hash.into_proto());
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
        let transactions_range_hash = Hash::from_proto(proto.get_transactions_range_hash())?;
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
            transactions_range_hash,
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
        if !self.activity_map.is_empty() {
            assert!(self.activity_map.len() <= VALIDATORS_MAX);
            proto.activity_map.resize(VALIDATORS_MAX, false);
            for bit in self.activity_map.iter() {
                proto.activity_map[bit] = true;
            }
        }
        proto.set_inputs_len(self.inputs_len);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_len(self.outputs_len);
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
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
        let mut activity_map = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.activity_map.iter().enumerate() {
            if *val {
                activity_map.insert(bit);
            }
        }
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let inputs_len = proto.get_inputs_len();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_len = proto.get_outputs_len();
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;
        if proto.activity_map.len() > VALIDATORS_MAX {
            return Err(
                CryptoError::InvalidBinaryLength(VALIDATORS_MAX, proto.activity_map.len()).into(),
            );
        }
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
            activity_map,
            gamma,
            inputs_len,
            inputs_range_hash,
            outputs_len,
            outputs_range_hash,
        })
    }
}

impl ProtoConvert for MacroBlock {
    type Proto = blockchain::MacroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_multisig(self.multisig.into_proto());
        if !self.multisigmap.is_empty() {
            assert!(self.multisigmap.len() <= VALIDATORS_MAX);
            proto.multisigmap.resize(VALIDATORS_MAX, false);
            for bit in self.multisigmap.iter() {
                proto.multisigmap[bit] = true;
            }
        }
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
        if proto.multisigmap.len() > VALIDATORS_MAX {
            return Err(
                CryptoError::InvalidBinaryLength(VALIDATORS_MAX, proto.multisigmap.len()).into(),
            );
        }

        let mut multisigmap = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.multisigmap.iter().enumerate() {
            if *val {
                multisigmap.insert(bit);
            }
        }

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
        if !self.multimap.is_empty() {
            assert!(self.multimap.len() <= VALIDATORS_MAX);
            proto.multimap.resize(VALIDATORS_MAX, false);
            for bit in self.multimap.iter() {
                proto.multimap[bit] = true;
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let multisig = if proto.has_multisig() {
            pbc::Signature::from_proto(proto.get_multisig())?
        } else {
            pbc::Signature::zero()
        };
        ensure!(
            proto.multimap.len() <= VALIDATORS_MAX,
            format_err!(
                "multimap greater than max count of max validators: map_len={}",
                proto.multimap.len()
            )
        );
        let mut multimap = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.multimap.iter().enumerate() {
            if *val {
                multimap.insert(bit);
            }
        }
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
    use stegos_crypto::pbc;
    use stegos_crypto::scc;

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn outputs() {
        let (_skey1, pkey1) = scc::make_random_keys();
        let (network_skey1, network_pkey1) = pbc::make_random_keys();

        let amount = 1_000_000;

        let (output, _gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        roundtrip(&output);

        let output = Output::new_stake(&pkey1, &network_skey1, &network_pkey1, amount)
            .expect("keys are valid");
        roundtrip(&output);

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

        let output = PublicPaymentOutput::new_locked(&pkey, 100, Timestamp::now());

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
        let signatures = vec![(1u32, &sig)];
        let view_change_proof = Some(ViewChangeProof::new(signatures.into_iter()));

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
        assert_eq!(block2.sig, block.sig);
        assert_eq!(block2.transactions.len(), block.transactions.len());
        for (tx1, tx2) in block2.transactions.iter().zip(block.transactions.iter()) {
            assert_eq!(Hash::digest(&tx1), Hash::digest(&tx2));
        }
    }

    #[test]
    fn macro_blocks() {
        let (_skey1, pkey1) = scc::make_random_keys();
        let (_skey2, pkey2) = scc::make_random_keys();
        let (skeypbc, pkeypbc) = pbc::make_random_keys();

        let epoch: u64 = 10;
        let timestamp = Timestamp::now();
        let view_change = 15;
        let amount: i64 = 1_000_000;
        let block_reward = 1000;
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

        let block = MacroBlock::new(
            previous,
            epoch,
            view_change,
            pkeypbc,
            random,
            difficulty,
            timestamp,
            block_reward,
            BitVector::new(0),
            gamma,
            inputs1,
            outputs1,
        );
        roundtrip(&block.header);
        roundtrip(&block);
        let block2 = roundtrip(&block);
        assert_eq!(block2.multisig, block.multisig);
        assert_eq!(block2.multisigmap, block.multisigmap);
        assert_eq!(block2.inputs.len(), block.inputs.len());
        for (input1, input2) in block.inputs.iter().zip(block2.inputs.iter()) {
            assert_eq!(Hash::digest(&input1), Hash::digest(&input2));
        }
        let outputs1 = block.outputs;
        let outputs2 = block2.outputs;
        assert_eq!(outputs1.len(), outputs2.len());
        for (input1, input2) in outputs1.iter().zip(outputs2.iter()) {
            assert_eq!(Hash::digest(&input1), Hash::digest(&input2));
        }
    }
}

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

use failure::{Error, Fail};
use stegos_serialization::traits::*;

use bitvector::BitVector;

use crate::*;
use std::collections::BTreeSet;
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::curve1174::cpt::{EncryptedPayload, PublicKey, SchnorrSig};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;
use stegos_crypto::CryptoError;

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Missing field '{}' in packet '{}'.", _1, _0)]
    MissingField(String, String),
    #[fail(display = "Duplicate value in field '{}'.", _0)]
    DuplicateValue(String),
}

// link protobuf dependencies
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for PaymentOutput {
    type Proto = blockchain::PaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(PaymentOutput {
            recipient,
            proof,
            payload,
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
        proto.set_payload(self.payload.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let validator = SecurePublicKey::from_proto(proto.get_validator())?;
        let amount = proto.get_amount();
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(StakeOutput {
            recipient,
            validator,
            amount,
            payload,
        })
    }
}

impl ProtoConvert for Output {
    type Proto = blockchain::Output;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Output::new();
        match self {
            Output::PaymentOutput(output) => proto.set_payment_output(output.into_proto()),
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

impl ProtoConvert for Transaction {
    type Proto = blockchain::Transaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Transaction::new();

        for txin in &self.body.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.body.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_gamma(self.body.gamma.into_proto());
        proto.set_fee(self.body.fee);
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

        Ok(Transaction {
            body: TransactionBody {
                txins,
                txouts,
                gamma,
                fee,
            },
            sig,
        })
    }
}

impl ProtoConvert for BaseBlockHeader {
    type Proto = blockchain::BaseBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::BaseBlockHeader::new();
        proto.set_version(self.version);
        proto.set_previous(self.previous.into_proto());
        proto.set_epoch(self.epoch);
        proto.set_timestamp(self.timestamp);
        if !self.multisig.is_zero() {
            proto.set_sig(self.multisig.into_proto());
        }
        if !self.multisigmap.is_empty() {
            assert!(self.multisigmap.len() <= WITNESSES_MAX);
            proto.sigmap.resize(WITNESSES_MAX, false);
            for bit in self.multisigmap.iter() {
                proto.sigmap[bit] = true;
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let epoch = proto.get_epoch();
        let timestamp = proto.get_timestamp();
        let sig = if proto.has_sig() {
            SecureSignature::from_proto(proto.get_sig())?
        } else {
            SecureSignature::zero()
        };
        if proto.sigmap.len() > WITNESSES_MAX {
            return Err(CryptoError::InvalidBinaryLength(WITNESSES_MAX, proto.sigmap.len()).into());
        }
        let mut sigmap = BitVector::new(WITNESSES_MAX);
        for (bit, val) in proto.sigmap.iter().enumerate() {
            if *val {
                sigmap.insert(bit);
            }
        }
        Ok(BaseBlockHeader {
            version,
            previous,
            epoch,
            timestamp,
            multisig: sig,
            multisigmap: sigmap,
        })
    }
}

impl ProtoConvert for KeyBlockHeader {
    type Proto = blockchain::KeyBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::KeyBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_leader(self.leader.into_proto());
        proto.set_facilitator(self.facilitator.into_proto());
        for witness in &self.witnesses {
            proto.witnesses.push(witness.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let leader = SecurePublicKey::from_proto(proto.get_leader())?;
        let facilitator = SecurePublicKey::from_proto(proto.get_facilitator())?;
        let mut witnesses = BTreeSet::new();
        for witness in proto.witnesses.iter() {
            if !witnesses.insert(SecurePublicKey::from_proto(witness)?) {
                return Err(ProtoError::DuplicateValue("witnesses".to_string()).into());
            }
        }

        Ok(KeyBlockHeader {
            base,
            leader,
            facilitator,
            witnesses,
        })
    }
}

impl ProtoConvert for KeyBlock {
    type Proto = blockchain::KeyBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::KeyBlock::new();
        proto.set_header(self.header.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = KeyBlockHeader::from_proto(proto.get_header())?;
        Ok(KeyBlock { header })
    }
}

impl ProtoConvert for SerializedNode<Box<Output>> {
    type Proto = blockchain::MerkleNode;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MerkleNode::new();
        proto.set_hash(self.hash.into_proto());
        if let Some(left) = self.left {
            proto.set_left(left as u64 + 1);
        } else {
            proto.set_left(0);
        }
        if let Some(right) = self.right {
            proto.set_right(right as u64 + 1);
        } else {
            proto.set_right(0);
        }
        if let Some(ref value) = self.value {
            proto.set_value(value.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let hash = Hash::from_proto(proto.get_hash())?;
        let left = if proto.get_left() > 0 {
            Some((proto.get_left() - 1) as usize)
        } else {
            None
        };
        let right = if proto.get_right() > 0 {
            Some((proto.get_right() - 1) as usize)
        } else {
            None
        };
        let value = if proto.has_value() {
            Some(Box::new(Output::from_proto(proto.get_value())?))
        } else {
            None
        };
        Ok(SerializedNode::<Box<Output>> {
            hash,
            left,
            right,
            value,
        })
    }
}

impl ProtoConvert for MonetaryBlockHeader {
    type Proto = blockchain::MonetaryBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MonetaryBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_gamma(self.gamma.into_proto());
        proto.set_monetary_adjustment(self.monetary_adjustment);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let monetary_adjustment = proto.get_monetary_adjustment();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;
        Ok(MonetaryBlockHeader {
            base,
            gamma,
            monetary_adjustment,
            inputs_range_hash,
            outputs_range_hash,
        })
    }
}

impl ProtoConvert for MonetaryBlockBody {
    type Proto = blockchain::MonetaryBlockBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MonetaryBlockBody::new();
        for input in &self.inputs {
            proto.inputs.push(input.into_proto());
        }
        for output in self.outputs.serialize() {
            proto.outputs.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut inputs = Vec::<Hash>::with_capacity(proto.inputs.len());
        for input in proto.inputs.iter() {
            inputs.push(Hash::from_proto(input)?);
        }

        let mut outputs = Vec::with_capacity(proto.outputs.len());
        for output in proto.outputs.iter() {
            outputs.push(SerializedNode::<Box<Output>>::from_proto(output)?);
        }
        let outputs = Merkle::deserialize(&outputs)?;

        Ok(MonetaryBlockBody { inputs, outputs })
    }
}

impl ProtoConvert for MonetaryBlock {
    type Proto = blockchain::MonetaryBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MonetaryBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_body(self.body.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MonetaryBlockHeader::from_proto(proto.get_header())?;
        let body = MonetaryBlockBody::from_proto(proto.get_body())?;
        Ok(MonetaryBlock { header, body })
    }
}

impl ProtoConvert for Block {
    type Proto = blockchain::Block;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Block::new();
        match self {
            Block::KeyBlock(key_block) => proto.set_key_block(key_block.into_proto()),
            Block::MonetaryBlock(monetary_block) => {
                proto.set_monetary_block(monetary_block.into_proto())
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = match proto.block {
            Some(blockchain::Block_oneof_block::key_block(ref key_block)) => {
                let key_block = KeyBlock::from_proto(key_block)?;
                Block::KeyBlock(key_block)
            }
            Some(blockchain::Block_oneof_block::monetary_block(ref monetary_block)) => {
                let monetary_block = MonetaryBlock::from_proto(monetary_block)?;
                Block::MonetaryBlock(monetary_block)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::hash::Hashable;
    use stegos_crypto::pbc::secure::make_random_keys as make_secure_random_keys;

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
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_secure_skey1, secure_pkey1, _secure_sig1) = make_secure_random_keys();

        let amount = 1_000_000;
        let timestamp = Utc::now().timestamp() as u64;

        let (output, _gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        roundtrip(&output);

        let output = Output::new_stake(timestamp, &skey1, &pkey1, &secure_pkey1, amount)
            .expect("keys are valid");
        roundtrip(&output);
    }

    fn mktransaction() -> Transaction {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _delta0) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount).expect("keys are valid");

        roundtrip(&output11);
        roundtrip(&gamma11);

        let outputs_gamma = gamma11;

        let tx = Transaction::new(&skey1, &inputs1, &[output11], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs1).unwrap();

        let tx2 = roundtrip(&tx);
        tx2.validate(&inputs1).unwrap();

        tx
    }

    #[test]
    fn transactions() {
        mktransaction();
    }

    #[test]
    fn key_blocks() {
        let (_skey0, pkey0, sig0) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());

        let mut base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        roundtrip(&sig0);
        base.multisig = sig0;
        base.multisigmap.insert(1);
        base.multisigmap.insert(13);
        base.multisigmap.insert(44);
        let base2 = roundtrip(&base);
        assert_eq!(base.multisig, base2.multisig);
        assert_eq!(base.multisigmap, base2.multisigmap);
        assert!(!base.multisigmap.contains(0));
        assert!(base.multisigmap.contains(1));
        assert!(base.multisigmap.contains(13));
        assert!(base.multisigmap.contains(44));

        let witnesses: BTreeSet<SecurePublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();
        let facilitator = pkey0.clone();

        let block = KeyBlock::new(base, leader, facilitator, witnesses);
        roundtrip(&block.header);
        roundtrip(&block);

        let block = Block::KeyBlock(block);
        roundtrip(&block);
    }

    #[test]
    fn monetary_blocks() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        // "genesis" output by 0
        let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();

        // Transaction from 1 to 2
        let inputs1 = [Hash::digest(&output0)];
        let (output1, gamma1) = Output::new_payment(timestamp, &skey1, &pkey2, amount).unwrap();
        let outputs1 = [output1];
        let gamma = gamma0 - gamma1;

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let base2 = roundtrip(&base);
        assert_eq!(base.multisig, base2.multisig);
        assert_eq!(base.multisigmap, base2.multisigmap);

        let block = MonetaryBlock::new(base, gamma.clone(), 0, &inputs1, &outputs1);
        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::MonetaryBlock(block);
        roundtrip(&block);
    }
}

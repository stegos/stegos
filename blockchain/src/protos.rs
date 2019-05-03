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

use failure::{ensure, format_err, Error, Fail};
use stegos_serialization::traits::*;

use bitvector::BitVector;

use crate::view_changes::*;
use crate::*;
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::curve1174::cpt::{EncryptedPayload, PublicKey, SchnorrSig};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
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
        proto.set_signature(self.signature.into_proto());
        proto.set_amount(self.amount);
        proto.set_payload(self.payload.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let validator = secure::PublicKey::from_proto(proto.get_validator())?;
        let signature = secure::Signature::from_proto(proto.get_signature())?;
        let amount = proto.get_amount();
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(StakeOutput {
            recipient,
            validator,
            signature,
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
        proto.set_height(self.height);
        proto.set_view_change(self.view_change);
        proto.set_random(self.random.into_proto());
        let since_the_epoch = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time is valid");
        let timestamp = since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_millis() as u64;
        proto.set_timestamp(timestamp);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let height = proto.get_height();
        let view_change = proto.get_view_change();
        let timestamp =
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(proto.get_timestamp());
        let random = secure::VRF::from_proto(proto.get_random())?;
        Ok(BaseBlockHeader {
            version,
            previous,
            height,
            view_change,
            timestamp,
            random,
        })
    }
}

impl ProtoConvert for KeyBlockHeader {
    type Proto = blockchain::KeyBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::KeyBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;

        Ok(KeyBlockHeader { base })
    }
}

impl ProtoConvert for KeyBlockBody {
    type Proto = blockchain::KeyBlockBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::KeyBlockBody::new();
        if !self.multisig.is_zero() {
            proto.set_sig(self.multisig.into_proto());
        }
        if !self.multisigmap.is_empty() {
            assert!(self.multisigmap.len() <= VALIDATORS_MAX);
            proto.sigmap.resize(VALIDATORS_MAX, false);
            for bit in self.multisigmap.iter() {
                proto.sigmap[bit] = true;
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let multisig = if proto.has_sig() {
            secure::Signature::from_proto(proto.get_sig())?
        } else {
            secure::Signature::zero()
        };
        if proto.sigmap.len() > VALIDATORS_MAX {
            return Err(
                CryptoError::InvalidBinaryLength(VALIDATORS_MAX, proto.sigmap.len()).into(),
            );
        }
        let mut multisigmap = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.sigmap.iter().enumerate() {
            if *val {
                multisigmap.insert(bit);
            }
        }
        Ok(KeyBlockBody {
            multisig,
            multisigmap,
        })
    }
}

impl ProtoConvert for KeyBlock {
    type Proto = blockchain::KeyBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::KeyBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_body(self.body.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = KeyBlockHeader::from_proto(proto.get_header())?;
        let body = KeyBlockBody::from_proto(proto.get_body())?;
        Ok(KeyBlock { header, body })
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

impl ProtoConvert for MicroBlockHeader {
    type Proto = blockchain::MicroBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_gamma(self.gamma.into_proto());
        proto.set_monetary_adjustment(self.monetary_adjustment);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        if let Some(proof) = &self.proof {
            proto.set_proof(proof.into_proto())
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let monetary_adjustment = proto.get_monetary_adjustment();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;

        let proof = if proto.has_proof() {
            Some(ViewChangeProof::from_proto(proto.get_proof())?)
        } else {
            None
        };
        Ok(MicroBlockHeader {
            proof,
            base,
            gamma,
            monetary_adjustment,
            inputs_range_hash,
            outputs_range_hash,
        })
    }
}

impl ProtoConvert for MicroBlockBody {
    type Proto = blockchain::MicroBlockBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlockBody::new();
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());

        for input in &self.inputs {
            proto.inputs.push(input.into_proto());
        }
        for output in self.outputs.serialize() {
            proto.outputs.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let sig = secure::Signature::from_proto(proto.get_sig())?;

        let pkey = secure::PublicKey::from_proto(proto.get_pkey())?;

        let mut inputs = Vec::<Hash>::with_capacity(proto.inputs.len());
        for input in proto.inputs.iter() {
            inputs.push(Hash::from_proto(input)?);
        }

        let mut outputs = Vec::with_capacity(proto.outputs.len());
        for output in proto.outputs.iter() {
            outputs.push(SerializedNode::<Box<Output>>::from_proto(output)?);
        }
        let outputs = Merkle::deserialize(&outputs)?;

        Ok(MicroBlockBody {
            sig,
            pkey,
            inputs,
            outputs,
        })
    }
}

impl ProtoConvert for MicroBlock {
    type Proto = blockchain::MicroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_body(self.body.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MicroBlockHeader::from_proto(proto.get_header())?;
        let body = MicroBlockBody::from_proto(proto.get_body())?;
        Ok(MicroBlock { header, body })
    }
}

impl ProtoConvert for Block {
    type Proto = blockchain::Block;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Block::new();
        match self {
            Block::KeyBlock(key_block) => proto.set_key_block(key_block.into_proto()),
            Block::MicroBlock(micro_block) => proto.set_micro_block(micro_block.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = match proto.block {
            Some(blockchain::Block_oneof_block::key_block(ref key_block)) => {
                let key_block = KeyBlock::from_proto(key_block)?;
                Block::KeyBlock(key_block)
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
        proto.set_height(self.height);
        proto.set_last_block(self.last_block.into_proto());
        proto.set_view_change(self.view_change);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let height = proto.get_height();
        let view_change = proto.get_view_change();
        let last_block = Hash::from_proto(proto.get_last_block())?;
        Ok(ChainInfo {
            height,
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
            secure::Signature::from_proto(proto.get_multisig())?
        } else {
            secure::Signature::zero()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::hash::{Hash, Hashable, Hasher};
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
        let (skey0, _pkey0) = make_random_keys();
        let (skey1, pkey1) = make_random_keys();
        let (secure_skey1, secure_pkey1) = make_secure_random_keys();

        let amount = 1_000_000;
        let timestamp = SystemTime::now();

        let (output, _gamma) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");
        roundtrip(&output);

        let output = Output::new_stake(
            timestamp,
            &skey1,
            &pkey1,
            &secure_pkey1,
            &secure_skey1,
            amount,
        )
        .expect("keys are valid");
        roundtrip(&output);

        let mut buf = output.into_buffer().unwrap();
        buf.pop();
        Output::from_buffer(&buf).expect_err("error");
    }

    fn mktransaction() -> Transaction {
        let (skey0, _pkey0) = make_random_keys();
        let (skey1, pkey1) = make_random_keys();
        let (_skey2, pkey2) = make_random_keys();

        let timestamp = SystemTime::now();
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
        let tx = mktransaction();
        roundtrip(&tx);

        let mut buf = tx.into_buffer().unwrap();
        buf.pop();
        Transaction::from_buffer(&buf).expect_err("error");
    }

    impl Hashable for KeyBlockBody {
        fn hash(&self, state: &mut Hasher) {
            "Key".hash(state);
            self.multisig.hash(state);
            for bit in self.multisigmap.iter() {
                (bit as u64).hash(state);
            }
        }
    }

    #[test]
    fn key_blocks() {
        let (skey0, _pkey0) = make_secure_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let previous = Hash::digest(&"test".to_string());
        let random = secure::make_VRF(&skey0, &Hash::digest("test"));
        let base = BaseBlockHeader::new(version, previous, height, 0, timestamp, random);
        let block = KeyBlock::new(base);

        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::KeyBlock(block);
        roundtrip(&block);
    }

    impl Hashable for MicroBlockBody {
        fn hash(&self, state: &mut Hasher) {
            "Monetary".hash(state);
            self.sig.hash(state);
            let inputs_count: u64 = self.inputs.len() as u64;
            inputs_count.hash(state);
            for input in &self.inputs {
                input.hash(state);
            }
            self.outputs.roothash().hash(state)
        }
    }

    #[test]
    fn micro_blocks() {
        let (skey0, _pkey0) = make_random_keys();
        let (skey1, pkey1) = make_random_keys();
        let (_skey2, pkey2) = make_random_keys();
        let (skeypbc, pkeypbc) = make_secure_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        // "genesis" output by 0
        let (output0, gamma0) = Output::new_payment(timestamp, &skey0, &pkey1, amount).unwrap();

        // Transaction from 1 to 2
        let inputs1 = [Hash::digest(&output0)];
        let (output1, gamma1) = Output::new_payment(timestamp, &skey1, &pkey2, amount).unwrap();
        let outputs1 = [output1];
        let gamma = gamma0 - gamma1;

        let seed = mix(Hash::digest("random"), view_change);
        let random = secure::make_VRF(&skeypbc, &seed);
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        roundtrip(&base);

        let block = MicroBlock::new(
            base,
            gamma.clone(),
            0,
            &inputs1,
            &outputs1,
            None,
            pkeypbc,
            &skeypbc,
        );
        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::MicroBlock(block);
        roundtrip(&block);
    }
}

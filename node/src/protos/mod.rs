//! Protobuf Definitions.

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

pub mod node;

use bitvector::BitVector;
use failure::{Error, Fail};
use std::collections::BTreeSet;
use stegos_blockchain::*;
use stegos_consensus::*;
use stegos_crypto::bulletproofs::{BulletProof, DotProof, L2_NBASIS, LR};
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::cpt::{EncryptedPayload, PublicKey, SchnorrSig};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;
use stegos_crypto::pbc::secure::G1;
use stegos_crypto::pbc::secure::G2;
use stegos_crypto::CryptoError;

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Missing field '{}' in packet '{}'.", _1, _0)]
    MissingField(String, String),
    #[fail(display = "Duplicate value in field '{}'.", _0)]
    DuplicateValue(String),
}

pub trait IntoProto<T: ::protobuf::Message> {
    fn into_proto(&self) -> T;
}

pub trait FromProto<T: ::protobuf::Message>: Sized {
    fn from_proto(proto: &T) -> Result<Self, Error>;
}

//
// Pt
//

impl IntoProto<node::Pt> for Pt {
    fn into_proto(&self) -> node::Pt {
        let mut proto = node::Pt::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Pt> for Pt {
    fn from_proto(proto: &node::Pt) -> Result<Self, Error> {
        Ok(Pt::try_from_bytes(proto.get_data())?)
    }
}

//
// Fr
//

impl IntoProto<node::Fr> for Fr {
    fn into_proto(&self) -> node::Fr {
        let mut proto = node::Fr::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Fr> for Fr {
    fn from_proto(proto: &node::Fr) -> Result<Self, Error> {
        Ok(Fr::try_from_bytes(proto.get_data())?)
    }
}

//
// G1
//

impl IntoProto<node::G1> for G1 {
    fn into_proto(&self) -> node::G1 {
        let mut proto = node::G1::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::G1> for G1 {
    fn from_proto(proto: &node::G1) -> Result<Self, Error> {
        Ok(G1::try_from_bytes(proto.get_data())?)
    }
}

//
// G2
//

impl IntoProto<node::G2> for G2 {
    fn into_proto(&self) -> node::G2 {
        let mut proto = node::G2::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::G2> for G2 {
    fn from_proto(proto: &node::G2) -> Result<Self, Error> {
        Ok(G2::try_from_bytes(proto.get_data())?)
    }
}

//
// Hash
//

impl IntoProto<node::Hash> for Hash {
    fn into_proto(&self) -> node::Hash {
        let mut proto = node::Hash::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Hash> for Hash {
    fn from_proto(proto: &node::Hash) -> Result<Self, Error> {
        Ok(Hash::try_from_bytes(proto.get_data())?)
    }
}

//
// Public Key
//

impl IntoProto<node::PublicKey> for PublicKey {
    fn into_proto(&self) -> node::PublicKey {
        let mut proto = node::PublicKey::new();
        let pt: Pt = (*self).into();
        proto.set_point(pt.into_proto());
        proto
    }
}

impl FromProto<node::PublicKey> for PublicKey {
    fn from_proto(proto: &node::PublicKey) -> Result<Self, Error> {
        let pt: Pt = Pt::from_proto(proto.get_point())?;
        Ok(PublicKey::from(pt))
    }
}

//
// SchnorrSig
//

impl IntoProto<node::SchnorrSig> for SchnorrSig {
    fn into_proto(&self) -> node::SchnorrSig {
        let mut proto = node::SchnorrSig::new();
        proto.set_K(self.K.into_proto());
        proto.set_u(self.u.into_proto());
        proto
    }
}

#[allow(non_snake_case)]
impl FromProto<node::SchnorrSig> for SchnorrSig {
    fn from_proto(proto: &node::SchnorrSig) -> Result<Self, Error> {
        let K: Pt = Pt::from_proto(proto.get_K())?;
        let u: Fr = Fr::from_proto(proto.get_u())?;
        Ok(SchnorrSig { K, u })
    }
}

//
// SecurePublicKey
//

impl IntoProto<node::SecurePublicKey> for SecurePublicKey {
    fn into_proto(&self) -> node::SecurePublicKey {
        let mut proto = node::SecurePublicKey::new();
        let g: G2 = (*self).into();
        proto.set_point(g.into_proto());
        proto
    }
}

impl FromProto<node::SecurePublicKey> for SecurePublicKey {
    fn from_proto(proto: &node::SecurePublicKey) -> Result<Self, Error> {
        let g: G2 = G2::from_proto(proto.get_point())?;
        Ok(SecurePublicKey::from(g))
    }
}

//
// SecureSignature
//

impl IntoProto<node::SecureSignature> for SecureSignature {
    fn into_proto(&self) -> node::SecureSignature {
        let mut proto = node::SecureSignature::new();
        let g: G1 = (*self).into();
        proto.set_point(g.into_proto());
        proto
    }
}

impl FromProto<node::SecureSignature> for SecureSignature {
    fn from_proto(proto: &node::SecureSignature) -> Result<Self, Error> {
        let g: G1 = G1::from_proto(proto.get_point())?;
        Ok(SecureSignature::from(g))
    }
}

//
// EncryptedPayload
//

impl IntoProto<node::EncryptedPayload> for EncryptedPayload {
    fn into_proto(&self) -> node::EncryptedPayload {
        let mut proto = node::EncryptedPayload::new();
        proto.set_apkg(self.apkg.into_proto());
        proto.set_ag(self.ag.into_proto());
        proto.set_ctxt(self.ctxt.clone());
        proto
    }
}

impl FromProto<node::EncryptedPayload> for EncryptedPayload {
    fn from_proto(proto: &node::EncryptedPayload) -> Result<Self, Error> {
        let apkg = Pt::from_proto(proto.get_apkg())?;
        let ag = Pt::from_proto(proto.get_ag())?;
        let ctxt = proto.get_ctxt().to_vec();
        Ok(EncryptedPayload { apkg, ag, ctxt })
    }
}

//
// BulletProof
//

impl IntoProto<node::LR> for LR {
    fn into_proto(&self) -> node::LR {
        let mut proto = node::LR::new();
        proto.set_x(self.x.into_proto());
        proto.set_l(self.l.into_proto());
        proto.set_r(self.r.into_proto());
        proto
    }
}

impl FromProto<node::LR> for LR {
    fn from_proto(proto: &node::LR) -> Result<Self, Error> {
        let x = Fr::from_proto(proto.get_x())?;
        let l = Pt::from_proto(proto.get_l())?;
        let r = Pt::from_proto(proto.get_r())?;
        Ok(LR { x, l, r })
    }
}

impl IntoProto<node::DotProof> for DotProof {
    fn into_proto(&self) -> node::DotProof {
        let mut proto = node::DotProof::new();
        proto.set_u(self.u.into_proto());
        proto.set_pcmt(self.pcmt.into_proto());
        proto.set_a(self.a.into_proto());
        proto.set_b(self.b.into_proto());
        for lr in self.xlrs.iter() {
            proto.xlrs.push(lr.into_proto());
        }
        proto
    }
}

impl FromProto<node::DotProof> for DotProof {
    fn from_proto(proto: &node::DotProof) -> Result<Self, Error> {
        let u = Pt::from_proto(proto.get_u())?;
        let pcmt = Pt::from_proto(proto.get_pcmt())?;
        let a = Fr::from_proto(proto.get_a())?;
        let b = Fr::from_proto(proto.get_b())?;
        let xlrs1 = proto.get_xlrs();
        if xlrs1.len() != L2_NBASIS {
            return Err(CryptoError::InvalidBinaryLength(L2_NBASIS, xlrs1.len()).into());
        }

        let zero = LR::from_proto(&xlrs1[0])?;
        let mut xlrs: [LR; L2_NBASIS] = [zero; L2_NBASIS];
        for (i, lr) in xlrs1.iter().enumerate() {
            xlrs[i] = LR::from_proto(lr)?;
        }

        Ok(DotProof {
            u,
            pcmt,
            a,
            b,
            xlrs,
        })
    }
}

impl IntoProto<node::BulletProof> for BulletProof {
    fn into_proto(&self) -> node::BulletProof {
        let mut proto = node::BulletProof::new();
        proto.set_vcmt(self.vcmt.into_proto());
        proto.set_acmt(self.acmt.into_proto());
        proto.set_scmt(self.scmt.into_proto());
        proto.set_t1_cmt(self.t1_cmt.into_proto());
        proto.set_t2_cmt(self.t2_cmt.into_proto());
        proto.set_tau_x(self.tau_x.into_proto());
        proto.set_mu(self.mu.into_proto());
        proto.set_t_hat(self.t_hat.into_proto());
        proto.set_dot_proof(self.dot_proof.into_proto());
        proto.set_x(self.x.into_proto());
        proto.set_y(self.y.into_proto());
        proto.set_z(self.z.into_proto());
        proto
    }
}

impl FromProto<node::BulletProof> for BulletProof {
    fn from_proto(proto: &node::BulletProof) -> Result<Self, Error> {
        let vcmt = Pt::from_proto(proto.get_vcmt())?;
        let acmt = Pt::from_proto(proto.get_acmt())?;
        let scmt = Pt::from_proto(proto.get_scmt())?;
        let t1_cmt = Pt::from_proto(proto.get_t1_cmt())?;
        let t2_cmt = Pt::from_proto(proto.get_t2_cmt())?;
        let tau_x = Fr::from_proto(proto.get_tau_x())?;
        let mu = Fr::from_proto(proto.get_mu())?;
        let t_hat = Fr::from_proto(proto.get_t_hat())?;
        let dot_proof = DotProof::from_proto(proto.get_dot_proof())?;
        let x = Fr::from_proto(proto.get_x())?;
        let y = Fr::from_proto(proto.get_y())?;
        let z = Fr::from_proto(proto.get_z())?;
        Ok(BulletProof {
            vcmt,
            acmt,
            scmt,
            t1_cmt,
            t2_cmt,
            tau_x,
            mu,
            t_hat,
            dot_proof,
            x,
            y,
            z,
        })
    }
}

impl IntoProto<node::Output> for MonetaryOutput {
    fn into_proto(&self) -> node::Output {
        let mut proto = node::Output::new();
        proto.set_ttl(0);
        proto.set_recipient(self.recipient.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl IntoProto<node::Output> for DataOutput {
    fn into_proto(&self) -> node::Output {
        let mut proto = node::Output::new();
        assert!(self.ttl > 0);
        proto.set_recipient(self.recipient.into_proto());
        proto.set_ttl(self.ttl);
        proto.set_vcmt(self.vcmt.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl IntoProto<node::Output> for Output {
    fn into_proto(&self) -> node::Output {
        match self {
            Output::MonetaryOutput(monetary) => monetary.into_proto(),
            Output::DataOutput(data) => data.into_proto(),
        }
    }
}

impl FromProto<node::Output> for MonetaryOutput {
    fn from_proto(proto: &node::Output) -> Result<Self, Error> {
        assert_eq!(proto.ttl, 0);
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(MonetaryOutput {
            recipient,
            proof,
            payload,
        })
    }
}

impl FromProto<node::Output> for DataOutput {
    fn from_proto(proto: &node::Output) -> Result<Self, Error> {
        assert_ne!(proto.ttl, 0);
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let ttl = proto.ttl;
        let vcmt = Pt::from_proto(proto.get_vcmt())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(DataOutput {
            recipient,
            ttl,
            vcmt,
            payload,
        })
    }
}

impl FromProto<node::Output> for Output {
    fn from_proto(proto: &node::Output) -> Result<Self, Error> {
        let ttl = proto.get_ttl();
        if ttl == 0 {
            Ok(Output::MonetaryOutput(MonetaryOutput::from_proto(proto)?))
        } else {
            Ok(Output::DataOutput(DataOutput::from_proto(proto)?))
        }
    }
}

impl IntoProto<node::Transaction> for Transaction {
    fn into_proto(&self) -> node::Transaction {
        let mut proto = node::Transaction::new();

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
}

impl FromProto<node::Transaction> for Transaction {
    fn from_proto(proto: &node::Transaction) -> Result<Self, Error> {
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

//
// Base Block
//

impl IntoProto<node::BaseBlockHeader> for BaseBlockHeader {
    fn into_proto(&self) -> node::BaseBlockHeader {
        let mut proto = node::BaseBlockHeader::new();
        proto.set_version(self.version);
        proto.set_previous(self.previous.into_proto());
        proto.set_epoch(self.epoch);
        proto.set_timestamp(self.timestamp);
        if !self.sig.is_null() {
            proto.set_sig(self.sig.into_proto());
        }
        if !self.sigmap.is_empty() {
            assert!(self.sigmap.len() <= WITNESSES_MAX);
            proto.sigmap.resize(WITNESSES_MAX, false);
            for bit in self.sigmap.iter() {
                proto.sigmap[bit] = true;
            }
        }
        proto
    }
}

impl FromProto<node::BaseBlockHeader> for BaseBlockHeader {
    fn from_proto(proto: &node::BaseBlockHeader) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let epoch = proto.get_epoch();
        let timestamp = proto.get_timestamp();
        let sig = if proto.has_sig() {
            SecureSignature::from_proto(proto.get_sig())?
        } else {
            SecureSignature::null()
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
            sig,
            sigmap,
        })
    }
}

//
// Key Block
//

impl IntoProto<node::KeyBlockHeader> for KeyBlockHeader {
    fn into_proto(&self) -> node::KeyBlockHeader {
        let mut proto = node::KeyBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_leader(self.leader.into_proto());
        for witness in &self.witnesses {
            proto.witnesses.push(witness.into_proto());
        }
        proto
    }
}

impl FromProto<node::KeyBlockHeader> for KeyBlockHeader {
    fn from_proto(proto: &node::KeyBlockHeader) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let leader = SecurePublicKey::from_proto(proto.get_leader())?;
        let mut witnesses = BTreeSet::new();
        for witness in proto.witnesses.iter() {
            if !witnesses.insert(SecurePublicKey::from_proto(witness)?) {
                return Err(ProtoError::DuplicateValue("witnesses".to_string()).into());
            }
        }

        Ok(KeyBlockHeader {
            base,
            leader,
            witnesses,
        })
    }
}

impl IntoProto<node::KeyBlock> for KeyBlock {
    fn into_proto(&self) -> node::KeyBlock {
        let mut proto = node::KeyBlock::new();
        proto.set_header(self.header.into_proto());
        proto
    }
}

impl FromProto<node::KeyBlock> for KeyBlock {
    fn from_proto(proto: &node::KeyBlock) -> Result<Self, Error> {
        let header = KeyBlockHeader::from_proto(proto.get_header())?;
        Ok(KeyBlock { header })
    }
}

//
// Monetary Block
//

impl IntoProto<node::MonetaryBlockHeader> for MonetaryBlockHeader {
    fn into_proto(&self) -> node::MonetaryBlockHeader {
        let mut proto = node::MonetaryBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_gamma(self.gamma.into_proto());
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        proto
    }
}

impl FromProto<node::MonetaryBlockHeader> for MonetaryBlockHeader {
    fn from_proto(proto: &node::MonetaryBlockHeader) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;
        Ok(MonetaryBlockHeader {
            base,
            gamma: gamma,
            inputs_range_hash,
            outputs_range_hash,
        })
    }
}

impl IntoProto<node::MerkleNode> for SerializedNode<Box<Output>> {
    fn into_proto(&self) -> node::MerkleNode {
        let mut proto = node::MerkleNode::new();
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
}

impl FromProto<node::MerkleNode> for SerializedNode<Box<Output>> {
    fn from_proto(proto: &node::MerkleNode) -> Result<Self, Error> {
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

impl IntoProto<node::MonetaryBlockBody> for MonetaryBlockBody {
    fn into_proto(&self) -> node::MonetaryBlockBody {
        let mut proto = node::MonetaryBlockBody::new();
        for input in &self.inputs {
            proto.inputs.push(input.into_proto());
        }
        for output in self.outputs.serialize() {
            proto.outputs.push(output.into_proto());
        }
        proto
    }
}

impl FromProto<node::MonetaryBlockBody> for MonetaryBlockBody {
    fn from_proto(proto: &node::MonetaryBlockBody) -> Result<Self, Error> {
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

impl IntoProto<node::MonetaryBlock> for MonetaryBlock {
    fn into_proto(&self) -> node::MonetaryBlock {
        let mut proto = node::MonetaryBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_body(self.body.into_proto());
        proto
    }
}

impl FromProto<node::MonetaryBlock> for MonetaryBlock {
    fn from_proto(proto: &node::MonetaryBlock) -> Result<Self, Error> {
        let header = MonetaryBlockHeader::from_proto(proto.get_header())?;
        let body = MonetaryBlockBody::from_proto(proto.get_body())?;
        Ok(MonetaryBlock { header, body })
    }
}

//
// enum Block
//

impl IntoProto<node::Block> for Block {
    fn into_proto(&self) -> node::Block {
        let mut proto = node::Block::new();
        match self {
            Block::KeyBlock(key_block) => proto.set_key_block(key_block.into_proto()),
            Block::MonetaryBlock(monetary_block) => {
                proto.set_monetary_block(monetary_block.into_proto())
            }
        }
        proto
    }
}

impl FromProto<node::Block> for Block {
    fn from_proto(proto: &node::Block) -> Result<Self, Error> {
        let block = match proto.block {
            Some(node::Block_oneof_block::key_block(ref key_block)) => {
                let key_block = KeyBlock::from_proto(key_block)?;
                Block::KeyBlock(key_block)
            }
            Some(node::Block_oneof_block::monetary_block(ref monetary_block)) => {
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

//
// Consensus
//

impl IntoProto<node::MonetaryBlockProposal> for MonetaryBlockProposal {
    fn into_proto(&self) -> node::MonetaryBlockProposal {
        let mut proto = node::MonetaryBlockProposal::new();
        for tx in &self.txs {
            proto.txs.push(tx.into_proto());
        }
        if let Some(ref fee_output) = self.fee_output {
            proto.set_fee_output(fee_output.into_proto());
        }
        proto.set_block_hash(self.block_hash.into_proto());
        proto.set_block_header(self.block_header.into_proto());
        proto
    }
}

impl FromProto<node::MonetaryBlockProposal> for MonetaryBlockProposal {
    fn from_proto(proto: &node::MonetaryBlockProposal) -> Result<Self, Error> {
        let mut txs = Vec::with_capacity(proto.txs.len());
        for tx in proto.txs.iter() {
            txs.push(Transaction::from_proto(tx)?);
        }
        let fee_output = if proto.has_fee_output() {
            Some(Output::from_proto(proto.get_fee_output())?)
        } else {
            None
        };
        let block_hash = Hash::from_proto(proto.get_block_hash())?;
        let block_header = MonetaryBlockHeader::from_proto(proto.get_block_header())?;
        Ok(MonetaryBlockProposal {
            txs,
            fee_output,
            block_hash,
            block_header,
        })
    }
}

impl IntoProto<node::ConsensusMessageBody> for ConsensusMessageBody {
    fn into_proto(&self) -> node::ConsensusMessageBody {
        let mut proto = node::ConsensusMessageBody::new();
        match self {
            ConsensusMessageBody::MonetaryBlockProposal(msg) => {
                proto.set_monetary_block_proposal(msg.into_proto())
            }
        }
        proto
    }
}

impl FromProto<node::ConsensusMessageBody> for ConsensusMessageBody {
    fn from_proto(proto: &node::ConsensusMessageBody) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(node::ConsensusMessageBody_oneof_body::monetary_block_proposal(ref msg)) => {
                let msg = MonetaryBlockProposal::from_proto(msg)?;
                ConsensusMessageBody::MonetaryBlockProposal(msg)
            }
            None => {
                return Err(ProtoError::MissingField("body".to_string(), "body".to_string()).into());
            }
        };
        Ok(msg)
    }
}

impl IntoProto<node::ConsensusMessage> for ConsensusMessage {
    fn into_proto(&self) -> node::ConsensusMessage {
        let mut proto = node::ConsensusMessage::new();
        proto.set_body(self.body.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
}

impl FromProto<node::ConsensusMessage> for ConsensusMessage {
    fn from_proto(proto: &node::ConsensusMessage) -> Result<Self, Error> {
        let body = ConsensusMessageBody::from_proto(proto.get_body())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        Ok(ConsensusMessage { body, sig, pkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;
    use stegos_crypto::bulletproofs::make_range_proof;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::curve1174::ecpt::ECp;
    use stegos_crypto::hash::Hashable;
    use stegos_crypto::pbc::secure::make_random_keys as make_secure_random_keys;

    fn roundtrip<M, T>(x: &T) -> T
    where
        M: ::protobuf::Message,
        T: IntoProto<M> + FromProto<M> + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn points() {
        let pt: Pt = Pt::from(ECp::random());
        roundtrip(&pt);

        let fr = Fr::random();
        roundtrip(&fr);

        let g1 = G1::generator();
        roundtrip(&g1);

        let g2 = G2::generator();
        roundtrip(&g2);
    }

    #[test]
    fn keys() {
        let (_skey, pkey, sig) = make_random_keys();
        roundtrip(&pkey);
        roundtrip(&sig);
    }

    #[test]
    fn secure_keys() {
        let (_skey, pkey, sig) = make_secure_random_keys();
        roundtrip(&pkey);
        roundtrip(&sig);
    }

    #[test]
    fn hash() {
        let mut rng: ThreadRng = thread_rng();
        let hash = Hash::try_from_bytes(&rng.gen::<[u8; 32]>()).unwrap();
        roundtrip(&hash);
    }

    #[test]
    fn bulletproofs() {
        let lr = LR {
            x: Fr::random(),
            l: Pt::from(ECp::random()),
            r: Pt::from(ECp::random()),
        };
        roundtrip(&lr);

        let dp = DotProof {
            u: Pt::random(),
            pcmt: Pt::random(),
            a: Fr::random(),
            b: Fr::random(),
            xlrs: [lr, lr, lr, lr, lr, lr],
        };

        roundtrip(&dp);

        let (bp, gamma) = make_range_proof(100);
        roundtrip(&bp);
        roundtrip(&gamma);
    }

    fn mktransaction() -> Transaction {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let data = b"hello";
        let fee: i64 = 0;
        let ttl = 10;

        // "genesis" output by 0
        let (output0, _delta0) =
            Output::new_monetary(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) =
            Output::new_monetary(timestamp, &skey1, &pkey2, amount).expect("keys are valid");
        let (output12, gamma12) =
            Output::new_data(timestamp, &skey1, &pkey2, ttl, data).expect("keys are valid");

        roundtrip(&output11);
        roundtrip(&gamma11);
        roundtrip(&output12);
        roundtrip(&gamma12);

        let outputs_gamma = gamma11 + gamma12;

        let tx = Transaction::new(&skey1, &inputs1, &[output11, output12], outputs_gamma, fee)
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
    fn monetary_block_proposal() {
        let (skey, pkey, _sig) = make_random_keys();
        let (cosi_skey, cosi_pkey, _cosi_sig) = make_secure_random_keys();
        let timestamp = Utc::now().timestamp() as u64;

        //
        // Block Proposal
        //
        let tx = mktransaction(); // re-use the test above
        let (fee_output, _fee_gamma) =
            Output::new_monetary(timestamp, &skey, &pkey, 100).expect("keys are valid");
        let mut txs = Vec::new();
        txs.push(tx);
        let block_hash = Hash::digest(&"test".to_string());
        let base = BaseBlockHeader::new(1, Hash::digest(&"dev".to_string()), 1, timestamp);
        let block_header = MonetaryBlockHeader {
            base,
            gamma: Fr::random(),
            inputs_range_hash: Hash::digest(&1u64),
            outputs_range_hash: Hash::digest(&2u64),
        };

        let monetary_block_proposal = ConsensusMessage::new_block_proposal(
            &cosi_skey,
            &cosi_pkey,
            txs.clone(),
            Some(fee_output),
            block_hash,
            block_header.clone(),
        );
        roundtrip(&monetary_block_proposal);

        let monetary_block_proposal = ConsensusMessage::new_block_proposal(
            &cosi_skey,
            &cosi_pkey,
            txs.clone(),
            None,
            block_hash,
            block_header.clone(),
        );
        roundtrip(&monetary_block_proposal);
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
        base.sig = sig0;
        base.sigmap.insert(1);
        base.sigmap.insert(13);
        base.sigmap.insert(44);
        roundtrip(&base);

        let witnesses: BTreeSet<SecurePublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();

        let block = KeyBlock::new(base, leader, witnesses);
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
        let (output0, gamma0) = Output::new_monetary(timestamp, &skey0, &pkey1, amount).unwrap();

        // Transaction from 1 to 2
        let inputs1 = [Hash::digest(&output0)];
        let (output1, gamma1) = Output::new_monetary(timestamp, &skey1, &pkey2, amount).unwrap();
        let outputs1 = [output1];
        let gamma = gamma0 - gamma1;

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        roundtrip(&base);

        let block = MonetaryBlock::new(base, gamma, &inputs1, &outputs1);
        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::MonetaryBlock(block);
        roundtrip(&block);
    }
}

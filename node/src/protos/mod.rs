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

use crate::consensus::{BlockProof, MonetaryBlockProof, SealedBlockMessage};

use crate::VRFTicket;
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
use stegos_crypto::pbc::secure::VRF;
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

impl IntoProto<node::PaymentOutput> for PaymentOutput {
    fn into_proto(&self) -> node::PaymentOutput {
        let mut proto = node::PaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl IntoProto<node::DataOutput> for DataOutput {
    fn into_proto(&self) -> node::DataOutput {
        let mut proto = node::DataOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_ttl(self.ttl);
        proto.set_vcmt(self.vcmt.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl IntoProto<node::EscrowOutput> for EscrowOutput {
    fn into_proto(&self) -> node::EscrowOutput {
        let mut proto = node::EscrowOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_validator(self.validator.into_proto());
        proto.set_amount(self.amount);
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl IntoProto<node::Output> for Output {
    fn into_proto(&self) -> node::Output {
        let mut proto = node::Output::new();
        match self {
            Output::PaymentOutput(output) => proto.set_payment_output(output.into_proto()),
            Output::DataOutput(output) => proto.set_data_output(output.into_proto()),
            Output::EscrowOutput(output) => proto.set_escrow_output(output.into_proto()),
        }
        proto
    }
}

impl FromProto<node::PaymentOutput> for PaymentOutput {
    fn from_proto(proto: &node::PaymentOutput) -> Result<Self, Error> {
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

impl FromProto<node::DataOutput> for DataOutput {
    fn from_proto(proto: &node::DataOutput) -> Result<Self, Error> {
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

impl FromProto<node::EscrowOutput> for EscrowOutput {
    fn from_proto(proto: &node::EscrowOutput) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let validator = SecurePublicKey::from_proto(proto.get_validator())?;
        let amount = proto.get_amount();
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(EscrowOutput {
            recipient,
            validator,
            amount,
            payload,
        })
    }
}

impl FromProto<node::Output> for Output {
    fn from_proto(proto: &node::Output) -> Result<Self, Error> {
        match proto.output {
            Some(node::Output_oneof_output::payment_output(ref output)) => {
                let output = PaymentOutput::from_proto(output)?;
                Ok(Output::PaymentOutput(output))
            }
            Some(node::Output_oneof_output::data_output(ref output)) => {
                let output = DataOutput::from_proto(output)?;
                Ok(Output::DataOutput(output))
            }
            Some(node::Output_oneof_output::escrow_output(ref output)) => {
                let output = EscrowOutput::from_proto(output)?;
                Ok(Output::EscrowOutput(output))
            }
            None => {
                Err(ProtoError::MissingField("output".to_string(), "output".to_string()).into())
            }
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

impl IntoProto<node::ConsensusMessageBody> for ConsensusMessageBody<Block, BlockProof> {
    fn into_proto(&self) -> node::ConsensusMessageBody {
        let mut proto = node::ConsensusMessageBody::new();
        match self {
            ConsensusMessageBody::Proposal { request, proof } => match (request, proof) {
                (Block::KeyBlock(block), BlockProof::KeyBlockProof) => {
                    let mut proposal = node::KeyBlockProposal::new();
                    proposal.set_block(block.into_proto());
                    proto.set_key_block_proposal(proposal);
                }
                (Block::MonetaryBlock(block), BlockProof::MonetaryBlockProof(proof)) => {
                    let mut proposal = node::MonetaryBlockProposal::new();
                    proposal.set_block(block.into_proto());
                    for tx_hash in &proof.tx_hashes {
                        proposal.tx_hashes.push(tx_hash.into_proto());
                    }
                    if let Some(ref fee_output) = proof.fee_output {
                        proposal.set_fee_output(fee_output.into_proto());
                    }
                    proposal.set_gamma(proof.gamma.into_proto());
                    proto.set_monetary_block_proposal(proposal);
                }
                _ => unreachable!(),
            },
            ConsensusMessageBody::Prevote {} => {
                proto.set_prevote(node::Prevote::new());
            }
            ConsensusMessageBody::Precommit { request_hash_sig } => {
                let mut msg = node::Precommit::new();
                msg.set_request_hash_sig(request_hash_sig.into_proto());
                proto.set_precommit(msg);
            }
        }
        proto
    }
}

impl FromProto<node::ConsensusMessageBody> for ConsensusMessageBody<Block, BlockProof> {
    fn from_proto(proto: &node::ConsensusMessageBody) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(node::ConsensusMessageBody_oneof_body::monetary_block_proposal(ref msg)) => {
                let request = Block::MonetaryBlock(MonetaryBlock::from_proto(msg.get_block())?);
                let fee_output = if msg.has_fee_output() {
                    Some(Output::from_proto(msg.get_fee_output())?)
                } else {
                    None
                };
                let gamma = Fr::from_proto(msg.get_gamma())?;
                let mut tx_hashes = Vec::with_capacity(msg.tx_hashes.len());
                for tx_hash in msg.tx_hashes.iter() {
                    tx_hashes.push(Hash::from_proto(tx_hash)?);
                }
                let proof = MonetaryBlockProof {
                    fee_output,
                    gamma,
                    tx_hashes,
                };
                let proof = BlockProof::MonetaryBlockProof(proof);
                ConsensusMessageBody::Proposal { request, proof }
            }
            Some(node::ConsensusMessageBody_oneof_body::key_block_proposal(ref msg)) => {
                let request = Block::KeyBlock(KeyBlock::from_proto(msg.get_block())?);
                let proof = BlockProof::KeyBlockProof;
                ConsensusMessageBody::Proposal { request, proof }
            }
            Some(node::ConsensusMessageBody_oneof_body::prevote(ref _msg)) => {
                ConsensusMessageBody::Prevote {}
            }
            Some(node::ConsensusMessageBody_oneof_body::precommit(ref msg)) => {
                let request_hash_sig = SecureSignature::from_proto(msg.get_request_hash_sig())?;
                ConsensusMessageBody::Precommit { request_hash_sig }
            }
            None => {
                return Err(ProtoError::MissingField("body".to_string(), "body".to_string()).into());
            }
        };
        Ok(msg)
    }
}

impl IntoProto<node::ConsensusMessage> for ConsensusMessage<Block, BlockProof> {
    fn into_proto(&self) -> node::ConsensusMessage {
        let mut proto = node::ConsensusMessage::new();
        proto.set_height(self.height);
        proto.set_epoch(self.epoch);
        proto.set_request_hash(self.request_hash.into_proto());
        proto.set_body(self.body.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
}

impl FromProto<node::ConsensusMessage> for ConsensusMessage<Block, BlockProof> {
    fn from_proto(proto: &node::ConsensusMessage) -> Result<Self, Error> {
        let height = proto.get_height();
        let epoch = proto.get_epoch();
        let request_hash = Hash::from_proto(proto.get_request_hash())?;
        let body = ConsensusMessageBody::from_proto(proto.get_body())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        Ok(ConsensusMessage {
            height,
            epoch,
            request_hash,
            body,
            sig,
            pkey,
        })
    }
}

//
// SealedBlock
//

impl IntoProto<node::SealedBlockMessage> for SealedBlockMessage {
    fn into_proto(&self) -> node::SealedBlockMessage {
        let mut proto = node::SealedBlockMessage::new();
        proto.set_block(self.block.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
}

impl FromProto<node::SealedBlockMessage> for SealedBlockMessage {
    fn from_proto(proto: &node::SealedBlockMessage) -> Result<Self, Error> {
        let block = Block::from_proto(proto.get_block())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        Ok(SealedBlockMessage { block, sig, pkey })
    }
}

//
// VRF types
//

impl IntoProto<node::VRF> for VRF {
    fn into_proto(&self) -> node::VRF {
        let mut proto = node::VRF::new();
        proto.set_rand(self.rand.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto
    }
}

impl FromProto<node::VRF> for VRF {
    fn from_proto(proto: &node::VRF) -> Result<Self, Error> {
        let rand = Hash::from_proto(proto.get_rand())?;
        let proof = G1::from_proto(proto.get_proof())?;
        Ok(VRF { rand, proof })
    }
}

impl IntoProto<node::VRFTicket> for VRFTicket {
    fn into_proto(&self) -> node::VRFTicket {
        let mut proto = node::VRFTicket::new();
        proto.set_random(self.random.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto
    }
}

impl FromProto<node::VRFTicket> for VRFTicket {
    fn from_proto(proto: &node::VRFTicket) -> Result<Self, Error> {
        let random = VRF::from_proto(proto.get_random())?;
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        Ok(VRFTicket { random, pkey, sig })
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

        let data = b"hello";
        let (output, _gamma) =
            Output::new_data(timestamp, &skey0, &pkey1, 1, data).expect("keys are valid");
        roundtrip(&output);

        let output = Output::new_escrow(timestamp, &skey1, &pkey1, &secure_pkey1, amount)
            .expect("keys are valid");
        roundtrip(&output);
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
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount).expect("keys are valid");
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
    fn consensus() {
        let (cosi_skey, cosi_pkey, cosi_sig) = make_secure_random_keys();

        let body = ConsensusMessageBody::Prevote {};
        let msg = ConsensusMessage::new(1, 1, Hash::digest(&1u64), &cosi_skey, &cosi_pkey, body);
        roundtrip(&msg);

        let body = ConsensusMessageBody::Precommit {
            request_hash_sig: cosi_sig,
        };
        let msg = ConsensusMessage::new(1, 1, Hash::digest(&1u64), &cosi_skey, &cosi_pkey, body);
        roundtrip(&msg);
    }

    #[test]
    fn sealed_block() {
        let (skey0, pkey0, _sig) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

        let witnesses: BTreeSet<SecurePublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();

        let block = Block::KeyBlock(KeyBlock::new(base, leader, witnesses));

        let sealed_block = SealedBlockMessage::new(&skey0, &pkey0, block);
        sealed_block.validate().unwrap();
        roundtrip(&sealed_block);
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

        let block = KeyBlock::new(base, leader, witnesses);
        roundtrip(&block.header);
        roundtrip(&block);

        let block = Block::KeyBlock(block);
        roundtrip(&block);

        //
        // KeyBlockProposal
        //
        let proof = BlockProof::KeyBlockProof;
        let proposal = ConsensusMessageBody::Proposal {
            request: block.clone(),
            proof,
        };
        roundtrip(&proposal);
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

        let block = MonetaryBlock::new(base, gamma.clone(), &inputs1, &outputs1);
        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::MonetaryBlock(block);
        roundtrip(&block);

        //
        // Monetary block proposal
        //

        let (fee_output, _fee_gamma) =
            Output::new_payment(timestamp, &skey1, &pkey1, 100).expect("keys are valid");
        let mut tx_hashes = Vec::new();
        tx_hashes.push(Hash::digest(&1u64));
        let proof = MonetaryBlockProof {
            fee_output: Some(fee_output),
            gamma: gamma.clone(),
            tx_hashes,
        };
        let proof = BlockProof::MonetaryBlockProof(proof);

        let proposal = ConsensusMessageBody::Proposal {
            request: block.clone(),
            proof,
        };
        roundtrip(&proposal);

        let proof = MonetaryBlockProof {
            fee_output: None,
            gamma: gamma.clone(),
            tx_hashes: Vec::new(),
        };
        let proof = BlockProof::MonetaryBlockProof(proof);
        let proposal = ConsensusMessageBody::Proposal {
            request: block.clone(),
            proof,
        };
        roundtrip(&proposal);
    }

    #[test]
    fn vrf_tickets() {
        let seed = Hash::digest(&"test".to_string());
        let (skey1, pkey1, _sig1) = make_secure_random_keys();

        let vrf = VRFTicket::new(seed, pkey1, &skey1);
        roundtrip(&vrf);
    }
}

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

use failure::Error;
use stegos_serialization::traits::*;

use crate::blockchain::*;
use crate::message::*;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;

// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for BlockConsensusMessageBody {
    type Proto = consensus::ConsensusMessageBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = consensus::ConsensusMessageBody::new();
        match self {
            ConsensusMessageBody::Proposal {
                request: block,
                proof: _proof,
            } => {
                let mut proposal = consensus::KeyBlockProposal::new();
                proposal.set_block(block.into_proto());
                proto.set_key_block_proposal(proposal);
            }
            ConsensusMessageBody::Prevote {} => {
                proto.set_prevote(consensus::Prevote::new());
            }
            ConsensusMessageBody::Precommit { request_hash_sig } => {
                let mut msg = consensus::Precommit::new();
                msg.set_request_hash_sig(request_hash_sig.into_proto());
                proto.set_precommit(msg);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(consensus::ConsensusMessageBody_oneof_body::key_block_proposal(ref msg)) => {
                let request = KeyBlock::from_proto(msg.get_block())?;
                let proof = ();
                ConsensusMessageBody::Proposal { request, proof }
            }
            Some(consensus::ConsensusMessageBody_oneof_body::prevote(ref _msg)) => {
                ConsensusMessageBody::Prevote {}
            }
            Some(consensus::ConsensusMessageBody_oneof_body::precommit(ref msg)) => {
                let request_hash_sig = secure::Signature::from_proto(msg.get_request_hash_sig())?;
                ConsensusMessageBody::Precommit { request_hash_sig }
            }
            None => {
                return Err(ProtoError::MissingField("body".to_string(), "body".to_string()).into());
            }
        };
        Ok(msg)
    }
}

impl ProtoConvert for BlockConsensusMessage {
    type Proto = consensus::ConsensusMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = consensus::ConsensusMessage::new();
        proto.set_height(self.height);
        proto.set_epoch(self.epoch);
        proto.set_request_hash(self.request_hash.into_proto());
        proto.set_body(self.body.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let height = proto.get_height();
        let epoch = proto.get_epoch();
        let request_hash = Hash::from_proto(proto.get_request_hash())?;
        let body = ConsensusMessageBody::from_proto(proto.get_body())?;
        let sig = secure::Signature::from_proto(proto.get_sig())?;
        let pkey = secure::PublicKey::from_proto(proto.get_pkey())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeSet;
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
    fn consensus() {
        let (network_skey, network_pkey, network_sig) = make_secure_random_keys();

        let body = ConsensusMessageBody::Prevote {};
        let msg = ConsensusMessage::new(
            1,
            1,
            Hash::digest(&1u64),
            &network_skey,
            &network_pkey,
            body,
        );
        roundtrip(&msg);

        let body = ConsensusMessageBody::Precommit {
            request_hash_sig: network_sig,
        };
        let msg = ConsensusMessage::new(
            1,
            1,
            Hash::digest(&1u64),
            &network_skey,
            &network_pkey,
            body,
        );
        roundtrip(&msg);
    }

    #[test]
    fn key_blocks() {
        let (skey0, pkey0, _sig0) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());

        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let validators: BTreeSet<secure::PublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();
        let facilitator = pkey0.clone();
        let random = secure::make_VRF(&skey0, &Hash::digest("test"));
        let block = KeyBlock::new(base, leader, facilitator, random, 0, validators);

        //
        // KeyBlockProposal
        //
        let proof = ();
        let proposal = ConsensusMessageBody::Proposal {
            request: block.clone(),
            proof,
        };
        roundtrip(&proposal);
    }
}

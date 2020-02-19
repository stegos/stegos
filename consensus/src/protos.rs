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

use failure::Error;
use stegos_serialization::traits::*;

use crate::message::*;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for ConsensusMessageBody {
    type Proto = consensus::ConsensusMessageBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = consensus::ConsensusMessageBody::new();
        match self {
            ConsensusMessageBody::Proposal(block_proposal) => {
                let mut proposal = consensus::MacroBlockProposal::new();
                proposal.set_header(block_proposal.header.into_proto());
                for transaction in &block_proposal.transactions {
                    proposal.transactions.push(transaction.into_proto());
                }
                proto.set_macro_block_proposal(proposal);
            }
            ConsensusMessageBody::Prevote => {
                proto.set_prevote(consensus::Prevote::new());
            }
            ConsensusMessageBody::Precommit(block_hash_sig) => {
                let mut msg = consensus::Precommit::new();
                msg.set_block_hash_sig(block_hash_sig.into_proto());
                proto.set_precommit(msg);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(consensus::ConsensusMessageBody_oneof_body::macro_block_proposal(ref msg)) => {
                let header = MacroBlockHeader::from_proto(msg.get_header())?;
                let mut transactions = Vec::<Transaction>::with_capacity(msg.transactions.len());
                for transaction in msg.transactions.iter() {
                    transactions.push(Transaction::from_proto(transaction)?);
                }
                let block_proposal = MacroBlockProposal {
                    header,
                    transactions,
                };
                ConsensusMessageBody::Proposal(block_proposal)
            }
            Some(consensus::ConsensusMessageBody_oneof_body::prevote(ref _msg)) => {
                ConsensusMessageBody::Prevote
            }
            Some(consensus::ConsensusMessageBody_oneof_body::precommit(ref msg)) => {
                let block_hash_sig = pbc::Signature::from_proto(msg.get_block_hash_sig())?;
                ConsensusMessageBody::Precommit(block_hash_sig)
            }
            None => {
                return Err(
                    ProtoError::MissingField("body".to_string(), "body".to_string()).into(),
                );
            }
        };
        Ok(msg)
    }
}

impl ProtoConvert for ConsensusMessage {
    type Proto = consensus::ConsensusMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = consensus::ConsensusMessage::new();
        proto.set_epoch(self.epoch);
        proto.set_round(self.round);
        proto.set_block_hash(self.block_hash.into_proto());
        proto.set_body(self.body.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        let round = proto.get_round();
        let block_hash = Hash::from_proto(proto.get_block_hash())?;
        let body = ConsensusMessageBody::from_proto(proto.get_body())?;
        let sig = pbc::Signature::from_proto(proto.get_sig())?;
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        Ok(ConsensusMessage {
            epoch,
            round,
            block_hash,
            body,
            sig,
            pkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bit_vec::BitVec;
    use stegos_blockchain::Timestamp;
    use stegos_crypto::hash::{Hashable, Hasher};
    use stegos_crypto::{pbc, scc};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    impl Hashable for ConsensusMessage {
        fn hash(&self, state: &mut Hasher) {
            self.epoch.hash(state);
            self.round.hash(state);
            self.block_hash.hash(state);
            self.body.hash(state);
            self.pkey.hash(state);
            self.sig.hash(state);
        }
    }

    #[test]
    fn consensus() {
        let (network_skey, network_pkey) = pbc::make_random_keys();

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

        let block_hash_sig = pbc::sign_hash(&Hash::digest("test"), &network_skey);
        let body = ConsensusMessageBody::Precommit(block_hash_sig);

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
    fn macro_blocks() {
        let (skey, pkey) = scc::make_random_keys();
        let (nskey, npkey) = pbc::make_random_keys();

        let epoch: u64 = 10;
        let view_change = 0;
        let timestamp = Timestamp::now();
        let previous = Hash::digest(&"test".to_string());
        let random = pbc::make_VRF(&nskey, &Hash::digest("test"));
        let difficulty = 100500;
        let block_reward = 0;
        let activity_map = BitVec::new();
        let validators = vec![(npkey.clone(), 100500i64)];
        let block = MacroBlock::empty(
            previous,
            epoch,
            view_change,
            npkey,
            random,
            difficulty,
            timestamp,
            block_reward,
            activity_map,
            validators,
        );
        // Transactions.
        let (tx, _inputs, _outputs) =
            PaymentTransaction::new_test(&skey, &pkey, 300, 2, 100, 1, 100)
                .expect("Invalid transaction");
        let transactions: Vec<Transaction> = vec![tx.into()];

        //
        // MacroBlockProposal
        //
        let proposal = ConsensusMessageBody::Proposal(MacroBlockProposal {
            header: block.header,
            transactions,
        });
        roundtrip(&proposal);
    }
}

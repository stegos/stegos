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

use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use crate::consensus::SealedBlockMessage;

use crate::VRFTicket;
use failure::Error;
use stegos_blockchain::*;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;
use stegos_crypto::pbc::secure::VRF;

impl ProtoConvert for SealedBlockMessage {
    type Proto = node::SealedBlockMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = node::SealedBlockMessage::new();
        proto.set_block(self.block.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = Block::from_proto(proto.get_block())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        Ok(SealedBlockMessage { block, sig, pkey })
    }
}

impl ProtoConvert for VRFTicket {
    type Proto = node::VRFTicket;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = node::VRFTicket::new();
        proto.set_random(self.random.into_proto());
        proto.set_height(self.height);
        proto.set_pkey(self.pkey.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let random = VRF::from_proto(proto.get_random())?;
        let height = proto.get_height();
        let pkey = SecurePublicKey::from_proto(proto.get_pkey())?;
        let sig = SecureSignature::from_proto(proto.get_sig())?;
        Ok(VRFTicket {
            random,
            height,
            pkey,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeSet;
    use stegos_crypto::hash::{Hash, Hashable};
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
    fn sealed_block() {
        let (skey0, pkey0, _sig) = make_secure_random_keys();

        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = Utc::now().timestamp() as u64;
        let previous = Hash::digest(&"test".to_string());
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

        let witnesses: BTreeSet<SecurePublicKey> = [pkey0].iter().cloned().collect();
        let leader = pkey0.clone();
        let facilitator = pkey0.clone();

        let block = Block::KeyBlock(KeyBlock::new(base, leader, facilitator, witnesses));

        let sealed_block = SealedBlockMessage::new(&skey0, &pkey0, block);
        sealed_block.validate().unwrap();
        roundtrip(&sealed_block);
    }

    #[test]
    fn vrf_tickets() {
        let seed = Hash::digest(&"test".to_string());
        let (skey1, pkey1, _sig1) = make_secure_random_keys();

        let vrf = VRFTicket::new(seed, 0, pkey1, &skey1);
        roundtrip(&vrf);
    }
}

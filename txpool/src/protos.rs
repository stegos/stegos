//
// Copyright (c) 2019 Stegos
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

use stegos_crypto::pbc::secure;

use failure::Error;

use crate::messages::{Message, PoolInfo};

use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for Message {
    type Proto = txpool::Message;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::Message::new();
        proto.set_pkey(self.pkey.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let pkey = secure::PublicKey::from_proto(proto.get_pkey())?;
        Ok(Message { pkey })
    }
}

impl ProtoConvert for PoolInfo {
    type Proto = txpool::PoolInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::PoolInfo::new();
        proto.set_pkey(self.pkey.into_proto());
        proto.set_sig(self.sig.into_proto());
        for msg in &self.accumulator {
            proto.accumulator.push(msg.into_proto());
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let pkey = secure::PublicKey::from_proto(proto.get_pkey())?;
        let sig = secure::Signature::from_proto(proto.get_sig())?;
        let mut accumulator = Vec::new();
        for msg in proto.get_accumulator().iter() {
            let msg = Message::from_proto(msg)?;
            accumulator.push(msg);
        }
        Ok(PoolInfo {
            pkey,
            sig,
            accumulator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stegos_crypto::hash::{Hash, Hashable};
    use stegos_crypto::pbc::secure;

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn message() {
        let (_, pkey0, _) = secure::make_random_keys();

        let message = Message { pkey: pkey0 };
        roundtrip(&message);
    }

    #[test]
    fn pool_info() {
        let (_, pkey0, _) = secure::make_random_keys();

        let message1 = Message { pkey: pkey0 };
        let (_, pkey, sig) = secure::make_random_keys();

        let message2 = Message { pkey };
        let accumulator = vec![message1, message2];
        let pool = PoolInfo {
            pkey,
            sig,
            accumulator,
        };
        roundtrip(&pool);
    }
}

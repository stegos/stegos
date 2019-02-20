//
// Copyright (c) 2019 Stegos AG
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
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_serialization::traits::*;

use crate::messages::{PoolInfo, PoolJoin};

use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for PoolJoin {
    type Proto = txpool::PoolJoin;
    fn into_proto(&self) -> Self::Proto {
        txpool::PoolJoin::new()
    }
    fn from_proto(_proto: &Self::Proto) -> Result<Self, Error> {
        Ok(PoolJoin {})
    }
}

impl ProtoConvert for PoolInfo {
    type Proto = txpool::PoolInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::PoolInfo::new();
        for msg in &self.participants {
            proto.participants.push(msg.into_proto());
        }
        proto.set_session_id(self.session_id.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut participants = Vec::new();
        for msg in proto.get_participants() {
            let pkey = secure::PublicKey::from_proto(msg)?;
            participants.push(pkey);
        }
        let session_id = Hash::from_proto(proto.get_session_id())?;
        Ok(PoolInfo {
            participants,
            session_id,
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
        let message = PoolJoin {};
        roundtrip(&message);
    }

    #[test]
    fn pool_info() {
        let (_, pkey, _) = secure::make_random_keys();
        let (_, pkey1, _) = secure::make_random_keys();

        let session_id = Hash::digest(&1u64);
        let mut participants: Vec<secure::PublicKey> = Vec::new();
        participants.push(pkey.clone());
        participants.push(pkey1);
        let pool = PoolInfo {
            participants,
            session_id,
        };
        roundtrip(&pool);
    }
}

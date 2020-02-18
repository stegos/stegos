//! Protobuf Definitions.

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
//use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use failure::{format_err, Error};
use protobuf::RepeatedField;
use stegos_blockchain::Block;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_serialization::traits::ProtoConvert;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RequestBlocks {
    pub epoch: u64,
}

impl Hashable for RequestBlocks {
    fn hash(&self, state: &mut Hasher) {
        self.epoch.hash(state);
    }
}

impl RequestBlocks {
    pub fn new(epoch: u64) -> RequestBlocks {
        Self { epoch }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseBlocks {
    pub blocks: Vec<Block>,
}

impl Hashable for ResponseBlocks {
    fn hash(&self, state: &mut Hasher) {
        for block in &self.blocks {
            block.hash(state);
        }
    }
}

impl ResponseBlocks {
    pub fn new(blocks: Vec<Block>) -> ResponseBlocks {
        Self { blocks }
    }
}

#[derive(Debug, Clone)]
pub enum ChainLoaderMessage {
    Request(RequestBlocks),
    Response(ResponseBlocks),
}

impl Hashable for ChainLoaderMessage {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ChainLoaderMessage::Request(r) => {
                "request".hash(state);
                r.hash(state)
            }
            ChainLoaderMessage::Response(r) => {
                "response".hash(state);
                r.hash(state)
            }
        }
    }
}

impl ProtoConvert for RequestBlocks {
    type Proto = loader::RequestBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::RequestBlocks::new();
        proto.set_epoch(self.epoch);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        Ok(RequestBlocks { epoch })
    }
}

impl ProtoConvert for ResponseBlocks {
    type Proto = loader::ResponseBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ResponseBlocks::new();
        let blocks: Vec<_> = self.blocks.iter().map(ProtoConvert::into_proto).collect();
        proto.set_blocks(RepeatedField::from_vec(blocks));
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let blocks: Result<Vec<_>, _> = proto
            .get_blocks()
            .iter()
            .map(ProtoConvert::from_proto)
            .collect();
        let blocks = blocks?;
        Ok(ResponseBlocks { blocks })
    }
}

impl ProtoConvert for ChainLoaderMessage {
    type Proto = loader::ChainLoaderMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ChainLoaderMessage::new();
        match self {
            ChainLoaderMessage::Request(r) => proto.set_request(r.into_proto()),
            ChainLoaderMessage::Response(r) => proto.set_response(r.into_proto()),
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let ref body = proto
            .body
            .as_ref()
            .ok_or_else(|| format_err!("No variants in ChainLoaderMessage found"))?;
        let chain_message = match body {
            loader::ChainLoaderMessage_oneof_body::request(ref r) => {
                ChainLoaderMessage::Request(RequestBlocks::from_proto(r)?)
            }
            loader::ChainLoaderMessage_oneof_body::response(ref r) => {
                ChainLoaderMessage::Response(ResponseBlocks::from_proto(r)?)
            }
        };
        Ok(chain_message)
    }
}

#[cfg(test)]
mod tests {
    /*
    use super::*;
    use stegos_crypto::hash::{Hash, Hashable};


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
        let message = PoolJoin { txins: Vec::<TXIN>::new(),
        ownsig: SchnorrSig::new() };
        roundtrip(&message);
    }

    #[test]
    fn pool_info() {
        let (_, pkey) = pbc::make_random_keys();
        let (_, pkey1) = pbc::make_random_keys();

        let session_id = Hash::digest(&1u64);
        let mut participants: Vec<pbc::PublicKey> = Vec::new();
        participants.push((pkey.clone(), Vec::new(), scc::SchnorrSig::new()));
        participants.push(pkey1);
        let pool = PoolInfo {
            participants,
            session_id,
        };
        roundtrip(&pool);
    }
    */
    use super::*;
    use stegos_crypto::hash::{Hash, Hashable};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn chain_loader() {
        let request = ChainLoaderMessage::Request(RequestBlocks::new(1));
        roundtrip(&request);
    }
}

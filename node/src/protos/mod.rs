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

use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use crate::loader::{ChainLoaderMessage, RequestBlocks, ResponseBlocks};
use failure::{format_err, Error};
use protobuf::RepeatedField;

impl ProtoConvert for RequestBlocks {
    type Proto = loader::RequestBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::RequestBlocks::new();
        proto.set_starting_height(self.starting_height);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let starting_height = proto.get_starting_height();
        Ok(RequestBlocks { starting_height })
    }
}

impl ProtoConvert for ResponseBlocks {
    type Proto = loader::ResponseBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ResponseBlocks::new();
        proto.set_height(self.height);
        let blocks: Vec<_> = self.blocks.iter().map(ProtoConvert::into_proto).collect();
        proto.set_blocks(RepeatedField::from_vec(blocks));
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let height = proto.get_height();
        let blocks: Result<Vec<_>, _> = proto
            .get_blocks()
            .iter()
            .map(ProtoConvert::from_proto)
            .collect();
        let blocks = blocks?;
        Ok(ResponseBlocks { height, blocks })
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

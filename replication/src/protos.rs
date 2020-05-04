//! Replication - Protocol Messages.

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
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use stegos_blockchain::protos::ProtoError;
use stegos_blockchain::{Block, LightBlock};
use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
pub enum NetworkName {
    Mainnet,
    Testnet,
    Devnet,
}

impl fmt::Display for NetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkName::Mainnet => write!(f, "mainnet"),
            NetworkName::Testnet => write!(f, "testnet"),
            NetworkName::Devnet => write!(f, "devnet"),
        }
    }
}

impl<'a> From<&'a str> for NetworkName {
    fn from(name: &'a str) -> Self {
        match name {
            "testnet" => NetworkName::Testnet,
            "dev" => NetworkName::Testnet,
            "mainnet" | _ => NetworkName::Mainnet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum ReplicationRequest {
    Subscribe {
        epoch: u64,
        offset: u32,
        light: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum ReplicationResponse {
    Subscribed {
        current_epoch: u64,
        current_offset: u32,
        network: NetworkName,
    },
    Block {
        current_epoch: u64,
        current_offset: u32,
        block: Block,
    },
    LightBlock {
        current_epoch: u64,
        current_offset: u32,
        block: LightBlock,
    },
}

impl ReplicationResponse {
    pub fn name(&self) -> &'static str {
        match self {
            ReplicationResponse::Subscribed { .. } => "Subscribed",
            ReplicationResponse::Block { .. } => "Block",
            ReplicationResponse::LightBlock { .. } => "LightBlock",
        }
    }
}

impl ProtoConvert for ReplicationRequest {
    type Proto = replication::ReplicationRequest;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = replication::ReplicationRequest::new();
        match self {
            ReplicationRequest::Subscribe {
                epoch,
                offset,
                light,
            } => {
                let mut request = replication::Subscribe::new();
                request.set_epoch(*epoch);
                request.set_offset(*offset);
                if !*light {
                    proto.set_subscribe_full(request);
                } else {
                    proto.set_subscribe_light(request);
                }
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.request {
            Some(replication::ReplicationRequest_oneof_request::subscribe_full(ref subscribe)) => {
                let epoch = subscribe.get_epoch();
                let offset = subscribe.get_offset();
                let light = false;
                let request = ReplicationRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                };
                Ok(request)
            }
            Some(replication::ReplicationRequest_oneof_request::subscribe_light(ref subscribe)) => {
                let epoch = subscribe.get_epoch();
                let offset = subscribe.get_offset();
                let light = true;
                let request = ReplicationRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                };
                Ok(request)
            }
            None => {
                return Err(
                    ProtoError::MissingField("request".to_string(), "request".to_string()).into(),
                );
            }
        }
    }
}

impl ProtoConvert for ReplicationResponse {
    type Proto = replication::ReplicationResponse;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = replication::ReplicationResponse::new();
        match self {
            ReplicationResponse::Subscribed {
                current_epoch,
                current_offset,
                network,
            } => {
                let mut response = replication::Subscribed::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                response.set_network(network.to_string());
                proto.set_subscribed(response);
            }
            ReplicationResponse::Block {
                current_epoch,
                current_offset,
                block,
            } => {
                let mut response = replication::Block::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                response.set_block(block.into_proto());
                proto.set_block(response);
            }
            ReplicationResponse::LightBlock {
                current_epoch,
                current_offset,
                block,
            } => {
                let mut response = replication::LightBlock::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                response.set_block(block.into_proto());
                proto.set_light_block(response);
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.response {
            Some(replication::ReplicationResponse_oneof_response::subscribed(ref subscribed)) => {
                let current_epoch = subscribed.get_current_epoch();
                let current_offset = subscribed.get_current_offset();
                let network = subscribed.get_network().into();
                let response = ReplicationResponse::Subscribed {
                    current_epoch,
                    current_offset,
                    network,
                };
                Ok(response)
            }
            Some(replication::ReplicationResponse_oneof_response::block(ref block)) => {
                let current_epoch = block.get_current_epoch();
                let current_offset = block.get_current_offset();
                let block = Block::from_proto(block.get_block())?;
                let response = ReplicationResponse::Block {
                    current_epoch,
                    current_offset,
                    block,
                };
                Ok(response)
            }
            Some(replication::ReplicationResponse_oneof_response::light_block(ref block)) => {
                let current_epoch = block.get_current_epoch();
                let current_offset = block.get_current_offset();
                let block = LightBlock::from_proto(block.get_block())?;
                let response = ReplicationResponse::LightBlock {
                    current_epoch,
                    current_offset,
                    block,
                };
                Ok(response)
            }
            None => {
                return Err(
                    ProtoError::MissingField("response".to_string(), "block".to_string()).into(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stegos_crypto::hash::{Hash, Hashable, Hasher};

    impl Hashable for ReplicationRequest {
        fn hash(&self, state: &mut Hasher) {
            match self {
                ReplicationRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                } => {
                    "ReplicationRequest::Subscribe".hash(state);
                    epoch.hash(state);
                    offset.hash(state);
                    light.hash(state);
                }
            }
        }
    }

    impl Hashable for ReplicationResponse {
        fn hash(&self, state: &mut Hasher) {
            match self {
                ReplicationResponse::Subscribed {
                    current_epoch,
                    current_offset,
                } => {
                    "ReplicationResponse::Subscribed".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                }
                ReplicationResponse::Block {
                    current_epoch,
                    current_offset,
                    block,
                } => {
                    "ReplicationResponse::Block".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                    block.hash(state);
                }
                ReplicationResponse::LightBlock {
                    current_epoch,
                    current_offset,
                    block,
                } => {
                    "ReplicationResponse::LightBlock".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                    block.hash(state);
                }
            }
        }
    }

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn requests() {
        let request = ReplicationRequest::Subscribe {
            epoch: 100500,
            offset: 12345,
            light: true,
        };
        roundtrip(&request);
    }

    #[test]
    fn responses() {
        let response = ReplicationResponse::Subscribed {
            current_epoch: 100500,
            current_offset: 12345,
        };
        roundtrip(&response);
    }
}

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

use crate::protos::replication;
use failure::Error;
use serde_derive::{Deserialize, Serialize};
use stegos_blockchain::protos::ProtoError;
use stegos_blockchain::Block;
use stegos_serialization::traits::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum ReplicationRequest {
    Subscribe { epoch: u64, offset: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum ReplicationResponse {
    Subscribed {
        current_epoch: u64,
        current_offset: u32,
    },
    Block {
        current_epoch: u64,
        current_offset: u32,
        block: Block,
    },
}

impl ProtoConvert for ReplicationRequest {
    type Proto = replication::ReplicationRequest;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = replication::ReplicationRequest::new();
        match self {
            ReplicationRequest::Subscribe { epoch, offset } => {
                let mut request = replication::Subscribe::new();
                request.set_epoch(*epoch);
                request.set_offset(*offset);
                proto.set_subscribe(request);
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.request {
            Some(replication::ReplicationRequest_oneof_request::subscribe(ref subscribe)) => {
                let epoch = subscribe.get_epoch();
                let offset = subscribe.get_offset();
                let request = ReplicationRequest::Subscribe { epoch, offset };
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
            } => {
                let mut response = replication::Subscribed::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
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
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.response {
            Some(replication::ReplicationResponse_oneof_response::subscribed(ref subscribed)) => {
                let current_epoch = subscribed.get_current_epoch();
                let current_offset = subscribed.get_current_offset();
                let response = ReplicationResponse::Subscribed {
                    current_epoch,
                    current_offset,
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
                ReplicationRequest::Subscribe { epoch, offset } => {
                    "ReplicationRequest::Subscribe".hash(state);
                    epoch.hash(state);
                    offset.hash(state);
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

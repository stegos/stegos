//! Sync - Protocol Messages.

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
use stegos_blockchain::protos::ProtoError;
use stegos_blockchain::{Block, LightBlock, Output};
use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum SyncRequest {
    Subscribe {
        epoch: u64,
        offset: u32,
        light: bool,
    },
    RequestOutputs(RequestOutputs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum SyncReply {
    Subscribed {
        current_epoch: u64,
        current_offset: u32,
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
    OutputsInfo(OutputsInfo),
}

impl SyncReply {
    pub fn name(&self) -> &'static str {
        match self {
            SyncReply::Subscribed { .. } => "Subscribed",
            SyncReply::Block { .. } => "Block",
            SyncReply::LightBlock { .. } => "LightBlock",
            SyncReply::OutputsInfo { .. } => "OutputsInfo",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOutputs {
    pub block_epoch: u64,
    pub block_offset: u32,
    pub outputs_ids: Vec<u32>,
}

// TODO: Limit vector sizes;
impl ProtoConvert for RequestOutputs {
    type Proto = sync::RequestOutputs;
    fn into_proto(&self) -> Self::Proto {
        let mut request = sync::RequestOutputs::new();
        request.set_block_epoch(self.block_epoch);
        request.set_block_offset(self.block_offset);

        for output_id in &self.outputs_ids {
            request.outputs_ids.push(*output_id);
        }
        request.outputs_ids.sort();
        request
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block_epoch = proto.get_block_epoch();
        let block_offset = proto.get_block_offset();
        let mut outputs_ids = Vec::<u32>::with_capacity(proto.outputs_ids.len());
        for output_id in proto.outputs_ids.iter() {
            outputs_ids.push(*output_id);
        }
        Ok(Self {
            block_epoch,
            block_offset,
            outputs_ids,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputsInfo {
    pub block_epoch: u64,
    pub block_offset: u32,
    pub found_outputs: Vec<Output>,
}

impl ProtoConvert for OutputsInfo {
    type Proto = sync::OutputsInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut info = sync::OutputsInfo::new();
        info.set_block_epoch(self.block_epoch);
        info.set_block_offset(self.block_offset);
        for output in &self.found_outputs {
            info.found_outputs.push(output.into_proto());
        }
        info
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block_epoch = proto.get_block_epoch();
        let block_offset = proto.get_block_offset();
        let mut found_outputs = Vec::<Output>::with_capacity(proto.found_outputs.len());
        for output in proto.found_outputs.iter() {
            found_outputs.push(Output::from_proto(output)?);
        }
        Ok(Self {
            block_epoch,
            block_offset,
            found_outputs,
        })
    }
}

impl ProtoConvert for SyncRequest {
    type Proto = sync::SyncRequest;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = sync::SyncRequest::new();
        match self {
            SyncRequest::Subscribe {
                epoch,
                offset,
                light,
            } => {
                let mut request = sync::Subscribe::new();
                request.set_epoch(*epoch);
                request.set_offset(*offset);
                if !*light {
                    proto.set_subscribe_full(request);
                } else {
                    proto.set_subscribe_light(request);
                }
            }
            SyncRequest::RequestOutputs(request_outputs) => {
                let request_outputs = request_outputs.into_proto();
                proto.set_request_outputs(request_outputs);
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.request {
            Some(sync::SyncRequest_oneof_request::subscribe_full(ref subscribe)) => {
                let epoch = subscribe.get_epoch();
                let offset = subscribe.get_offset();
                let light = false;
                let request = SyncRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                };
                Ok(request)
            }
            Some(sync::SyncRequest_oneof_request::subscribe_light(ref subscribe)) => {
                let epoch = subscribe.get_epoch();
                let offset = subscribe.get_offset();
                let light = true;
                let request = SyncRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                };
                Ok(request)
            }
            Some(sync::SyncRequest_oneof_request::request_outputs(ref request_outputs)) => {
                let request =
                    SyncRequest::RequestOutputs(RequestOutputs::from_proto(request_outputs)?);
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

impl ProtoConvert for SyncReply {
    type Proto = sync::SyncReply;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = sync::SyncReply::new();
        match self {
            SyncReply::Subscribed {
                current_epoch,
                current_offset,
            } => {
                let mut response = sync::Subscribed::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                proto.set_subscribed(response);
            }
            SyncReply::Block {
                current_epoch,
                current_offset,
                block,
            } => {
                let mut response = sync::Block::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                response.set_block(block.into_proto());
                proto.set_block(response);
            }
            SyncReply::LightBlock {
                current_epoch,
                current_offset,
                block,
            } => {
                let mut response = sync::LightBlock::new();
                response.set_current_epoch(*current_epoch);
                response.set_current_offset(*current_offset);
                response.set_block(block.into_proto());
                proto.set_light_block(response);
            }
            SyncReply::OutputsInfo(outputs_info) => {
                let response = outputs_info.into_proto();
                proto.set_outputs_info(response);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.response {
            Some(sync::SyncReply_oneof_response::subscribed(ref subscribed)) => {
                let current_epoch = subscribed.get_current_epoch();
                let current_offset = subscribed.get_current_offset();
                let response = SyncReply::Subscribed {
                    current_epoch,
                    current_offset,
                };
                Ok(response)
            }
            Some(sync::SyncReply_oneof_response::block(ref block)) => {
                let current_epoch = block.get_current_epoch();
                let current_offset = block.get_current_offset();
                let block = Block::from_proto(block.get_block())?;
                let response = SyncReply::Block {
                    current_epoch,
                    current_offset,
                    block,
                };
                Ok(response)
            }
            Some(sync::SyncReply_oneof_response::light_block(ref block)) => {
                let current_epoch = block.get_current_epoch();
                let current_offset = block.get_current_offset();
                let block = LightBlock::from_proto(block.get_block())?;
                let response = SyncReply::LightBlock {
                    current_epoch,
                    current_offset,
                    block,
                };
                Ok(response)
            }
            Some(sync::SyncReply_oneof_response::outputs_info(ref outputs_info)) => {
                let response = SyncReply::OutputsInfo(OutputsInfo::from_proto(&outputs_info)?);
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

    impl Hashable for SyncRequest {
        fn hash(&self, state: &mut Hasher) {
            match self {
                SyncRequest::Subscribe {
                    epoch,
                    offset,
                    light,
                } => {
                    "SyncRequest::Subscribe".hash(state);
                    epoch.hash(state);
                    offset.hash(state);
                    light.hash(state);
                }
                SyncRequest::RequestOutputs(request_outputs) => request_outputs.hash(state),
            }
        }
    }

    impl Hashable for OutputsInfo {
        fn hash(&self, state: &mut Hasher) {
            self.block_epoch.hash(state);
            self.block_offset.hash(state);
            for output in &self.found_outputs {
                output.hash(state);
            }
        }
    }

    impl Hashable for RequestOutputs {
        fn hash(&self, state: &mut Hasher) {
            self.block_epoch.hash(state);
            self.block_offset.hash(state);
            for output in &self.outputs_ids {
                output.hash(state);
            }
        }
    }

    impl Hashable for SyncReply {
        fn hash(&self, state: &mut Hasher) {
            match self {
                SyncReply::Subscribed {
                    current_epoch,
                    current_offset,
                } => {
                    "SyncReply::Subscribed".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                }
                SyncReply::Block {
                    current_epoch,
                    current_offset,
                    block,
                } => {
                    "SyncReply::Block".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                    block.hash(state);
                }
                SyncReply::LightBlock {
                    current_epoch,
                    current_offset,
                    block,
                } => {
                    "SyncReply::LightBlock".hash(state);
                    current_epoch.hash(state);
                    current_offset.hash(state);
                    block.hash(state);
                }
                SyncReply::OutputsInfo(outputs_info) => {
                    "SyncReply::OutputsInfo".hash(state);
                    outputs_info.hash(state);
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
        let request = SyncRequest::Subscribe {
            epoch: 100500,
            offset: 12345,
            light: true,
        };
        roundtrip(&request);
    }

    #[test]
    fn responses() {
        let response = SyncReply::Subscribed {
            current_epoch: 100500,
            current_offset: 12345,
        };
        roundtrip(&response);
    }
}

//! message.rs - ValueShuffle Protobuf Encoding.

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

use super::message::*;
use failure::Error;
use stegos_serialization::traits::*;

// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/valueshuffle/mod.rs"));

impl ProtoConvert for Message {
    type Proto = valueshuffle::Message;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = valueshuffle::Message::new();
        match self {
            Message::Example { payload } => {
                let mut example = valueshuffle::Example::new();
                example.set_payload(payload.clone());
                proto.set_example(example);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(valueshuffle::Message_oneof_body::example(ref msg)) => {
                let payload = msg.get_payload().to_string();
                Message::Example { payload }
            }
            None => {
                return Err(ProtoError::MissingField("body".to_string(), "body".to_string()).into());
            }
        };
        Ok(msg)
    }
}

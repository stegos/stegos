// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::pubsub::proto::pubsub_proto as rpc_proto;

use bytes::{BufMut, BytesMut};
use futures::future;
use libp2p_core::{upgrade::Negotiated, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use protobuf::Message as ProtobufMessage;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::{io, iter};
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

/// Implementation of `ConnectionUpgrade` for the floodsub protocol.
#[derive(Debug, Clone)]
pub struct FloodsubConfig {}

impl FloodsubConfig {
    /// Builds a new `FloodsubConfig`.
    #[inline]
    pub fn new() -> FloodsubConfig {
        FloodsubConfig {}
    }
}

impl UpgradeInfo for FloodsubConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/floodsub/1.0.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for FloodsubConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<Negotiated<TSocket>, FloodsubCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            FloodsubCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for FloodsubConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<Negotiated<TSocket>, FloodsubCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            FloodsubCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct FloodsubCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for FloodsubCodec {
    type Item = FloodsubRpc;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut proto = rpc_proto::RPC::new();

        for message in item.messages.into_iter() {
            let mut msg = rpc_proto::Message::new();
            msg.set_data(message.data);
            msg.set_topic(message.topic);
            proto.mut_publish().push(msg);
        }

        for topic in item.subscriptions.into_iter() {
            let mut subscription = rpc_proto::RPC_SubOpts::new();
            subscription.set_subscribe(topic.action == FloodsubSubscriptionAction::Subscribe);
            subscription.set_topic(topic.topic);
            proto.mut_subscriptions().push(subscription);
        }

        let msg_size = proto.compute_size();
        // Reserve enough space for the data and the length. The length has a maximum of 32 bits,
        // which means that 5 bytes is enough for the variable-length integer.
        dst.reserve(msg_size as usize + 5);

        proto
            .write_length_delimited_to_writer(&mut dst.by_ref().writer())
            .expect(
                "there is no situation in which the protobuf message can be invalid, and \
                 writing to a BytesMut never fails as we reserved enough space beforehand",
            );
        Ok(())
    }
}

impl Decoder for FloodsubCodec {
    type Item = FloodsubRpc;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };

        let mut rpc: rpc_proto::RPC = protobuf::parse_from_bytes(&packet)?;

        let mut messages = Vec::with_capacity(rpc.get_publish().len());
        for mut publish in rpc.take_publish().into_iter() {
            messages.push(FloodsubMessage {
                data: publish.take_data(),
                topic: publish.take_topic(),
            });
        }

        Ok(Some(FloodsubRpc {
            messages,
            subscriptions: rpc
                .take_subscriptions()
                .into_iter()
                .map(|mut sub| FloodsubSubscription {
                    action: if sub.get_subscribe() {
                        FloodsubSubscriptionAction::Subscribe
                    } else {
                        FloodsubSubscriptionAction::Unsubscribe
                    },
                    topic: sub.take_topic(),
                })
                .collect(),
        }))
    }
}

/// An RPC received by the floodsub system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FloodsubRpc {
    /// List of messages that were part of this RPC query.
    pub messages: Vec<FloodsubMessage>,
    /// List of subscriptions.
    pub subscriptions: Vec<FloodsubSubscription>,
}

/// A message received by the floodsub system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FloodsubMessage {
    /// The topic message belong to.
    pub topic: String,

    /// Content of the message. Its meaning is out of scope of this library.
    pub data: Vec<u8>,
}

impl FloodsubMessage {
    pub fn digest(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// A subscription received by the floodsub system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FloodsubSubscription {
    /// Action to perform.
    pub action: FloodsubSubscriptionAction,
    /// The topic from which to subscribe or unsubscribe.
    pub topic: String,
}

/// Action that a subscription wants to perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FloodsubSubscriptionAction {
    /// The remote wants to subscribe to the given topic.
    Subscribe,
    /// The remote wants to unsubscribe from the given topic.
    Unsubscribe,
}

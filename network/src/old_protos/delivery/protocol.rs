//
// MIT License
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

use crate::metrics;

use crate::utils::FutureResult;
use bytes::buf::ext::BufMutExt;
use bytes::BytesMut;
use futures::future;
use futures_codec::{Decoder, Encoder, Framed};
use futures_io::{AsyncRead, AsyncWrite};
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use protobuf::Message;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::{io, iter};
use stegos_crypto::pbc;
use unsigned_varint::codec;

use super::proto::delivery_proto;

// Protocol label for metrics
const PROTOCOL_LABEL: &str = "delivery";

/// Implementation of `ConnectionUpgrade` for the floodsub protocol.
#[derive(Default, Debug, Clone)]
pub struct DeliveryConfig {}

impl DeliveryConfig {
    /// Builds a new `DeliveryConfig`.
    #[inline]
    pub fn new() -> DeliveryConfig {
        DeliveryConfig {}
    }
}

impl UpgradeInfo for DeliveryConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/stegos/delivery/1.0.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for DeliveryConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, DeliveryCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            DeliveryCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for DeliveryConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, DeliveryCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            DeliveryCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct DeliveryCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for DeliveryCodec {
    type Item = DeliveryMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let proto = match item {
            DeliveryMessage::UnicastMessage(unicast) => {
                let mut msg = delivery_proto::Message::new();
                msg.set_seqno(unicast.seq_no);
                let mut unicast_proto = delivery_proto::Unicast::new();
                unicast_proto.set_to(unicast.to.to_bytes().to_vec());
                unicast_proto.set_payload(unicast.payload);
                unicast_proto.set_dont_route(unicast.dont_route);
                msg.set_unicast(unicast_proto);
                msg
            }
            DeliveryMessage::BroadcastMessage(broadcast) => {
                let mut msg = delivery_proto::Message::new();
                msg.set_seqno(broadcast.seq_no);
                let mut broadcast_proto = delivery_proto::Broadcast::new();
                broadcast_proto.set_payload(broadcast.payload);
                broadcast_proto.set_from(broadcast.from.to_bytes().to_vec());
                for t in broadcast.topics.iter() {
                    broadcast_proto.topics.push(t.to_string());
                }
                msg.set_broadcast(broadcast_proto);
                msg
            }
        };

        let msg_size = proto.compute_size();
        // Reserve enough space for the data and the length. The length has a maximum of 32 bits,
        // which means that 5 bytes is enough for the variable-length integer.
        dst.reserve(msg_size as usize + 5);
        metrics::OUTGOING_TRAFFIC
            .with_label_values(&[&PROTOCOL_LABEL])
            .inc_by(msg_size as i64);

        proto
            .write_length_delimited_to_writer(&mut dst.writer())
            .expect(
                "there is no situation in which the protobuf message can be invalid, and \
                 writing to a BytesMut never fails as we reserved enough space beforehand",
            );
        Ok(())
    }
}

impl Decoder for DeliveryCodec {
    type Item = DeliveryMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };
        metrics::INCOMING_TRAFFIC
            .with_label_values(&[&PROTOCOL_LABEL])
            .inc_by(packet.len() as i64);
        let message: delivery_proto::Message = protobuf::parse_from_bytes(&packet)?;

        let seq_no = message.get_seqno().to_vec();

        match message.typ {
            Some(delivery_proto::Message_oneof_typ::unicast(msg)) => {
                let to = pbc::PublicKey::try_from_bytes(msg.get_to()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad protobuf encoding, failed to decode unicast to field",
                    )
                })?;
                let payload = msg.get_payload().to_vec();
                let dont_route = msg.get_dont_route();
                Ok(Some(DeliveryMessage::UnicastMessage(Unicast {
                    to,
                    payload,
                    dont_route,
                    seq_no,
                })))
            }
            Some(delivery_proto::Message_oneof_typ::broadcast(msg)) => {
                let mut topics: Vec<String> = Vec::new();
                let from = pbc::PublicKey::try_from_bytes(msg.get_from()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad protobuf encoding, failed to decode broadcast from field",
                    )
                })?;
                let payload = msg.get_payload().to_vec();
                for t in msg.get_topics().iter() {
                    topics.push(t.to_string());
                }
                Ok(Some(DeliveryMessage::BroadcastMessage(Broadcast {
                    from,
                    payload,
                    topics,
                    seq_no,
                })))
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad protobuf encoding, unknown message type",
            )),
        }
    }
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum DeliveryMessage {
    UnicastMessage(Unicast),
    BroadcastMessage(Broadcast),
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Unicast {
    pub to: pbc::PublicKey,
    pub payload: Vec<u8>,
    pub dont_route: bool,
    pub seq_no: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Broadcast {
    pub from: pbc::PublicKey,
    pub topics: Vec<String>,
    pub payload: Vec<u8>,
    pub seq_no: Vec<u8>,
}

impl Unicast {
    pub fn digest(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl Broadcast {
    pub fn digest(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Broadcast, DeliveryCodec, DeliveryMessage, Unicast};
    use async_std::net::{TcpListener, TcpStream};
    use futures::future;
    use futures::prelude::*;
    use futures_codec::Framed;
    use rand;
    use stegos_crypto::pbc;

    #[test]
    fn correct_transfer() {
        let (_, pkey) = pbc::make_random_keys();

        let msg = DeliveryMessage::UnicastMessage(Unicast {
            to: pkey,
            payload: random_vec(1024),
            dont_route: false,
            seq_no: rand::random::<[u8; 20]>().to_vec(),
        });

        test_one(msg, "127.0.0.1:12644".parse().unwrap());

        let (_, node_id) = pbc::make_random_keys();

        let msg = DeliveryMessage::BroadcastMessage(Broadcast {
            from: node_id,
            payload: random_vec(1024),
            topics: vec![
                "topic1".to_string(),
                "topic2".to_string(),
                "topic3".to_string(),
                "topic4".to_string(),
            ],
            seq_no: rand::random::<[u8; 20]>().to_vec(),
        });

        test_one(msg, "127.0.0.1:12643".parse().unwrap());
    }

    fn test_one(msg: DeliveryMessage, listener_addr: std::net::SocketAddr) {
        let msg_server = msg.clone();
        let msg_client = msg.clone();

        let server = Box::pin(async {
            let listener = TcpListener::bind(&listener_addr).await.unwrap();
            let (client, addr) = listener.accept().await.unwrap();
            let mut client = Framed::new(
                client,
                DeliveryCodec {
                    length_prefix: Default::default(),
                },
            );
            let msg = client.next().await.unwrap().unwrap();
            let msg = msg.clone();
            assert_eq!(msg, msg_server);
        });

        let client_future = Box::pin(async {
            let client = TcpStream::connect(&listener_addr).await.unwrap();
            let mut s = Framed::new(
                client,
                DeliveryCodec {
                    length_prefix: Default::default(),
                },
            );
            s.send(msg_client).await;
        });

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(futures::future::join(server, client_future));
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

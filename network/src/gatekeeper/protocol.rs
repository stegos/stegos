//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

use bytes::{BufMut, BytesMut};
use futures::future;
use libp2p::core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p::Multiaddr;
use protobuf::Message as ProtobufMessage;
use std::{io, iter};
use stegos_crypto::pbc::secure;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

use super::proto::gatekeeper_proto::{
    self, ConnectionType as ProtoConnectionType, Message, Message_oneof_typ,
};

/// Implementation of `ConnectionUpgrade` for the Gatekeeper protocol.
#[derive(Debug, Clone, Default)]
pub struct GatekeeperConfig {}

impl GatekeeperConfig {
    pub fn new() -> Self {
        GatekeeperConfig {}
    }
}

impl UpgradeInfo for GatekeeperConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/stegos/gatekeeper/0.1.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for GatekeeperConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, GatekeeperCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            GatekeeperCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for GatekeeperConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, GatekeeperCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            GatekeeperCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct GatekeeperCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for GatekeeperCodec {
    type Item = GatekeeperMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let proto = match item {
            GatekeeperMessage::Request { conn_type, node_id } => {
                let mut msg_typ = gatekeeper_proto::HelloRequest::new();
                msg_typ.set_conn_type(conn_type.into());
                msg_typ.set_node_id(node_id.to_bytes().to_vec());
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_request(msg_typ);
                proto_msg
            }
            GatekeeperMessage::Reply {
                conn_type,
                node_id,
                others,
            } => {
                let mut msg_typ = gatekeeper_proto::HelloReply::new();
                msg_typ.set_conn_type(conn_type.into());
                msg_typ.set_node_id(node_id.to_bytes().to_vec());
                for addr in others.iter() {
                    msg_typ.mut_other_nodes().push(addr.to_bytes());
                }

                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_reply(msg_typ);
                proto_msg
            }
        };

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

impl Decoder for GatekeeperCodec {
    type Item = GatekeeperMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };

        let message: Message = protobuf::parse_from_bytes(&packet)?;

        match message.typ {
            Some(Message_oneof_typ::request(mut request_msg)) => {
                let node_id = secure::PublicKey::try_from_bytes(&request_msg.take_node_id())
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bad protobuf encoding, failed to decode node_id",
                        )
                    })?;
                Ok(Some(GatekeeperMessage::Request {
                    conn_type: request_msg.get_conn_type().into(),
                    node_id,
                }))
            }
            Some(Message_oneof_typ::reply(mut reply_msg)) => {
                let node_id = secure::PublicKey::try_from_bytes(&reply_msg.take_node_id())
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bad protobuf encoding, failed to decode node_id",
                        )
                    })?;

                let mut others: Vec<Multiaddr> = Vec::new();
                for addr in reply_msg.take_other_nodes().iter() {
                    if let Ok(addr_) = Multiaddr::from_bytes(addr.to_vec()) {
                        others.push(addr_);
                    }
                }
                Ok(Some(GatekeeperMessage::Reply {
                    conn_type: reply_msg.get_conn_type().into(),
                    node_id,
                    others,
                }))
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad protobuf encoding",
                ));
            }
        }
    }
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum GatekeeperMessage {
    Request {
        conn_type: ConnectionType,
        node_id: secure::PublicKey,
    },
    Reply {
        conn_type: ConnectionType,
        node_id: secure::PublicKey,
        others: Vec<Multiaddr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionType {
    FullNode,
    Routing,
    Query,
    None,
}

impl From<ProtoConnectionType> for ConnectionType {
    fn from(item: ProtoConnectionType) -> ConnectionType {
        match item {
            ProtoConnectionType::FULL_NODE => ConnectionType::FullNode,
            ProtoConnectionType::ROUTING => ConnectionType::Routing,
            ProtoConnectionType::QUERY => ConnectionType::Query,
            ProtoConnectionType::NONE => ConnectionType::None,
        }
    }
}

impl From<ConnectionType> for ProtoConnectionType {
    fn from(item: ConnectionType) -> ProtoConnectionType {
        match item {
            ConnectionType::FullNode => ProtoConnectionType::FULL_NODE,
            ConnectionType::Routing => ProtoConnectionType::ROUTING,
            ConnectionType::Query => ProtoConnectionType::QUERY,
            ConnectionType::None => ProtoConnectionType::NONE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionType, GatekeeperConfig, GatekeeperMessage};
    use futures::{Future, Sink, Stream};
    use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade};
    use stegos_crypto::pbc::secure;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn correct_transfer() {
        let request = GatekeeperMessage::Request {
            conn_type: ConnectionType::FullNode,
            node_id: secure::PublicKey::from(secure::G2::generator()),
        };

        test_one(request);

        let reply = GatekeeperMessage::Reply {
            conn_type: ConnectionType::Routing,
            node_id: secure::PublicKey::from(secure::G2::generator()),
            others: vec![
                "/ip4/1.2.3.4/tcp/1111".parse().unwrap(),
                "/ip4/1.2.3.4/tcp/1231".parse().unwrap(),
                "/ip4/1.2.3.4/tcp/1221".parse().unwrap(),
            ],
        };

        test_one(reply);
    }

    fn test_one(msg: GatekeeperMessage) {
        let msg_server = msg.clone();
        let msg_client = msg.clone();

        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let server = listener
            .incoming()
            .into_future()
            .map_err(|(e, _)| e)
            .and_then(|(c, _)| {
                GatekeeperConfig::new().upgrade_inbound(c.unwrap(), b"/stegos/gatekeeper/0.1.0")
            })
            .and_then({
                let msg_server = msg_server.clone();
                move |s| {
                    s.into_future().map_err(|(err, _)| err).map(move |(v, _)| {
                        assert_eq!(v.unwrap(), msg_server);
                        ()
                    })
                }
            });

        let client = TcpStream::connect(&listener_addr)
            .and_then(|c| GatekeeperConfig::new().upgrade_outbound(c, b"/stegos/gatekeeper/0.1.0"))
            .and_then(|s| s.send(msg_client))
            .map(|_| ());

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(server.select(client).map_err(|_| panic!()))
            .unwrap();
    }
}

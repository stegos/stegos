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
use protobuf::Message as ProtobufMessage;
use std::{io, iter};
use stegos_crypto::pbc::secure;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

use super::proto::unicast_wire_proto::{self, Message, Message_oneof_typ};

/// Implementation of `ConnectionUpgrade` for the floodsub protocol.
#[derive(Debug, Clone)]
pub struct UnicastSendConfig {}

impl UnicastSendConfig {
    /// Builds a new `UnicastSendConfig`.
    #[inline]
    pub fn new() -> UnicastSendConfig {
        UnicastSendConfig {}
    }
}

impl UpgradeInfo for UnicastSendConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/stegos/direct-send/1.0.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for UnicastSendConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, UnicastWireCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            UnicastWireCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for UnicastSendConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, UnicastWireCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            UnicastWireCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct UnicastWireCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for UnicastWireCodec {
    type Item = UnicastWireMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let proto = match item {
            UnicastWireMessage::Challenge(msg) => {
                let mut msg_typ = unicast_wire_proto::Challenge::new();
                msg_typ.set_challenge(msg.challenge);
                let mut proto_msg = unicast_wire_proto::Message::new();
                proto_msg.set_challenge(msg_typ);
                proto_msg
            }
            UnicastWireMessage::ChallengeReply(msg) => {
                let mut msg_typ = unicast_wire_proto::ChallengeReply::new();
                msg_typ.set_signature(msg.signature.into_bytes().to_vec());
                msg_typ.set_sender_challenge(msg.sender_challenge);
                let mut proto_msg = unicast_wire_proto::Message::new();
                proto_msg.set_reply(msg_typ);
                proto_msg
            }
            UnicastWireMessage::Data(msg) => {
                let mut msg_typ = unicast_wire_proto::Data::new();
                msg_typ.set_sender_pkey(msg.sender_pkey.into_bytes().to_vec());
                msg_typ.set_protocol_id(msg.protocol_id.into_bytes());
                msg_typ.set_data(msg.data);
                msg_typ.set_sender_signature(msg.sender_signature.into_bytes().to_vec());
                let mut proto_msg = unicast_wire_proto::Message::new();
                proto_msg.set_data(msg_typ);
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

impl Decoder for UnicastWireCodec {
    type Item = UnicastWireMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };

        let message: Message = protobuf::parse_from_bytes(&packet)?;

        match message.typ {
            Some(Message_oneof_typ::challenge(challenge_msg)) => {
                let challenge = challenge_msg.get_challenge();
                Ok(Some(UnicastWireMessage::Challenge(ChallengeMessage {
                    challenge,
                })))
            }
            Some(Message_oneof_typ::reply(mut reply_msg)) => {
                let signature = secure::Signature::try_from_bytes(&reply_msg.take_signature())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "bad protobuf encoding")
                    })?;
                let sender_challenge = reply_msg.get_sender_challenge();
                Ok(Some(UnicastWireMessage::ChallengeReply(
                    ChallengeReplyMessage {
                        signature,
                        sender_challenge,
                    },
                )))
            }
            Some(Message_oneof_typ::data(mut data_msg)) => {
                let sender_pkey = secure::PublicKey::try_from_bytes(&data_msg.take_sender_pkey())
                    .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad protobuf encoding")
                })?;
                let protocol_id = String::from_utf8(data_msg.take_protocol_id()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad protobuf encoding")
                })?;
                let sender_signature = secure::Signature::try_from_bytes(
                    &data_msg.take_sender_signature(),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad protobuf encoding"))?;
                let data = data_msg.take_data();
                Ok(Some(UnicastWireMessage::Data(DataMessage {
                    sender_pkey,
                    protocol_id,
                    data,
                    sender_signature,
                })))
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
pub enum UnicastWireMessage {
    Challenge(ChallengeMessage),
    ChallengeReply(ChallengeReplyMessage),
    Data(DataMessage),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeMessage {
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeReplyMessage {
    pub signature: secure::Signature,
    pub sender_challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataMessage {
    pub sender_pkey: secure::PublicKey,
    pub protocol_id: String,
    pub data: Vec<u8>,
    pub sender_signature: secure::Signature,
}

#[cfg(test)]
mod tests {
    use super::{
        ChallengeMessage, ChallengeReplyMessage, DataMessage, UnicastSendConfig, UnicastWireMessage,
    };
    use futures::{Future, Sink, Stream};
    use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade};
    use stegos_crypto::pbc::secure;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn correct_transfer() {
        let challenge = UnicastWireMessage::Challenge(ChallengeMessage {
            challenge: rand::random::<u64>(),
        });

        test_one(challenge);

        let reply = UnicastWireMessage::ChallengeReply(ChallengeReplyMessage {
            signature: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            sender_challenge: rand::random::<u64>(),
        });

        test_one(reply);

        let data = UnicastWireMessage::Data(DataMessage {
            sender_pkey: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
            protocol_id: "loren ipsum".to_string(),
            data: random_vec(1024),
            sender_signature: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
        });

        test_one(data);
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }

    fn test_one(msg: UnicastWireMessage) {
        let msg_server = msg.clone();
        let msg_client = msg.clone();

        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let server = listener
            .incoming()
            .into_future()
            .map_err(|(e, _)| e)
            .and_then(|(c, _)| {
                UnicastSendConfig::new().upgrade_inbound(c.unwrap(), b"/stegos/ncp/1.0.0")
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
            .and_then(|c| UnicastSendConfig::new().upgrade_outbound(c, b"/stegos/ncp/1.0.0"))
            .and_then(|s| s.send(msg_client))
            .map(|_| ());

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(server.select(client).map_err(|_| panic!()))
            .unwrap();
    }
}

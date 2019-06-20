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
use libp2p_core::{upgrade::Negotiated, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use protobuf::Message as ProtobufMessage;
use std::{io, iter};
use stegos_crypto::hashcash::HashCashProof;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

use super::proto::gatekeeper_proto::{self, Message, Message_oneof_typ};

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
    type Output = Framed<Negotiated<TSocket>, GatekeeperCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
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
    type Output = Framed<Negotiated<TSocket>, GatekeeperCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
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
            GatekeeperMessage::UnlockRequest { proof } => {
                let mut msg_typ = gatekeeper_proto::UnlockRequest::new();
                if let Some(proof) = proof {
                    let mut proof_proto = gatekeeper_proto::HashcashProof::new();
                    proof_proto.set_seed(proof.seed);
                    proof_proto.set_nbits(proof.nbits as u32);
                    proof_proto.set_count(proof.count);
                    msg_typ.set_proof(proof_proto);
                }
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_unlock_request(msg_typ);
                proto_msg
            }
            GatekeeperMessage::ChallengeReply { seed, nbits } => {
                let mut msg_typ = gatekeeper_proto::ChallengeReply::new();
                msg_typ.set_seed(seed);
                msg_typ.set_nbits(nbits as u32);
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_challenge_reply(msg_typ);
                proto_msg
            }
            GatekeeperMessage::PermitReply { connection_allowed } => {
                let mut msg_typ = gatekeeper_proto::PermitReply::new();
                msg_typ.set_connection_allowed(connection_allowed);
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_permit_reply(msg_typ);
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
            Some(Message_oneof_typ::unlock_request(unlock_request_msg)) => {
                let proof = if unlock_request_msg.has_proof() {
                    let proof_msg = unlock_request_msg.get_proof();
                    let seed = proof_msg.get_seed();
                    let nbits = proof_msg.get_nbits() as usize;
                    let count = proof_msg.get_count();
                    Some(HashCashProof {
                        seed: seed.to_vec(),
                        nbits,
                        count,
                    })
                } else {
                    None
                };
                Ok(Some(GatekeeperMessage::UnlockRequest { proof }))
            }
            Some(Message_oneof_typ::challenge_reply(reply_msg)) => {
                Ok(Some(GatekeeperMessage::ChallengeReply {
                    seed: reply_msg.get_seed().to_vec(),
                    nbits: reply_msg.get_nbits() as usize,
                }))
            }
            Some(Message_oneof_typ::permit_reply(reply_msg)) => {
                Ok(Some(GatekeeperMessage::PermitReply {
                    connection_allowed: reply_msg.get_connection_allowed(),
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

/// Struct

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum GatekeeperMessage {
    UnlockRequest { proof: Option<HashCashProof> },
    ChallengeReply { seed: Vec<u8>, nbits: usize },
    PermitReply { connection_allowed: bool },
}

#[cfg(test)]
mod tests {
    use super::{GatekeeperCodec, GatekeeperMessage};
    use futures::{future, Future, Sink, Stream};
    use stegos_crypto::hashcash::HashCashProof;
    use tokio::codec::Framed;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn correct_transfer() {
        let unlock_request_null = GatekeeperMessage::UnlockRequest { proof: None };
        test_one(unlock_request_null);

        let proof = HashCashProof {
            seed: rand::random::<[u8; 20]>().to_vec(),
            nbits: rand::random::<usize>(),
            count: rand::random::<i64>(),
        };
        let unlock_request_proof = GatekeeperMessage::UnlockRequest { proof: Some(proof) };
        test_one(unlock_request_proof);

        let challenge_reply = GatekeeperMessage::ChallengeReply {
            seed: random_vec(256),
            nbits: 16,
        };
        test_one(challenge_reply);

        let permit_reply = GatekeeperMessage::PermitReply {
            connection_allowed: false,
        };
        test_one(permit_reply);
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
                future::ok(Framed::new(
                    c.unwrap(),
                    GatekeeperCodec {
                        length_prefix: Default::default(),
                    },
                ))
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
            .and_then(|c| {
                future::ok(Framed::new(
                    c,
                    GatekeeperCodec {
                        length_prefix: Default::default(),
                    },
                ))
            })
            .and_then(|s| s.send(msg_client))
            .map(|_| ());

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(server.select(client).map_err(|_| panic!()))
            .unwrap();
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

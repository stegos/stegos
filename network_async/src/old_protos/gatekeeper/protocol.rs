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

use crate::metrics;

use crate::utils::FutureResult;
use bytes::buf::ext::BufMutExt;
use bytes::BytesMut;
use futures::future;
use futures_codec::{Decoder, Encoder, Framed};
use futures_io::{AsyncRead, AsyncWrite};
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use protobuf::Message as ProtobufMessage;
use std::{io, iter};
use unsigned_varint::codec;

use super::proto::gatekeeper_proto::{self, Message, Message_oneof_typ};

// Prtocol label for metrics
const PROTOCOL_LABEL: &'static str = "gatekeeper";

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
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, GatekeeperCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

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
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, GatekeeperCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

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
            GatekeeperMessage::UnlockRequest { proof } => {
                let mut msg_typ = gatekeeper_proto::UnlockRequest::new();
                if let Some(proof) = proof {
                    let mut proof_proto = gatekeeper_proto::VDFProof::new();
                    proof_proto.set_challenge(proof.challenge);
                    proof_proto.set_difficulty(proof.difficulty);
                    proof_proto.set_vdf_proof(proof.proof);
                    msg_typ.set_proof(proof_proto);
                }
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_unlock_request(msg_typ);
                proto_msg
            }
            GatekeeperMessage::ChallengeReply {
                challenge,
                difficulty,
            } => {
                let mut msg_typ = gatekeeper_proto::ChallengeReply::new();
                msg_typ.set_challenge(challenge);
                msg_typ.set_difficulty(difficulty);
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

impl Decoder for GatekeeperCodec {
    type Item = GatekeeperMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };

        metrics::INCOMING_TRAFFIC
            .with_label_values(&[&PROTOCOL_LABEL])
            .inc_by(packet.len() as i64);

        let message: Message = protobuf::parse_from_bytes(&packet)?;

        match message.typ {
            Some(Message_oneof_typ::unlock_request(unlock_request_msg)) => {
                let proof = if unlock_request_msg.has_proof() {
                    let proof_msg = unlock_request_msg.get_proof();
                    let challenge = proof_msg.get_challenge();
                    let difficulty = proof_msg.get_difficulty();
                    let vdf_proof = proof_msg.get_vdf_proof();
                    Some(VDFProof {
                        challenge: challenge.to_vec(),
                        difficulty,
                        proof: vdf_proof.to_vec(),
                    })
                } else {
                    None
                };
                Ok(Some(GatekeeperMessage::UnlockRequest { proof }))
            }
            Some(Message_oneof_typ::challenge_reply(reply_msg)) => {
                Ok(Some(GatekeeperMessage::ChallengeReply {
                    challenge: reply_msg.get_challenge().to_vec(),
                    difficulty: reply_msg.get_difficulty(),
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

/// Structs
/// VDF solution proof
#[derive(Debug, Clone, PartialEq)]
pub struct VDFProof {
    pub challenge: Vec<u8>,
    pub difficulty: u64,
    pub proof: Vec<u8>,
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum GatekeeperMessage {
    UnlockRequest { proof: Option<VDFProof> },
    ChallengeReply { challenge: Vec<u8>, difficulty: u64 },
    PermitReply { connection_allowed: bool },
}

// #[cfg(test)]
// mod tests {
//     use super::{GatekeeperCodec, GatekeeperMessage, VDFProof};
//     use futures::{future, Future, Sink, Stream};
//     use futures_codec::Framed;
//     use tokio::net::{TcpListener, TcpStream};

//     #[test]
//     fn correct_transfer() {
//         let unlock_request_null = GatekeeperMessage::UnlockRequest { proof: None };
//         test_one(unlock_request_null);

//         let proof = VDFProof {
//             challenge: rand::random::<[u8; 20]>().to_vec(),
//             difficulty: rand::random::<u64>(),
//             proof: rand::random::<[u8; 20]>().to_vec(),
//         };
//         let unlock_request_proof = GatekeeperMessage::UnlockRequest { proof: Some(proof) };
//         test_one(unlock_request_proof);

//         let challenge_reply = GatekeeperMessage::ChallengeReply {
//             challenge: random_vec(256),
//             difficulty: 16,
//         };
//         test_one(challenge_reply);

//         let permit_reply = GatekeeperMessage::PermitReply {
//             connection_allowed: false,
//         };
//         test_one(permit_reply);
//     }

//     fn test_one(msg: GatekeeperMessage) {
//         let msg_server = msg.clone();
//         let msg_client = msg.clone();

//         let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
//         let listener_addr = listener.local_addr().unwrap();

//         let server = listener
//             .incoming()
//             .into_future()
//             .map_err(|(e, _)| e)
//             .and_then(|(c, _)| {
//                 future::ok(Framed::new(
//                     c.unwrap(),
//                     GatekeeperCodec {
//                         length_prefix: Default::default(),
//                     },
//                 ))
//             })
//             .and_then({
//                 let msg_server = msg_server.clone();
//                 move |s| {
//                     s.into_future().map_err(|(err, _)| err).map(move |(v, _)| {
//                         assert_eq!(v.unwrap(), msg_server);
//                         ()
//                     })
//                 }
//             });

//         let client = TcpStream::connect(&listener_addr)
//             .and_then(|c| {
//                 future::ok(Framed::new(
//                     c,
//                     GatekeeperCodec {
//                         length_prefix: Default::default(),
//                     },
//                 ))
//             })
//             .and_then(|s| s.send(msg_client))
//             .map(|_| ());

//         let mut runtime = tokio::runtime::Runtime::new().unwrap();
//         runtime
//             .block_on(server.select(client).map_err(|_| panic!()).map(drop))
//             .unwrap();
//     }

//     fn random_vec(len: usize) -> Vec<u8> {
//         let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
//         key
//     }
// }

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
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::{io, iter};
use unsigned_varint::codec;

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
            NetworkName::Devnet => write!(f, "dev"),
        }
    }
}

#[derive(Debug)]
pub struct NetworkNameParseError(());

impl fmt::Display for NetworkNameParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Invalid network name")
    }
}

impl Error for NetworkNameParseError {
    fn description(&self) -> &str {
        "invalid network name"
    }
}

impl FromStr for NetworkName {
    type Err = NetworkNameParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "testnet" => Ok(NetworkName::Testnet),
            "dev" => Ok(NetworkName::Devnet),
            "mainnet" => Ok(NetworkName::Mainnet),
            _ => Err(NetworkNameParseError(())),
        }
    }
}

use super::proto::gatekeeper_proto::{self, Message, Message_oneof_typ};

// Prtocol label for metrics
const PROTOCOL_LABEL: &str = "gatekeeper";

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
            GatekeeperMessage::UnlockRequest { proof, metadata } => {
                let mut msg_typ = gatekeeper_proto::UnlockRequest::new();
                if let Some(proof) = proof {
                    let mut proof_proto = gatekeeper_proto::VDFProof::new();
                    proof_proto.set_challenge(proof.challenge);
                    proof_proto.set_difficulty(proof.difficulty);
                    proof_proto.set_vdf_proof(proof.proof);
                    msg_typ.set_proof(proof_proto);
                }

                if let Some(metadata) = metadata {
                    let mut metadata_proto = gatekeeper_proto::Metadata::new();
                    metadata_proto.set_network(metadata.network);
                    metadata_proto.set_version(metadata.version);
                    metadata_proto.set_port(metadata.port as u32);
                    msg_typ.set_metadata(metadata_proto);
                }

                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_unlock_request(msg_typ);
                proto_msg
            }
            GatekeeperMessage::ChallengeReply {
                challenge,
                difficulty,
                metadata,
            } => {
                let mut msg_typ = gatekeeper_proto::ChallengeReply::new();
                msg_typ.set_challenge(challenge);
                msg_typ.set_difficulty(difficulty);
                if let Some(metadata) = metadata {
                    let mut metadata_proto = gatekeeper_proto::Metadata::new();
                    metadata_proto.set_network(metadata.network);
                    metadata_proto.set_version(metadata.version);
                    metadata_proto.set_port(metadata.port as u32);
                    msg_typ.set_metadata(metadata_proto);
                }
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_challenge_reply(msg_typ);
                proto_msg
            }
            GatekeeperMessage::PermitReply {
                connection_allowed,
                reason,
            } => {
                let mut msg_typ = gatekeeper_proto::PermitReply::new();
                msg_typ.set_connection_allowed(connection_allowed);
                msg_typ.set_reason(reason);
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_permit_reply(msg_typ);
                proto_msg
            }
            GatekeeperMessage::PublicIpUnlock {} => {
                let msg_typ = gatekeeper_proto::PublicIpUnlock::new();
                let mut proto_msg = gatekeeper_proto::Message::new();
                proto_msg.set_public_ip_unlock(msg_typ);
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

                let metadata = if unlock_request_msg.has_metadata() {
                    let metadata_proto = unlock_request_msg.get_metadata();
                    Some(Metadata {
                        network: metadata_proto.get_network().to_string(),
                        version: metadata_proto.get_version(),
                        port: metadata_proto.get_port() as u16,
                    })
                } else {
                    None
                };

                Ok(Some(GatekeeperMessage::UnlockRequest { proof, metadata }))
            }
            Some(Message_oneof_typ::challenge_reply(reply_msg)) => {
                let metadata = if reply_msg.has_metadata() {
                    let metadata_proto = reply_msg.get_metadata();
                    Some(Metadata {
                        network: metadata_proto.get_network().to_string(),
                        version: metadata_proto.get_version(),
                        port: metadata_proto.get_port() as u16,
                    })
                } else {
                    None
                };

                Ok(Some(GatekeeperMessage::ChallengeReply {
                    challenge: reply_msg.get_challenge().to_vec(),
                    difficulty: reply_msg.get_difficulty(),
                    metadata,
                }))
            }
            Some(Message_oneof_typ::permit_reply(reply_msg)) => {
                Ok(Some(GatekeeperMessage::PermitReply {
                    connection_allowed: reply_msg.get_connection_allowed(),
                    reason: reply_msg.get_reason().to_string(),
                }))
            }

            Some(Message_oneof_typ::public_ip_unlock(_)) => {
                Ok(Some(GatekeeperMessage::PublicIpUnlock {}))
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad protobuf encoding",
            )),
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

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Metadata {
    pub network: String,
    pub version: u64,
    pub port: u16,
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum GatekeeperMessage {
    ChallengeReply {
        challenge: Vec<u8>,
        difficulty: u64,
        metadata: Option<Metadata>,
    }, // Server challenge
    UnlockRequest {
        proof: Option<VDFProof>,

        metadata: Option<Metadata>,
    }, // Proof from client
    PermitReply {
        connection_allowed: bool,
        reason: String,
    }, // Response from server
    PublicIpUnlock {}, // Repeat UnlockRequest but from listener side
}

#[cfg(test)]
mod tests {
    use super::{GatekeeperCodec, GatekeeperMessage, Metadata, VDFProof};
    use async_std::net::{TcpListener, TcpStream};
    use futures::prelude::*;
    use futures_codec::Framed;

    #[test]
    fn correct_transfer() {
        let unlock_request_null = GatekeeperMessage::UnlockRequest {
            proof: None,
            metadata: None,
        };
        test_one(unlock_request_null, "127.0.0.1:13644".parse().unwrap());

        let proof = VDFProof {
            challenge: rand::random::<[u8; 20]>().to_vec(),
            difficulty: rand::random::<u64>(),
            proof: rand::random::<[u8; 20]>().to_vec(),
        };
        let unlock_request_proof = GatekeeperMessage::UnlockRequest {
            proof: Some(proof.clone()),
            metadata: None,
        };
        test_one(unlock_request_proof, "127.0.0.1:13641".parse().unwrap());

        let metadata = Metadata {
            network: "123".to_string(),
            version: 1,
            port: 3,
        };
        let unlock_request_proof = GatekeeperMessage::UnlockRequest {
            proof: Some(proof),
            metadata: Some(metadata.clone()),
        };
        test_one(unlock_request_proof, "127.0.0.1:13645".parse().unwrap());

        let challenge_reply = GatekeeperMessage::ChallengeReply {
            challenge: random_vec(256),
            difficulty: 16,
            metadata: None,
        };
        test_one(challenge_reply, "127.0.0.1:13642".parse().unwrap());

        let challenge_reply = GatekeeperMessage::ChallengeReply {
            challenge: random_vec(256),
            difficulty: 16,
            metadata: Some(metadata),
        };
        test_one(challenge_reply, "127.0.0.1:13646".parse().unwrap());

        let permit_reply = GatekeeperMessage::PermitReply {
            connection_allowed: false,
            reason: String::from("test"),
        };
        test_one(permit_reply, "127.0.0.1:13643".parse().unwrap());
    }

    fn test_one(msg: GatekeeperMessage, listener_addr: std::net::SocketAddr) {
        let msg_server = msg.clone();
        let msg_client = msg.clone();

        let server = Box::pin(async {
            let listener = TcpListener::bind(&listener_addr).await.unwrap();
            let (client, _) = listener.accept().await.unwrap();
            let mut client = Framed::new(
                client,
                GatekeeperCodec {
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
                GatekeeperCodec {
                    length_prefix: Default::default(),
                },
            );
            s.send(msg_client).await.unwrap();
        });

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(futures::future::join(server, client_future));
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

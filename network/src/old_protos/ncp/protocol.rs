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
use libp2p_core::{InboundUpgrade, Multiaddr, OutboundUpgrade, PeerId, UpgradeInfo};
use protobuf::Message;
use std::convert::TryFrom;
use std::{io, iter};
use stegos_crypto::pbc;
use unsigned_varint::codec;

use super::proto::ncp_proto;

// Protocol label for metrics
const PROTOCOL_LABEL: &str = "ncp";

/// Implementation of `ConnectionUpgrade` for the floodsub protocol.
#[derive(Default, Debug, Clone)]
pub struct NcpConfig {}

impl NcpConfig {
    /// Builds a new `NcpConfig`.
    #[inline]
    pub fn new() -> NcpConfig {
        NcpConfig {}
    }
}

impl UpgradeInfo for NcpConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/stegos/ncp/1.0.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for NcpConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, NcpCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            NcpCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for NcpConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, NcpCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            NcpCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct NcpCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for NcpCodec {
    type Item = NcpMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let proto = match item {
            NcpMessage::GetPeersRequest => {
                let mut msg = ncp_proto::Message::new();
                msg.set_field_type(ncp_proto::Message_MessageType::GET_PEERS_REQ);
                msg
            }
            NcpMessage::GetPeersResponse { response } => {
                let mut msg = ncp_proto::Message::new();
                msg.set_field_type(ncp_proto::Message_MessageType::GET_PEERS_RES);

                for peer in response.peers.into_iter() {
                    let mut peer_info = ncp_proto::Message_PeerInfo::new();
                    peer_info.set_peer_id(peer.peer_id.into_bytes());
                    peer_info.set_node_id(peer.node_id.to_bytes().to_vec());
                    for addr in peer.addresses.into_iter() {
                        peer_info.mut_addrs().push(addr.to_vec());
                    }
                    msg.mut_peers().push(peer_info);
                }

                msg
            }
            NcpMessage::Ping => {
                let mut msg = ncp_proto::Message::new();
                msg.set_field_type(ncp_proto::Message_MessageType::PING);
                msg
            }
            NcpMessage::Pong => {
                let mut msg = ncp_proto::Message::new();
                msg.set_field_type(ncp_proto::Message_MessageType::PONG);
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

impl Decoder for NcpCodec {
    type Item = NcpMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };

        metrics::INCOMING_TRAFFIC
            .with_label_values(&[&PROTOCOL_LABEL])
            .inc_by(packet.len() as i64);
        let message: ncp_proto::Message = protobuf::parse_from_bytes(&packet)?;

        match message.get_field_type() {
            ncp_proto::Message_MessageType::GET_PEERS_REQ => Ok(Some(NcpMessage::GetPeersRequest)),

            ncp_proto::Message_MessageType::GET_PEERS_RES => {
                let mut response = GetPeersResponse { peers: vec![] };
                for peer in message.get_peers().iter() {
                    let peer_id =
                        PeerId::from_bytes(peer.get_peer_id().to_vec()).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "bad protobuf encoding, failed to decode node_id",
                            )
                        })?;
                    let node_id =
                        pbc::PublicKey::try_from_bytes(peer.get_node_id()).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "bad protobuf encoding, failed to decode node_id",
                            )
                        })?;

                    let mut peer_info = PeerInfo {
                        peer_id,
                        node_id,
                        addresses: vec![],
                    };
                    for addr in peer.get_addrs().iter() {
                        if let Ok(addr_) = Multiaddr::try_from(addr.to_vec()) {
                            peer_info.addresses.push(addr_);
                        }
                    }
                    response.peers.push(peer_info);
                }
                Ok(Some(NcpMessage::GetPeersResponse { response }))
            }
            ncp_proto::Message_MessageType::PING => Ok(Some(NcpMessage::Ping)),
            ncp_proto::Message_MessageType::PONG => Ok(Some(NcpMessage::Pong)),
        }
    }
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum NcpMessage {
    GetPeersRequest,
    GetPeersResponse { response: GetPeersResponse },
    Ping,
    Pong,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub node_id: pbc::PublicKey,
    pub addresses: Vec<Multiaddr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetPeersResponse {
    pub peers: Vec<PeerInfo>,
}

impl PeerInfo {
    pub fn new(peer_id: &PeerId, node_id: &pbc::PublicKey) -> Self {
        Self {
            peer_id: peer_id.clone(),
            node_id: *node_id,
            addresses: vec![],
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::{GetPeersResponse, NcpCodec, NcpMessage, PeerInfo};
//     use futures::{future, Future, Sink, Stream};
//     use futures_codec::Framed;
//     use libp2p_core::PeerId;
//     use stegos_crypto::pbc;
//     use tokio::net::{TcpListener, TcpStream};

//     #[test]
//     fn correct_transfer() {
//         test_one(NcpMessage::GetPeersRequest);

//         test_one(NcpMessage::Ping);

//         test_one(NcpMessage::Pong);

//         let (_, node_id) = pbc::make_random_keys();

//         let msg = NcpMessage::GetPeersResponse {
//             response: GetPeersResponse {
//                 peers: vec![PeerInfo {
//                     peer_id: PeerId::random(),
//                     node_id,
//                     addresses: vec![
//                         "/ip4/1.2.3.4/tcp/1111".parse().unwrap(),
//                         "/ip4/1.2.3.4/tcp/1231".parse().unwrap(),
//                         "/ip4/1.2.3.4/tcp/1221".parse().unwrap(),
//                     ],
//                 }],
//             },
//         };

//         test_one(msg);
//     }

//     fn test_one(msg: NcpMessage) {
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
//                     NcpCodec {
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
//                     NcpCodec {
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
// }

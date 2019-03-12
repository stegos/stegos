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
use libp2p::core::{InboundUpgrade, OutboundUpgrade, PeerId, UpgradeInfo};
use libp2p::Multiaddr;
use log::debug;
use protobuf::Message;
use std::{io, iter};
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

use super::proto::ncp_proto;

/// Implementation of `ConnectionUpgrade` for the floodsub protocol.
#[derive(Debug, Clone)]
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
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, NcpCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

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
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<TSocket, NcpCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

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
                    for addr in peer.addresses.into_iter() {
                        peer_info.mut_addrs().push(addr.to_bytes());
                    }
                    msg.mut_peers().push(peer_info);
                }

                msg
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

impl Decoder for NcpCodec {
    type Item = NcpMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_prefix.decode(src)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let message: ncp_proto::Message = protobuf::parse_from_bytes(&packet)?;

        match message.get_field_type() {
            ncp_proto::Message_MessageType::GET_PEERS_REQ => Ok(Some(NcpMessage::GetPeersRequest)),

            ncp_proto::Message_MessageType::GET_PEERS_RES => {
                let mut response = GetPeersResponse { peers: vec![] };
                for peer in message.get_peers().into_iter() {
                    if let Ok(peer_id) = PeerId::from_bytes(peer.get_peer_id().to_vec()) {
                        let mut peer_info = PeerInfo {
                            peer_id,
                            addresses: vec![],
                        };
                        for addr in peer.get_addrs().into_iter() {
                            if let Ok(addr_) = Multiaddr::from_bytes(addr.to_vec()) {
                                peer_info.addresses.push(addr_);
                            }
                        }
                        response.peers.push(peer_info);
                    }
                }
                Ok(Some(NcpMessage::GetPeersResponse { response }))
            }
        }
    }
}

/// Message that we can send to a peer or received from a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum NcpMessage {
    GetPeersRequest,
    GetPeersResponse { response: GetPeersResponse },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetPeersResponse {
    pub peers: Vec<PeerInfo>,
}

impl PeerInfo {
    pub fn new(peer_id: &PeerId) -> Self {
        Self {
            peer_id: peer_id.clone(),
            addresses: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GetPeersResponse, NcpConfig, NcpMessage, PeerInfo};
    use futures::{Future, Sink, Stream};
    use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade};
    use libp2p::core::{PeerId, PublicKey};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn correct_transfer() {
        test_one(NcpMessage::GetPeersRequest);

        let msg = NcpMessage::GetPeersResponse {
            response: GetPeersResponse {
                peers: vec![PeerInfo {
                    peer_id: random_peerid(),
                    addresses: vec![
                        "/ip4/1.2.3.4/tcp/1111".parse().unwrap(),
                        "/ip4/1.2.3.4/tcp/1231".parse().unwrap(),
                        "/ip4/1.2.3.4/tcp/1221".parse().unwrap(),
                    ],
                }],
            },
        };

        test_one(msg);
    }

    fn random_peerid() -> PeerId {
        let key = (0..2048).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        PeerId::from_public_key(PublicKey::Rsa(key))
    }

    fn test_one(msg: NcpMessage) {
        let msg_server = msg.clone();
        let msg_client = msg.clone();

        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let server = listener
            .incoming()
            .into_future()
            .map_err(|(e, _)| e)
            .and_then(|(c, _)| NcpConfig::new().upgrade_inbound(c.unwrap(), b"/stegos/ncp/1.0.0"))
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
            .and_then(|c| NcpConfig::new().upgrade_outbound(c, b"/stegos/ncp/1.0.0"))
            .and_then(|s| s.send(msg_client))
            .map(|_| ());

        let mut runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(server.select(client).map_err(|_| panic!()))
            .unwrap();
    }
}

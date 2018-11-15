//
// MIT License
//
// Copyright (c) 2018 Stegos
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
#![allow(dead_code)]

use super::ncp as ncp_proto;
use bytes::{Bytes, BytesMut};
use futures::{future, sink, stream, Sink, Stream};
use libp2p::core::{ConnectionUpgrade, Endpoint, Multiaddr, PeerId};
use protobuf::{self, Message};
use std::io::Error as IoError;
use std::iter;
use tokio_codec::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

/// Configuration for a Kademlia connection upgrade. When applied to a connection, turns this
/// connection into a `Stream + Sink` whose items are of type `NcpMsg`.
#[derive(Debug, Default, Copy, Clone)]
pub struct NcpProtocolConfig;

impl<C, Maf> ConnectionUpgrade<C, Maf> for NcpProtocolConfig
where
    C: AsyncRead + AsyncWrite + 'static, // TODO: 'static :-/
{
    type Output = (Endpoint, NcpStreamSink<C>);
    type MultiaddrFuture = Maf;
    type Future = future::FutureResult<((Self::Output), Self::MultiaddrFuture), IoError>;
    type NamesIter = iter::Once<(Bytes, ())>;
    type UpgradeIdentifier = ();

    #[inline]
    fn protocol_names(&self) -> Self::NamesIter {
        iter::once(("/stegos/ncp/1.0.0".into(), ()))
    }

    #[inline]
    fn upgrade(self, incoming: C, _: (), e: Endpoint, addr: Maf) -> Self::Future {
        future::ok(((e, ncp_protocol(incoming)), addr))
    }
}

pub type NcpStreamSink<S> = stream::AndThen<
    sink::With<
        stream::FromErr<Framed<S, codec::UviBytes<Vec<u8>>>, IoError>,
        NcpMsg,
        fn(NcpMsg) -> Result<Vec<u8>, IoError>,
        Result<Vec<u8>, IoError>,
    >,
    fn(BytesMut) -> Result<NcpMsg, IoError>,
    Result<NcpMsg, IoError>,
>;

// Upgrades a socket to use the NCP protocol.
fn ncp_protocol<S>(socket: S) -> NcpStreamSink<S>
where
    S: AsyncRead + AsyncWrite,
{
    Framed::new(socket, codec::UviBytes::default())
        .from_err::<IoError>()
        .with::<_, fn(_) -> _, _>(|request| -> Result<_, IoError> {
            let proto_struct = msg_to_proto(request);
            Ok(proto_struct.write_to_bytes().unwrap()) // TODO: error?
        }).and_then::<fn(_) -> _, _>(|bytes| {
            let response = protobuf::parse_from_bytes(&bytes)?;
            proto_to_msg(response)
        })
}

/// Message that we can send to a peer or received from a peer.
// TODO: document the rest
#[derive(Debug, Clone, PartialEq)]
pub enum NcpMsg {
    /// Ping request
    Ping {
        ping_data: Vec<u8>,
    },

    /// Ping request
    Pong {
        ping_data: Vec<u8>,
    },
    GetPeersRequest,
    GetPeersResponse {
        response: GetPeersResponse,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PeerInfo {
    pub(crate) peer_id: PeerId,
    pub(crate) addresses: Vec<Multiaddr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetPeersResponse {
    pub(crate) last_chunk: bool,
    pub(crate) peers: Vec<PeerInfo>,
}

impl PeerInfo {
    pub(crate) fn new(peer_id: &PeerId) -> Self {
        Self {
            peer_id: peer_id.clone(),
            addresses: vec![],
        }
    }
}

// Turns a type-safe NCP message into the corresponding row protobuf message.
fn msg_to_proto(ncp_msg: NcpMsg) -> ncp_proto::Message {
    match ncp_msg {
        NcpMsg::Ping { ping_data } => {
            let mut msg = ncp_proto::Message::new();
            msg.set_field_type(ncp_proto::Message_MessageType::PING);
            msg.set_pingData(ping_data);
            msg
        }
        NcpMsg::Pong { ping_data } => {
            let mut msg = ncp_proto::Message::new();
            msg.set_field_type(ncp_proto::Message_MessageType::PONG);
            msg.set_pingData(ping_data);
            msg
        }
        NcpMsg::GetPeersRequest => {
            let mut msg = ncp_proto::Message::new();
            msg.set_field_type(ncp_proto::Message_MessageType::GET_PEERS_REQ);
            msg
        }
        NcpMsg::GetPeersResponse { response } => {
            let mut msg = ncp_proto::Message::new();
            msg.set_field_type(ncp_proto::Message_MessageType::GET_PEERS_RES);
            msg.set_last_chunk(response.last_chunk);

            for peer in response.peers.into_iter() {
                let mut peer_info = ncp_proto::Message_PeerInfo::new();
                peer_info.set_peer_id(peer.peer_id.into_bytes());
                for addr in peer.addresses.into_iter() {
                    peer_info.mut_addrs().push(addr.into_bytes());
                }
                msg.mut_peers().push(peer_info);
            }

            msg
        }
    }
}

/// Turns a raw NCP message into a type-safe message.
fn proto_to_msg(mut message: ncp_proto::Message) -> Result<NcpMsg, IoError> {
    match message.get_field_type() {
        ncp_proto::Message_MessageType::PING => {
            let ping_data = message.take_pingData();
            Ok(NcpMsg::Ping { ping_data })
        }

        ncp_proto::Message_MessageType::PONG => {
            let ping_data = message.take_pingData();
            Ok(NcpMsg::Pong { ping_data })
        }

        ncp_proto::Message_MessageType::GET_PEERS_REQ => Ok(NcpMsg::GetPeersRequest),

        ncp_proto::Message_MessageType::GET_PEERS_RES => {
            let mut response = GetPeersResponse {
                last_chunk: message.get_last_chunk(),
                peers: vec![],
            };
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
            Ok(NcpMsg::GetPeersResponse { response })
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate libp2p;
    extern crate simple_logger;
    extern crate tokio_current_thread;

    use futures::{Future, Sink, Stream};
    use libp2p::core::{PeerId, PublicKey, Transport};
    use libp2p::tcp::TcpConfig;
    use ncp::protocol::{GetPeersResponse, NcpMsg, NcpProtocolConfig, PeerInfo};
    use rand;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn log_test() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        info!("log test");
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn correct_transfer() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        info!("transfer test");
        // We open a server and a client, send a message between the two, and check that they were
        // successfully received.

        test_one(NcpMsg::Ping {
            ping_data: vec![1, 2, 3, 4, 5],
        });
        test_one(NcpMsg::Pong {
            ping_data: vec![1, 2, 3, 4, 5],
        });
        test_one(NcpMsg::GetPeersRequest);

        let msg = NcpMsg::GetPeersResponse {
            response: GetPeersResponse {
                last_chunk: true,
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

        // TODO: all messages

        fn random_peerid() -> PeerId {
            let key = (0..2048).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
            PeerId::from_public_key(PublicKey::Rsa(key))
        }

        fn test_one(msg_server: NcpMsg) {
            let msg_client = msg_server.clone();
            let (tx, rx) = mpsc::channel();

            let bg_thread = thread::spawn(move || {
                let transport = TcpConfig::new().with_upgrade(NcpProtocolConfig);

                let (listener, addr) = transport
                    .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                    .unwrap();
                tx.send(addr).unwrap();

                let future = listener
                    .into_future()
                    .map_err(|(err, _)| err)
                    .and_then(|(client, _)| client.unwrap().map(|v| v.0))
                    .and_then(|proto| {
                        proto
                            .1
                            .into_future()
                            .map_err(|(err, _)| err)
                            .map(|(v, _)| v)
                    }).map(|recv_msg| {
                        assert_eq!(recv_msg.unwrap(), msg_server);
                        ()
                    });

                let _ = tokio_current_thread::block_on_all(future).unwrap();
            });

            let transport = TcpConfig::new().with_upgrade(NcpProtocolConfig);

            let future = transport
                .dial(rx.recv().unwrap())
                .unwrap_or_else(|_| panic!())
                .and_then(|proto| (proto.0).1.send(msg_client))
                .map(|_| ());

            let _ = tokio_current_thread::block_on_all(future).unwrap();
            bg_thread.join().unwrap();
        }
    }
}

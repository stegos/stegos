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

use super::ncp_proto;
use bytes::{Bytes, BytesMut};
use futures::{future, sink, stream, Sink, Stream};
use libp2p::core::{ConnectionUpgrade, Endpoint};
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

type NcpStreamSink<S> = stream::AndThen<
    sink::With<
        stream::FromErr<Framed<S, codec::UviBytes<Vec<u8>>>, IoError>,
        NcpMsg,
        fn(NcpMsg) -> Result<Vec<u8>, IoError>,
        Result<Vec<u8>, IoError>,
    >,
    fn(BytesMut) -> Result<NcpMsg, IoError>,
    Result<NcpMsg, IoError>,
>;

// Upgrades a socket to use the Kademlia protocol.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    GetPeersResponse,
}

// Turns a type-safe kadmelia message into the corresponding row protobuf message.
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
        NcpMsg::GetPeersResponse => {
            let mut msg = ncp_proto::Message::new();
            msg.set_field_type(ncp_proto::Message_MessageType::GET_PEERS_RES);
            msg
        }
    }
}

/// Turns a raw Kademlia message into a type-safe message.
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

        ncp_proto::Message_MessageType::GET_PEERS_RES => Ok(NcpMsg::GetPeersResponse),
    }
}

#[cfg(test)]
mod tests {
    extern crate libp2p;
    extern crate tokio_current_thread;

    use futures::{Future, Sink, Stream};
    use libp2p::core::Transport;
    use libp2p::tcp::TcpConfig;
    use ncp::protocol::{NcpMsg, NcpProtocolConfig};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn correct_transfer() {
        // We open a server and a client, send a message between the two, and check that they were
        // successfully received.

        test_one(NcpMsg::Ping {
            ping_data: vec![1, 2, 3, 4, 5],
        });
        test_one(NcpMsg::Pong {
            ping_data: vec![1, 2, 3, 4, 5],
        });
        // TODO: all messages

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

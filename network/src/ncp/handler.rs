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

use super::super::node::Inner;
use super::protocol::{GetPeersResponse, NcpMsg, NcpStreamSink, PeerInfo};
use futures::future;
use futures::future::{loop_fn, Loop};
use futures::{Future, IntoFuture, Sink, Stream};
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::peerstore::{PeerAccess, Peerstore};
use log::*;
use parking_lot::RwLock;
use std::io::Error as IoError;
use std::sync::Arc;
use std::time::Duration;
use tokio_io::{AsyncRead, AsyncWrite};

pub(crate) fn ncp_handler<S>(
    socket: NcpStreamSink<S>,
    endpoint: Endpoint,
    _addr: Multiaddr,
    node: Arc<RwLock<Inner>>,
) -> Box<dyn Future<Item = (), Error = IoError> + Send>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let inner = node.clone();

    // If we are dialing, send request for peers list
    // TODO: handle possible error
    let sock = match endpoint {
        Endpoint::Dialer => socket.send(NcpMsg::GetPeersRequest).wait().unwrap(),
        Endpoint::Listener => socket,
    };

    let fut = loop_fn(sock, {
        let inner = inner.clone();
        move |socket| {
            socket.into_future().map_err(|(e, _)| e).and_then({
                let inner = inner.clone();
                move |(msg, rest)| {
                    if let Some(msg) = msg {
                        // One message has been received. We send it back to the client.
                        debug!("Received a message: {:?}", msg);
                        match msg {
                            NcpMsg::Ping { ping_data } => {
                                let resp = NcpMsg::Pong { ping_data };
                                Box::new(rest.send(resp).map(|m| Loop::Continue(m)))
                                    as Box<dyn Future<Item = _, Error = _> + Send>
                            }
                            NcpMsg::Pong { ping_data: _ } => {
                                Box::new(future::ok(Loop::Continue(rest)))
                                    as Box<dyn Future<Item = _, Error = _> + Send>
                            }
                            NcpMsg::GetPeersRequest => {
                                let mut response = GetPeersResponse {
                                    last_chunk: true,
                                    peers: vec![],
                                };

                                let inner = inner.read();
                                let peerstore = (&*inner).peer_store.clone();

                                for peer in peerstore.peers() {
                                    let peerstore = peerstore.clone();
                                    let mut peer_info = PeerInfo::new(&peer);
                                    for addr in peerstore.peer_or_create(&peer).addrs() {
                                        peer_info.addresses.push(addr);
                                    }
                                    response.peers.push(peer_info);
                                }

                                Box::new(
                                    rest.send(NcpMsg::GetPeersResponse { response })
                                        .map(|m| Loop::Continue(m)),
                                )
                                    as Box<dyn Future<Item = _, Error = _> + Send>
                            }
                            NcpMsg::GetPeersResponse { response } => {
                                let inner = inner.read();
                                let peerstore = (&*inner).peer_store.clone();
                                let hour = Duration::from_secs(3600);

                                for peer in response.peers.into_iter() {
                                    peerstore
                                        .peer_or_create(&peer.peer_id)
                                        .add_addrs(peer.addresses, hour);
                                }
                                if response.last_chunk {
                                    Box::new(Ok(Loop::Break(())).into_future())
                                        as Box<dyn Future<Item = _, Error = _> + Send>
                                } else {
                                    Box::new(future::ok(Loop::Continue(rest)))
                                        as Box<dyn Future<Item = _, Error = _> + Send>
                                }
                            }
                        }
                    } else {
                        // End of stream. Connection closed. Breaking the loop.
                        debug!("Received EOF\n => Dropping connection");
                        Box::new(Ok(Loop::Break(())).into_future())
                            as Box<dyn Future<Item = _, Error = _> + Send>
                    }
                }
            })
        }
    });

    Box::new(fut) as Box<dyn Future<Item = _, Error = _> + Send>
}

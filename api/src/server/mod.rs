//! WebSocket API - Server.

//
// Copyright (c) 2019 Stegos AG
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

use crate::crypto::ApiToken;
use crate::network_api::NetworkApi;
use crate::{decode, encode, Request, Response};
use failure::{bail, Error};
use futures::prelude::*;
use futures::select;
use futures::SinkExt;
use log::*;
use stegos_network::Network;
// use stegos_wallet::api::{WalletControlResponse, WalletNotification, WalletResponse};
// use stegos_wallet::Wallet;

use std::pin::Pin;

use api::clone_apis;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tungstenite::protocol::Message;

use tokio::task::JoinHandle;
/// The number of values to fit in the output buffer.
const OUTPUT_BUFFER_SIZE: usize = 10;
/// Topic used for debugging.
const CONSOLE_TOPIC: &'static str = "console";

/// A type definition for sink.
type WsSink = Box<dyn Sink<Message, Error = Error> + Send + Unpin>;
/// A type definition for stream.
type WsStream = Box<dyn Stream<Item = Result<Message, Error>> + Send + Unpin>;

pub mod api;
pub mod register;
use api::*;
use register::Register;

/// Handler of incoming connections.
struct WebSocketHandler {
    /// Remote address.
    peer: SocketAddr,
    /// API Token.
    api_token: ApiToken,
    /// Outgoing stream.
    sink: WsSink,
    /// Incoming stream.
    stream: WsStream,

    register: Register,
}

impl WebSocketHandler {
    fn new(
        peer: SocketAddr,
        api_token: ApiToken,
        sink: WsSink,
        stream: WsStream,
        apis: Vec<Box<dyn ApiHandler>>,
        network: Network,
        version: String,
        chain_name: String,
    ) -> Self {
        let mut register = Register::new();
        let network_api = NetworkApi::new(network, version, chain_name);
        for api in apis {
            register.add_api(api);
        }
        register.add_api(Box::new(network_api));

        WebSocketHandler {
            peer,
            api_token,
            sink,
            stream,
            register,
        }
    }

    async fn send(sink: &mut WsSink, api_token: &ApiToken, msg: Response) -> Result<(), Error> {
        let msg = encode(api_token, &msg);
        let msg = Message::Text(msg);
        Self::send_raw(sink, msg).await
    }

    async fn send_raw(sink: &mut WsSink, msg: Message) -> Result<(), Error> {
        SinkExt::send(sink, msg).await.map_err(From::from)
    }

    async fn receive(
        stream: &mut WsStream,
        sink: &mut WsSink,
        api_token: ApiToken,
        peer: SocketAddr,
    ) -> Result<Request, Error> {
        loop {
            let result = stream.next().await;
            match result {
                Some(Ok(Message::Text(msg))) => {
                    return decode(&api_token, &msg);
                }
                Some(Ok(Message::Ping(msg))) => {
                    trace!("[{}] => Ping(len={})", peer, msg.len());
                    sink.send(Message::Pong(msg));
                }
                Some(Ok(Message::Pong(msg))) => {
                    trace!("[{}] => Pong(len={})", peer, msg.len());
                }
                Some(Ok(Message::Binary(msg))) => {
                    bail!("[{}] => Binary(len={})", peer, msg.len());
                }
                Some(Ok(Message::Close(data))) => {
                    bail!("[{}] => Close(has_data={})", peer, data.is_some());
                }
                Some(Err(e)) => {
                    bail!("[{}] => Error({})", peer, e);
                }
                None => {
                    bail!("[{}] => EOF", peer);
                }
            }
        }
    }

    async fn spawn(mut self) {
        loop {
            let api_token = self.api_token;
            let peer = self.peer;
            let mut receive_orig = Self::receive(&mut self.stream, &mut self.sink, api_token, peer);
            let mut receive = unsafe { Pin::new_unchecked(&mut receive_orig) };
            let mut receive = receive.fuse();
            select! {
                notification = self.register.notifications.next() => {
                    drop(receive);
                    drop(receive_orig);
                    let notifiocation = if let Some(notification) = notification {
                        trace!("Forwarding notification = {:?}", notification);
                        let kind = notification.0;
                        let response = Response { kind, id:0 };
                        Self::send(&mut self.sink, &self.api_token, response).await;
                    } else {
                        trace!("Notifications stream ended.");
                    };
                }
                req = receive => {
                    drop(receive);
                    drop(receive_orig);
                    let req = match req {
                        Ok(res) => res,
                        Err(e) => {
                            trace!("{}", e);
                            return ();
                        }
                    };
                    let id = req.id;
                    let req = RawRequest(req);
                    trace!("Request = {:?}", req);
                    let block = async {
                        let kind = self.register.try_process("nothing", req).await?.0;
                        let response = Response { kind, id };
                        Self::send(&mut self.sink, &self.api_token, response).await
                    };
                    if let Err(e) = block.await {
                        warn!("Error during processing of request, error={}", e);
                    };

                }
            };
        }

        //     // Process incoming messages.
        //     loop {
        //         match self.stream.poll()? {
        //             Async::Ready(Some(Message::Text(msg))) => {
        //                 trace!("[{}] => Text({})", self.peer, &msg);
        //                 let request: Request = decode(&self.api_token, &msg)?;
        //                 trace!("[{}] => {:?}", self.peer, request);
        //                 match request.kind {
        //                     RequestKind::NetworkRequest(network_request) => {
        //                         match self.handle_network_request(network_request) {
        //                             Ok(NetworkResult::Immediate(r)) => {
        //                                 let response = Response {
        //                                     kind: ResponseKind::NetworkResponse(r),
        //                                     id: request.id,
        //                                 };
        //                                 try_send!(self, response);
        //                             }
        //                             Ok(NetworkResult::Async(rx)) => {
        //                                 self.network_responses.push((request.id, rx));
        //                             }
        //                             Err(e) => {
        //                                 let r = NetworkResponse::Error {
        //                                     error: format!("{}", e),
        //                                 };
        //                                 let response = Response {
        //                                     kind: ResponseKind::NetworkResponse(r),
        //                                     id: request.id,
        //                                 };
        //                                 try_send!(self, response);
        //                             }
        //                         };
        //                     }
        //                     RequestKind::WalletsRequest(wallet_request) => {
        //                         if let Some(wallet) = &self.wallet {
        //                             self.wallet_responses
        //                                 .push((request.id, wallet.request(wallet_request)));
        //                         } else {
        //                             let r = WalletControlResponse::Error {
        //                                 error: format!("Wallet API is not supported on the full node"),
        //                             };
        //                             let r = WalletResponse::WalletControlResponse(r);
        //                             let r = Response {
        //                                 kind: ResponseKind::WalletResponse(r),
        //                                 id: request.id,
        //                             };
        //                             try_send!(self, r);
        //                         }
        //                     }
        //                     RequestKind::NodeRequest(node_request) => {
        //                         if let Some(node) = &self.node {
        //                             self.node_responses
        //                                 .push((request.id, node.request(node_request)));
        //                         } else {
        //                             let r = NodeResponse::Error {
        //                                 error: format!("Node API is not supported on the light node"),
        //                             };
        //                             let r = Response {
        //                                 kind: ResponseKind::NodeResponse(r),
        //                                 id: request.id,
        //                             };
        //                             try_send!(self, r);
        //                         }
        //                     }
        //                 }
        //             }
        //             Async::Ready(Some(OwnedMessage::Binary(msg))) => {
        //                 trace!("[{}] => Binary(len={})", self.peer, msg.len());
        //                 return Err(WebSocketError::RequestError("BinaryIsNotSupported"));
        //             }
        //             Async::Ready(Some(OwnedMessage::Ping(msg))) => {
        //                 trace!("[{}] => Ping(len={})", self.peer, msg.len());
        //                 try_send_raw!(self, OwnedMessage::Pong(msg));
        //             }
        //             Async::Ready(Some(OwnedMessage::Pong(msg))) => {
        //                 trace!("[{}] => Pong(len={})", self.peer, msg.len());
        //             }
        //             Async::Ready(Some(OwnedMessage::Close(data))) => {
        //                 trace!("[{}] => Close(has_data={})", self.peer, data.is_some());
        //                 return Ok(Async::Ready(()));
        //             }
        //             Async::Ready(None) => {
        //                 trace!("[{}] => EOF", self.peer);
        //                 return Ok(Async::Ready(()));
        //             }
        //             Async::NotReady => break,
        //         }
        //     }

        //     // Network unicast messages.
        //     for (topic, rx) in self.network_unicast.iter_mut() {
        //         loop {
        //             match rx.poll().unwrap() {
        //                 Async::Ready(Some(msg)) => {
        //                     let msg = NetworkNotification::UnicastMessage {
        //                         topic: topic.clone(),
        //                         from: msg.from,
        //                         data: msg.data,
        //                     };
        //                     let msg = Response {
        //                         kind: ResponseKind::NetworkNotification(msg),
        //                         id: 0,
        //                     };
        //                     try_send!(self, msg);
        //                 }
        //                 Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
        //                 Async::NotReady => break,
        //             }
        //         }
        //     }

        //     // Network broadcast messages.
        //     for (topic, rx) in self.network_broadcast.iter_mut() {
        //         loop {
        //             match rx.poll().unwrap() {
        //                 Async::Ready(Some(data)) => {
        //                     let msg = NetworkNotification::BroadcastMessage {
        //                         topic: topic.clone(),
        //                         data,
        //                     };
        //                     let msg = Response {
        //                         kind: ResponseKind::NetworkNotification(msg),
        //                         id: 0,
        //                     };
        //                     try_send!(self, msg);
        //                 }
        //                 Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
        //                 Async::NotReady => break,
        //             }
        //         }
        //     }

        //     // Network responses
        //     let mut i = 0;
        //     while i < self.network_responses.len() {
        //         match self.network_responses[i].1.poll() {
        //             Ok(Async::Ready(response)) => {
        //                 let (id, _) = self.network_responses.swap_remove(i);
        //                 let resp = match response {
        //                     NetworkServiceResponse::ConnectedNodes { nodes } => Response {
        //                         kind: ResponseKind::NetworkResponse(NetworkResponse::ConnectedNodes {
        //                             total: nodes.len(),
        //                             nodes,
        //                         }),
        //                         id,
        //                     },
        //                 };
        //                 try_send!(self, resp);
        //                 continue;
        //             }
        //             Ok(Async::NotReady) => {}
        //             Err(oneshot::Canceled) => panic!("missing response for WalletRequest"),
        //         }
        //         i += 1;
        //     }

        //     // Wallet notifications.
        //     while let Some(wallet_notifications) = &mut self.wallet_notifications {
        //         match wallet_notifications.poll().unwrap() {
        //             Async::Ready(Some(notification)) => {
        //                 let response = Response {
        //                     kind: ResponseKind::WalletNotification(notification),
        //                     id: 0,
        //                 };
        //                 try_send!(self, response);
        //             }
        //             Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
        //             Async::NotReady => break,                          // fall through
        //         }
        //     }

        //     // Wallet responses.
        //     let mut i = 0;
        //     while i < self.wallet_responses.len() {
        //         match self.wallet_responses[i].1.poll() {
        //             Ok(Async::Ready(response)) => {
        //                 let (id, _) = self.wallet_responses.swap_remove(i);
        //                 let response = Response {
        //                     kind: ResponseKind::WalletResponse(response),
        //                     id,
        //                 };
        //                 try_send!(self, response);
        //                 continue;
        //             }
        //             Ok(Async::NotReady) => {}
        //             Err(oneshot::Canceled) => panic!("missing response for WalletRequest"),
        //         }
        //         i += 1;
        //     }

        //     // Node responses.
        //     let mut i = 0;
        //     while i < self.node_responses.len() {
        //         match self.node_responses[i].1.poll() {
        //             Ok(Async::Ready(mut response)) => {
        //                 match &mut response {
        //                     NodeResponse::SubscribedStatus { rx, .. } => {
        //                         self.status_notifications = rx.take();
        //                     }
        //                     NodeResponse::SubscribedChain { rx, .. } => {
        //                         self.chain_notifications = rx.take();
        //                     }
        //                     _ => {}
        //                 };
        //                 let (id, _) = self.node_responses.swap_remove(i);
        //                 let response = Response {
        //                     kind: ResponseKind::NodeResponse(response),
        //                     id,
        //                 };
        //                 try_send!(self, response);
        //                 continue;
        //             }
        //             Ok(Async::NotReady) => {}
        //             Err(oneshot::Canceled) => panic!("missing response for NodeRequest"),
        //         }
        //         i += 1;
        //     }

        //     // Status notifications.
        //     if let Some(status_notifications) = &mut self.status_notifications {
        //         loop {
        //             match status_notifications.poll().unwrap() {
        //                 Async::Ready(Some(msg)) => {
        //                     let msg = Response {
        //                         kind: ResponseKind::StatusNotification(msg),
        //                         id: 0,
        //                     };
        //                     try_send!(self, msg);
        //                 }
        //                 Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
        //                 Async::NotReady => break,                          // fall through
        //             }
        //         }
        //     }

        //     // Chain notifications.
        //     if let Some(chain_notifications) = &mut self.chain_notifications {
        //         loop {
        //             match chain_notifications.poll().unwrap() {
        //                 Async::Ready(Some(msg)) => {
        //                     match &msg {
        //                         ChainNotification::MicroBlockPrepared(block) => {
        //                             trace!(
        //                                 "Prepared Micro Block: epoch={}, offset={}",
        //                                 block.header.epoch,
        //                                 block.header.offset
        //                             );
        //                         }
        //                         ChainNotification::MicroBlockReverted(block) => {
        //                             trace!(
        //                                 "Reverted Micro Block: epoch={}, offset={}",
        //                                 block.block.header.epoch,
        //                                 block.block.header.offset
        //                             );
        //                         }
        //                         ChainNotification::MacroBlockCommitted(block) => {
        //                             trace!("Comitted Macro Block: epoch={}", block.block.header.epoch);
        //                         }
        //                     }
        //                     let msg = Response {
        //                         kind: ResponseKind::ChainNotification(msg),
        //                         id: 0,
        //                     };
        //                     try_send!(self, msg);
        //                 }
        //                 Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
        //                 Async::NotReady => break,
        //             }
        //         }
        //     }

        //     // Flush sink.
        //     trace!("[{}] Flush", self.peer);
        //     self.sink.poll_complete()?;
        //     Ok(Async::NotReady)
        // }
    }
}

pub async fn spawn_server(
    endpoint: String,
    api_token: ApiToken,
    apis: Vec<Box<dyn ApiHandler>>,
    network: Network,
    version: String,
    chain_name: String,
) -> Result<JoinHandle<()>, Error> {
    let addr: SocketAddr = endpoint.parse()?;
    info!(target: "stegos_api", "Starting API Server on {}", &addr);
    let mut listener = TcpListener::bind(&addr).await?;

    Ok(tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            tokio::spawn(handle_connection(
                stream,
                addr,
                api_token.clone(),
                clone_apis(&apis),
                network.clone(),
                version.clone(),
                chain_name.clone(),
            ));
        }
    }))
}

async fn handle_connection(
    raw_stream: TcpStream,
    peer: SocketAddr,
    api_token: ApiToken,
    apis: Vec<Box<dyn ApiHandler>>,
    network: Network,
    version: String,
    chain_name: String,
) {
    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    debug!("[{}] Accepted", peer);
    let (sink, stream) = ws_stream.split();
    let sink = sink.buffer(OUTPUT_BUFFER_SIZE);
    let sink: WsSink = Box::new(sink.sink_map_err(From::from));
    let stream: WsStream = Box::new(stream.map_err(From::from));
    info!("[{}] Connected", peer);
    WebSocketHandler::new(
        peer, api_token, sink, stream, apis, network, version, chain_name,
    )
    .spawn()
    .await
}

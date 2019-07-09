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
use crate::{
    decode, encode, NetworkNotification, NetworkRequest, NetworkResponse, Request, RequestId,
    RequestKind, Response, ResponseKind,
};
use failure::Error;
use futures::sync::{mpsc, oneshot};
use futures::{task, Async, AsyncSink, Future, Poll, Sink, Stream};
use log::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use stegos_network::{Network, UnicastMessage};
use stegos_node::{Node, NodeNotification, NodeResponse};
use stegos_wallet::{WalletManager, WalletsNotification, WalletsResponse};
use tokio::net::TcpListener;
use tokio::runtime::TaskExecutor;
use websocket::message::OwnedMessage;
use websocket::result::WebSocketError;
use websocket::server::upgrade::r#async::IntoWs;

/// The number of values to fit in the output buffer.
const OUTPUT_BUFFER_SIZE: usize = 10;
/// Topic used for debugging.
const CONSOLE_TOPIC: &'static str = "console";

/// A type definition for sink.
type WsSink = Box<dyn Sink<SinkItem = OwnedMessage, SinkError = WebSocketError> + Send>;
/// A type definition for stream.
type WsStream = Box<dyn Stream<Item = OwnedMessage, Error = WebSocketError> + Send>;

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
    /// True if outgoing buffer should be flushed on the next poll().
    need_flush: bool,
    /// Network API.
    network: Network,
    /// Network unicast subscribtions.
    network_unicast: HashMap<String, mpsc::UnboundedReceiver<UnicastMessage>>,
    /// Network broadcast subscribtions.
    network_broadcast: HashMap<String, mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Wallet API.
    wallet: WalletManager,
    /// Wallet events.
    wallet_notifications: mpsc::UnboundedReceiver<WalletsNotification>,
    /// Wallet RPC responses.
    wallet_responses: Vec<(RequestId, oneshot::Receiver<WalletsResponse>)>,
    /// Node API.
    node: Node,
    /// Node RPC responses.
    node_responses: Vec<(RequestId, oneshot::Receiver<NodeResponse>)>,
    /// Synchronization Status Changed Notification.
    node_notifications: mpsc::UnboundedReceiver<NodeNotification>,
}

impl WebSocketHandler {
    fn new(
        peer: SocketAddr,
        api_token: ApiToken,
        sink: WsSink,
        stream: WsStream,
        network: Network,
        wallet: WalletManager,
        node: Node,
    ) -> Self {
        let need_flush = false;
        let mut network_unicast = HashMap::new();
        let rx = network.subscribe_unicast(CONSOLE_TOPIC).unwrap();
        network_unicast.insert(CONSOLE_TOPIC.to_string(), rx);
        let mut network_broadcast = HashMap::new();
        let rx = network.subscribe(CONSOLE_TOPIC).unwrap();
        network_broadcast.insert(CONSOLE_TOPIC.to_string(), rx);
        let wallet_notifications = wallet.subscribe();
        let wallet_responses = Vec::new();
        let node_responses = Vec::new();
        let node_notifications = node.subscribe();
        WebSocketHandler {
            peer,
            api_token,
            sink,
            stream,
            need_flush,
            network,
            network_unicast,
            network_broadcast,
            wallet,
            wallet_notifications,
            wallet_responses,
            node,
            node_responses,
            node_notifications,
        }
    }

    fn handle_network_request(
        &mut self,
        network_request: NetworkRequest,
    ) -> Result<NetworkResponse, Error> {
        match network_request {
            NetworkRequest::SubscribeUnicast { topic } => {
                if !self.network_unicast.contains_key(&topic) {
                    let rx = self.network.subscribe_unicast(&topic)?;
                    self.network_unicast.insert(topic, rx);
                    task::current().notify();
                }
                Ok(NetworkResponse::SubscribedUnicast)
            }
            NetworkRequest::SubscribeBroadcast { topic } => {
                if !self.network_broadcast.contains_key(&topic) {
                    let rx = self.network.subscribe(&topic)?;
                    self.network_broadcast.insert(topic, rx);
                    task::current().notify();
                }
                Ok(NetworkResponse::SubscribedBroadcast)
            }
            NetworkRequest::UnsubscribeUnicast { topic } => {
                self.network_unicast.remove(&topic);
                Ok(NetworkResponse::UnsubscribedUnicast)
            }
            NetworkRequest::UnsubscribeBroadcast { topic } => {
                self.network_broadcast.remove(&topic);
                Ok(NetworkResponse::UnsubscribedBroadcast)
            }
            NetworkRequest::SendUnicast { topic, to, data } => {
                self.network.send(to, &topic, data)?;
                Ok(NetworkResponse::SentUnicast)
            }
            NetworkRequest::PublishBroadcast { topic, data } => {
                self.network.publish(&topic, data)?;
                Ok(NetworkResponse::PublishedBroadcast)
            }
        }
    }

    fn on_request(&mut self, request: Request) -> Result<(), WebSocketError> {
        match request.kind {
            RequestKind::NetworkRequest(network_request) => {
                let resp = match self.handle_network_request(network_request) {
                    Ok(r) => r,
                    Err(e) => NetworkResponse::Error {
                        error: format!("{}", e),
                    },
                };
                let response = Response {
                    kind: ResponseKind::NetworkResponse(resp),
                    id: request.id,
                };
                self.send(response);
            }
            RequestKind::WalletsRequest(wallet_request) => {
                self.wallet_responses
                    .push((request.id, self.wallet.request(wallet_request)));
            }
            RequestKind::NodeRequest(node_request) => {
                self.node_responses
                    .push((request.id, self.node.request(node_request)));
            }
        }
        Ok(())
    }

    fn send(&mut self, msg: Response) {
        trace!("[{}] <= {:?}", self.peer, msg);
        let msg = encode(&self.api_token, &msg);
        if let Err(e) = self.send_raw(OwnedMessage::Text(msg)) {
            error!("Failed to send message: {}", e);
        }
    }

    fn send_raw(&mut self, msg: OwnedMessage) -> Result<(), WebSocketError> {
        match self.sink.start_send(msg)? {
            AsyncSink::Ready => {
                self.need_flush = true;
                Ok(())
            }
            AsyncSink::NotReady(msg) => {
                warn!("The output buffer is full, discarding message: {:?}", msg);
                Ok(())
            }
        }
    }
}

impl Drop for WebSocketHandler {
    fn drop(&mut self) {
        info!("[{}] Disconnected", self.peer);
    }
}

impl Future for WebSocketHandler {
    type Item = ();
    type Error = WebSocketError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Process incoming messages.
        loop {
            match self.stream.poll()? {
                Async::Ready(Some(OwnedMessage::Text(msg))) => {
                    trace!("[{}] => Text({})", self.peer, &msg);
                    let request: Request = decode(&self.api_token, &msg)?;
                    trace!("[{}] => {:?}", self.peer, request);
                    self.on_request(request)?
                }
                Async::Ready(Some(OwnedMessage::Binary(msg))) => {
                    trace!("[{}] => Binary(len={})", self.peer, msg.len());
                    return Err(WebSocketError::RequestError("BinaryIsNotSupported"));
                }
                Async::Ready(Some(OwnedMessage::Ping(msg))) => {
                    trace!("[{}] => Ping(len={})", self.peer, msg.len());
                    self.send_raw(OwnedMessage::Pong(msg))?
                }
                Async::Ready(Some(OwnedMessage::Pong(msg))) => {
                    trace!("[{}] => Pong(len={})", self.peer, msg.len());
                }
                Async::Ready(Some(OwnedMessage::Close(data))) => {
                    trace!("[{}] => Close(has_data={})", self.peer, data.is_some());
                    return Ok(Async::Ready(()));
                }
                Async::Ready(None) => {
                    trace!("[{}] => EOF", self.peer);
                    return Ok(Async::Ready(()));
                }
                Async::NotReady => break,
            }
        }

        // Network unicast messages.
        let mut network_notifications: Vec<NetworkNotification> = Vec::new();
        for (topic, rx) in self.network_unicast.iter_mut() {
            loop {
                match rx.poll() {
                    Ok(Async::Ready(Some(msg))) => {
                        network_notifications.push(NetworkNotification::UnicastMessage {
                            topic: topic.clone(),
                            from: msg.from,
                            data: msg.data,
                        });
                    }
                    Ok(Async::Ready(None)) => break,
                    Ok(Async::NotReady) => break,
                    Err(()) => unreachable!(),
                }
            }
        }

        // Network broadcast messages.
        for (topic, rx) in self.network_broadcast.iter_mut() {
            loop {
                match rx.poll() {
                    Ok(Async::Ready(Some(data))) => {
                        network_notifications.push(NetworkNotification::BroadcastMessage {
                            topic: topic.clone(),
                            data,
                        });
                    }
                    Ok(Async::Ready(None)) => break,
                    Ok(Async::NotReady) => break,
                    Err(()) => unreachable!(),
                }
            }
        }

        // Flush all network notifications (a workaround for borrow-checker).
        for notification in network_notifications {
            let notification = Response {
                kind: ResponseKind::NetworkNotification(notification),
                id: 0,
            };
            self.send(notification);
        }

        // Wallet notifications.
        loop {
            match self.wallet_notifications.poll() {
                Ok(Async::Ready(Some(notification))) => {
                    let response = Response {
                        kind: ResponseKind::WalletsNotification(notification),
                        id: 0,
                    };
                    self.send(response);
                }
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Wallet failure"),
            }
        }

        let wallet_responses = std::mem::replace(&mut self.wallet_responses, Vec::new());
        for (id, mut rx) in wallet_responses {
            match rx.poll() {
                Ok(Async::Ready(response)) => {
                    let response = Response {
                        kind: ResponseKind::WalletsResponse(response),
                        id,
                    };
                    self.send(response);
                }
                Ok(Async::NotReady) => self.wallet_responses.push((id, rx)),
                Err(_) => panic!("disconnected"),
            }
        }

        let node_responses = std::mem::replace(&mut self.node_responses, Vec::new());
        for (id, mut rx) in node_responses {
            match rx.poll() {
                Ok(Async::Ready(response)) => {
                    let response = Response {
                        kind: ResponseKind::NodeResponse(response),
                        id,
                    };
                    self.send(response)
                }
                Ok(Async::NotReady) => self.node_responses.push((id, rx)),
                Err(_) => panic!("disconnected"),
            }
        }

        // Node notifications.
        loop {
            match self.node_notifications.poll().expect("connected") {
                Async::Ready(Some(msg)) => {
                    let msg = Response {
                        kind: ResponseKind::NodeNotification(msg),
                        id: 0,
                    };
                    self.send(msg);
                }
                Async::Ready(None) => return Ok(Async::Ready(())),
                Async::NotReady => break, // fall through
            }
        }

        // Flush output buffer.
        if self.need_flush {
            match self.sink.poll_complete()? {
                Async::Ready(()) => self.need_flush = false,
                Async::NotReady => {}
            }
        }

        Ok(Async::NotReady)
    }
}

pub struct WebSocketServer {}

impl WebSocketServer {
    pub fn spawn(
        endpoint: String,
        api_token: ApiToken,
        executor: TaskExecutor,
        network: Network,
        wallet: WalletManager,
        node: Node,
    ) -> Result<(), Error> {
        let executor2 = executor.clone();
        let network2 = network.clone();
        let wallet2 = wallet.clone();
        let node2 = node.clone();
        let addr: SocketAddr = endpoint.parse()?;
        info!("Starting WebSocket API on {}", &addr);
        let server = TcpListener::bind(&addr)?
            .incoming()
            .map_err(|e| {
                error!("Failed to accept: {:?}", e);
            })
            .for_each(move |s| {
                let network3 = network2.clone();
                let wallet3 = wallet2.clone();
                let node3 = node2.clone();
                let peer = match s.peer_addr() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to get remote peer info: errpr={}", e);
                        return Ok(());
                    }
                };
                let api_token = api_token.clone();
                debug!("[{}] accepted", peer);
                let s = s
                    .into_ws()
                    .map_err(move |(_s, _req, _buf, e)| {
                        error!("[{}] Failed to upgrade to websocket: {}", &peer, e);
                    })
                    .and_then(move |upgrade| {
                        upgrade
                            .accept()
                            .map(|(s, _headers)| s)
                            .and_then(move |s| {
                                let (sink, stream) = s.split();
                                let sink = sink.buffer(OUTPUT_BUFFER_SIZE);
                                let sink: WsSink = Box::new(sink);
                                let stream: WsStream = Box::new(stream);
                                info!("[{}] Connected", peer);
                                WebSocketHandler::new(
                                    peer,
                                    api_token,
                                    sink,
                                    stream,
                                    network3.clone(),
                                    wallet3.clone(),
                                    node3.clone(),
                                )
                            })
                            .map_err(move |e| {
                                error!("[{}] Error: {}", &peer, e);
                            })
                    });
                // Spawn the connection handler.
                executor2.spawn(s);
                Ok(())
            });

        // Spawn the server.
        executor.spawn(server);
        Ok(())
    }
}

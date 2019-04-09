//! WebSocket API.

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

#![deny(warnings)]

mod config;

pub use crate::config::WebSocketConfig;
use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::oneshot;
use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};
use log::*;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json;
use std::net::SocketAddr;
use stegos_node::{Node, NodeRequest, NodeResponse};
use stegos_wallet::{Wallet, WalletNotification, WalletRequest, WalletResponse};
use tokio::net::TcpListener;
use tokio::runtime::TaskExecutor;
use websocket::message::OwnedMessage;
use websocket::result::WebSocketError;
use websocket::server::upgrade::r#async::IntoWs;

/// The number of values to fit in the output buffer.
const OUTPUT_BUFFER_SIZE: usize = 10;

/// A type definition for sink.
type WsSink = Box<Sink<SinkItem = OwnedMessage, SinkError = WebSocketError> + Send>;
/// A type definition for stream.
type WsStream = Box<Stream<Item = OwnedMessage, Error = WebSocketError> + Send>;

pub type RequestId = u64;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RequestKind {
    WalletRequest(WalletRequest),
    NodeRequest(NodeRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Request {
    #[serde(flatten)]
    kind: RequestKind,
    #[serde(default)]
    id: u64,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ResponseKind {
    WalletResponse(WalletResponse),
    NodeResponse(NodeResponse),
}

fn is_default(id: &RequestId) -> bool {
    *id == 0
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct Response {
    #[serde(flatten)]
    kind: ResponseKind,
    #[serde(skip_serializing_if = "is_default")]
    id: RequestId,
}

/// Handler of incoming connections.
struct WebSocketHandler {
    /// Remote address.
    peer: SocketAddr,
    /// Outgoing stream.
    sink: WsSink,
    /// Incoming stream.
    stream: WsStream,
    /// True if outgoing buffer should be flushed on the next poll().
    need_flush: bool,
    /// Wallet API.
    wallet: Wallet,
    /// Wallet events.
    wallet_notifications: UnboundedReceiver<WalletNotification>,
    /// Wallet RPC responses.
    wallet_responses: Vec<(RequestId, oneshot::Receiver<WalletResponse>)>,
    /// Node API.
    node: Node,
    /// Node RPC responses.
    node_responses: Vec<(RequestId, oneshot::Receiver<NodeResponse>)>,
}

impl WebSocketHandler {
    fn new(peer: SocketAddr, sink: WsSink, stream: WsStream, wallet: Wallet, node: Node) -> Self {
        let need_flush = false;
        let wallet_notifications = wallet.subscribe();
        let wallet_responses = Vec::new();
        let node_responses = Vec::new();
        WebSocketHandler {
            peer,
            sink,
            stream,
            need_flush,
            wallet,
            wallet_notifications,
            wallet_responses,
            node,
            node_responses,
        }
    }

    fn on_message(&mut self, text: String) -> Result<(), WebSocketError> {
        let request: Request = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                error!("Invalid request: {}", e);
                return Err(WebSocketError::RequestError("Invalid request"));
            }
        };
        match request.kind {
            RequestKind::WalletRequest(wallet_request) => {
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

    fn on_wallet_notification(&mut self, notification: WalletNotification) {
        let msg = serde_json::to_string(&notification).expect("serialized");
        if let Err(e) = self.send(msg) {
            error!("Failed to send notification: {}", e);
        }
    }

    fn on_response(&mut self, response: Response) {
        let msg = serde_json::to_string(&response).expect("serialized");
        if let Err(e) = self.send(msg) {
            error!("Failed to send response: {}", e);
        }
    }

    fn send(&mut self, text: String) -> Result<(), WebSocketError> {
        self.send_raw(OwnedMessage::Text(text))
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
                    debug!("[{}] Received text: {}", self.peer, &msg);
                    self.on_message(msg)?
                }
                Async::Ready(Some(OwnedMessage::Binary(msg))) => {
                    debug!("[{}] Received binary: len={}", self.peer, msg.len());
                    return Err(WebSocketError::RequestError("BinaryIsNotSupported"));
                }
                Async::Ready(Some(OwnedMessage::Ping(msg))) => {
                    debug!("[{}] Received ping: len={}", self.peer, msg.len());
                    self.send_raw(OwnedMessage::Pong(msg))?
                }
                Async::Ready(Some(OwnedMessage::Pong(msg))) => {
                    debug!("[{}] Received pong: len={}", self.peer, msg.len());
                }
                Async::Ready(Some(OwnedMessage::Close(data))) => {
                    debug!(
                        "[{}] Received close: has_data={}",
                        self.peer,
                        data.is_some()
                    );
                    return Ok(Async::Ready(()));
                }
                Async::Ready(None) => {
                    debug!("[{}] Received eof", self.peer);
                    return Ok(Async::Ready(()));
                }
                Async::NotReady => break,
            }
        }

        loop {
            match self.wallet_notifications.poll() {
                Ok(Async::Ready(Some(notification))) => {
                    self.on_wallet_notification(notification);
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
                        kind: ResponseKind::WalletResponse(response),
                        id,
                    };
                    self.on_response(response);
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
                    self.on_response(response)
                }
                Ok(Async::NotReady) => self.node_responses.push((id, rx)),
                Err(_) => panic!("disconnected"),
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

pub struct WebSocketAPI {}

impl WebSocketAPI {
    pub fn spawn(
        cfg: WebSocketConfig,
        executor: TaskExecutor,
        wallet: Wallet,
        node: Node,
    ) -> Result<(), Error> {
        let executor2 = executor.clone();
        let wallet2 = wallet.clone();
        let node2 = node.clone();
        let addr: SocketAddr = format!("{}:{}", cfg.bind_ip, cfg.bind_port).parse()?;
        info!("Starting WebSocket API on {}", &addr);
        let server = TcpListener::bind(&addr)?
            .incoming()
            .map_err(|e| {
                error!("Failed to accept: {:?}", e);
            })
            .for_each(move |s| {
                let wallet3 = wallet2.clone();
                let node3 = node2.clone();
                let peer = s.peer_addr().expect("has peer address");
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
                                    sink,
                                    stream,
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

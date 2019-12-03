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
use stegos_network::{Network, NetworkResponse as NetworkServiceResponse, UnicastMessage};
use stegos_node::{ChainNotification, Node, NodeResponse, StatusNotification};
use stegos_wallet::api::{WalletNotification, WalletResponse};
use stegos_wallet::Wallet;
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
    /// Output buffer.
    sink_buf: Option<OwnedMessage>,
    /// Incoming stream.
    stream: WsStream,
    /// Network API.
    network: Network,
    /// Network unicast subscribtions.
    network_unicast: HashMap<String, mpsc::UnboundedReceiver<UnicastMessage>>,
    /// Network broadcast subscribtions.
    network_broadcast: HashMap<String, mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Responses from the network subsystem
    network_responses: Vec<(RequestId, oneshot::Receiver<NetworkServiceResponse>)>,
    /// Wallet API.
    wallet: Wallet,
    /// Wallet events.
    wallet_notifications: mpsc::UnboundedReceiver<WalletNotification>,
    /// Wallet RPC responses.
    wallet_responses: Vec<(RequestId, oneshot::Receiver<WalletResponse>)>,
    /// Node API.
    node: Node,
    /// Node RPC responses.
    node_responses: Vec<(RequestId, oneshot::Receiver<NodeResponse>)>,
    /// Subscription to status notifications.
    status_notifications: Option<mpsc::Receiver<StatusNotification>>,
    /// Subscription to blockchain notifications.
    chain_notifications: Option<mpsc::Receiver<ChainNotification>>,
    /// Server version.
    version: String,
}

enum NetworkResult {
    Immediate(NetworkResponse),
    Async(oneshot::Receiver<NetworkServiceResponse>),
}

impl WebSocketHandler {
    fn new(
        peer: SocketAddr,
        api_token: ApiToken,
        sink: WsSink,
        stream: WsStream,
        network: Network,
        wallet: Wallet,
        node: Node,
        version: String,
    ) -> Self {
        let sink_buf = None;
        let mut network_unicast = HashMap::new();
        let rx = network.subscribe_unicast(CONSOLE_TOPIC).unwrap();
        network_unicast.insert(CONSOLE_TOPIC.to_string(), rx);
        let mut network_broadcast = HashMap::new();
        let rx = network.subscribe(CONSOLE_TOPIC).unwrap();
        network_broadcast.insert(CONSOLE_TOPIC.to_string(), rx);
        let network_responses = Vec::new();
        let wallet_notifications = wallet.subscribe();
        let wallet_responses = Vec::new();
        let node_responses = Vec::new();
        let status_notifications = None;
        let chain_notifications = None;
        WebSocketHandler {
            peer,
            api_token,
            sink,
            sink_buf,
            stream,
            network,
            network_unicast,
            network_broadcast,
            network_responses,
            wallet,
            wallet_notifications,
            wallet_responses,
            node,
            node_responses,
            status_notifications,
            chain_notifications,
            version,
        }
    }

    fn handle_network_request(
        &mut self,
        network_request: NetworkRequest,
    ) -> Result<NetworkResult, Error> {
        match network_request {
            NetworkRequest::VersionInfo {} => {
                let version = self.version.clone();
                Ok(NetworkResult::Immediate(NetworkResponse::VersionInfo {
                    version,
                }))
            }
            NetworkRequest::SubscribeUnicast { topic } => {
                if !self.network_unicast.contains_key(&topic) {
                    let rx = self.network.subscribe_unicast(&topic)?;
                    self.network_unicast.insert(topic, rx);
                    task::current().notify();
                }
                Ok(NetworkResult::Immediate(NetworkResponse::SubscribedUnicast))
            }
            NetworkRequest::SubscribeBroadcast { topic } => {
                if !self.network_broadcast.contains_key(&topic) {
                    let rx = self.network.subscribe(&topic)?;
                    self.network_broadcast.insert(topic, rx);
                    task::current().notify();
                }
                Ok(NetworkResult::Immediate(
                    NetworkResponse::SubscribedBroadcast,
                ))
            }
            NetworkRequest::UnsubscribeUnicast { topic } => {
                self.network_unicast.remove(&topic);
                Ok(NetworkResult::Immediate(
                    NetworkResponse::UnsubscribedUnicast,
                ))
            }
            NetworkRequest::UnsubscribeBroadcast { topic } => {
                self.network_broadcast.remove(&topic);
                Ok(NetworkResult::Immediate(
                    NetworkResponse::UnsubscribedBroadcast,
                ))
            }
            NetworkRequest::SendUnicast { topic, to, data } => {
                self.network.send(to, &topic, data)?;
                Ok(NetworkResult::Immediate(NetworkResponse::SentUnicast))
            }
            NetworkRequest::PublishBroadcast { topic, data } => {
                self.network.publish(&topic, data)?;
                Ok(NetworkResult::Immediate(
                    NetworkResponse::PublishedBroadcast,
                ))
            }
            NetworkRequest::ConnectedNodesRequest {} => {
                let rx = self.network.list_connected_nodes()?;
                Ok(NetworkResult::Async(rx))
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
        macro_rules! try_send_raw {
            ($self:expr, $msg:expr) => {{
                let msg = $msg;
                assert!(self.sink_buf.is_none());
                trace!("[{}] <= {:?}", self.peer, msg);
                match self.sink.start_send(msg)? {
                    AsyncSink::Ready => {}
                    AsyncSink::NotReady(msg) => {
                        trace!("[{}] Not ready", self.peer);
                        self.sink_buf = Some(msg);
                        trace!("[{}] Flush", self.peer);
                        self.sink.poll_complete()?;
                        return Ok(Async::NotReady);
                    }
                }
            }};
        }

        macro_rules! try_send {
            ($self:expr, $msg:expr) => {{
                trace!("[{}] <= {:?}", self.peer, $msg);
                let msg2 = encode(&self.api_token, &$msg);
                try_send_raw!(self, OwnedMessage::Text(msg2));
            }};
        }

        trace!("[{}] Poll", self.peer);
        if let Some(msg) = self.sink_buf.take() {
            // Flush pending item.
            try_send_raw!(self, msg);
        }
        assert!(self.sink_buf.is_none());

        // Process incoming messages.
        loop {
            match self.stream.poll()? {
                Async::Ready(Some(OwnedMessage::Text(msg))) => {
                    trace!("[{}] => Text({})", self.peer, &msg);
                    let request: Request = decode(&self.api_token, &msg)?;
                    trace!("[{}] => {:?}", self.peer, request);
                    match request.kind {
                        RequestKind::NetworkRequest(network_request) => {
                            match self.handle_network_request(network_request) {
                                Ok(NetworkResult::Immediate(r)) => {
                                    let response = Response {
                                        kind: ResponseKind::NetworkResponse(r),
                                        id: request.id,
                                    };
                                    try_send!(self, response);
                                }
                                Ok(NetworkResult::Async(rx)) => {
                                    self.network_responses.push((request.id, rx));
                                }
                                Err(e) => {
                                    let r = NetworkResponse::Error {
                                        error: format!("{}", e),
                                    };
                                    let response = Response {
                                        kind: ResponseKind::NetworkResponse(r),
                                        id: request.id,
                                    };
                                    try_send!(self, response);
                                }
                            };
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
                }
                Async::Ready(Some(OwnedMessage::Binary(msg))) => {
                    trace!("[{}] => Binary(len={})", self.peer, msg.len());
                    return Err(WebSocketError::RequestError("BinaryIsNotSupported"));
                }
                Async::Ready(Some(OwnedMessage::Ping(msg))) => {
                    trace!("[{}] => Ping(len={})", self.peer, msg.len());
                    try_send_raw!(self, OwnedMessage::Pong(msg));
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
        for (topic, rx) in self.network_unicast.iter_mut() {
            loop {
                match rx.poll().unwrap() {
                    Async::Ready(Some(msg)) => {
                        let msg = NetworkNotification::UnicastMessage {
                            topic: topic.clone(),
                            from: msg.from,
                            data: msg.data,
                        };
                        let msg = Response {
                            kind: ResponseKind::NetworkNotification(msg),
                            id: 0,
                        };
                        try_send!(self, msg);
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                    Async::NotReady => break,
                }
            }
        }

        // Network broadcast messages.
        for (topic, rx) in self.network_broadcast.iter_mut() {
            loop {
                match rx.poll().unwrap() {
                    Async::Ready(Some(data)) => {
                        let msg = NetworkNotification::BroadcastMessage {
                            topic: topic.clone(),
                            data,
                        };
                        let msg = Response {
                            kind: ResponseKind::NetworkNotification(msg),
                            id: 0,
                        };
                        try_send!(self, msg);
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                    Async::NotReady => break,
                }
            }
        }

        // Network responses
        let mut i = 0;
        while i < self.network_responses.len() {
            match self.network_responses[i].1.poll() {
                Ok(Async::Ready(response)) => {
                    let (id, _) = self.network_responses.swap_remove(i);
                    let resp = match response {
                        NetworkServiceResponse::ConnectedNodes { nodes } => Response {
                            kind: ResponseKind::NetworkResponse(NetworkResponse::ConnectedNodes {
                                total: nodes.len(),
                                nodes,
                            }),
                            id,
                        },
                    };
                    try_send!(self, resp);
                    continue;
                }
                Ok(Async::NotReady) => {}
                Err(oneshot::Canceled) => panic!("missing response for WalletRequest"),
            }
            i += 1;
        }

        // Wallet notifications.
        loop {
            match self.wallet_notifications.poll().unwrap() {
                Async::Ready(Some(notification)) => {
                    let response = Response {
                        kind: ResponseKind::WalletNotification(notification),
                        id: 0,
                    };
                    try_send!(self, response);
                }
                Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                Async::NotReady => break,                          // fall through
            }
        }

        // Wallet responses.
        let mut i = 0;
        while i < self.wallet_responses.len() {
            match self.wallet_responses[i].1.poll() {
                Ok(Async::Ready(response)) => {
                    let (id, _) = self.wallet_responses.swap_remove(i);
                    let response = Response {
                        kind: ResponseKind::WalletResponse(response),
                        id,
                    };
                    try_send!(self, response);
                    continue;
                }
                Ok(Async::NotReady) => {}
                Err(oneshot::Canceled) => panic!("missing response for WalletRequest"),
            }
            i += 1;
        }

        // Node responses.
        let mut i = 0;
        while i < self.node_responses.len() {
            match self.node_responses[i].1.poll() {
                Ok(Async::Ready(mut response)) => {
                    match &mut response {
                        NodeResponse::SubscribedStatus { rx, .. } => {
                            self.status_notifications = rx.take();
                        }
                        NodeResponse::SubscribedChain { rx, .. } => {
                            self.chain_notifications = rx.take();
                        }
                        _ => {}
                    };
                    let (id, _) = self.node_responses.swap_remove(i);
                    let response = Response {
                        kind: ResponseKind::NodeResponse(response),
                        id,
                    };
                    try_send!(self, response);
                    continue;
                }
                Ok(Async::NotReady) => {}
                Err(oneshot::Canceled) => panic!("missing response for NodeRequest"),
            }
            i += 1;
        }

        // Status notifications.
        if let Some(status_notifications) = &mut self.status_notifications {
            loop {
                match status_notifications.poll().unwrap() {
                    Async::Ready(Some(msg)) => {
                        let msg = Response {
                            kind: ResponseKind::StatusNotification(msg),
                            id: 0,
                        };
                        try_send!(self, msg);
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                    Async::NotReady => break,                          // fall through
                }
            }
        }

        // Chain notifications.
        if let Some(chain_notifications) = &mut self.chain_notifications {
            loop {
                match chain_notifications.poll().unwrap() {
                    Async::Ready(Some(msg)) => {
                        match &msg {
                            ChainNotification::MicroBlockPrepared(block) => {
                                trace!(
                                    "Prepared Micro Block: epoch={}, offset={}",
                                    block.header.epoch,
                                    block.header.offset
                                );
                            }
                            ChainNotification::MicroBlockReverted(block) => {
                                trace!(
                                    "Reverted Micro Block: epoch={}, offset={}",
                                    block.block.header.epoch,
                                    block.block.header.offset
                                );
                            }
                            ChainNotification::MacroBlockCommitted(block) => {
                                trace!("Comitted Macro Block: epoch={}", block.block.header.epoch);
                            }
                        }
                        let msg = Response {
                            kind: ResponseKind::ChainNotification(msg),
                            id: 0,
                        };
                        try_send!(self, msg);
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                    Async::NotReady => break,
                }
            }
        }

        // Flush sink.
        trace!("[{}] Flush", self.peer);
        self.sink.poll_complete()?;
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
        wallet: Wallet,
        node: Node,
        version: String,
    ) -> Result<(), Error> {
        let executor2 = executor.clone();
        let network2 = network.clone();
        let wallet2 = wallet.clone();
        let node2 = node.clone();
        let version2 = version.clone();
        let addr: SocketAddr = endpoint.parse()?;
        info!(target: "stegos_api", "Starting API Server on {}", &addr);
        let server = TcpListener::bind(&addr)?
            .incoming()
            .map_err(|e| {
                error!("Failed to accept: {:?}", e);
            })
            .for_each(move |s| {
                let network3 = network2.clone();
                let wallet3 = wallet2.clone();
                let node3 = node2.clone();
                let version3 = version2.clone();
                let peer = match s.peer_addr() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to get remote peer info: errpr={}", e);
                        return Ok(());
                    }
                };
                let api_token = api_token.clone();
                debug!("[{}] Accepted", peer);
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
                                    version3.clone(),
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

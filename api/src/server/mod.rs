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
use crate::{decode, encode, InnerResponses, Request, Response, ResponseKind};
use failure::{bail, Error};
use futures::prelude::*;
use futures::select;
use futures::SinkExt;
use log::*;
use stegos_network::Network;

use std::pin::Pin;

use api::clone_apis;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::Message;

use tokio::task::JoinHandle;
/// The number of values to fit in the output buffer.
const OUTPUT_BUFFER_SIZE: usize = 100;
/// Topic used for debugging.
// const CONSOLE_TOPIC: &'static str = "console";

/// A type definition for stream.
type WsStream = sink::Buffer<WebSocketStream<TcpStream>, Message>;

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
    /// Incoming stream.
    connection: WsStream,

    register: Register,
}

impl WebSocketHandler {
    fn new(
        peer: SocketAddr,
        api_token: ApiToken,
        connection: WsStream,
        apis: Vec<Box<dyn ApiHandler>>,
        network: Option<Network>,
        version: String,
        chain_name: String,
    ) -> Self {
        let mut register = Register::new();
        if let Some(network) = network {
            let network_api = NetworkApi::new(network, version, chain_name);
            register.add_api(Box::new(network_api));
        }
        for api in apis {
            register.add_api(api);
        }

        WebSocketHandler {
            peer,
            api_token,
            connection,
            register,
        }
    }

    async fn send(sink: &mut WsStream, api_token: &ApiToken, msg: Response) -> Result<(), Error> {
        let msg = encode(api_token, &msg);
        let msg = Message::Text(msg);
        Self::send_raw(sink, msg).await
    }

    async fn send_raw(sink: &mut WsStream, msg: Message) -> Result<(), Error> {
        SinkExt::send(sink, msg).await.map_err(From::from)
    }

    async fn receive(
        connection: &mut WsStream,
        api_token: ApiToken,
        peer: SocketAddr,
    ) -> Result<Request, Error> {
        loop {
            let result = connection.next().await;
            match result {
                Some(Ok(Message::Text(msg))) => {
                    return decode(&api_token, &msg);
                }
                Some(Ok(Message::Ping(msg))) => {
                    trace!("[{}] => Ping(len={})", peer, msg.len());
                    let _err = connection.send(Message::Pong(msg)).await;
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
            let mut receive_orig = Self::receive(&mut self.connection, api_token, peer);
            let receive = unsafe { Pin::new_unchecked(&mut receive_orig) };
            let mut receive = receive.fuse();
            select! {
                notification = self.register.notifications.next() => {
                    drop(receive);
                    drop(receive_orig);
                    let notifiocation = if let Some(notification) = notification {
                        trace!("Forwarding notification = {:?}", notification);
                        let kind = notification.0;
                        let response = Response { kind, id:0 };
                        if let Err(e) = Self::send(&mut self.connection, &self.api_token, response).await {
                            error!("Error during response send = {}", e);
                        }
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
                        let kind = match self.register.try_process("nothing", req).await {
                            Ok(response) => response.0,
                            Err(e) => {ResponseKind::Inner(InnerResponses::InternalError {
                                error: e.to_string()
                            })}
                        };
                        let response = Response { kind, id };
                        Self::send(&mut self.connection, &self.api_token, response).await
                    };
                    if let Err(e) = block.await {
                        warn!("Error during processing of request, error={}", e);
                    };

                }
            };
        }
    }
}

pub async fn spawn_server(
    endpoint: String,
    api_token: ApiToken,
    apis: Vec<Box<dyn ApiHandler>>,
    network: Option<Network>,
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
    network: Option<Network>,
    version: String,
    chain_name: String,
) {
    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    debug!("[{}] Accepted", peer);
    let stream = ws_stream.buffer(OUTPUT_BUFFER_SIZE);
    info!("[{}] Connected", peer);
    WebSocketHandler::new(peer, api_token, stream, apis, network, version, chain_name)
        .spawn()
        .await
}

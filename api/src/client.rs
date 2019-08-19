//! WebSocket Client.

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
use crate::{decode, encode, Request, Response};
use futures::future::Future;
use futures::sink::Sink;
use futures::stream::{SplitSink, SplitStream, Stream};
use futures::{task, AsyncSink};
use futures::{Async, Poll};
use log::*;
use std::time::Duration;
use tokio::codec::Framed;
use tokio::net::TcpStream;
use tokio_timer::{clock, Delay};
use websocket::header::Headers;
use websocket::r#async::MessageCodec;
use websocket::result::WebSocketError;
pub use websocket::url;
use websocket::{ClientBuilder, OwnedMessage};

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type S = Framed<TcpStream, MessageCodec<OwnedMessage>>;
type ClientSink = SplitSink<S>;
type ClientStream = SplitStream<S>;
type ConnectionFuture = Box<dyn Future<Item = (S, Headers), Error = WebSocketError> + Send>;

enum State {
    WaitReconnect(Delay),
    Connect(ConnectionFuture),
    Connected(ClientSink, ClientStream),
}

pub struct WebSocketClient {
    /// Remote endpoint.
    endpoint: String,
    /// API Token.
    api_token: ApiToken,
    /// True if outgoing buffer should be flushed on the next poll().
    need_flush: bool,
    /// Connection state.
    state: State,
}

impl WebSocketClient {
    pub fn new(endpoint: String, api_token: ApiToken) -> Self {
        let state = State::WaitReconnect(Delay::new(clock::now()));
        let need_flush = false;
        Self {
            endpoint,
            api_token,
            need_flush,
            state,
        }
    }

    pub fn send(&mut self, msg: Request) -> Result<(), WebSocketError> {
        trace!("[{}] <= {:?}", self.endpoint, msg);
        let msg = encode(&self.api_token, &msg);
        let msg = OwnedMessage::Text(msg);
        self.send_raw(msg)
    }

    fn send_raw(&mut self, msg: OwnedMessage) -> Result<(), WebSocketError> {
        let sink = match &mut self.state {
            State::Connected(sink, _) => sink,
            _ => {
                return Err(WebSocketError::IoError(
                    std::io::ErrorKind::NotConnected.into(),
                ));
            }
        };

        match sink.start_send(msg)? {
            AsyncSink::Ready => {
                task::current().notify();
                self.need_flush = true;
                Ok(())
            }
            AsyncSink::NotReady(_msg) => Err(WebSocketError::IoError(
                std::io::ErrorKind::WouldBlock.into(),
            )),
        }
    }

    /// Returns true if client is connected to remote part.
    pub fn is_connected(&self) -> bool {
        match &self.state {
            State::Connected(..) => true,
            _ => false,
        }
    }
}

impl WebSocketClient {
    fn poll_impl(&mut self) -> Poll<Response, WebSocketError> {
        match &mut self.state {
            State::Connect(connection_fut) => {
                trace!("poll: state=Connect");
                match connection_fut.poll()? {
                    Async::Ready((duplex, _)) => {
                        let (sink, stream) = duplex.split();
                        let state = State::Connected(sink, stream);
                        std::mem::replace(&mut self.state, state);
                        task::current().notify();
                        debug!("[{}] Connected", self.endpoint);
                    }
                    Async::NotReady => {}
                }
            }
            State::WaitReconnect(delay) => {
                trace!("poll: state=WaitReconnect");
                match delay.poll().unwrap() {
                    Async::Ready(()) => {
                        let connect_fut = ClientBuilder::new(&self.endpoint)
                            .unwrap()
                            .async_connect_insecure();
                        let state = State::Connect(connect_fut);
                        std::mem::replace(&mut self.state, state);
                        task::current().notify();
                        debug!("[{}] Connecting...", self.endpoint);
                    }
                    Async::NotReady => {}
                }
            }
            State::Connected(sink, stream) => {
                trace!("poll: state=Connected");
                if self.need_flush {
                    match sink.poll_complete()? {
                        Async::Ready(()) => {
                            self.need_flush = false;
                        }
                        Async::NotReady => {}
                    }
                }

                match stream.poll()? {
                    Async::Ready(Some(OwnedMessage::Text(msg))) => {
                        trace!("[{}] => Text({})", self.endpoint, msg);
                        let response: Response = decode(&self.api_token, &msg)?;
                        trace!("[{}] => {:?}", self.endpoint, response);
                        return Ok(Async::Ready(response));
                    }
                    Async::Ready(Some(OwnedMessage::Binary(msg))) => {
                        trace!("[{}] => Binary(len={})", self.endpoint, msg.len());
                        return Err(WebSocketError::ResponseError("binary is not supported"));
                    }
                    Async::Ready(Some(OwnedMessage::Ping(msg))) => {
                        trace!("[{}] => Ping(len={})", self.endpoint, msg.len());
                        self.send_raw(OwnedMessage::Pong(msg))?;
                    }
                    Async::Ready(Some(OwnedMessage::Pong(msg))) => {
                        trace!("[{}] => Pong(len={})", self.endpoint, msg.len());
                    }
                    Async::Ready(Some(OwnedMessage::Close(data))) => {
                        trace!("[{}] => Close(has_data={})", self.endpoint, data.is_some());
                        return Err(WebSocketError::IoError(
                            std::io::ErrorKind::ConnectionReset.into(),
                        ));
                    }
                    Async::Ready(None) => {
                        trace!("[{}] => EOF", self.endpoint);
                        return Err(WebSocketError::IoError(
                            std::io::ErrorKind::ConnectionReset.into(),
                        ));
                    }
                    Async::NotReady => {}
                }
            }
        }
        Ok(Async::NotReady)
    }
}

// Event loop.
impl Future for WebSocketClient {
    type Item = Response;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.poll_impl() {
            Ok(r) => Ok(r),
            Err(e) => {
                error!("[{}] {:?}", self.endpoint, e);
                let deadline = clock::now() + RECONNECT_TIMEOUT;
                let state2 = State::WaitReconnect(Delay::new(deadline));
                std::mem::replace(&mut self.state, state2);
                task::current().notify();
                debug!(
                    "[{}] Reconnecting after {:?}",
                    self.endpoint, RECONNECT_TIMEOUT
                );
                Ok(Async::NotReady)
            }
        }
    }
}

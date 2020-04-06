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
use crate::ResponseKind;
use crate::{decode, encode, Request, Response};
use failure::bail;
use failure::Error;
use futures::prelude::*;
use futures::ready;
use futures::task::{Context, Poll};
use futures::SinkExt;
use log::*;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
use std::collections::VecDeque;

pub struct WebSocketClient {
    /// Remote endpoint.
    endpoint: String,
    /// API Token.
    api_token: ApiToken,
    connection: WebSocketStream<TcpStream>,
    /// Pending notifications.
    pending_notifications: VecDeque<Response>,
}

impl WebSocketClient {
    pub async fn new(endpoint: String, api_token: ApiToken) -> Result<Self, Error> {
        let connection = tokio_tungstenite::connect_async(&endpoint).await?.0;
        let pending_notifications = VecDeque::new();
        Ok(Self {
            endpoint,
            api_token,
            connection,
            pending_notifications,
        })
    }

    pub async fn request(&mut self, msg: Request) -> Result<Response, Error> {
        trace!("[{}] <= {:?}", self.endpoint, msg);
        let msg = encode(&self.api_token, &msg);
        let msg = Message::Text(msg);
        self.send_raw(msg).await;
        loop {
            let response = self.receive().await?;
            match response.kind {
                // response @ ResponseKind::NetworkResponse(_) |
                // response @ ResponseKind::WalletResponse(_) |
                ResponseKind::NodeResponse(_) => {
                    return Ok(response);
                }
                _ => {
                    trace!("Received notification in response of request, pushing to pending list, notification = {:?}", response);
                    self.pending_notifications.push_back(response);
                }
            }
        }
    }

    pub async fn notification(&mut self) -> Result<Response, Error> {
        if let Some(item) = self.pending_notifications.pop_front() {
            return Ok(item);
        }
        assert!(self.pending_notifications.is_empty());
        self.receive().await
    }

    async fn send_raw(&mut self, msg: Message) -> Result<(), Error> {
        SinkExt::send(&mut self.connection, msg)
            .await
            .map_err(From::from)
    }

    async fn receive(&mut self) -> Result<Response, Error> {
        let result = self.connection.next().await;
        let result = match result {
            Some(result) => result?,
            None => bail!("Stream gone on receive."),
        };
        let result = result.into_text()?;
        decode(&self.api_token, &result)
    }
}

// impl Stream for WebSocketClient
// {
//     type Item = Result<Response, Error>;

//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         if let Some(i) = buffer.pop_front() {
//             return Poll::Ready(Some(Ok(i)))
//         }
//         let x = ready!(Stream::poll_next(Pin::new(&mut self.connection), cx));
//         match
//         Poll::Ready(x.map(|x|x.map_err(Into::into)))
//     }
// }

// impl Sink<Message> for WebSocketClient
// {
//     type Error = Error;

//     fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         let x = ready!(Sink::poll_ready(Pin::new(&mut self.connection), cx));
//         Poll::Ready(x.map_err(Into::into))
//     }

//     fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
//         let x = Sink::start_send(Pin::new(&mut self.connection), item);
//         x.map_err(Into::into)

//     }

//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         let x = ready!(Sink::poll_flush(Pin::new(&mut self.connection), cx));
//         Poll::Ready(x.map_err(Into::into))
//     }

//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         let x = ready!(Sink::poll_close(Pin::new(&mut self.connection), cx));
//         Poll::Ready(x.map_err(Into::into))
//     }
// }

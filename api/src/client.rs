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
use crate::InnerResponses;
use crate::ResponseKind;
use crate::{decode, encode, Request, Response};
use failure::bail;
use failure::Error;
use futures::prelude::*;
use futures::SinkExt;
use log::*;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);
use futures_retry::{FutureRetry, RetryPolicy};
use std::collections::VecDeque;
use std::time::Duration;

fn handle_connection_error(_e: WsError) -> RetryPolicy<WsError> {
    // This is kinda unrealistical error handling, don't use it as it is!
    debug!("Error on reconnect");
    RetryPolicy::WaitRetry(RECONNECT_TIMEOUT)
}

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
        loop {
            self.send_raw(msg.clone()).await?;
            'inner: loop {
                let response = self.receive().await?;
                let response = if let Some(response) = response {
                    response
                } else {
                    warn!("Disconected during receive, trying to request again.");
                    break 'inner;
                };

                match response.kind {
                    ResponseKind::NetworkResponse(_)
                    | ResponseKind::WalletResponse(_)
                    | ResponseKind::NodeResponse(_)
                    | ResponseKind::Raw(_) => {
                        return Ok(response);
                    }
                    _ => {
                        trace!("Received notification in response of request, pushing to pending list, notification = {:?}", response);
                        self.pending_notifications.push_back(response);
                    }
                }
            }
        }
    }

    pub async fn notification(&mut self) -> Result<Response, Error> {
        loop {
            if let Some(item) = self.pending_notifications.pop_front() {
                return Ok(item);
            }

            assert!(self.pending_notifications.is_empty());

            if let Some(receive) = self.receive().await? {
                return Ok(receive);
            }
        }
    }

    async fn send_raw(&mut self, msg: Message) -> Result<(), Error> {
        if let Err(e) = SinkExt::send(&mut self.connection, msg.clone()).await {
            info!("Error on sending message to websocket, reconnecting");
            debug!("Websocket::send_raw error = {:?}", e);
            tokio::time::delay_for(RECONNECT_TIMEOUT).await;
            let endpoit = self.endpoint.clone();
            if let Ok(connection) = FutureRetry::new(
                || tokio_tungstenite::connect_async(&endpoit),
                handle_connection_error,
            )
            .await
            {
                self.connection = (connection.0).0;
                info!("Reconnected to websocket, trying to resend last request.");
                let msg = SinkExt::send(&mut self.connection, msg).await?;
                self.push_reconnect_notification();
                msg
            } else {
                return Err(e.into());
            }
        }
        Ok(())
    }
    async fn receive_raw(&mut self) -> Result<Message, Error> {
        let result = self.connection.next().await;
        let result = match result {
            Some(result) => result?,
            None => bail!("Stream gone on receive, check if api.token is correct."),
        };
        Ok(result)
    }

    /// Returns None - on reconnect
    async fn receive(&mut self) -> Result<Option<Response>, Error> {
        let result = match self.receive_raw().await {
            Err(e) => {
                info!("Error on receiving message to websocket, reconnecting");
                debug!("Websocket::receive error = {:?}", e);
                tokio::time::delay_for(RECONNECT_TIMEOUT).await;
                let endpoit = self.endpoint.clone();
                if let Ok(connection) = FutureRetry::new(
                    || tokio_tungstenite::connect_async(&endpoit),
                    handle_connection_error,
                )
                .await
                {
                    self.connection = (connection.0).0;
                    info!("Reconnected to websocket, trying to receive again.");
                    self.push_reconnect_notification();
                    return Ok(None);
                } else {
                    return Err(e.into());
                }
            }
            Ok(result) => result,
        };
        let result = result.into_text()?;
        decode(&self.api_token, &result)
    }

    fn push_reconnect_notification(&mut self) {
        let kind = ResponseKind::Inner(InnerResponses::Reconnect);
        let response = Response { id: 0, kind };
        self.pending_notifications.push_back(response);
    }
}

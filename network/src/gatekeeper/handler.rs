//
// MIT License
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

use super::protocol::{GatekeeperCodec, GatekeeperConfig, GatekeeperMessage};

use futures::prelude::*;
use libp2p::core::{
    protocols_handler::{KeepAlive, ProtocolsHandlerUpgrErr},
    upgrade::{InboundUpgrade, OutboundUpgrade},
    ProtocolsHandler, ProtocolsHandlerEvent,
};
use log::{debug, trace};
use smallvec::SmallVec;
use std::{
    fmt, io,
    time::{Duration, Instant},
};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

/// Event passed to protocol handler from upper level
pub enum GatekeeperSendEvent {
    Shutdown,
    Send(GatekeeperMessage),
}

/// Protocol handler that handles communication with the remote for the Gatekeeper protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct GatekeeperHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Configuration for the Ncp protocol.
    config: GatekeeperConfig,

    /// If true, we are trying to shut down the existing Gatekeeper substream and should refuse any
    /// incoming connection.
    shutting_down: bool,

    /// Keep connection alive for data to arrive
    keep_alive: KeepAlive,

    /// Internal failure happened
    internal_failure: bool,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState<TSubstream>>,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[GatekeeperMessage; 16]>,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Waiting for a message from the remote.
    WaitingInput(Framed<TSubstream, GatekeeperCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<TSubstream, GatekeeperCodec>, GatekeeperMessage),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<TSubstream, GatekeeperCodec>),
    /// The substream is being closed.
    Closing(Framed<TSubstream, GatekeeperCodec>),
}

impl<TSubstream> GatekeeperHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Builds a new `NcpHandler`.
    pub fn new() -> Self {
        GatekeeperHandler {
            config: GatekeeperConfig::new(),
            shutting_down: false,
            keep_alive: KeepAlive::Until(Instant::now() + Duration::from_secs(5)),
            internal_failure: false,
            substreams: Vec::new(),
            send_queue: SmallVec::new(),
        }
    }

    #[inline]
    fn shutdown(&mut self) {
        self.shutting_down = true;
        self.keep_alive = KeepAlive::Now;
        for n in (0..self.substreams.len()).rev() {
            let substream = self.substreams.swap_remove(n);
            self.substreams
                .push(SubstreamState::Closing(substream.into_substream()));
        }
    }
}

impl<TSubstream> SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<TSubstream, GatekeeperCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl<TSubstream> ProtocolsHandler for GatekeeperHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type InEvent = GatekeeperSendEvent;
    type OutEvent = GatekeeperMessage;
    type Error = io::Error;
    type Substream = TSubstream;
    type InboundProtocol = GatekeeperConfig;
    type OutboundProtocol = GatekeeperConfig;
    type OutboundOpenInfo = GatekeeperMessage;

    #[inline]
    fn listen_protocol(&self) -> Self::InboundProtocol {
        self.config.clone()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        trace!(target: "stegos_network::gatekeeper", "successfully negotiated inbound substream");
        if self.shutting_down {
            return ();
        }
        self.keep_alive = KeepAlive::Forever;
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        trace!(target: "stegos_network::gatekeeper", "successfully negotiated outbound substream");
        if self.shutting_down {
            return;
        }
        self.keep_alive = KeepAlive::Forever;
        self.substreams
            .push(SubstreamState::PendingSend(protocol, message))
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            GatekeeperSendEvent::Shutdown => self.shutdown(),
            GatekeeperSendEvent::Send(message) => {
                self.keep_alive = KeepAlive::Forever;
                self.send_queue.push(message);
            }
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        _: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<Self::Substream>>::Error,
        >,
    ) {
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive.clone()
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        io::Error,
    > {
        if self.internal_failure {
            self.internal_failure = false;
            // let other substreams to be closed gracefully
            self.shutdown();
            return Ok(Async::NotReady);
        }

        if !self.send_queue.is_empty() {
            let message = self.send_queue.remove(0);
            return Ok(Async::Ready(
                ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    info: message,
                    upgrade: self.config.clone(),
                },
            ));
        }

        for n in (0..self.substreams.len()).rev() {
            let mut substream = self.substreams.swap_remove(n);
            loop {
                substream = match substream {
                    SubstreamState::WaitingInput(mut substream) => match substream.poll() {
                        Ok(Async::Ready(Some(message))) => {
                            self.substreams
                                .push(SubstreamState::WaitingInput(substream));
                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(message)));
                        }
                        Ok(Async::Ready(None)) => {
                            self.keep_alive =
                                KeepAlive::Until(Instant::now() + Duration::from_secs(5));
                            SubstreamState::Closing(substream)
                        }
                        Ok(Async::NotReady) => {
                            self.substreams
                                .push(SubstreamState::WaitingInput(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            debug!(target: "stegos_network::gatekeeper", "error waiting for input: error={}", e);
                            SubstreamState::Closing(substream)
                        }
                    },
                    SubstreamState::PendingSend(mut substream, message) => {
                        match substream.start_send(message) {
                            Ok(AsyncSink::Ready) => SubstreamState::PendingFlush(substream),
                            Ok(AsyncSink::NotReady(message)) => {
                                self.substreams
                                    .push(SubstreamState::PendingSend(substream, message));
                                return Ok(Async::NotReady);
                            }
                            Err(e) => {
                                debug!(target: "stegos_network::gatekeeper", "error sending message: error={}", e);
                                self.internal_failure = true;
                                return Ok(Async::NotReady);
                            }
                        }
                    }
                    SubstreamState::PendingFlush(mut substream) => {
                        match substream.poll_complete() {
                            Ok(Async::Ready(())) => SubstreamState::Closing(substream),
                            Ok(Async::NotReady) => {
                                self.substreams
                                    .push(SubstreamState::PendingFlush(substream));
                                return Ok(Async::NotReady);
                            }
                            Err(e) => {
                                debug!(target: "stegos_network::gatekeeper", "error flushing substream: error={}", e);
                                self.internal_failure = true;
                                return Ok(Async::NotReady);
                            }
                        }
                    }
                    SubstreamState::Closing(mut substream) => match substream.close() {
                        Ok(Async::Ready(())) => {
                            // Let connection be closed after 5 idle secs
                            self.keep_alive =
                                KeepAlive::Until(Instant::now() + Duration::from_secs(5));
                            self.substreams.shrink_to_fit();
                            break;
                        }
                        Ok(Async::NotReady) => {
                            self.substreams.push(SubstreamState::Closing(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            debug!(target: "stegos_network::gatekeeper", "failure closing substream: error={}", e);
                            self.internal_failure = true;
                            break;
                        }
                    },
                }
            }
        }

        Ok(Async::NotReady)
    }
}

impl<TSubstream> fmt::Debug for GatekeeperHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("GatekeeperHandler")
            .field("shutting_down", &self.shutting_down)
            .field("internal_failure", &self.internal_failure)
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

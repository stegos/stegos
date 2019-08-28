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
use libp2p_core::upgrade::{InboundUpgrade, Negotiated, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use log::{debug, trace};
use smallvec::SmallVec;
use std::{fmt, io, time::Instant};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::NETWORK_IDLE_TIMEOUT;

/// Event passed to protocol handler from upper level
pub enum GatekeeperSendEvent {
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

    /// Keep connection alive for data to arrive
    keep_alive: KeepAlive,

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
    WaitingInput(Framed<Negotiated<TSubstream>, GatekeeperCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(
        Framed<Negotiated<TSubstream>, GatekeeperCodec>,
        GatekeeperMessage,
    ),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<Negotiated<TSubstream>, GatekeeperCodec>),
    /// The substream is being closed.
    Closing(Framed<Negotiated<TSubstream>, GatekeeperCodec>),
}

impl<TSubstream> GatekeeperHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Builds a new `NcpHandler`.
    pub fn new() -> Self {
        GatekeeperHandler {
            config: GatekeeperConfig::new(),
            keep_alive: KeepAlive::Yes,
            substreams: Vec::new(),
            send_queue: SmallVec::new(),
        }
    }
}

impl<TSubstream> SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<Negotiated<TSubstream>, GatekeeperCodec> {
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
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        trace!(target: "stegos_network::gatekeeper", "successfully negotiated inbound substream");
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        trace!(target: "stegos_network::gatekeeper", "successfully negotiated outbound substream");
        self.substreams
            .push(SubstreamState::PendingSend(protocol, message))
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            GatekeeperSendEvent::Send(message) => {
                self.keep_alive = KeepAlive::Yes;
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
        self.keep_alive
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        io::Error,
    > {
        if !self.send_queue.is_empty() {
            let message = self.send_queue.remove(0);
            return Ok(Async::Ready(
                ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    info: message,
                    protocol: SubstreamProtocol::new(self.config.clone()),
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
                        Ok(Async::Ready(None)) => SubstreamState::Closing(substream),
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
                                return Ok(Async::NotReady);
                            }
                        }
                    }
                    SubstreamState::Closing(mut substream) => match substream.close() {
                        Ok(Async::Ready(())) => {
                            self.substreams.shrink_to_fit();
                            break;
                        }
                        Ok(Async::NotReady) => {
                            self.substreams.push(SubstreamState::Closing(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            debug!(target: "stegos_network::gatekeeper", "failure closing substream: error={}", e);
                            break;
                        }
                    },
                }
            }
        }

        if self.substreams.is_empty() {
            self.keep_alive = KeepAlive::Until(Instant::now() + NETWORK_IDLE_TIMEOUT);
        } else {
            self.keep_alive = KeepAlive::Yes;
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
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

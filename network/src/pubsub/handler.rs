// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use super::behavior::{FloodsubRecvEvent, FloodsubSendEvent};
use super::protocol::{FloodsubCodec, FloodsubConfig, FloodsubRpc};

use futures::prelude::*;
use libp2p::core::{
    protocols_handler::{KeepAlive, ProtocolsHandlerUpgrErr, SubstreamProtocol},
    upgrade::{InboundUpgrade, Negotiated, OutboundUpgrade},
    ProtocolsHandler, ProtocolsHandlerEvent,
};
use log::{debug, trace};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::{fmt, io};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

/// Protocol handler that handles communication with the remote for the floodsub protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct FloodsubHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Configuration for the floodsub protocol.
    config: FloodsubConfig,

    /// Accept incoming substreams
    enabled_incoming: bool,

    /// Allow outgoing substreams
    enabled_outgoing: bool,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState<TSubstream>>,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[FloodsubRpc; 16]>,
    /// Events to send upstream
    out_events: VecDeque<FloodsubRecvEvent>,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Waiting for a message from the remote.
    WaitingInput(Framed<Negotiated<TSubstream>, FloodsubCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<Negotiated<TSubstream>, FloodsubCodec>, FloodsubRpc),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<Negotiated<TSubstream>, FloodsubCodec>),
    /// The substream is being closed.
    Closing(Framed<Negotiated<TSubstream>, FloodsubCodec>),
}

impl<TSubstream> SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<Negotiated<TSubstream>, FloodsubCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl<TSubstream> FloodsubHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Builds a new `FloodsubHandler`.
    pub fn new() -> Self {
        FloodsubHandler {
            config: FloodsubConfig::new(),
            enabled_incoming: false,
            enabled_outgoing: false,
            substreams: Vec::new(),
            send_queue: SmallVec::new(),
            out_events: VecDeque::new(),
        }
    }

    #[inline]
    fn disable(&mut self) {
        self.enabled_incoming = false;
        self.enabled_outgoing = false;
        for n in (0..self.substreams.len()).rev() {
            let substream = self.substreams.swap_remove(n);
            self.substreams
                .push(SubstreamState::Closing(substream.into_substream()));
        }
    }
}

impl<TSubstream> ProtocolsHandler for FloodsubHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type InEvent = FloodsubSendEvent;
    type OutEvent = FloodsubRecvEvent;
    type Error = io::Error;
    type Substream = TSubstream;
    type InboundProtocol = FloodsubConfig;
    type OutboundProtocol = FloodsubConfig;
    type OutboundOpenInfo = FloodsubRpc;

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        if !self.enabled_incoming {
            debug!(target: "stegos_network::pubsub", "protocol is disabled. dropping incoming substream");
            return ();
        }
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        if !self.enabled_outgoing {
            debug!(target: "stegos_network::pubsub", "protocol is disabled. dropping outgoing substream");
            return ();
        }
        self.substreams
            .push(SubstreamState::PendingSend(protocol, message))
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            FloodsubSendEvent::EnableIncoming => {
                self.enabled_incoming = true;
                self.out_events
                    .push_back(FloodsubRecvEvent::EnabledIncoming);
            }
            FloodsubSendEvent::EnableOutgoing => {
                self.enabled_incoming = true;
                self.enabled_outgoing = true;
                self.out_events
                    .push_back(FloodsubRecvEvent::EnabledOutgoing);
            }
            FloodsubSendEvent::Disable => {
                self.disable();
                self.out_events.push_back(FloodsubRecvEvent::Disabled);
            }
            FloodsubSendEvent::Publish(message) => {
                self.send_queue.push(message);
            }
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        e: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<Self::Substream>>::Error,
        >,
    ) {
        trace!(target: "stegos_network::pubsub", "got dial outbound failure: {}", e);
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        if self.enabled_incoming || self.enabled_outgoing || !self.substreams.is_empty() {
            KeepAlive::Yes
        } else {
            KeepAlive::No
        }
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        io::Error,
    > {
        if !self.out_events.is_empty() {
            let message = self.out_events.pop_front().unwrap();
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(message)));
        }

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
                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                FloodsubRecvEvent::Message(message),
                            )));
                        }
                        Ok(Async::Ready(None)) => SubstreamState::Closing(substream),
                        Ok(Async::NotReady) => {
                            self.substreams
                                .push(SubstreamState::WaitingInput(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            debug!(target: "stegos_network::pubsub", "error reading from substream: error={}", e);
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
                                debug!(target: "stegos_network::pubsub", "error sending to substream: error={}", e);
                                SubstreamState::Closing(substream)
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
                                debug!(target: "stegos_network::pubsub", "error flushing substream: error={}", e);
                                SubstreamState::Closing(substream)
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
                            trace!(target: "stegos_network::pubsub", "failure closing substream: {}", e);
                            break;
                        }
                    },
                }
            }
        }

        Ok(Async::NotReady)
    }
}

impl<TSubstream> fmt::Debug for FloodsubHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("FloodsubHandler")
            .field("enabled_incoming", &self.enabled_incoming)
            .field("enabled_outgoing", &self.enabled_outgoing)
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

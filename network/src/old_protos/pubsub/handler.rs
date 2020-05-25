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
use futures::task::{Context, Poll};
use futures_codec::Framed;
use libp2p_core::upgrade::{InboundUpgrade, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p_swarm::NegotiatedSubstream;
use log::{debug, trace};
use smallvec::SmallVec;
use std::pin::Pin;
use std::{fmt, io, time::Instant};

use crate::NETWORK_IDLE_TIMEOUT;

/// Protocol handler that handles communication with the remote for the floodsub protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct FloodsubHandler {
    /// Configuration for the floodsub protocol.
    config: FloodsubConfig,
    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState>,
    /// KeepAlive status
    keep_alive: KeepAlive,
    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[FloodsubRpc; 16]>,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState {
    /// Waiting for a message from the remote.
    WaitingInput(Framed<NegotiatedSubstream, FloodsubCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<NegotiatedSubstream, FloodsubCodec>, FloodsubRpc),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<NegotiatedSubstream, FloodsubCodec>),
    /// The substream is being closed.
    Closing(Framed<NegotiatedSubstream, FloodsubCodec>),
}

impl SubstreamState {
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<NegotiatedSubstream, FloodsubCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl FloodsubHandler {
    /// Builds a new `FloodsubHandler`.
    pub fn new() -> Self {
        FloodsubHandler {
            config: FloodsubConfig::new(),
            substreams: Vec::new(),
            keep_alive: KeepAlive::Yes,
            send_queue: SmallVec::new(),
        }
    }
}

impl Default for FloodsubHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolsHandler for FloodsubHandler {
    type InEvent = FloodsubSendEvent;
    type OutEvent = FloodsubRecvEvent;
    type Error = io::Error;
    type InboundProtocol = FloodsubConfig;
    type OutboundProtocol = FloodsubConfig;
    type OutboundOpenInfo = FloodsubRpc;

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        self.substreams
            .push(SubstreamState::PendingSend(protocol, message))
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
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
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        trace!(target: "stegos_network::pubsub", "got dial outbound failure: {}", e);
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<
        ProtocolsHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            io::Error,
        >,
    > {
        if !self.send_queue.is_empty() {
            let message = self.send_queue.remove(0);
            return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                info: message,
                protocol: SubstreamProtocol::new(self.config.clone()),
            });
        }

        for n in (0..self.substreams.len()).rev() {
            let mut substream = self.substreams.swap_remove(n);
            loop {
                substream = match substream {
                    SubstreamState::WaitingInput(mut substream) => {
                        match substream.poll_next_unpin(cx) {
                            Poll::Ready(Some(Ok(message))) => {
                                self.substreams
                                    .push(SubstreamState::WaitingInput(substream));
                                return Poll::Ready(ProtocolsHandlerEvent::Custom(
                                    FloodsubRecvEvent::Message(message),
                                ));
                            }
                            Poll::Ready(Some(Err(error))) => {
                                debug!(target: "stegos_network::pubsub", "error reading from substream: error={}", error);
                                SubstreamState::Closing(substream)
                            }
                            Poll::Ready(None) => SubstreamState::Closing(substream),
                            Poll::Pending => {
                                self.substreams
                                    .push(SubstreamState::WaitingInput(substream));
                                return Poll::Pending;
                            }
                        }
                    }
                    SubstreamState::PendingSend(mut substream, message) => {
                        match Sink::poll_ready(Pin::new(&mut substream), cx) {
                            Poll::Ready(Ok(())) => {
                                match Sink::start_send(Pin::new(&mut substream), message) {
                                    Ok(()) => SubstreamState::PendingFlush(substream),
                                    Err(error) => {
                                        debug!(target: "stegos_network::pubsub", "error sending to substream: error={}", error);
                                        SubstreamState::Closing(substream)
                                    }
                                }
                            }
                            Poll::Pending => {
                                self.substreams
                                    .push(SubstreamState::PendingSend(substream, message));
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(error)) => {
                                debug!(target: "stegos_network::pubsub", "error sending to substream: error={}", error);
                                SubstreamState::Closing(substream)
                            }
                        }
                    }

                    SubstreamState::PendingFlush(mut substream) => {
                        match Sink::poll_flush(Pin::new(&mut substream), cx) {
                            Poll::Ready(Ok(())) => SubstreamState::Closing(substream),
                            Poll::Ready(Err(error)) => {
                                debug!(target: "stegos_network::pubsub", "error flushing substream: error={}", error);
                                SubstreamState::Closing(substream)
                            }
                            Poll::Pending => {
                                self.substreams
                                    .push(SubstreamState::PendingFlush(substream));
                                return Poll::Pending;
                            }
                        }
                    }

                    SubstreamState::Closing(mut substream) => {
                        match Sink::poll_close(Pin::new(&mut substream), cx) {
                            Poll::Ready(Ok(())) => {
                                self.substreams.shrink_to_fit();
                                break;
                            }
                            Poll::Ready(Err(error)) => {
                                trace!(target: "stegos_network::pubsub", "failure closing substream: {}", error);
                                break;
                            }
                            Poll::Pending => {
                                self.substreams.push(SubstreamState::Closing(substream));
                                return Poll::Pending;
                            }
                        }
                    }
                }
            }
        }

        if self.substreams.is_empty() {
            self.keep_alive = KeepAlive::Until(Instant::now() + NETWORK_IDLE_TIMEOUT);
        } else {
            self.keep_alive = KeepAlive::Yes;
        }

        Poll::Pending
    }
}

impl fmt::Debug for FloodsubHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("FloodsubHandler")
            .field("keep_alive", &self.keep_alive)
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

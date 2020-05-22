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

use super::protocol::{DeliveryCodec, DeliveryConfig, DeliveryMessage};

use futures::task::{Context, Poll};
use futures::Sink;
use futures::StreamExt;
use futures_codec::Framed;
use libp2p_core::upgrade::{InboundUpgrade, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use libp2p_swarm::NegotiatedSubstream;
use log::{debug, trace};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::pin::Pin;
use std::{fmt, io, time::Instant};

use crate::NETWORK_IDLE_TIMEOUT;

/// Protocol handler that handles communication with the remote for the Delivery protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct DeliveryHandler {
    /// Configuration for the Delivery protocol.
    config: DeliveryConfig,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState>,

    // How long to keep connection open
    keep_alive: KeepAlive,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[DeliveryMessage; 16]>,

    /// Events to send upstream
    out_events: VecDeque<DeliveryRecvEvent>,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState {
    /// Waiting for a message from the remote.
    WaitingInput(Framed<NegotiatedSubstream, DeliveryCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<NegotiatedSubstream, DeliveryCodec>, DeliveryMessage),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<NegotiatedSubstream, DeliveryCodec>),
    /// The substream is being closed.
    Closing(Framed<NegotiatedSubstream, DeliveryCodec>),
}

impl SubstreamState {
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<NegotiatedSubstream, DeliveryCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl DeliveryHandler {
    /// Builds a new `DeliveryHandler`.
    pub fn new() -> Self {
        DeliveryHandler {
            config: DeliveryConfig::new(),
            substreams: Vec::new(),
            keep_alive: KeepAlive::Yes,
            send_queue: SmallVec::new(),
            out_events: VecDeque::new(),
        }
    }
}

impl Default for DeliveryHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolsHandler for DeliveryHandler {
    type InEvent = DeliverySendEvent;
    type OutEvent = DeliveryRecvEvent;
    type Error = io::Error;
    type InboundProtocol = DeliveryConfig;
    type OutboundProtocol = DeliveryConfig;
    type OutboundOpenInfo = DeliveryMessage;

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
            DeliverySendEvent::Deliver(message) => {
                self.send_queue.push(message);
            }
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        _: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
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
        if !self.out_events.is_empty() {
            let message = self.out_events.pop_front().unwrap();
            return Poll::Ready(ProtocolsHandlerEvent::Custom(message));
        }

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
                                    DeliveryRecvEvent::Message(message),
                                ));
                            }
                            Poll::Ready(Some(Err(e))) => {
                                debug!(target: "stegos_network::delivery", "error reading from substream: error={}", e);
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
                                    Ok(()) => (SubstreamState::PendingFlush(substream)),
                                    Err(error) => {
                                        debug!(target: "stegos_network::delivery", "error sending to substream: error={}", error);
                                        SubstreamState::Closing(substream)
                                    }
                                }
                            }
                            Poll::Pending => (SubstreamState::PendingSend(substream, message)),
                            Poll::Ready(Err(error)) => {
                                debug!(target: "stegos_network::delivery", "error sending to substream: error={}", error);
                                SubstreamState::Closing(substream)
                            }
                        }
                    }
                    SubstreamState::PendingFlush(mut substream) => {
                        match Sink::poll_flush(Pin::new(&mut substream), cx) {
                            Poll::Ready(Ok(())) => SubstreamState::Closing(substream),
                            Poll::Ready(Err(e)) => {
                                debug!(target: "stegos_network::delivery", "error flushing substream: error={}", e);
                                SubstreamState::Closing(substream)
                            }
                            Poll::Pending => {
                                self.substreams
                                    .push(SubstreamState::PendingFlush(substream));
                                return Poll::Pending;
                            }
                        }
                    }
                    SubstreamState::Closing(mut stream) => {
                        match Sink::poll_close(Pin::new(&mut stream), cx) {
                            Poll::Ready(Ok(())) => {
                                self.substreams.shrink_to_fit();
                                break;
                            }
                            Poll::Ready(Err(e)) => {
                                trace!(target: "stegos_network::delivery", "failure closing substream: {}", e);
                                break;
                            }
                            Poll::Pending => {
                                self.substreams.push(SubstreamState::Closing(stream));
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

#[derive(Debug, Clone)]
pub enum DeliveryRecvEvent {
    Message(DeliveryMessage),
}

#[derive(Debug, Clone)]
pub enum DeliverySendEvent {
    Deliver(DeliveryMessage),
}

impl fmt::Debug for DeliveryHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("DeliveryHandler")
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .field("out queue", &self.out_events.len())
            .finish()
    }
}

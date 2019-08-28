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

use futures::prelude::*;
use libp2p_core::upgrade::{InboundUpgrade, Negotiated, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use log::{debug, trace};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::{fmt, io, time::Instant};
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::NETWORK_IDLE_TIMEOUT;

/// Protocol handler that handles communication with the remote for the Delivery protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct DeliveryHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Configuration for the Delivery protocol.
    config: DeliveryConfig,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState<TSubstream>>,

    // How long to keep connection open
    keep_alive: KeepAlive,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[DeliveryMessage; 16]>,

    /// Events to send upstream
    out_events: VecDeque<DeliveryRecvEvent>,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Waiting for a message from the remote.
    WaitingInput(Framed<Negotiated<TSubstream>, DeliveryCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(
        Framed<Negotiated<TSubstream>, DeliveryCodec>,
        DeliveryMessage,
    ),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<Negotiated<TSubstream>, DeliveryCodec>),
    /// The substream is being closed.
    Closing(Framed<Negotiated<TSubstream>, DeliveryCodec>),
}

impl<TSubstream> SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<Negotiated<TSubstream>, DeliveryCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl<TSubstream> DeliveryHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
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

impl<TSubstream> ProtocolsHandler for DeliveryHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type InEvent = DeliverySendEvent;
    type OutEvent = DeliveryRecvEvent;
    type Error = io::Error;
    type Substream = TSubstream;
    type InboundProtocol = DeliveryConfig;
    type OutboundProtocol = DeliveryConfig;
    type OutboundOpenInfo = DeliveryMessage;

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
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
                                DeliveryRecvEvent::Message(message),
                            )));
                        }
                        Ok(Async::Ready(None)) => SubstreamState::Closing(substream),
                        Ok(Async::NotReady) => {
                            self.substreams
                                .push(SubstreamState::WaitingInput(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            debug!(target: "stegos_network::delivery", "error reading from substream: error={}", e);
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
                                debug!(target: "stegos_network::delivery", "error sending to substream: error={}", e);
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
                                debug!(target: "stegos_network::delivery", "error flushing substream: error={}", e);
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
                            trace!(target: "stegos_network::delivery", "failure closing substream: {}", e);
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

#[derive(Debug)]
pub enum DeliveryRecvEvent {
    Message(DeliveryMessage),
}

#[derive(Debug)]
pub enum DeliverySendEvent {
    Deliver(DeliveryMessage),
}

impl<TSubstream> fmt::Debug for DeliveryHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("DeliveryHandler")
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .field("out queue", &self.out_events.len())
            .finish()
    }
}

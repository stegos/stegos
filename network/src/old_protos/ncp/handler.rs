//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

use super::behavior::{NcpRecvEvent, NcpSendEvent};
use super::protocol::{NcpCodec, NcpConfig, NcpMessage};

use futures::prelude::*;
use futures::task::{Context, Poll};
use libp2p_core::upgrade::{InboundUpgrade, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};

use futures_codec::Framed;
use log::{debug, trace};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::pin::Pin;
use std::time::Instant;
use std::{fmt, io};

use libp2p_swarm::NegotiatedSubstream;

use crate::NETWORK_IDLE_TIMEOUT;

/// Protocol handler that handles communication with the remote for the NCP protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct NcpHandler {
    /// Configuration for the Ncp protocol.
    config: NcpConfig,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState>,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[NcpMessage; 16]>,

    /// Queue of events to send upper level (layer)
    out_events: VecDeque<NcpRecvEvent>,

    /// Keep alive for the connection
    keep_alive: KeepAlive,
    /// Terminate connection on next poll()
    terminating: bool,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState {
    /// Waiting for a message from the remote.
    WaitingInput(Framed<NegotiatedSubstream, NcpCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<NegotiatedSubstream, NcpCodec>, NcpMessage),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<NegotiatedSubstream, NcpCodec>),
    /// The substream is being closed.
    Closing(Framed<NegotiatedSubstream, NcpCodec>),
}

impl NcpHandler {
    /// Builds a new `NcpHandler`.
    /// TODO: set to intially disabled, when upgrade is implemented
    pub fn new() -> Self {
        NcpHandler {
            config: NcpConfig::new(),
            substreams: Vec::new(),
            send_queue: SmallVec::new(),
            out_events: VecDeque::new(),
            keep_alive: KeepAlive::Yes,
            terminating: false,
        }
    }
}

impl Default for NcpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SubstreamState {
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<NegotiatedSubstream, NcpCodec> {
        match self {
            SubstreamState::WaitingInput(substream) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl ProtocolsHandler for NcpHandler {
    type InEvent = NcpSendEvent;
    type OutEvent = NcpRecvEvent;
    type Error = io::Error;
    type InboundProtocol = NcpConfig;
    type OutboundProtocol = NcpConfig;
    type OutboundOpenInfo = NcpMessage;

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        trace!(target: "stegos_network::ncp", "successfully negotiated inbound substream");
        self.substreams.push(SubstreamState::WaitingInput(protocol))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        trace!(target: "stegos_network::ncp", "successfully negotiated outbound substream");
        self.substreams
            .push(SubstreamState::PendingSend(protocol, message))
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            NcpSendEvent::Send(message) => self.send_queue.push(message),
            NcpSendEvent::Terminate => self.terminating = true,
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
        if self.terminating {
            return Poll::Ready(ProtocolsHandlerEvent::Close(io::Error::new(
                io::ErrorKind::TimedOut,
                "stale connectio",
            )));
        }

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
                                    NcpRecvEvent::Recv(message),
                                ));
                            }
                            Poll::Ready(Some(Err(e))) => {
                                debug!(target: "stegos_network::ncp", "error reading from substream: error={}", e);
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
                                        debug!(target: "stegos_network::ncp", "error sending to substream: error={}", error);
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
                                debug!(target: "stegos_network::ncp", "error sending to substream: error={}", error);
                                SubstreamState::Closing(substream)
                            }
                        }
                    }
                    SubstreamState::PendingFlush(mut substream) => {
                        match Sink::poll_flush(Pin::new(&mut substream), cx) {
                            Poll::Ready(Ok(())) => SubstreamState::Closing(substream),
                            Poll::Ready(Err(error)) => {
                                debug!(target: "stegos_network::gatekeeper", "error sending message: error={}", error);
                                return Poll::Pending;
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
                                debug!(target: "stegos_network::ncp", "failure closing substream: error={}", error);
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

impl fmt::Debug for NcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("NcpHandler")
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

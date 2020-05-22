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

use super::handler::{HandlerInEvent, HandlerOutEvent, ReplicationHandler};
use super::protocol::ReplicationVersion;
use futures::channel::mpsc;
use futures::task::{Context, Poll};
use libp2p_core::connection::ConnectionId;
use libp2p_core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use log::*;
use std::collections::VecDeque;

/// Replication event.
#[derive(Debug)]
pub enum ReplicationEvent {
    ResolvedVersion {
        peer_id: PeerId,
        version: ReplicationVersion,
    },
    Registered {
        peer_id: PeerId,
        multiaddr: Multiaddr,
    },
    Unregistered {
        peer_id: PeerId,
        multiaddr: Multiaddr,
    },
    Disconnected {
        peer_id: PeerId,
    },
    Connected {
        peer_id: PeerId,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    ConnectionFailed {
        peer_id: PeerId,
        error: std::io::Error,
    },
    Accepted {
        peer_id: PeerId,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
}

/// Replication protocol.
#[derive(Default)]
pub struct Replication {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<HandlerInEvent, ReplicationEvent>>,
}

impl Replication {
    /// Creates a `Replication`.
    pub fn new() -> Self {
        Replication {
            events: VecDeque::new(),
        }
    }

    pub fn connect(&mut self, peer_id: PeerId) {
        debug!("[{}] Connecting", peer_id);
        let event = NetworkBehaviourAction::<HandlerInEvent, ReplicationEvent>::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: HandlerInEvent::Connect,
        };
        self.events.push_back(event);
    }

    pub fn disconnect(&mut self, peer_id: PeerId) {
        debug!("[{}] Disconnecting", peer_id);
        let event = NetworkBehaviourAction::<HandlerInEvent, ReplicationEvent>::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: HandlerInEvent::Disconnect,
        };
        self.events.push_back(event);
    }
}

impl NetworkBehaviour for Replication {
    type ProtocolsHandler = ReplicationHandler;
    type OutEvent = ReplicationEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        ReplicationHandler::new()
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _: &PeerId) {}

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        let multiaddr = match endpoint {
            ConnectedPoint::Dialer { address } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        }
        .clone();
        debug!("[{}] Connected: multiaddr={}", peer_id, multiaddr);
        let event = ReplicationEvent::Registered {
            peer_id: peer_id.clone(),
            multiaddr,
        };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        let multiaddr = match endpoint {
            ConnectedPoint::Dialer { address } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        }
        .clone();
        debug!("[{}] Disconnected: multiaddr={}", peer_id, multiaddr);
        let event = ReplicationEvent::Unregistered {
            peer_id: peer_id.clone(),
            multiaddr,
        };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        let event = ReplicationEvent::Disconnected {
            peer_id: peer_id.clone(),
        };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    /// Called on incoming events from handler.
    fn inject_event(&mut self, peer_id: PeerId, _: ConnectionId, event: HandlerOutEvent) {
        let event = match event {
            HandlerOutEvent::ResolvedVersion { version } => {
                ReplicationEvent::ResolvedVersion { version, peer_id }
            }
            HandlerOutEvent::Connected { tx, rx } => {
                ReplicationEvent::Connected { peer_id, tx, rx }
            }
            HandlerOutEvent::ConnectionFailed { error } => {
                ReplicationEvent::ConnectionFailed { peer_id, error }
            }
            HandlerOutEvent::Accepted { tx, rx } => ReplicationEvent::Accepted { peer_id, tx, rx },
        };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    fn poll(
        &mut self,
        _cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if let Some(event) = self.events.pop_front() {
            trace!("Generated event: {:?}", event);
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

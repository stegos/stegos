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
use futures::prelude::*;
use futures::sync::mpsc;
use libp2p_core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use log::*;
use std::collections::VecDeque;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// Replication event.
#[derive(Debug)]
pub enum ReplicationEvent {
    Registered {
        peer_id: PeerId,
        multiaddr: Multiaddr,
    },
    Unregistered {
        peer_id: PeerId,
        multiaddr: Multiaddr,
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
pub struct Replication<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<HandlerInEvent, ReplicationEvent>>,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Replication<TSubstream> {
    /// Creates a `Replication`.
    pub fn new() -> Self {
        Replication {
            events: VecDeque::new(),
            marker: PhantomData,
        }
    }

    pub fn connect(&mut self, peer_id: PeerId) {
        debug!("[{}] Connecting", peer_id);
        let event = NetworkBehaviourAction::<HandlerInEvent, ReplicationEvent>::SendEvent {
            peer_id,
            event: HandlerInEvent::Connect,
        };
        self.events.push_back(event);
    }

    pub fn disconnect(&mut self, peer_id: PeerId) {
        debug!("[{}] Disconnecting", peer_id);
        let event = NetworkBehaviourAction::<HandlerInEvent, ReplicationEvent>::SendEvent {
            peer_id,
            event: HandlerInEvent::Disconnect,
        };
        self.events.push_back(event);
    }
}

impl<TSubstream> NetworkBehaviour for Replication<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    type ProtocolsHandler = ReplicationHandler<TSubstream>;
    type OutEvent = ReplicationEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        ReplicationHandler::new()
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, peer_id: PeerId, point: ConnectedPoint) {
        let multiaddr = match point {
            ConnectedPoint::Dialer { address } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        };
        debug!("[{}] Connected: multiaddr={}", peer_id, multiaddr);
        let event = ReplicationEvent::Registered { peer_id, multiaddr };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, addr: ConnectedPoint) {
        let multiaddr = match addr {
            ConnectedPoint::Dialer { address } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        };
        debug!("[{}] Disconnected: multiaddr={}", peer_id, multiaddr);
        let event = ReplicationEvent::Unregistered {
            peer_id: peer_id.clone(),
            multiaddr,
        };
        let event = NetworkBehaviourAction::GenerateEvent(event);
        self.events.push_back(event);
    }

    /// Called on incoming events from handler.
    fn inject_node_event(&mut self, peer_id: PeerId, event: HandlerOutEvent) {
        let event = match event {
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
        _: &mut impl PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        trace!("Poll");

        if let Some(event) = self.events.pop_front() {
            trace!("Generated event: {:?}", event);
            return Async::Ready(event);
        }

        Async::NotReady
    }
}

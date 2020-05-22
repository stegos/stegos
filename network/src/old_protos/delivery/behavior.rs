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

use super::handler::{DeliveryHandler, DeliveryRecvEvent, DeliverySendEvent};
pub use super::protocol::{DeliveryMessage, Unicast};

use crate::utils::ExpiringQueue;
use futures::task::{Context, Poll};
use libp2p_core::{connection::ConnectionId, Multiaddr, PeerId};
use libp2p_swarm::{
    DialPeerCondition, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
    ProtocolsHandler,
};
use log::{debug, error};
use smallvec::SmallVec;
use std::{
    collections::{hash_map::HashMap, hash_set::HashSet, VecDeque},
    time::Duration,
};
use stegos_crypto::utils::u8v_to_hexstr;

// Set timeout for connecting to peer to 15 secs
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Delivery {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<DeliverySendEvent, DeliveryEvent>>,

    /// List of peers the network is connected to
    connected_peers: HashSet<PeerId>,

    // Pending peers, peers we are trying to dial
    dial_queue: ExpiringQueue<PeerId, ()>,

    // Sending queue
    send_queue: HashMap<PeerId, SmallVec<[DeliveryMessage; 16]>>,
}

impl Delivery {
    /// Creates a `Delivery`.
    pub fn new() -> Self {
        Delivery {
            events: VecDeque::new(),
            connected_peers: HashSet::new(),
            dial_queue: ExpiringQueue::new(DIAL_TIMEOUT),
            send_queue: HashMap::new(),
        }
    }
}

impl Default for Delivery {
    fn default() -> Self {
        Self::new()
    }
}

impl Delivery {
    pub fn deliver_unicast(&mut self, next_hop: &PeerId, message: Unicast) {
        if self.connected_peers.contains(next_hop) {
            debug!(target: "stegos_network::delivery", "delivering message to connected peer: peer_id={}, seq_no={}", next_hop, u8v_to_hexstr(&message.seq_no));
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: next_hop.clone(),
                    handler: NotifyHandler::Any,
                    event: DeliverySendEvent::Deliver(DeliveryMessage::UnicastMessage(message)),
                });
            return;
        }

        debug!(target: "stegos_network::delivery", "dialing peer for message delivery: peer_id={}, seq_no={}", next_hop, u8v_to_hexstr(&message.seq_no));
        if !self.dial_queue.contains_key(next_hop) {
            self.dial_queue.insert(next_hop.clone(), ());
            self.events.push_back(NetworkBehaviourAction::DialPeer {
                peer_id: next_hop.clone(),
                condition: DialPeerCondition::Disconnected,
            });
        }
        self.send_queue
            .entry(next_hop.clone())
            .or_insert_with(SmallVec::new)
            .push(DeliveryMessage::UnicastMessage(message));
    }
}

impl NetworkBehaviour for Delivery {
    type ProtocolsHandler = DeliveryHandler;
    type OutEvent = DeliveryEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DeliveryHandler::new()
    }

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, id: &PeerId) {
        debug!(target: "stegos_network::delivery", "peer connected: peer_id={}", id);
        self.connected_peers.insert(id.clone());
        if self.dial_queue.contains_key(&id) {
            self.dial_queue.remove(&id);
            if let Some(queue) = self.send_queue.get_mut(id) {
                debug!(target: "stegos_network::delivery", "delivering queued messages: peer_id={}, queue_len={}", id, queue.len());
                for m in queue.drain() {
                    self.events
                        .push_back(NetworkBehaviourAction::NotifyHandler {
                            peer_id: id.clone(),
                            handler: NotifyHandler::Any,
                            event: DeliverySendEvent::Deliver(m),
                        });
                }
            }
            self.send_queue.remove(id);
        }
    }

    fn inject_disconnected(&mut self, id: &PeerId) {
        let was_in = self.connected_peers.remove(id);
        debug_assert!(was_in);
    }

    fn inject_event(
        &mut self,
        propagation_source: PeerId,
        _: ConnectionId,
        event: DeliveryRecvEvent,
    ) {
        match event {
            DeliveryRecvEvent::Message(msg) => match msg {
                DeliveryMessage::UnicastMessage(unicast) => {
                    debug!(target: "stegos_network::delivery", "received unicast message from peer: peer_id={}, seq_no={}", propagation_source, u8v_to_hexstr(&unicast.seq_no));
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        DeliveryEvent::Message(DeliveryMessage::UnicastMessage(unicast)),
                    ))
                }
                DeliveryMessage::BroadcastMessage(_) => unimplemented!(),
            },
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        // Purge failed dialouts
        loop {
            match self.dial_queue.poll(cx) {
                Poll::Ready(Ok(ref entry)) => {
                    debug!(target: "stegos_network::delivery", "dialout timeout: peer_id={}", entry.0);
                    // Drop sending queue for the peer
                    self.send_queue.remove(&entry.0);
                }
                Poll::Ready(Err(e)) => {
                    error!(target: "stegos_network::delivery", "dial_queue timer error: {}", e);
                    break;
                }
                Poll::Pending => break,
            }
        }

        Poll::Pending
    }
}

/// Event that can happen on the Delivery behaviour.
#[derive(Debug)]
pub enum DeliveryEvent {
    /// A message has been received.
    Message(DeliveryMessage),
}

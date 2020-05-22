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

use super::handler::FloodsubHandler;
use super::metrics;
use super::protocol::{
    FloodsubMessage, FloodsubRpc, FloodsubSubscription, FloodsubSubscriptionAction,
};

use futures::prelude::*;
use futures::task::{Context, Poll};
use libp2p_core::connection::ConnectionId;
use libp2p_core::{Multiaddr, PeerId};
use libp2p_swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use log::{debug, trace};
use lru_time_cache::LruCache;
use smallvec::SmallVec;
use std::collections::{hash_map::HashMap, hash_set::HashSet, VecDeque};
use tokio::time::{Delay, Duration, Instant};
use update_rate::{RateCounter, RollingRateCounter};

// How many samples to use for rate calculation
const PUBSUB_SAMPLES: u64 = 100;
const METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const LRU_EXPIRE_TIME: Duration = Duration::from_secs(60); // 1 minute to allow transaction retransmit

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Floodsub {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<FloodsubSendEvent, FloodsubEvent>>,

    /// List of peers the network is connected to, and the topics that they're subscribed to.
    connected_peers: HashSet<PeerId>,

    /// List of peers we are allowed to send to
    unlocked_remotes: HashMap<PeerId, SmallVec<[String; 8]>>,

    /// List of peers we accept messages from
    allowed_remotes: HashSet<PeerId>,

    /// List of topics we're subscribed to. Necessary to filter out messages that we receive
    /// erroneously.
    subscribed_topics: SmallVec<[String; 16]>,

    /// We keep track of the messages we received (in the format `hash(source ID, seq_no)`) so that
    /// we don't dispatch the same message twice if we receive it twice on the network.
    received: LruCache<u64, ()>,

    /// Tracking incoming message rate for peers
    incoming_rates: HashMap<PeerId, RollingRateCounter>,

    /// Metrics uodate delay (update metrics at this interval)
    metrics_update_delay: Delay,

    /// Do we relay (disabled on edge nodes)
    relaying: bool,
}

impl Floodsub {
    /// Creates a `Floodsub`.
    pub fn new(relaying: bool) -> Self {
        Floodsub {
            events: VecDeque::new(),
            connected_peers: HashSet::new(),
            unlocked_remotes: HashMap::new(),
            allowed_remotes: HashSet::new(),
            subscribed_topics: SmallVec::new(),
            received: LruCache::with_expiry_duration_and_capacity(LRU_EXPIRE_TIME, 1_000_000),
            incoming_rates: HashMap::new(),
            metrics_update_delay: tokio::time::delay_for(METRICS_UPDATE_INTERVAL),
            relaying,
        }
    }
}

impl Floodsub {
    /// Subscribes to a topic.
    ///
    /// Returns true if the subscription worked. Returns false if we were already subscribed.
    pub fn subscribe(&mut self, topic: String) -> bool {
        if self.subscribed_topics.iter().any(|t| t == &topic) {
            return false;
        }

        for peer in self.unlocked_remotes.keys() {
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: peer.clone(),
                    handler: NotifyHandler::Any,
                    event: FloodsubSendEvent::Publish(FloodsubRpc {
                        messages: Vec::new(),
                        subscriptions: vec![FloodsubSubscription {
                            topic: topic.clone(),
                            action: FloodsubSubscriptionAction::Subscribe,
                        }],
                    }),
                });
        }

        self.subscribed_topics.push(topic);
        true
    }

    /// Publishes a message to the network.
    ///
    /// > **Note**: Doesn't do anything if we're not subscribed to the topic.
    pub fn publish(&mut self, topic: String, data: Vec<u8>) {
        let message = FloodsubMessage { data, topic };

        // Don't publish the message if we're not subscribed ourselves to any of the topics.
        if !self.subscribed_topics.iter().any(|t| t == &message.topic) {
            return;
        }

        self.received.notify_insert(message.digest(), ());
        super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);

        // Send to peers we know are subscribed to the topic.
        for (peer_id, sub_topic) in self.unlocked_remotes.iter() {
            if !sub_topic.iter().any(|t| t == &message.topic) {
                continue;
            }

            trace!(target: "stegos_network::pubsub", "sending message to peer: peer_id={}", peer_id);
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: peer_id.clone(),
                    handler: NotifyHandler::Any,
                    event: FloodsubSendEvent::Publish(FloodsubRpc {
                        subscriptions: Vec::new(),
                        messages: vec![message.clone()],
                    }),
                });
        }
    }

    pub fn enable_outgoing(&mut self, peer_id: &PeerId) {
        debug!(target: "stegos_network::gatekeeper", "enabling pubsub dialer: peer_id={}", peer_id);
        if !self.connected_peers.contains(peer_id) {
            debug!(target: "stegos_network::pubsub", "peer appears to be disconnected: peer_id={}", peer_id);
            return;
        }

        if !self.unlocked_remotes.contains_key(peer_id) {
            self.unlocked_remotes
                .insert(peer_id.clone(), SmallVec::new());
        }
        super::metrics::UNLOCKED_PEERS.set(self.unlocked_remotes.len() as i64);

        if !self.allowed_remotes.contains(peer_id) {
            debug!(target: "stegos_network::pubsub", "autoenabling receive: peer_id={}", peer_id);
            self.allowed_remotes.insert(peer_id.clone());
        }

        for p in self.unlocked_remotes.keys() {
            debug!(target: "stegos_network::pubsub", "remote peer send unlocked: peer_id={}, receive_enabled={}", p, self.allowed_remotes.contains(peer_id));
        }

        // We need to send our subscriptions to the newly-enabled node.
        for topic in self.subscribed_topics.iter() {
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: peer_id.clone(),
                    handler: NotifyHandler::Any,
                    event: FloodsubSendEvent::Publish(FloodsubRpc {
                        messages: Vec::new(),
                        subscriptions: vec![FloodsubSubscription {
                            topic: topic.clone(),
                            action: FloodsubSubscriptionAction::Subscribe,
                        }],
                    }),
                });
        }
    }

    pub fn enable_incoming(&mut self, peer_id: &PeerId) {
        debug!(target: "stegos_network::gatekeeper", "enabling pubsub listener: peer_id={}", peer_id);
        if !self.connected_peers.contains(peer_id) {
            debug!(target: "stegos_network::pubsub", "peer appears to be disconnected: peer_id={}", peer_id);
            return;
        }

        if self.allowed_remotes.contains(peer_id) {
            debug!(target: "stegos_network::pubsub", "peer is already allowed, skipping: peer_id={}", peer_id);
            return;
        }

        self.allowed_remotes.insert(peer_id.clone());
        for p in self.allowed_remotes.iter() {
            debug!(target: "stegos_network::pubsub", "peer receive enabled: peer_id={}, send_enabled={}", p, self.unlocked_remotes.contains_key(p));
        }
    }
}

impl NetworkBehaviour for Floodsub {
    type ProtocolsHandler = FloodsubHandler;
    type OutEvent = FloodsubEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        FloodsubHandler::new()
    }

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, id: &PeerId) {
        debug!(target: "stegos_network::pubsub", "peer connected: peer_id={}", id);
        self.connected_peers.insert(id.clone());
        super::metrics::CONNECTED_PEERS.set(self.connected_peers.len() as i64);
    }

    fn inject_disconnected(&mut self, id: &PeerId) {
        debug!(target: "stegos_network::pubsub", "peer disconnected: peer_id={}", id);
        let was_in = self.connected_peers.remove(id);
        debug_assert!(was_in);
        self.allowed_remotes.remove(id);
        self.unlocked_remotes.remove(id);
        super::metrics::CONNECTED_PEERS.set(self.connected_peers.len() as i64);
        super::metrics::UNLOCKED_PEERS.set(self.unlocked_remotes.len() as i64);
    }

    fn inject_event(
        &mut self,
        propagation_source: PeerId,
        _: ConnectionId,
        event: FloodsubRecvEvent,
    ) {
        self.incoming_rates
            .entry(propagation_source.clone())
            .or_insert_with(|| RollingRateCounter::new(PUBSUB_SAMPLES))
            .update();

        if !self.allowed_remotes.contains(&propagation_source) {
            debug!(target: "stegos_network::pubsub", "event from unwanted peer, dropping: peer_id={}", propagation_source);
            return;
        }

        match event {
            FloodsubRecvEvent::Message(event) => {
                // Update connected peers topics
                for subscription in event.subscriptions {
                    let remote_peer_topics = self
                        .unlocked_remotes
                        .entry(propagation_source.clone())
                        .or_insert_with(SmallVec::new);
                    match subscription.action {
                        FloodsubSubscriptionAction::Subscribe => {
                            if !remote_peer_topics.contains(&subscription.topic) {
                                remote_peer_topics.push(subscription.topic.clone());
                            }
                            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                FloodsubEvent::Subscribed {
                                    peer_id: propagation_source.clone(),
                                    topic: subscription.topic,
                                },
                            ));
                        }
                        FloodsubSubscriptionAction::Unsubscribe => {
                            if let Some(pos) = remote_peer_topics
                                .iter()
                                .position(|t| t == &subscription.topic)
                            {
                                remote_peer_topics.remove(pos);
                            }
                            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                FloodsubEvent::Unsubscribed {
                                    peer_id: propagation_source.clone(),
                                    topic: subscription.topic,
                                },
                            ));
                        }
                    }
                }

                // List of messages we're going to propagate on the network.
                let mut rpcs_to_dispatch: Vec<(PeerId, FloodsubRpc)> = Vec::new();

                for message in event.messages {
                    // Use `self.received` to skip the messages that we have already received in the past.
                    // Note that this can false positive.
                    if self.received.contains_key(&message.digest()) {
                        trace!(target: "stegos_network::pubsub", "LRU cache hit");
                        super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);
                        continue;
                    } else {
                        self.received.notify_insert(message.digest(), ());
                    }
                    super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);
                    trace!(target: "stegos_network::pubsub", "processing message: peer_id={}", propagation_source);

                    // Add the message to be dispatched to the user.
                    if self.subscribed_topics.iter().any(|t| t == &message.topic) {
                        let event = FloodsubEvent::Message(message.clone());
                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }

                    // Finish, if we are not relay
                    if !self.relaying {
                        debug!(target: "stegos_network::pubsub", "skipping message forwarding...");
                        return;
                    }

                    // Propagate the message to everyone else who is subscribed to any of the topics.
                    for (peer_id, subscr_topics) in self.unlocked_remotes.iter() {
                        if peer_id == &propagation_source {
                            continue;
                        }

                        if !subscr_topics.iter().any(|t| t == &message.topic) {
                            continue;
                        }

                        if let Some(pos) = rpcs_to_dispatch.iter().position(|(p, _)| p == peer_id) {
                            rpcs_to_dispatch[pos].1.messages.push(message.clone());
                        } else {
                            rpcs_to_dispatch.push((
                                peer_id.clone(),
                                FloodsubRpc {
                                    subscriptions: Vec::new(),
                                    messages: vec![message.clone()],
                                },
                            ));
                        }
                    }
                }

                for (peer_id, rpc) in rpcs_to_dispatch {
                    self.events
                        .push_back(NetworkBehaviourAction::NotifyHandler {
                            peer_id,
                            handler: NotifyHandler::Any,
                            event: FloodsubSendEvent::Publish(rpc),
                        });
                }
            }
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
        while let Poll::Ready(_) = self.metrics_update_delay.poll_unpin(cx) {
            for (peer_id, counter) in self.incoming_rates.iter() {
                metrics::INCOMING_RATES
                    .with_label_values(&[&peer_id.clone().to_base58()])
                    .set(counter.rate());
            }
            self.metrics_update_delay
                .reset(Instant::now() + METRICS_UPDATE_INTERVAL);
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

/// Event that can happen on the floodsub behaviour.
#[derive(Debug)]
pub enum FloodsubEvent {
    /// A message has been received.
    Message(FloodsubMessage),

    /// A remote subscribed to a topic.
    Subscribed {
        /// Remote that has subscribed.
        peer_id: PeerId,
        /// The topic it has subscribed to.
        topic: String,
    },

    /// A remote unsubscribed from a topic.
    Unsubscribed {
        /// Remote that has unsubscribed.
        peer_id: PeerId,
        /// The topic it has subscribed from.
        topic: String,
    },
}

#[derive(Debug, Clone)]
/// Event passed to protocol handler
pub enum FloodsubSendEvent {
    /// Publish message
    Publish(FloodsubRpc),
}

#[derive(Debug)]
/// Event received from handler
pub enum FloodsubRecvEvent {
    Message(FloodsubRpc),
}

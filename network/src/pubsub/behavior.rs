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
use super::topic::{Topic, TopicHash};

use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::core::{protocols_handler::ProtocolsHandler, Multiaddr, PeerId};
use log::{debug, trace};
use lru_time_cache::LruCache;
use rand;
use smallvec::SmallVec;
use std::time::{Duration, Instant};
use std::{
    collections::{hash_map::HashMap, hash_set::HashSet, VecDeque},
    iter,
    marker::PhantomData,
};
use stegos_crypto::utils::u8v_to_hexstr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;
use update_rate::{RateCounter, RollingRateCounter};

// How many samples to use for rate calculation
const PUBSUB_SAMPLES: u64 = 100;
const METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Floodsub<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<FloodsubSendEvent, FloodsubEvent>>,

    /// Peer id of the local node. Used for the source of the messages that we publish.
    local_peer_id: PeerId,

    /// List of peers the network is connected to, and the topics that they're subscribed to.
    connected_peers: HashSet<PeerId>,

    /// List of peers we are allowed to send to
    unlocked_remotes: HashMap<PeerId, SmallVec<[TopicHash; 8]>>,

    /// List of peers we accept messages from
    allowed_remotes: HashSet<PeerId>,

    /// List of topics we're subscribed to. Necessary to filter out messages that we receive
    /// erroneously.
    subscribed_topics: SmallVec<[Topic; 16]>,

    /// We keep track of the messages we received (in the format `hash(source ID, seq_no)`) so that
    /// we don't dispatch the same message twice if we receive it twice on the network.
    received: LruCache<u64, ()>,

    /// Tracking incoming message rate for peers
    incoming_rates: HashMap<PeerId, RollingRateCounter>,

    /// Metrics uodate delay (update metrics at this interval)
    metrics_update_delay: Delay,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Floodsub<TSubstream> {
    /// Creates a `Floodsub`.
    pub fn new(local_peer_id: PeerId) -> Self {
        Floodsub {
            events: VecDeque::new(),
            local_peer_id,
            connected_peers: HashSet::new(),
            unlocked_remotes: HashMap::new(),
            allowed_remotes: HashSet::new(),
            subscribed_topics: SmallVec::new(),
            received: LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(60 * 15),
                1_000_000,
            ),
            incoming_rates: HashMap::new(),
            metrics_update_delay: Delay::new(Instant::now() + METRICS_UPDATE_INTERVAL),
            marker: PhantomData,
        }
    }
}

impl<TSubstream> Floodsub<TSubstream> {
    /// Subscribes to a topic.
    ///
    /// Returns true if the subscription worked. Returns false if we were already subscribed.
    pub fn subscribe(&mut self, topic: Topic) -> bool {
        if self
            .subscribed_topics
            .iter()
            .any(|t| t.hash() == topic.hash())
        {
            return false;
        }

        for peer in self.unlocked_remotes.keys() {
            self.events.push_back(NetworkBehaviourAction::SendEvent {
                peer_id: peer.clone(),
                event: FloodsubSendEvent::Publish(FloodsubRpc {
                    messages: Vec::new(),
                    subscriptions: vec![FloodsubSubscription {
                        topic: topic.hash().clone(),
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
    pub fn publish(&mut self, topic: impl Into<TopicHash>, data: impl Into<Vec<u8>>) {
        self.publish_many(iter::once(topic), data)
    }

    /// Publishes a message with multiple topics to the network.
    ///
    /// > **Note**: Doesn't do anything if we're not subscribed to any of the topics.
    pub fn publish_many(
        &mut self,
        topic: impl IntoIterator<Item = impl Into<TopicHash>>,
        data: impl Into<Vec<u8>>,
    ) {
        let mut message = FloodsubMessage {
            source: self.local_peer_id.clone(),
            data: data.into(),
            // If the sequence numbers are predictable, then an attacker could flood the network
            // with packets with the predetermined sequence numbers and absorb our legitimate
            // messages. We therefore use a random number.
            sequence_number: rand::random::<[u8; 20]>().to_vec(),
            topics: topic.into_iter().map(|t| t.into().clone()).collect(),
        };

        // Don't publish the message if we're not subscribed ourselves to any of the topics.
        if !self
            .subscribed_topics
            .iter()
            .any(|t| message.topics.iter().any(|u| t.hash() == u))
        {
            return;
        }

        // Guard against very unlikely event of Hash collision
        if self.received.contains_key(&message.digest()) {
            loop {
                message.sequence_number = rand::random::<[u8; 20]>().to_vec();
                if !self.received.contains_key(&message.digest()) {
                    break;
                }
            }
        }

        self.received.insert(message.digest(), ());
        super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);

        // Send to peers we know are subscribed to the topic.
        for (peer_id, sub_topic) in self.unlocked_remotes.iter() {
            if !sub_topic
                .iter()
                .any(|t| message.topics.iter().any(|u| t == u))
            {
                continue;
            }

            trace!(target: "stegos_network::pubsub", "sending message to peer: peer_id={}, seq_no={}", peer_id, u8v_to_hexstr(&message.sequence_number));
            self.events.push_back(NetworkBehaviourAction::SendEvent {
                peer_id: peer_id.clone(),
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

        if !self.allowed_remotes.contains(peer_id) {
            debug!(target: "stegos_network::pubsub", "autoenabling receive: peer_id={}", peer_id);
            self.allowed_remotes.insert(peer_id.clone());
        }

        for p in self.unlocked_remotes.keys() {
            debug!(target: "stegos_network::pubsub", "remote peer send unlocked: peer_id={}, receive_enabled={}", p, self.allowed_remotes.contains(peer_id));
        }

        // We need to send our subscriptions to the newly-enabled node.
        for topic in self.subscribed_topics.iter() {
            self.events.push_back(NetworkBehaviourAction::SendEvent {
                peer_id: peer_id.clone(),
                event: FloodsubSendEvent::Publish(FloodsubRpc {
                    messages: Vec::new(),
                    subscriptions: vec![FloodsubSubscription {
                        topic: topic.hash().clone(),
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

impl<TSubstream> NetworkBehaviour for Floodsub<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = FloodsubHandler<TSubstream>;
    type OutEvent = FloodsubEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        FloodsubHandler::new()
    }

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, id: PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::pubsub", "peer connected: peer_id={}", id);
        self.connected_peers.insert(id.clone());
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::pubsub", "peer disconnected: peer_id={}", id);
        let was_in = self.connected_peers.remove(id);
        debug_assert!(was_in);
        self.allowed_remotes.remove(id);
        self.unlocked_remotes.remove(id);
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: FloodsubRecvEvent) {
        self.incoming_rates
            .entry(propagation_source.clone())
            .or_insert(RollingRateCounter::new(PUBSUB_SAMPLES))
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
                        .or_insert(SmallVec::new());
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
                    if self.received.insert(message.digest(), ()).is_some() {
                        trace!(target: "stegos_network::pubsub", "LRU cache hit: set_seqno={}", u8v_to_hexstr(&message.sequence_number));
                        super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);
                        continue;
                    }
                    super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);
                    trace!(target: "stegos_network::pubsub", "processing message: peer_id={}, seq_no={}", propagation_source, u8v_to_hexstr(&message.sequence_number));

                    // Add the message to be dispatched to the user.
                    if self
                        .subscribed_topics
                        .iter()
                        .any(|t| message.topics.iter().any(|u| t.hash() == u))
                    {
                        let event = FloodsubEvent::Message(message.clone());
                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }

                    // Propagate the message to everyone else who is subscribed to any of the topics.
                    for (peer_id, subscr_topics) in self.unlocked_remotes.iter() {
                        if peer_id == &propagation_source {
                            continue;
                        }

                        if !subscr_topics
                            .iter()
                            .any(|t| message.topics.iter().any(|u| t == u))
                        {
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
                    self.events.push_back(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: FloodsubSendEvent::Publish(rpc),
                    });
                }
            }
        }
    }

    fn poll(
        &mut self,
        _: &mut PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        loop {
            match self.metrics_update_delay.poll() {
                Ok(Async::Ready(_)) => {
                    for (peer_id, counter) in self.incoming_rates.iter() {
                        metrics::INCOMING_RATES
                            .with_label_values(&[&peer_id.clone().to_base58()])
                            .set(counter.rate());
                    }
                    self.metrics_update_delay
                        .reset(Instant::now() + METRICS_UPDATE_INTERVAL);
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    debug!(target: "stegos_network::pubsub", "metrics delay timer error: error={}", e);
                    break;
                }
            }
        }

        if let Some(event) = self.events.pop_front() {
            return Async::Ready(event);
        }

        Async::NotReady
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
        topic: TopicHash,
    },

    /// A remote unsubscribed from a topic.
    Unsubscribed {
        /// Remote that has unsubscribed.
        peer_id: PeerId,
        /// The topic it has subscribed from.
        topic: TopicHash,
    },
}

#[derive(Debug)]
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

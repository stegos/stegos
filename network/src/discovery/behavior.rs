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

use crate::{ExpiringQueue, UnicastDataMessage};
use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::kad::{Kademlia, KademliaOut};
use libp2p::multihash::{encode, Hash::SHA2256, Multihash};
use libp2p::{core::ProtocolsHandler, Multiaddr, PeerId};
use log::*;
use lru::LruCache;
use smallvec::SmallVec;
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use stegos_crypto::pbc::secure;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;

/// One minute dialout timeout
const DISCOVERY_TIMEOUT: u64 = 60;
/// Sixe of table to store mappings pbc::secure::PublicKey to PeerId
const PROVIDERS_CACHE_SIZE: usize = 1024;

enum DiscoveryEvent {
    SendData(UnicastDataMessage),
    Deliver(PeerId, UnicastDataMessage),
}

pub enum DiscoveryOutEvent {
    Deliver(PeerId, UnicastDataMessage),
    KadEvent(KademliaOut),
}

/// Kademlia-based network discovery
pub struct DiscoveryBehaviour<TSubstream> {
    /// Kademlia systems
    kademlia: Kademlia<TSubstream>,
    /// When to send random request to gather network info
    next_query: Delay,
    /// Delay to the next random poll
    delay_between_queries: Duration,
    /// Internal events to be processed by poll() function
    events: VecDeque<DiscoveryEvent>,
    /// Set of nodes, waiting to be discovered/
    discovery_peer_queue: ExpiringQueue<secure::PublicKey>,
    /// Set of peers, waiting to be discovered/
    discovery_addr_queue: ExpiringQueue<PeerId>,
    /// Map PeerId to secure::PublicKey
    discovered_peers: HashMap<PeerId, secure::PublicKey>,
    /// Hash map of per-key message queues
    delivery_queues: HashMap<secure::PublicKey, Vec<UnicastDataMessage>>,
    /// Table of known mappings of pbc::secure::PublicKey to PeerId
    known_providers: LruCache<Multihash, SmallVec<[PeerId; 20]>>,
}

impl<TSubstream> DiscoveryBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(local_peer_id: PeerId) -> Self {
        DiscoveryBehaviour {
            kademlia: Kademlia::new(local_peer_id),
            next_query: Delay::new(Instant::now()),
            delay_between_queries: Duration::from_secs(1),
            events: VecDeque::new(),
            discovery_peer_queue: ExpiringQueue::new(DISCOVERY_TIMEOUT),
            discovery_addr_queue: ExpiringQueue::new(DISCOVERY_TIMEOUT),
            discovered_peers: HashMap::new(),
            delivery_queues: HashMap::new(),
            known_providers: LruCache::new(PROVIDERS_CACHE_SIZE),
        }
    }

    pub fn add_providing(&mut self, key: PeerId) {
        self.kademlia.add_providing(key);
    }

    pub fn send(&mut self, msg: UnicastDataMessage) {
        self.events.push_back(DiscoveryEvent::SendData(msg));
    }

    fn node_discovery_state(&mut self, pkey: &secure::PublicKey) -> NodeDiscoveryState {
        let node_key_hash = node_id_hash(pkey);
        if let Some(peer_ids) = self.known_providers.get(&node_key_hash) {
            if NetworkBehaviour::addresses_of_peer(&mut self.kademlia, &peer_ids[0]).len() > 0 {
                // We know peer_id and IPs of destination, pass to upstream for Delivery
                return NodeDiscoveryState::Discovered(peer_ids[0].clone());
            } else {
                // We know PeerId, but not IPs yet
                return NodeDiscoveryState::PeerIdKnown(peer_ids[0].clone());
            }
        } else {
            // Mapping secure::PublicKeey -> PeerId not known yet
            return NodeDiscoveryState::PeerIdUnknown;
        }
    }
}

impl<TSubstream> NetworkBehaviour for DiscoveryBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = <Kademlia<TSubstream> as NetworkBehaviour>::ProtocolsHandler;
    type OutEvent = DiscoveryOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NetworkBehaviour::new_handler(&mut self.kademlia)
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        self.kademlia.addresses_of_peer(peer_id)
    }

    fn inject_connected(&mut self, peer_id: PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::inject_connected(&mut self.kademlia, peer_id, endpoint)
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::inject_disconnected(&mut self.kademlia, peer_id, endpoint)
    }

    fn inject_node_event(
        &mut self,
        peer_id: PeerId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        NetworkBehaviour::inject_node_event(&mut self.kademlia, peer_id, event)
    }

    fn poll(
        &mut self,
        params: &mut PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // Process results of Kademlia discovery
        match self.kademlia.poll(params) {
            Async::Ready(NetworkBehaviourAction::GenerateEvent(action)) => {
                debug!(target: "stegos_network::discovery", "Event from Kademlia: {:?}", action);
                match action {
                    KademliaOut::FindNodeResult {
                        ref key,
                        ref closer_peers,
                    } => {
                        debug!(
                            target: "stegos_network::discovery",
                            "Kademlia query for {:?} yielded {:?} results",
                            key,
                            closer_peers.len()
                        );
                        // Check if we have enough info to deliver message
                        for peer in closer_peers.iter() {
                            if self.discovery_addr_queue.contains(peer) {
                                // Discovered peer we were waiting for deliver messages, if any...
                                if let Some(node_id) = self.discovered_peers.get(peer) {
                                    if let Some(mut queue) = self.delivery_queues.remove(node_id) {
                                        for m in queue.drain(..).into_iter() {
                                            self.events
                                                .push_back(DiscoveryEvent::Deliver(peer.clone(), m))
                                        }
                                    }
                                }
                                self.discovery_addr_queue.remove(peer);
                            }
                        }
                    }
                    KademliaOut::GetProvidersResult {
                        ref key,
                        closer_peers: _,
                        ref provider_peers,
                    } => {
                        debug!(target: "stegos_network::discovery", "Got providers: {:#?} for key: {:#?}", provider_peers, key);
                        if !self.known_providers.contains(key) {
                            self.known_providers.put(key.clone(), SmallVec::new());
                        }
                        for peer in provider_peers.iter() {
                            self.known_providers
                                .get_mut(key)
                                .unwrap()
                                .push(peer.clone());
                        }
                        let check_queue: Vec<secure::PublicKey> = self
                            .discovery_peer_queue
                            .keys()
                            .map(|v| v.clone())
                            .collect();
                        for node_id in check_queue.iter() {
                            if node_id_hash(node_id) == *key {
                                for p in provider_peers.iter() {
                                    self.discovered_peers.insert(p.clone(), node_id.clone());
                                }
                                match self.node_discovery_state(node_id) {
                                    NodeDiscoveryState::Discovered(ref peer) => {
                                        if let Some(mut queue) =
                                            self.delivery_queues.remove(node_id)
                                        {
                                            for m in queue.drain(..).into_iter() {
                                                self.events.push_back(DiscoveryEvent::Deliver(
                                                    peer.clone(),
                                                    m,
                                                ))
                                            }
                                        }
                                        self.discovery_peer_queue.remove(node_id);
                                        self.discovery_addr_queue.remove(peer);
                                    }
                                    NodeDiscoveryState::PeerIdKnown(peer_id) => {
                                        debug!("Found the peer_id for node, but no addresses yet.");
                                        if let Some(node_id) = self.discovered_peers.get(&peer_id) {
                                            self.discovery_peer_queue.remove(&node_id);
                                        }
                                        self.discovery_addr_queue.insert(&peer_id);
                                        self.kademlia.find_node(peer_id);
                                    }
                                    NodeDiscoveryState::PeerIdUnknown => {
                                        // PeerId not yes discovered, lets wait futher
                                    }
                                }
                            }
                        }
                    }
                    KademliaOut::Discovered {
                        ref peer_id,
                        ref addresses,
                        ref ty,
                    } => {
                        debug!(target: "stegos_network::discovery",
                            "Discovered peer: peer_id={} addresses={:?} connected={:?}",
                            peer_id.to_base58(), addresses, ty
                        );
                    }
                }
                return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                    DiscoveryOutEvent::KadEvent(action),
                ));
            }
            Async::Ready(NetworkBehaviourAction::DialAddress { address }) => {
                return Async::Ready(NetworkBehaviourAction::DialAddress { address });
            }
            Async::Ready(NetworkBehaviourAction::DialPeer { peer_id }) => {
                return Async::Ready(NetworkBehaviourAction::DialPeer { peer_id });
            }
            Async::Ready(NetworkBehaviourAction::SendEvent { peer_id, event }) => {
                return Async::Ready(NetworkBehaviourAction::SendEvent { peer_id, event });
            }
            Async::Ready(NetworkBehaviourAction::ReportObservedAddr { address }) => {
                return Async::Ready(NetworkBehaviourAction::ReportObservedAddr { address });
            }
            Async::NotReady => (),
        }
        // Handle internal events
        if let Some(event) = self.events.pop_front() {
            match event {
                DiscoveryEvent::SendData(msg) => {
                    let node_key_hash = node_id_hash(&msg.to);
                    match self.node_discovery_state(&msg.to) {
                        NodeDiscoveryState::Discovered(peer_id) => {
                            self.discovered_peers
                                .insert(peer_id.clone(), msg.to.clone());
                            return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                                DiscoveryOutEvent::Deliver(peer_id, msg),
                            ));
                        }
                        NodeDiscoveryState::PeerIdKnown(peer_id) => {
                            self.discovered_peers
                                .insert(peer_id.clone(), msg.to.clone());
                            self.discovery_addr_queue.insert(&peer_id);
                            self.kademlia.find_node(peer_id);
                        }
                        NodeDiscoveryState::PeerIdUnknown => {
                            self.discovery_peer_queue.insert(&msg.to);
                            self.kademlia.get_providers(node_key_hash);
                        }
                    }
                    self.delivery_queues
                        .entry(msg.to.clone())
                        .or_insert(Vec::new())
                        .push(msg);
                }
                DiscoveryEvent::Deliver(peer_id, message) => {
                    return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                        DiscoveryOutEvent::Deliver(peer_id, message),
                    ));
                }
            }
        }
        loop {
            match self.discovery_peer_queue.poll() {
                Ok(Async::Ready(entry)) => {
                    debug!("Node id {} discovery timeout!", entry);
                    // Drop sending queue for the node
                    self.delivery_queues.remove(&entry);
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!("Interval timer error: {}", e);
                    break;
                }
            }
        }

        loop {
            match self.discovery_addr_queue.poll() {
                Ok(Async::Ready(entry)) => {
                    debug!("Peer id {} discovery timeout!", entry.to_base58());
                    // Drop sending queue for the node
                    if let Some(key) = self.discovered_peers.get(&entry) {
                        self.delivery_queues.remove(key);
                    }
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!("Interval timer error: {}", e);
                    break;
                }
            }
        }
        trace!("Done checking queues");
        // Initiate new shake of DHT network
        loop {
            match self.next_query.poll() {
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(_)) => {
                    debug!("Shooting at DHT to gather nodes information");
                    let random_peer_id = PeerId::random();
                    self.kademlia.find_node(random_peer_id);

                    // Reset the `Delay` to the next random.
                    self.next_query
                        .reset(Instant::now() + self.delay_between_queries);
                    self.delay_between_queries =
                        cmp::min(self.delay_between_queries * 2, Duration::from_secs(60));
                }
                Err(err) => {
                    error!("Kad discovery timer errored: {:?}", err);
                    break;
                }
            }
        }
        trace!("Done discovery poll");
        Async::NotReady
    }
}

// Possible state of mapping secure::PublicKey to Multiaddrs
#[derive(Debug, PartialEq, Eq)]
enum NodeDiscoveryState {
    // PeerId for node is unknown,
    PeerIdUnknown,
    // Discovered PeerId, but no Multiaddrs yet
    PeerIdKnown(PeerId),
    // Full info found, can be used for delivery
    Discovered(PeerId),
}

fn node_id_hash(key: &secure::PublicKey) -> Multihash {
    encode(SHA2256, &key.clone().to_bytes()).expect("should never fail")
}

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

use crate::delivery::Unicast;
use crate::kad::{kbucket::KBucketsPeerId, Kademlia, KademliaOut, NodeInfo};
use crate::utils::LruBimap;
use futures::prelude::*;
use futures::task::{Context, Poll};
use libp2p_core::connection::ConnectionId;
use libp2p_core::ConnectedPoint;
use libp2p_core::{Multiaddr, PeerId};
use libp2p_swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler};
use log::*;
use lru_time_cache::LruCache;
use std::cmp;
use std::collections::{HashSet, VecDeque};
use stegos_crypto::pbc;
use stegos_crypto::utils::u8v_to_hexstr;
use tokio::time::{Delay, Duration, Instant};

// How often check connections to the known closest peers
const MONITORING_INTERVAL: u64 = 30;
// Try to keep open connections to at leasy followin number of closest peers
const MIN_CLOSEST_PEERS: usize = 10;
// Deliver message to N closest node ids, if node is not present in DHT
const DELIVERY_REPLICATION: usize = 5;
// TTL for known nodes
const NODES_TTL: Duration = Duration::from_secs(5 * 60);

pub enum DiscoveryOutEvent {
    DialPeer { peer_id: PeerId },
    KadEvent { event: KademliaOut },
    Route { next_hop: PeerId, message: Unicast },
}

/// Kademlia-based network discovery
pub struct Discovery {
    my_id: pbc::PublicKey,
    /// Kademlia systems
    kademlia: Kademlia,
    /// Known nodes
    known_nodes: LruBimap<pbc::PublicKey, PeerId>,
    /// Outbound events
    out_events: VecDeque<DiscoveryOutEvent>,
    /// Set of currently connected peers
    connected_peers: HashSet<PeerId>,

    /// We keep track of the messages we received (in the format `hash(source ID, seq_no)`) so that
    /// we don't dispatch the same message twice if we receive it twice on the network.
    received: LruCache<u64, ()>,

    /// When to send random request to gather network info
    next_query: Delay,
    /// Delay to the next random poll
    delay_between_queries: Duration,
    /// Delay to next monitoring check
    next_connection_check: Delay,
}

impl Discovery {
    pub fn new(local_node_id: pbc::PublicKey) -> Self {
        Discovery {
            my_id: local_node_id,
            kademlia: Kademlia::without_init(local_node_id),
            known_nodes: LruBimap::<pbc::PublicKey, PeerId>::with_expiry_duration(NODES_TTL),
            out_events: VecDeque::new(),
            connected_peers: HashSet::new(),
            next_query: tokio::time::delay_for(Duration::from_secs(30)),
            delay_between_queries: Duration::from_secs(1),
            next_connection_check: tokio::time::delay_for(Duration::from_secs(MONITORING_INTERVAL)),
            received: LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(60 * 15),
                100_000,
            ),
        }
    }

    pub fn change_network_key(&mut self, new_pkey: pbc::PublicKey) {
        self.kademlia.change_id(new_pkey);
        self.my_id = new_pkey;
    }

    /// Sets peer_id to the corresponging node_id
    pub fn set_peer_id(&mut self, node_id: &pbc::PublicKey, peer_id: PeerId) {
        self.kademlia.set_peer_id(node_id, peer_id);
    }

    /// Adds a known address for the given `PeerId`. We are connected to this address.
    pub fn add_connected_address(&mut self, node_id: &pbc::PublicKey, address: Multiaddr) {
        self.kademlia.add_connected_address(node_id, address);
    }

    /// Adds a known address for the given `PeerId`. We are not connected or don't know whether we
    /// are connected to this address.
    pub fn add_not_connected_address(&mut self, node_id: &pbc::PublicKey, address: Multiaddr) {
        self.kademlia.add_not_connected_address(node_id, address);
    }

    pub fn add_node(&mut self, node_id: pbc::PublicKey, peer_id: PeerId) {
        self.known_nodes.insert(node_id, peer_id);
    }

    pub fn deliver_unicast(&mut self, to: &pbc::PublicKey, payload: Vec<u8>) {
        let mut message = Unicast {
            to: *to,
            payload,
            dont_route: false,
            seq_no: rand::random::<[u8; 20]>().to_vec(),
        };

        // Guard against very unlikely event of Hash collision
        if self.received.contains_key(&message.digest()) {
            loop {
                message.seq_no = rand::random::<[u8; 20]>().to_vec();
                if !self.received.contains_key(&message.digest()) {
                    break;
                }
            }
        }
        self.received.insert(message.digest(), ());
        super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);

        self.route(to, message);
    }

    pub fn route(&mut self, to: &pbc::PublicKey, message: Unicast) {
        // Check if we already know node's peer_id
        if let Some(peer_id) = self.known_nodes.get_by_key(to) {
            debug!(target: "stegos_network::delivery", "found node's peer_id: node_id={}, peer_id={}, seq_no={}", to, peer_id, u8v_to_hexstr(&message.seq_no));
            self.out_events.push_back(DiscoveryOutEvent::Route {
                next_hop: peer_id.clone(),
                message,
            });
            return;
        }

        // If destination node is present in out DHT, send payload directly
        if let Some(node_info) = self.kademlia.get_node(to) {
            if let Some(peer_id) = node_info.peer_id() {
                if self.connected_peers.contains(&peer_id) || node_info.has_addresses() {
                    debug!(target: "stegos_network::delivery", "node is connected, delivering: node_id={}, peer_id={}, seq_no={}", to, peer_id, u8v_to_hexstr(&message.seq_no));
                    self.out_events.push_back(DiscoveryOutEvent::Route {
                        next_hop: peer_id,
                        message,
                    });
                    return;
                }
            }
        }

        debug!(target: "stegos_network::delivery", "finding route to node: node_id={}, seq_no={}", to, u8v_to_hexstr(&message.seq_no));
        // Collect DELIVERY_REPLICATION closest nodes with both peer_id and IPs known
        let closer_peers_temp: Vec<pbc::PublicKey> =
            self.kademlia.find_closest_with_self(to).collect();

        debug!(target: "stegos_network::delivery", "found closer ppers: count={}", closer_peers_temp.len());

        let closer_peers: Vec<(pbc::PublicKey, NodeInfo)> = closer_peers_temp
            .into_iter()
            .take_while(|p| p.distance_with(to) <= self.my_id.distance_with(to))
            .filter_map(|n| {
                if let Some(node_info) = self.kademlia.get_node(&n) {
                    Some((n, node_info))
                } else {
                    None
                }
            })
            .filter(|n| n.1.has_peer_id() && n.1.has_addresses())
            .take(DELIVERY_REPLICATION)
            .collect();
        debug!(target: "stegos_network::delivery", "collected closer nodes: count={}", closer_peers.len());

        // Should be sorted in ascending order by XOR distance
        let distances: Vec<u32> = closer_peers.iter().map(|p| p.0.distance_with(to)).collect();

        debug!(target: "stegos_network::delivery", "closest peers disctances: {:?}", distances);
        if closer_peers.is_empty() {
            debug!(target: "stegos_network::delivery", "couldn't find closer peers for node: node_id={}, seq_no={}", to, u8v_to_hexstr(&message.seq_no));
            return;
        }

        // deliver to N closer peers
        for p in closer_peers.iter() {
            debug!(target: "stegos_network::delivery", "we are closest node, delivering to other closest: to_node_id={}, seq_no={}", p.0, u8v_to_hexstr(&message.seq_no));
            self.out_events.push_back(DiscoveryOutEvent::Route {
                next_hop: p.1.peer_id().unwrap(), // we filtered nodes without peer_id
                message: message.clone(),
            });
        }
    }

    pub fn is_duplicate(&mut self, msg: &Unicast) -> bool {
        match self.received.contains_key(&msg.digest()) {
            true => true,
            false => {
                self.received.insert(msg.digest(), ());
                super::metrics::LRU_CACHE_SIZE.set(self.received.len() as i64);
                false
            }
        }
    }
}

impl NetworkBehaviour for Discovery {
    type ProtocolsHandler = <Kademlia as NetworkBehaviour>::ProtocolsHandler;
    type OutEvent = DiscoveryOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NetworkBehaviour::new_handler(&mut self.kademlia)
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        self.kademlia.addresses_of_peer(peer_id)
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {
        self.connected_peers.insert(peer_id.clone());
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        debug!(target: "stegos_network::discovery", "new peer connected: peer_id={}", peer_id);
        NetworkBehaviour::inject_connection_established(&mut self.kademlia, peer_id, conn, endpoint)
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        debug!(target: "stegos_network::discovery", "peer disconnected: peer_id={}", peer_id);
        NetworkBehaviour::inject_connection_closed(&mut self.kademlia, peer_id, conn, endpoint)
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        self.connected_peers.remove(peer_id);
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        cid: ConnectionId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        NetworkBehaviour::inject_event(&mut self.kademlia, peer_id, cid, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // Return pending events
        if let Some(event) = self.out_events.pop_front() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
        }

        // Process results of Kademlia discovery
        match self.kademlia.poll(cx, params) {
            Poll::Ready(NetworkBehaviourAction::GenerateEvent(action)) => {
                trace!(target: "stegos_network::discovery", "Event from Kademlia: {:?}", action);
                match action {
                    KademliaOut::FindNodeResult {
                        ref key,
                        ref closer_peers,
                    } => {
                        debug!(
                            target: "stegos_network::discovery",
                            "Kademlia query for {} yielded {} results",
                            u8v_to_hexstr(key.as_bytes()),
                            closer_peers.len()
                        );
                    }
                    KademliaOut::GetProvidersResult {
                        ref key,
                        closer_peers: _,
                        ref provider_peers,
                    } => {
                        debug!(target: "stegos_network::discovery", "Got providers: key={} num_providers={}", u8v_to_hexstr(key.as_bytes()), provider_peers.len());
                    }
                    KademliaOut::Discovered {
                        ref peer_id,
                        ref node_id,
                        ref addresses,
                        ty,
                    } => {
                        if peer_id.is_some() {
                            let peer_id = peer_id.clone().unwrap();
                            self.known_nodes.insert(*node_id, peer_id.clone());
                            debug!(target: "stegos_network::discovery",
                                "Discovered peer: node_id={}, peer_id={}, addresses={:?}, connected={:?}",
                                node_id, peer_id, addresses, ty
                            );
                            if !addresses.is_empty() {
                                self.kademlia.set_peer_id(node_id, peer_id.clone());
                                for addr in addresses.iter() {
                                    if self.connected_peers.contains(&peer_id) {
                                        self.kademlia.add_connected_address(node_id, addr.clone());
                                    } else {
                                        self.kademlia
                                            .add_not_connected_address(node_id, addr.clone());
                                    }
                                }
                            }
                        } else {
                            debug!(target: "stegos_network::discovery",
                                "Discovered peer: node_id={}, peer_id=Unknown, addresses={:?} connected={:?}",
                                node_id, addresses, ty
                            );
                        }
                    }
                }
                return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
                    DiscoveryOutEvent::KadEvent { event: action },
                ));
            }
            Poll::Ready(NetworkBehaviourAction::DialAddress { address }) => {
                return Poll::Ready(NetworkBehaviourAction::DialAddress { address });
            }
            Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition }) => {
                return Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition });
            }
            Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler,
                event,
            }) => {
                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                });
            }
            Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address }) => {
                return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address });
            }
            Poll::Pending => (),
        }
        // Check if we are connected to enough closes peers
        while let Poll::Ready(_) = self.next_connection_check.poll_unpin(cx) {
            self.next_connection_check
                .reset(Instant::now() + Duration::from_secs(MONITORING_INTERVAL));
            let my_id = *self.kademlia.my_id();
            let closest_nodes: Vec<pbc::PublicKey> = self
                .kademlia
                .find_closest(&my_id)
                .take(MIN_CLOSEST_PEERS)
                .collect();
            if !closest_nodes.is_empty() {
                debug!(target: "stegos_network::discovery", "Checking connection to the known closest peers: count={}, firts/last distance={}/{}", closest_nodes.len(), my_id.distance_with(&closest_nodes[0]), my_id.distance_with(&closest_nodes[closest_nodes.len()-1]));
            }
            for node in closest_nodes.iter() {
                if let Some(node_info) = self.kademlia.get_node(&node) {
                    if let Some(p) = node_info.peer_id() {
                        if !self.connected_peers.contains(&p) {
                            debug!(target: "stegos_network::discovery", "connecting to known closest peer: {}, distance: {}", p, &my_id.distance_with(node));
                            self.out_events
                                .push_back(DiscoveryOutEvent::DialPeer { peer_id: p.clone() });
                        } else {
                            debug!(target: "stegos_network::discovery", "already connected to closest peer: {}, distance: {}", p, &my_id.distance_with(node));
                        }
                    }
                }
            }
        }

        // Initiate new shake of DHT network
        while let Poll::Ready(_) = self.next_query.poll_unpin(cx) {
            debug!(target: "stegos_network::discovery", "Shooting at DHT to gather nodes information");
            let random_node_id = pbc::make_random_keys().1;
            self.kademlia.find_node(random_node_id);
            self.kademlia.find_node(self.my_id);
            // Reset the `Delay` to the next random.
            self.next_query
                .reset(Instant::now() + self.delay_between_queries);
            self.delay_between_queries =
                cmp::min(self.delay_between_queries * 2, Duration::from_secs(60));
        }

        Poll::Pending
    }
}

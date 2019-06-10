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

use futures::prelude::*;
use libp2p::core::{
    protocols_handler::ProtocolsHandler,
    swarm::{ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};
use log::*;
use lru_time_cache::LruCache;
use rand::{thread_rng, Rng};
use smallvec::SmallVec;
use std::{
    collections::VecDeque,
    marker::PhantomData,
    time::{Duration, Instant},
};
use stegos_crypto::pbc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;

use crate::config::NetworkConfig;
use crate::ncp::handler::NcpHandler;
use crate::ncp::protocol::{GetPeersResponse, NcpMessage, PeerInfo};
use crate::utils::ExpiringQueue;

// Size of table for "known" peers
const KNOWN_PEERS_TABLE_SIZE: usize = 1024;

// Treat connection as dead after 5 minutes inactivity
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Ncp<TSubstream> {
    /// Out network key
    node_id: pbc::PublicKey,
    /// Queue of internal events
    events: VecDeque<NcpEvent>,
    /// Events that need to be yielded to the outside when polling.
    out_events: VecDeque<NcpOutEvent>,
    /// List of connected peers (including disabled)
    connected_peers: ExpiringQueue<PeerId, Instant>,
    /// Known peers
    known_peers: LruCache<Vec<u8>, (pbc::PublicKey, SmallVec<[Multiaddr; 16]>)>,
    /// Maximum connections allowd
    max_connections: usize,
    /// Minimum connections to keep
    min_connections: usize,
    /// Delay to the next check for connections
    monitor_delay: Delay,
    /// Interval between monitoring events
    delay_between_monitor_events: Duration,
    /// Seed nodes (we keep them in case we were too long offline and need to restart the net)
    seed_nodes: Vec<Multiaddr>,
    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Ncp<TSubstream> {
    /// Creates a NetworkBehaviour for NCP.
    pub fn new(config: &NetworkConfig, network_pkey: pbc::PublicKey) -> Self {
        let seed_nodes: Vec<Multiaddr> = config
            .seed_nodes
            .iter()
            .filter_map(|a| match a.parse() {
                Ok(addr) => Some(addr),
                Err(_) => None,
            })
            .collect();
        Ncp {
            node_id: network_pkey,
            events: VecDeque::new(),
            out_events: VecDeque::new(),
            connected_peers: ExpiringQueue::new(IDLE_TIMEOUT),
            known_peers:
                LruCache::<Vec<u8>, (pbc::PublicKey, SmallVec<[Multiaddr; 16]>)>::with_capacity(
                    KNOWN_PEERS_TABLE_SIZE,
                ),
            max_connections: config.max_connections,
            min_connections: config.min_connections,
            monitor_delay: Delay::new(
                Instant::now()
                    + Duration::from_secs(config.monitoring_interval)
                    + Duration::from_secs(thread_rng().gen_range(0, 30)),
            ),
            delay_between_monitor_events: Duration::from_secs(config.monitoring_interval),
            seed_nodes,
            marker: PhantomData,
        }
    }

    pub fn change_network_key(&mut self, new_pkey: pbc::PublicKey) {
        self.node_id = new_pkey;
        // Update all connected peers with our new network key
        for p in self.connected_peers.keys() {
            self.events
                .push_back(NcpEvent::SendPeers { peer_id: p.clone() });
        }
    }

    // Terminate connection to peer
    pub fn terminate(&mut self, peer_id: PeerId) {
        debug!(target: "stegos_network::ncp", "terminating connection with peer: peer_id={}", peer_id);
        self.events.push_back(NcpEvent::Terminate { peer_id });
    }
}

impl<TSubstream> NetworkBehaviour for Ncp<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = NcpHandler<TSubstream>;
    type OutEvent = NcpOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NcpHandler::new()
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let small = self
            .known_peers
            .get(peer.as_bytes())
            .map(|(_, v)| v.clone())
            .unwrap_or(SmallVec::new());
        let addresses: Vec<Multiaddr> = small.iter().map(|v| v.clone()).collect();
        addresses
    }

    fn inject_connected(&mut self, id: PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::ncp", "peer connected: peer_id={}", id.to_base58());
        self.events.push_back(NcpEvent::RequestPeers {
            peer_id: id.clone(),
        });
        self.out_events.push_back(NcpOutEvent::Connected {
            peer_id: id.clone(),
        });
        self.connected_peers.insert(id, Instant::now());
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::ncp", "peer disconnected: peer_id={}", id.to_base58());
        self.connected_peers.remove(id);
        self.out_events.push_back(NcpOutEvent::Disconnected {
            peer_id: id.clone(),
        });
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: NcpRecvEvent) {
        // Process received NCP message (passed from Handler as Custom(message))
        debug!(target: "stegos_network::ncp", "Received a message: {:?}", event);
        self.connected_peers
            .insert(propagation_source.clone(), Instant::now());
        match event {
            NcpRecvEvent::Recv(NcpMessage::GetPeersRequest) => {
                self.events.push_back(NcpEvent::SendPeers {
                    peer_id: propagation_source,
                });
            }
            NcpRecvEvent::Recv(NcpMessage::GetPeersResponse { response }) => {
                self.events.push_back(NcpEvent::StorePeers {
                    from: propagation_source,
                    message: response,
                });
            }
            NcpRecvEvent::Recv(NcpMessage::Ping) => {
                debug!(target: "stegos_network::ncp", "received ping request: peer_id={}", propagation_source.to_base58());
                self.events.push_back(NcpEvent::SendPong {
                    peer_id: propagation_source,
                })
            }
            NcpRecvEvent::Recv(NcpMessage::Pong) => {
                debug!(target: "stegos_network::ncp", "received pong request: peer_id={}", propagation_source.to_base58());
            }
        }
    }

    fn poll(
        &mut self,
        poll_parameters: &mut PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // Send out accumulated events
        if let Some(event) = self.out_events.pop_front() {
            return Async::Ready(NetworkBehaviourAction::GenerateEvent(event));
        }

        // Check established connections and request more, if needed.
        loop {
            match self.monitor_delay.poll() {
                Ok(Async::Ready(_)) => {
                    debug!(
                        target: "stegos_network::ncp",
                        "monitoring event: connected_peers={}, known_peers={}",
                        self.connected_peers.len(),
                        self.known_peers.len(),
                    );
                    // Setup delay to the next event
                    self.monitor_delay.reset(
                        Instant::now()
                            + self.delay_between_monitor_events
                            + Duration::from_secs(thread_rng().gen_range(0, 30)),
                    );
                    // refresh peers in known peers, so they wouldn't be purged
                    for p in self.connected_peers.keys() {
                        self.events
                            .push_back(NcpEvent::SendPing { peer_id: p.clone() });
                        let _ = self.known_peers.get(p.as_bytes());
                    }
                    if self.connected_peers.len() >= self.max_connections {
                        // Already have max connected_peers
                        continue;
                    }
                    if self.connected_peers.len() < self.min_connections {
                        let mut seen_peers: Vec<PeerId> = Vec::new();
                        let mut bad_peer_ids: Vec<Vec<u8>> = Vec::new();
                        for (peer_bytes, _addresses) in self.known_peers.peek_iter() {
                            if let Ok(peer) = PeerId::from_bytes(peer_bytes.clone()) {
                                seen_peers.push(peer.clone());
                                if peer == *poll_parameters.local_peer_id()
                                    || self.connected_peers.contains_key(&peer)
                                {
                                    continue;
                                }
                                trace!(target: "stegos_network::ncp", "Dialing peer: {:#?}", peer);
                                self.out_events
                                    .push_back(NcpOutEvent::DialPeer { peer_id: peer });
                            } else {
                                bad_peer_ids.push(peer_bytes.clone());
                            }
                        }
                        // remove broken (can't really happen) peer_ids from known peers
                        for p in bad_peer_ids.iter() {
                            self.known_peers.remove(p);
                        }

                        // if nuymebr of connections is below threshold, ask all connected peers for theis neighbors
                        // otherwise pick 3 random peers from connected and ask them for their neighbors
                        if self.connected_peers.len() < self.min_connections {
                            for p in self.connected_peers.keys() {
                                self.events
                                    .push_back(NcpEvent::RequestPeers { peer_id: p.clone() });
                            }
                        } else {
                            let idx = rand::thread_rng().gen_range(0, self.connected_peers.len());
                            if let Some(p) = self.connected_peers.keys().nth(idx) {
                                self.events
                                    .push_back(NcpEvent::RequestPeers { peer_id: p.clone() });
                            }
                        }
                    };
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!(target: "stegos_network::ncp", "Interval timer error: {}", e);
                    break;
                }
            }
        }

        // Check for expired idle connections
        loop {
            match self.connected_peers.poll() {
                Ok(Async::Ready((peer, last_seen))) => {
                    match last_seen {
                        Some(instant) => {
                            debug!(target: "stegos_network::ncp", "peer was inactive for {}.{:.3}s, terminating: peer_id={}", instant.elapsed().as_secs(), instant.elapsed().subsec_millis(), peer.to_base58());
                        }
                        None => {
                            debug!(target: "stegos_network::ncp", "peer was inactive for too long, terminating: peer_id={}", peer.to_base58());
                        }
                    }
                    self.events.push_back(NcpEvent::Terminate { peer_id: peer });
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!(target: "stegos_network::ncp", "connected peers timer error: {}", e);
                    break;
                }
            }
        }

        if let Some(event) = self.events.pop_front() {
            match event {
                NcpEvent::StorePeers { from, message } => {
                    debug!(target: "stegos_network::ncp", "received peers: from_peer={}", from.to_base58());
                    for peer in message.peers.into_iter() {
                        if peer.peer_id != *poll_parameters.local_peer_id() {
                            let id = peer.peer_id.clone();
                            if !self.known_peers.contains_key(id.as_bytes()) {
                                self.known_peers.insert(
                                    id.clone().into_bytes(),
                                    (peer.node_id.clone(), SmallVec::new()),
                                );
                            }
                            for addr in peer.addresses.into_iter() {
                                // Safe to unwrap, since we initalized entry on previous step
                                if self
                                    .known_peers
                                    .get_mut(id.as_bytes())
                                    .unwrap()
                                    .1
                                    .iter()
                                    .all(|a| *a != addr)
                                {
                                    self.known_peers
                                        .get_mut(id.as_bytes())
                                        .unwrap()
                                        .1
                                        .push(addr)
                                }
                            }
                            self.out_events.push_back(NcpOutEvent::DiscoveredPeer {
                                peer_id: peer.peer_id.clone(),
                                node_id: peer.node_id.clone(),
                                addresses: self
                                    .known_peers
                                    .get(id.as_bytes())
                                    .unwrap()
                                    .1
                                    .iter()
                                    .map(|v| v.clone())
                                    .collect(),
                            });
                        }
                    }
                }
                NcpEvent::SendPeers { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending peers info: to_peer={}", peer_id.to_base58());
                    let mut response = GetPeersResponse { peers: vec![] };
                    let mut connected: Vec<PeerId> =
                        self.connected_peers.keys().map(|v| v.clone()).collect();
                    for peer in connected.drain(..) {
                        if peer == peer_id {
                            continue;
                        }
                        if self.known_peers.get(&peer.clone().into_bytes()).is_none() {
                            continue;
                        }
                        let node_id = self.known_peers.get(&peer.clone().into_bytes()).unwrap().0;
                        let mut peer_info = PeerInfo::new(&peer, &node_id);
                        for addr in self.addresses_of_peer(&peer) {
                            peer_info.addresses.push(addr);
                        }
                        if peer_info.addresses.len() > 0 {
                            response.peers.push(peer_info);
                        }
                    }
                    let peer = poll_parameters.local_peer_id().clone();
                    let mut peer_info = PeerInfo::new(&peer, &self.node_id);
                    for addr in poll_parameters.external_addresses() {
                        peer_info.addresses.push(addr.clone());
                    }
                    response.peers.push(peer_info);
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpSendEvent::Send(NcpMessage::GetPeersResponse { response }),
                    });
                }
                NcpEvent::RequestPeers { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending peers request: to_peer={}", peer_id.to_base58());
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpSendEvent::Send(NcpMessage::GetPeersRequest),
                    });
                }
                NcpEvent::SendPing { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending ping request: to_peer={}", peer_id.to_base58());
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpSendEvent::Send(NcpMessage::Ping),
                    });
                }
                NcpEvent::SendPong { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending pong reply: to_peer={}", peer_id.to_base58());
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpSendEvent::Send(NcpMessage::Pong),
                    });
                }
                NcpEvent::Terminate { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending terminate to handler: peer_id={}", peer_id.to_base58());
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpSendEvent::Terminate,
                    });
                }
            }
        }
        Async::NotReady
    }
}

/// Event that can happen on the floodsub behaviour.
#[derive(Debug)]
pub enum NcpEvent {
    StorePeers {
        from: PeerId,
        message: GetPeersResponse,
    },
    /// Send info about connected peers.
    SendPeers { peer_id: PeerId },
    /// Request list of connected peers from neighbor
    RequestPeers { peer_id: PeerId },
    /// Send Ping request to the peer
    SendPing { peer_id: PeerId },
    /// Send Pong reply to the peer
    SendPong { peer_id: PeerId },
    /// Terminate connection to peer
    Terminate { peer_id: PeerId },
}

/// Events to send to upper level
pub enum NcpOutEvent {
    /// Instructs the swarm to dial the given multiaddress without any expectation of a peer id.
    DialAddress {
        /// The address to dial.
        address: Multiaddr,
    },
    /// Instructs the swarm to try reach the given peer.
    DialPeer {
        /// The peer to try reach.
        peer_id: PeerId,
    },
    DiscoveredPeer {
        node_id: pbc::PublicKey,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    Connected {
        peer_id: PeerId,
    },
    Disconnected {
        peer_id: PeerId,
    },
}

/// Event passed to protocol handler
pub enum NcpSendEvent {
    Send(NcpMessage),
    Terminate,
}

// Event received from protocol handler
#[derive(Debug)]
pub enum NcpRecvEvent {
    Recv(NcpMessage),
}

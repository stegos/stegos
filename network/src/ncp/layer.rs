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
use rand::{seq::SliceRandom, thread_rng, Rng};
use smallvec::SmallVec;
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    marker::PhantomData,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;
use void::Void;

use crate::config::NetworkConfig;
use crate::ncp::handler::NcpHandler;
use crate::ncp::protocol::{GetPeersResponse, NcpMessage, PeerInfo};

const KNOWN_PEERS_TABLE_SIZE: usize = 1024;

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Ncp<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NcpEvent>,
    /// List of connected peers
    connected_peers: HashSet<PeerId>,
    /// Known peers
    known_peers: LruCache<Vec<u8>, SmallVec<[Multiaddr; 16]>>,
    /// Maximum connections allowd
    max_connections: usize,
    /// Minimum connections to keep
    min_connections: usize,
    /// Delay to the next check for connections
    monitor_delay: Delay,
    /// Interval between monitoring events
    delay_between_monitor_events: Duration,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Ncp<TSubstream> {
    /// Creates a NetworkBehaviour for NCP.
    pub fn new(config: &NetworkConfig) -> Self {
        let mut events = VecDeque::new();

        // Randmoize seed nodes array
        let mut rng = thread_rng();
        let mut addrs = config.seed_nodes.clone();
        addrs.shuffle(&mut rng);

        for addr in addrs.iter() {
            debug!(target: "stegos_network::ncp", "dialing peer with address {}", addr);
            match addr.parse::<Multiaddr>() {
                Ok(maddr) => {
                    events.push_back(NcpEvent::DialAddress {
                        address: maddr.clone(),
                    });
                }
                Err(e) => {
                    error!(target: "stegos_network::ncp", "failed to parse address: {}, error: {}", addr, e)
                }
            }
        }

        Ncp {
            events,
            connected_peers: HashSet::new(),
            known_peers: LruCache::<Vec<u8>, SmallVec<[Multiaddr; 16]>>::with_capacity(
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
            marker: PhantomData,
        }
    }
}

impl<TSubstream> NetworkBehaviour for Ncp<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = NcpHandler<TSubstream>;
    type OutEvent = Void;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NcpHandler::new()
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let small = self
            .known_peers
            .get(peer.as_bytes())
            .map(|v| v.clone())
            .unwrap_or(SmallVec::new());
        let addresses: Vec<Multiaddr> = small.iter().map(|v| v.clone()).collect();
        addresses
    }

    fn inject_connected(&mut self, id: PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::ncp", "peer connected: peer_id={}", id.to_base58());
        // Send information about connected peers to the freshly connected peer.
        self.connected_peers.insert(id.clone());
        self.events.push_back(NcpEvent::SendPeers { peer_id: id });
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::ncp", "peer disconnected: peer_id={}", id.to_base58());
        self.connected_peers.remove(id);
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: NcpMessage) {
        // Process received NCP message (passed from Handler as Custom(message))
        debug!(target: "stegos_network::ncp", "Received a message: {:?}", event);
        match event {
            NcpMessage::GetPeersRequest => {
                self.events.push_back(NcpEvent::SendPeers {
                    peer_id: propagation_source,
                });
            }
            NcpMessage::GetPeersResponse { response } => {
                self.events.push_back(NcpEvent::StorePeers {
                    from: propagation_source,
                    message: response,
                });
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
        loop {
            match self.monitor_delay.poll() {
                Ok(Async::Ready(_)) => {
                    debug!(
                        target: "stegos_network::ncp",
                        "monitoring event: connected_peers={}, known_peers={}",
                        self.connected_peers.len(),
                        self.known_peers.len(),
                    );
                    // refresh peers in known peers, so they wouldn't be purged
                    for p in self.connected_peers.iter() {
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
                                    || self.connected_peers.contains(&peer)
                                {
                                    continue;
                                }
                                trace!(target: "stegos_network::ncp", "Dialing peer: {:#?}", peer);
                                self.events.push_back(NcpEvent::DialPeer { peer_id: peer });
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
                            for p in self.connected_peers.iter() {
                                self.events
                                    .push_back(NcpEvent::RequestPeers { peer_id: p.clone() });
                            }
                        } else {
                            let idx = rand::thread_rng().gen_range(0, self.connected_peers.len());
                            if let Some(p) = self.connected_peers.iter().nth(idx) {
                                self.events
                                    .push_back(NcpEvent::RequestPeers { peer_id: p.clone() });
                            }
                        }
                    };
                    // Share our connected peers info with others.
                    // Setup delay to the next event
                    self.monitor_delay.reset(
                        Instant::now()
                            + self.delay_between_monitor_events
                            + Duration::from_secs(thread_rng().gen_range(0, 30)),
                    );
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!(target: "stegos_network::ncp", "Interval timer error: {}", e);
                    break;
                }
            }
        }
        if let Some(event) = self.events.pop_front() {
            match event {
                NcpEvent::DialAddress { address } => {
                    return Async::Ready(NetworkBehaviourAction::DialAddress { address });
                }
                NcpEvent::DialPeer { peer_id } => {
                    return Async::Ready(NetworkBehaviourAction::DialPeer { peer_id });
                }
                NcpEvent::StorePeers { from, message } => {
                    debug!(target: "stegos_network::ncp", "received peers: from_peer={}", from.to_base58());
                    for peer in message.peers.into_iter() {
                        if peer.peer_id != *poll_parameters.local_peer_id() {
                            for addr in peer.addresses.into_iter() {
                                let id = peer.peer_id.clone();
                                if !self.known_peers.contains_key(id.as_bytes()) {
                                    self.known_peers
                                        .insert(id.clone().into_bytes(), SmallVec::new());
                                }
                                // Safe to unwrap, since we initalized entry on previous step
                                if self
                                    .known_peers
                                    .get_mut(id.as_bytes())
                                    .unwrap()
                                    .iter()
                                    .all(|a| *a != addr)
                                {
                                    self.known_peers.get_mut(id.as_bytes()).unwrap().push(addr)
                                }
                            }
                        }
                    }
                }
                NcpEvent::SendPeers { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending peers info: to_peer={}", peer_id.to_base58());
                    let mut response = GetPeersResponse { peers: vec![] };
                    let mut connected = self.connected_peers.clone();
                    for peer in connected.drain() {
                        if peer == peer_id {
                            continue;
                        }
                        let mut peer_info = PeerInfo::new(&peer);
                        for addr in self.addresses_of_peer(&peer) {
                            peer_info.addresses.push(addr);
                        }
                        if peer_info.addresses.len() > 0 {
                            response.peers.push(peer_info);
                        }
                    }
                    let peer = poll_parameters.local_peer_id().clone();
                    let mut peer_info = PeerInfo::new(&peer);
                    for addr in poll_parameters.external_addresses() {
                        peer_info.addresses.push(addr);
                    }
                    response.peers.push(peer_info);
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpMessage::GetPeersResponse { response },
                    });
                }
                NcpEvent::RequestPeers { peer_id } => {
                    debug!(target: "stegos_network::ncp", "sending peers request: to_peer={}", peer_id.to_base58());
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpMessage::GetPeersRequest,
                    });
                }
            }
        }
        Async::NotReady
    }
}

/// Event that can happen on the floodsub behaviour.
pub enum NcpEvent {
    /// Store peers information, received from the neighbor
    StorePeers {
        from: PeerId,
        message: GetPeersResponse,
    },

    /// Send info about connected peers.
    SendPeers { peer_id: PeerId },

    /// Request list of connected peers from neighbor
    RequestPeers { peer_id: PeerId },

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
}

impl fmt::Debug for NcpEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            NcpEvent::StorePeers { from, .. } => {
                write!(f, "NcpEvent::StorePeers: from={}", from.to_base58())
            }
            NcpEvent::SendPeers { peer_id, .. } => {
                write!(f, "NcpEvent::SendPeers: to={}", peer_id.to_base58())
            }
            NcpEvent::RequestPeers { peer_id, .. } => {
                write!(f, "NcpEvent::RequestPeers: from={}", peer_id.to_base58())
            }
            NcpEvent::DialPeer { peer_id, .. } => {
                write!(f, "NcpEvent::DialPeer: peer={}", peer_id.to_base58())
            }
            NcpEvent::DialAddress { address, .. } => {
                write!(f, "NcpEvent::DialAddress: address={}", address)
            }
        }
    }
}

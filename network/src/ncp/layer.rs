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

use crate::config::NetworkConfig;
use futures::prelude::*;
use libp2p::core::{
    protocols_handler::ProtocolsHandler,
    swarm::{ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};
use log::*;
use std::{
    collections::{HashSet, VecDeque},
    marker::PhantomData,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Interval;
use void::Void;

use crate::ncp::handler::NcpHandler;
use crate::ncp::protocol::{GetPeersResponse, NcpMessage, PeerInfo};
use crate::PeerStore;

/// Network behaviour that automatically identifies nodes periodically, and returns information
/// about them.
pub struct Ncp<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NcpEvent>,

    /// List of connected peers
    connected_peers: HashSet<PeerId>,

    max_connections: usize,
    min_connections: usize,
    monitor: Interval,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Ncp<TSubstream> {
    /// Creates a NetworkBehaviour for NCP.
    pub fn new(config: &NetworkConfig) -> Self {
        let mut events = VecDeque::new();

        for addr in config.seed_nodes.iter() {
            debug!("Dialing peer with address {}", addr);
            match addr.parse::<Multiaddr>() {
                Ok(maddr) => {
                    events.push_back(NcpEvent::DialAddress {
                        address: maddr.clone(),
                    });
                }
                Err(e) => error!("failed to parse address: {}, error: {}", addr, e),
            }
        }

        Ncp {
            events,
            connected_peers: HashSet::new(),
            max_connections: config.max_connections,
            min_connections: config.min_connections,
            monitor: Interval::new_interval(Duration::from_secs(config.monitoring_interval)),
            marker: PhantomData,
        }
    }
}

impl<TSubstream, TTopology> NetworkBehaviour<TTopology> for Ncp<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
    TTopology: PeerStore,
{
    type ProtocolsHandler = NcpHandler<TSubstream>;
    type OutEvent = Void;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NcpHandler::new()
    }

    fn inject_connected(&mut self, id: PeerId, _: ConnectedPoint) {
        debug!("Peer connected: {:#?}", id);
        // Send information about connected peers to the freshly connected peer.
        self.connected_peers.insert(id.clone());
        self.events.push_back(NcpEvent::SendPeers { peer_id: id });
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!("Peer disconnected: {:#?}", id);
        self.connected_peers.remove(id);
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: NcpMessage) {
        // Process received NCP message (passed from Handler as Custom(message))
        debug!("Received a message: {:?}", event);
        match event {
            NcpMessage::GetPeersRequest => {
                self.events.push_back(NcpEvent::SendPeers {
                    peer_id: propagation_source.clone(),
                });
            }
            NcpMessage::GetPeersResponse { response } => {
                self.events
                    .push_back(NcpEvent::StorePeers { message: response });
            }
        }
    }

    fn poll(
        &mut self,
        poll_parameters: &mut PollParameters<TTopology>,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        trace!("NCP poll function");
        loop {
            match self.monitor.poll() {
                Ok(Async::Ready(Some(_))) => {
                    trace!("Monitor event fired!");
                    if self.connected_peers.len() >= self.max_connections {
                        // Already have max connected_peers
                        continue;
                    }
                    if self.connected_peers.len() < self.min_connections {
                        let topology = poll_parameters.topology();
                        let peers = topology.peers();
                        trace!("Known peers: {:#?}", peers);
                        trace!("Connected peers: {:#?}", self.connected_peers);

                        for p in peers.into_iter() {
                            if topology.local_peer_id() == p || self.connected_peers.contains(p) {
                                continue;
                            };
                            trace!("Dialing peer: {:#?}", p);
                            self.events
                                .push_back(NcpEvent::DialPeer { peer_id: p.clone() });
                        }
                    };
                    // Share our connected peers info with others.
                    for p in self.connected_peers.iter() {
                        self.events
                            .push_back(NcpEvent::RequestPeers { peer_id: p.clone() });
                    }
                }
                Ok(Async::Ready(None)) => {
                    trace!("Time finished!");
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!("Interval timer error: {}", e);
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
                NcpEvent::StorePeers { message } => {
                    let topology = poll_parameters.topology();

                    for peer in message.peers.into_iter() {
                        if peer.peer_id != *topology.local_peer_id() {
                            for addr in peer.addresses.into_iter() {
                                let id = peer.peer_id.clone();
                                topology.store_address(id, addr);
                            }
                        }
                    }
                }
                NcpEvent::SendPeers { peer_id } => {
                    let topology = poll_parameters.topology();
                    let mut response = GetPeersResponse { peers: vec![] };

                    for peer in self.connected_peers.iter() {
                        let mut peer_info = PeerInfo::new(&peer);
                        for addr in topology.addresses_of_peer(&peer) {
                            peer_info.addresses.push(addr);
                        }
                        if peer_info.addresses.len() > 0 {
                            response.peers.push(peer_info);
                        }
                    }
                    let peer = topology.local_peer_id().clone();
                    let mut peer_info = PeerInfo::new(&peer);
                    for addr in topology.addresses_of_peer(&peer) {
                        peer_info.addresses.push(addr);
                    }
                    response.peers.push(peer_info);
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpMessage::GetPeersResponse { response },
                    });
                }
                NcpEvent::RequestPeers { peer_id } => {
                    return Async::Ready(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: NcpMessage::GetPeersRequest,
                    });
                }
            }
        }
        trace!("Finished NCP poll");
        Async::NotReady
    }
}

/// Event that can happen on the floodsub behaviour.
#[derive(Debug)]
pub enum NcpEvent {
    /// Store peers information, received from the neighbor
    StorePeers { message: GetPeersResponse },

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

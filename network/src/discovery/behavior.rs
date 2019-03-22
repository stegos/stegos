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

use crate::kad::{Kademlia, KademliaOut};
use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{core::ProtocolsHandler, Multiaddr, PeerId};
use log::*;
use std::cmp;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use stegos_crypto::pbc::secure;
use stegos_crypto::utils::u8v_to_hexstr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;

pub enum DiscoveryOutEvent {
    KadEvent(KademliaOut),
}

/// Kademlia-based network discovery
pub struct Discovery<TSubstream> {
    /// Kademlia systems
    kademlia: Kademlia<TSubstream>,
    /// Set of currently connected peers
    connected_peers: HashSet<PeerId>,
    /// When to send random request to gather network info
    next_query: Delay,
    /// Delay to the next random poll
    delay_between_queries: Duration,
}

impl<TSubstream> Discovery<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(local_node_id: secure::PublicKey) -> Self {
        Discovery {
            kademlia: Kademlia::without_init(local_node_id),
            connected_peers: HashSet::new(),
            next_query: Delay::new(Instant::now() + Duration::from_secs(30)),
            delay_between_queries: Duration::from_secs(1),
        }
    }

    /// Sets peer_id to the corresponging node_id
    pub fn set_peer_id(&mut self, node_id: &secure::PublicKey, peer_id: PeerId) {
        self.kademlia.set_peer_id(node_id, peer_id);
    }

    /// Adds a known address for the given `PeerId`. We are connected to this address.
    pub fn add_connected_address(&mut self, node_id: &secure::PublicKey, address: Multiaddr) {
        self.kademlia.add_connected_address(node_id, address);
    }

    /// Adds a known address for the given `PeerId`. We are not connected or don't know whether we
    /// are connected to this address.
    pub fn add_not_connected_address(&mut self, node_id: &secure::PublicKey, address: Multiaddr) {
        self.kademlia.add_not_connected_address(node_id, address);
    }
}

impl<TSubstream> NetworkBehaviour for Discovery<TSubstream>
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
        debug!(target: "stegos_network::discovery", "new peer connected: peer_id={}", peer_id.to_base58());
        self.connected_peers.insert(peer_id.clone());
        NetworkBehaviour::inject_connected(&mut self.kademlia, peer_id, endpoint)
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, endpoint: ConnectedPoint) {
        debug!(target: "stegos_network::discovery", "peer disconnected: peer_id={}", peer_id.to_base58());
        self.connected_peers.remove(peer_id);
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
                            debug!(target: "stegos_network::discovery",
                                "Discovered peer: node_id={}, peer_id={}, addresses={:?}, connected={:?}",
                                node_id, peer_id.to_base58(), addresses, ty
                            );
                            self.kademlia.set_peer_id(node_id, peer_id.clone());
                            for addr in addresses.iter() {
                                if self.connected_peers.contains(&peer_id) {
                                    self.kademlia.add_connected_address(node_id, addr.clone());
                                } else {
                                    self.kademlia
                                        .add_not_connected_address(node_id, addr.clone());
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
        trace!("Done checking queues");
        // Initiate new shake of DHT network
        loop {
            match self.next_query.poll() {
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(_)) => {
                    debug!("Shooting at DHT to gather nodes information");
                    let (_, random_node_id, _) = secure::make_random_keys();
                    self.kademlia.find_node(random_node_id);

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

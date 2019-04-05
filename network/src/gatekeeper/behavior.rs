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

use futures::prelude::*;
use libp2p::core::{
    protocols_handler::ProtocolsHandler,
    swarm::{ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};
use log::*;
use rand::{seq::SliceRandom, thread_rng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
};
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use tokio::io::{AsyncRead, AsyncWrite};

use super::handler::{GatekeeperHandler, GatekeeperSendEvent};
use super::protocol::{ConnectionType, GatekeeperMessage};
use crate::config::NetworkConfig;

/// Network behavior to handle initial nodes handshake
pub struct Gatekeeper<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>>,
    /// List of connected peers
    connected_peers: HashSet<PeerId>,
    /// My PBC PublicKey
    my_pkey: secure::PublicKey,
    /// Peers we are trying to connect to
    connecting_peers: HashSet<PeerId>,
    /// Addresses we are trying to connect to
    connecting_addresses: HashSet<Multiaddr>,
    /// Negotiating peers
    negotiating: HashMap<PeerId, (PeerKind, NegotiateState)>,
    /// Upstream events when Dialer/Listeners are ready
    protocol_updates: VecDeque<(PeerId, ProtocolUpdateEvent)>,
    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

#[derive(Debug, PartialEq)]
enum PeerKind {
    Dialer,
    Listener,
}

#[derive(Debug)]
enum NegotiateState {
    PreparingListener,
    PreparingDialer,
    WaitingHello,
    WaitingReply,
    Connected,
}

impl<TSubstream> Gatekeeper<TSubstream> {
    /// Creates a NetworkBehaviour for NCP.
    pub fn new(config: &NetworkConfig, keychain: &KeyChain) -> Self {
        let mut connecting_addresses: HashSet<Multiaddr> = HashSet::new();
        let mut events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>> =
            VecDeque::new();

        // Randmoize seed nodes array
        let mut rng = thread_rng();
        let mut addrs = config.seed_nodes.clone();
        addrs.shuffle(&mut rng);

        for addr in addrs.iter() {
            debug!(target: "stegos_network::ncp", "dialing peer with address {}", addr);
            match addr.parse::<Multiaddr>() {
                Ok(maddr) => {
                    events.push_back(NetworkBehaviourAction::DialAddress {
                        address: maddr.clone(),
                    });
                    connecting_addresses.insert(maddr);
                }
                Err(e) => {
                    error!(target: "stegos_network::ncp", "failed to parse address: {}, error: {}", addr, e)
                }
            }
        }

        Gatekeeper {
            events,
            connected_peers: HashSet::new(),
            my_pkey: keychain.network_pkey.clone(),
            connecting_peers: HashSet::new(),
            connecting_addresses,
            negotiating: HashMap::new(),
            protocol_updates: VecDeque::new(),
            marker: PhantomData,
        }
    }

    pub fn shutdown(&mut self, peer_id: &PeerId) {
        self.events.push_back(NetworkBehaviourAction::SendEvent {
            peer_id: peer_id.clone(),
            event: GatekeeperSendEvent::Shutdown,
        });
    }

    pub fn dial_peer(&mut self, peer_id: PeerId) {
        self.connecting_peers.insert(peer_id.clone());
        self.events
            .push_back(NetworkBehaviourAction::DialPeer { peer_id });
    }

    pub fn dial_address(&mut self, address: Multiaddr) {
        self.connecting_addresses.insert(address.clone());
        self.events
            .push_back(NetworkBehaviourAction::DialAddress { address });
    }

    pub fn notify(&mut self, peer_id: &PeerId, event: ProtocolUpdateEvent) {
        self.protocol_updates.push_back((peer_id.clone(), event));
    }
}

impl<TSubstream> NetworkBehaviour for Gatekeeper<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = GatekeeperHandler<TSubstream>;
    type OutEvent = GatekeeperOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        GatekeeperHandler::new()
    }

    fn addresses_of_peer(&mut self, _peer: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, id: PeerId, cp: ConnectedPoint) {
        debug!(target: "stegos_network::gatekeeper", "peer connected: peer_id={}", id.to_base58());
        self.connected_peers.insert(id.clone());
        if let ConnectedPoint::Dialer { address } = cp {
            // We are dialing, so if we have dialed peer/address in queue, start negotiaions
            if self.connecting_peers.remove(&id) | self.connecting_addresses.remove(&address) {
                self.negotiating.insert(
                    id.clone(),
                    (PeerKind::Dialer, NegotiateState::PreparingListener),
                );
                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                    GatekeeperOutEvent::PrepareListener { peer_id: id },
                ));
            } else {
                // For now let all connections be full node
                // TODO: handle different kinds of connections properly
                self.events.push_back(NetworkBehaviourAction::SendEvent {
                    peer_id: id,
                    event: GatekeeperSendEvent::Send(GatekeeperMessage::Request {
                        conn_type: ConnectionType::None,
                        node_id: self.my_pkey.clone(),
                    }),
                })
            }
        } else {
            if self.connecting_peers.remove(&id) {
                // Let dialing peer decide what to do...
                debug!(target: "stegos_network::gatekeeper", "Got incoming connect from peer we are trying to connect: peer_id={}", id.to_base58());
            }
            self.negotiating.insert(
                id.clone(),
                (PeerKind::Listener, NegotiateState::WaitingHello),
            );
        }
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!(target: "stegos_network::gatekeeper", "peer disconnected: peer_id={}", id.to_base58());
        self.connected_peers.remove(id);
        self.negotiating.remove(id);
        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
            GatekeeperOutEvent::Disconnected {
                peer_id: id.clone(),
            },
        ));
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: GatekeeperMessage) {
        // Process received NCP message (passed from Handler as Custom(message))
        debug!(target: "stegos_network::gatekeeper", "Received a message: {:?}", event);
        match event {
            GatekeeperMessage::Request {
                conn_type: _,
                node_id: _,
            } => {
                // TODO: validate node/peer
                if let Some((kind, state)) = self.negotiating.get_mut(&propagation_source) {
                    debug_assert_eq!(*kind, PeerKind::Listener);
                    *state = NegotiateState::PreparingListener;
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::PrepareListener {
                            peer_id: propagation_source.clone(),
                        },
                    ));
                }
            }
            GatekeeperMessage::Reply { conn_type, .. } => {
                if let Some((kind, state)) = self.negotiating.get_mut(&propagation_source) {
                    // TODO: handle refusals
                    debug_assert_eq!(*kind, PeerKind::Dialer);
                    debug_assert_eq!(conn_type, ConnectionType::FullNode);
                    *state = NegotiateState::PreparingDialer;
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::PrepareDialer {
                            peer_id: propagation_source.clone(),
                        },
                    ));
                }
            }
        }
    }

    fn poll(
        &mut self,
        _poll_parameters: &mut PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if let Some((peer_id, event)) = self.protocol_updates.pop_front() {
            match event {
                ProtocolUpdateEvent::EnabledListener => {
                    if let Some((kind, state)) = self.negotiating.get_mut(&peer_id) {
                        if *kind == PeerKind::Dialer {
                            *state = NegotiateState::WaitingReply;
                            debug!(target: "stegos_network::gatekeeper", "dialer: enabled listener for peer: peer_id={}", peer_id.to_base58());
                            self.events.push_back(NetworkBehaviourAction::SendEvent {
                                peer_id,
                                event: GatekeeperSendEvent::Send(GatekeeperMessage::Request {
                                    conn_type: ConnectionType::FullNode,
                                    node_id: self.my_pkey.clone(),
                                }),
                            });
                        } else {
                            *state = NegotiateState::PreparingDialer;
                            debug!(target: "stegos_network::gatekeeper", "listener: enabled listener for peer: peer_id={}", peer_id.to_base58());
                            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                GatekeeperOutEvent::PrepareDialer { peer_id },
                            ));
                        }
                    }
                }
                ProtocolUpdateEvent::EnabledDialer => {
                    if let Some((kind, state)) = self.negotiating.get_mut(&peer_id) {
                        if *kind == PeerKind::Dialer {
                            // Dialout fully negotiated...
                            *state = NegotiateState::Connected;
                            debug!(target: "stegos_network::gatekeeper", "dialer: fully negotiated node: {}", peer_id.to_base58());
                            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                GatekeeperOutEvent::Connected { peer_id },
                            ))
                        } else {
                            // Our side is fully initialized, send ack to the remote
                            *state = NegotiateState::Connected;
                            debug!(target: "stegos_network::gatekeeper", "listener: fully negotiated node: {}", peer_id.to_base58());
                            self.events.push_back(NetworkBehaviourAction::SendEvent {
                                peer_id: peer_id.clone(),
                                event: GatekeeperSendEvent::Send(GatekeeperMessage::Reply {
                                    conn_type: ConnectionType::FullNode,
                                    node_id: self.my_pkey.clone(),
                                    others: Vec::new(),
                                }),
                            });
                            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                GatekeeperOutEvent::Connected { peer_id },
                            ))
                        }
                    }
                }
            }
        }
        if let Some(event) = self.events.pop_front() {
            return Async::Ready(event);
        }

        Async::NotReady
    }
}

// to be extended?
#[derive(Debug)]
pub enum GatekeeperOutEvent {
    Message {
        peer_id: PeerId,
        message: GatekeeperMessage,
    },
    PrepareDialer {
        peer_id: PeerId,
    },
    PrepareListener {
        peer_id: PeerId,
    },
    Connected {
        peer_id: PeerId,
    },
    Disconnected {
        peer_id: PeerId,
    },
}

#[derive(Debug)]
pub enum ProtocolUpdateEvent {
    EnabledListener,
    EnabledDialer,
}

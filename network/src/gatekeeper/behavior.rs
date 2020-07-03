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

use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::prelude::*;
use futures::task::{Context, Poll};
use libp2p_core::connection::ConnectionId;
use libp2p_core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
    protocols_handler::ProtocolsHandler, DialPeerCondition, NetworkBehaviour,
    NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use log::*;
use lru_time_cache::LruCache;
use rand::{seq::SliceRandom, thread_rng};
use std::cmp::max;
use std::error;
use std::time::{Duration, SystemTime};
use std::{
    collections::{HashSet, VecDeque},
    thread,
};
use stegos_crypto::vdf::VDF;

use super::handler::{GatekeeperHandler, GatekeeperSendEvent};
use super::protocol::{GatekeeperMessage, NetworkName, VDFProof};
use crate::config::NetworkConfig;
use crate::utils::{socket_to_multi_addr, ExpiringQueue, PeerIdKey};
use libp2p_core::multiaddr::Protocol;
use std::collections::HashMap;

use super::protocol::Metadata;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

// How long to wait for remote peer to connect
const HASH_CASH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
// How long proof/puzzle are considered valid
const HASH_CASH_PROOF_TTL: Duration = Duration::from_secs(365 * 24 * 60 * 60);
// How long to wait for next event
const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Network behavior to handle initial nodes handshake
pub struct Gatekeeper {
    /// My metadata
    my_metadata: Metadata,
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>>,
    /// List of connected peers
    connected_peers: HashSet<PeerId>,
    /// Peers we should be connected to
    desired_peers: HashSet<PeerId>,
    /// Addresses we are trying to keep connected to
    desired_addesses: HashSet<Multiaddr>,
    /// Peers we are trying to negotiate with
    pending_out_peers: ExpiringQueue<PeerId, DialerPeerState>,
    /// Incoming peers tring to negotiate with us
    pending_in_peers: ExpiringQueue<PeerId, ListenerPeerState>,
    /// Unlocked peers (passed VDF handshake)
    unlocked_peers: LruCache<PeerIdKey, ()>,
    /// Upstream events when Dialer/Listeners are ready
    protocol_updates: VecDeque<PeerEvent>,
    /// Channel used to send solutions for VDF puzzles
    solution_sink: UnboundedSender<Solution>,
    /// Output channel with VDF proofs
    solution_stream: UnboundedReceiver<Solution>,
    /// Solvers - set of currently running solvers
    solvers: HashSet<PeerId>,
    /// Number of allowed solvers threads (max(num_vpus-2, 1))
    solver_threads: usize,
    /// VDF challenges geneated by us
    our_challenges: LruCache<PeerIdKey, VDFChallenge>,
    /// Incoming solved Challenges
    solved_vdfs: LruCache<PeerIdKey, (VDFChallenge, Option<Vec<u8>>)>,
    /// Queue of VDF challenges from remote peers, waiting to be solved
    challenges_queue: VecDeque<PeerId>,
    /// VDF complexity
    hanshake_puzzle_difficulty: u64,
    /// Netwrok readyness threshold
    readiness_threshold: usize,

    // Back connect feature
    /// List of addresses resolved from peer.
    peers_addresses: HashMap<PeerId, Vec<Ipv4Addr>>,
    /// Reported metadata by peer.
    peers_metadata: HashMap<PeerId, Metadata>,
}

impl Gatekeeper {
    /// Creates a NetworkBehaviour for Gatekeeper.
    pub fn new(config: &NetworkConfig, metadata: Metadata) -> Self {
        let mut desired_addesses: HashSet<Multiaddr> = HashSet::new();
        let events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>> =
            VecDeque::new();

        // Randomize seed nodes array
        let mut rng = thread_rng();
        let mut addrs = config.seed_nodes.clone();
        addrs.shuffle(&mut rng);

        for addr in addrs.iter() {
            let addr = addr.parse::<SocketAddr>().expect("Invalid seed_node");
            let addr = socket_to_multi_addr(&addr);
            // debug!(target: "stegos_network::gatekeeper", "dialing peer with address {}", addr);
            // events.push_back(NetworkBehaviourAction::DialAddress {
            //     address: addr.clone(),
            // });
            desired_addesses.insert(addr);
        }

        let (solution_sink, solution_stream) = unbounded::<Solution>();
        let solver_threads = max(num_cpus::get() - 2, 1);
        debug!(target: "stegos_network::gatekeeper", "number of VDF solver threads: {}", solver_threads);
        Gatekeeper {
            events,
            connected_peers: HashSet::new(),
            desired_peers: HashSet::new(),
            desired_addesses,
            pending_out_peers: ExpiringQueue::new(HANDSHAKE_STEP_TIMEOUT),
            pending_in_peers: ExpiringQueue::new(HANDSHAKE_STEP_TIMEOUT),
            unlocked_peers: LruCache::<PeerIdKey, ()>::with_expiry_duration(HASH_CASH_PROOF_TTL),
            our_challenges: LruCache::<PeerIdKey, VDFChallenge>::with_expiry_duration(
                HASH_CASH_TIMEOUT,
            ),
            solved_vdfs:
                LruCache::<PeerIdKey, (VDFChallenge, Option<Vec<u8>>)>::with_expiry_duration(
                    HASH_CASH_PROOF_TTL,
                ),
            protocol_updates: VecDeque::new(),
            solution_sink,
            solution_stream,
            solvers: HashSet::new(),
            solver_threads,
            challenges_queue: VecDeque::new(),
            hanshake_puzzle_difficulty: config.hanshake_puzzle_difficulty,
            readiness_threshold: config.readiness_threshold,
            peers_addresses: HashMap::new(),
            peers_metadata: HashMap::new(),
            my_metadata: metadata,
        }
    }

    pub fn is_network_ready(&self) -> bool {
        self.unlocked_peers.len() >= self.readiness_threshold
    }

    pub fn dial_peer(&mut self, peer_id: PeerId) {
        self.desired_peers.insert(peer_id.clone());
        self.events.push_back(NetworkBehaviourAction::DialPeer {
            peer_id,
            condition: DialPeerCondition::Disconnected,
        });
    }

    pub fn dial_address(&mut self, address: Multiaddr) {
        self.desired_addesses.insert(address.clone());
        self.events
            .push_back(NetworkBehaviourAction::DialAddress { address });
    }

    pub fn enable_dialer(&mut self, peer_id: PeerId) {
        if self.pending_in_peers.contains_key(&peer_id) {
            self.pending_in_peers.remove(&peer_id);

            debug!(target: "stegos_network::gatekeeper", "dialer enabled, sending permit reply: peer_id={}", peer_id);
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::Any,
                    event: GatekeeperSendEvent::Send(GatekeeperMessage::PermitReply {
                        connection_allowed: true,
                        reason: String::new(),
                    }),
                });
        } else {
            debug!(target: "stegos_network::gatekeeper", "dialer enabled, peer fully negotiated: peer_id={}", peer_id);
            self.pending_out_peers.remove(&peer_id);
        }
    }

    pub fn enable_listener(&mut self, peer_id: PeerId) {
        let challenge = self.solved_vdfs.get(&peer_id.clone().into());
        let proof = match challenge {
            Some((p, Some(proof))) => Some(VDFProof {
                challenge: p.challenge.clone(),
                difficulty: p.difficulty,
                proof: proof.clone(),
            }),
            Some((_, None)) => None,
            None => None,
        };
        debug!(target: "stegos_network::gatekeeper", "listener enabled, sending unlock request: peer_id={}, with_proof={}", peer_id, proof.is_some());
        self.pending_out_peers
            .insert(peer_id.clone(), DialerPeerState::UnlockRequestSent);
        self.events
            .push_back(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: GatekeeperSendEvent::Send(GatekeeperMessage::UnlockRequest {
                    proof,
                    metadata: self.my_metadata.clone().into(),
                }),
            })
    }

    fn send_new_challenge(&mut self, peer_id: PeerId) {
        let challenge = generate_challenge(&peer_id);
        self.our_challenges.insert(
            peer_id.clone().into(),
            VDFChallenge {
                challenge: challenge.clone(),
                difficulty: self.hanshake_puzzle_difficulty,
            },
        );
        self.pending_in_peers
            .insert(peer_id.clone(), ListenerPeerState::WaitingProof);
        self.events
            .push_back(NetworkBehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: GatekeeperSendEvent::Send(GatekeeperMessage::ChallengeReply {
                    challenge,
                    difficulty: self.hanshake_puzzle_difficulty,
                    metadata: Some(self.my_metadata.clone()),
                }),
            })
    }

    // Returns true if we this is second phase of back-connect.
    fn back_connect(&mut self, peer_id: PeerId) -> Option<bool> {
        if let Some(ListenerPeerState::PublicIpResolving) = self.pending_in_peers.get(&peer_id) {
            return Some(true);
        }

        let addresses = self.peers_addresses.get(&peer_id)?;
        let metadata = self.peers_metadata.get(&peer_id)?;
        if metadata.port == 0 {
            return None;
        }
        for addr in addresses {
            //TODO: Add waiting list.
            let mut multiaddr = Multiaddr::empty();
            multiaddr.push(Protocol::Ip4(*addr));
            multiaddr.push(Protocol::Tcp(metadata.port));
            debug!(target: "stegos_network::gatekeeper", "trying to back-connect: peer_id={}, addr={}", peer_id, multiaddr);
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: peer_id.clone(),
                    handler: NotifyHandler::Any,
                    event: GatekeeperSendEvent::Send(GatekeeperMessage::PermitReply {
                        connection_allowed: false,
                        reason: String::from("Trying to back-connect, only public topics allowed."),
                    }),
                });
            self.events
                .push_back(NetworkBehaviourAction::DialAddress { address: multiaddr });
        }
        self.pending_in_peers
            .insert(peer_id, ListenerPeerState::PublicIpResolving);
        Some(false)
    }

    fn handle_unlock_request(&mut self, peer_id: PeerId, proof: Option<VDFProof>) {
        let peer_version = self
            .peers_metadata
            .get(&peer_id)
            .map(|m| m.version)
            .unwrap_or_default();

        if self.unlocked_peers.contains_key(&peer_id.clone().into()) {
            debug!(target: "stegos_network::gatekeeper", "unlock request from already unlocked peer: peer_id={}", peer_id);
            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);

            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer {
                    peer_id,
                    version: peer_version,
                },
            ));
            return;
        }

        if self.pending_out_peers.contains_key(&peer_id) {
            debug!(target: "stegos_network::gatekeeper", "unlock request from the peer we are interested in, let in without puzzle solving: peer_id={}", peer_id);
            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);
            self.unlocked_peers.insert(peer_id.clone().into(), ());

            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer {
                    peer_id,
                    version: peer_version,
                },
            ));
            return;
        }

        let proof = match proof {
            Some(p) => p,
            None => {
                debug!(target: "stegos_network::gatekeeper", "unlock request without proof: peer_id={}", peer_id);
                self.send_new_challenge(peer_id);
                return;
            }
        };

        let challenge = match self.our_challenges.get(&peer_id.clone().into()) {
            Some(p) => p,
            None => {
                debug!(target: "stegos_network::gatekeeper", "unlock request with proof, but no puzzle, sending new puzzle: peer_id={}", peer_id);
                self.send_new_challenge(peer_id);
                return;
            }
        };

        if proof.challenge == challenge.challenge
            && proof.difficulty == challenge.difficulty
            && local_check_proof(&proof, challenge.difficulty)
        {
            match self.back_connect(peer_id.clone()) {
                Some(true) => {}
                Some(false) => {
                    trace!(target: "stegos_network::gatekeeper", "peer support back-connect, postpone unlock, peer_id={}", peer_id);
                    return;
                }
                None => {
                    let ban = !cfg!(feature = "old_protos");
                    info!(target: "stegos_network::gatekeeper", "Skiped back connect procedure, not enough info for peer found. Maybe peer version is old, peer_id={}, banning={}", peer_id, ban);
                    if ban {
                        self.events
                            .push_back(NetworkBehaviourAction::NotifyHandler {
                                peer_id: peer_id.clone(),
                                handler: NotifyHandler::Any,
                                event: GatekeeperSendEvent::Send(GatekeeperMessage::PermitReply {
                                    connection_allowed: false,
                                    reason: String::from("Old protos is not supported."),
                                }),
                            });
                        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                            GatekeeperOutEvent::BanPeer { peer_id },
                        ));
                        return;
                    };
                }
            }

            self.unlocked_peers.insert(peer_id.clone().into(), ());
            debug!(target: "stegos_network::gatekeeper", "unlock request with valid proof, peer_id={}", peer_id);

            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);

            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer {
                    peer_id,
                    version: peer_version,
                },
            ));

            if self.unlocked_peers.len() >= self.readiness_threshold {
                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                    GatekeeperOutEvent::NetworkReady,
                ));
            }
        } else {
            debug!(target: "stegos_network::gatekeeper", "unlock request with invalid proof, sending new puzzle: peer_id={}", peer_id);
            self.send_new_challenge(peer_id);
        }
    }
    fn register_metadata(&mut self, peer_id: PeerId, metadata: Option<Metadata>) {
        let network = metadata
            .as_ref()
            .map(|metadata| metadata.network.clone())
            .unwrap_or_else(|| NetworkName::Mainnet.to_string());
        if let Some(metadata) = metadata {
            debug!(target: "stegos_network::gatekeeper", "Resolved metadata for peer: peer_id={}, metadata={:?}", peer_id, metadata);
            self.peers_metadata.insert(peer_id.clone(), metadata);
        }
        if network != self.my_metadata.network {
            warn!(target: "stegos_network::gatekeeper", "Peer network not equal to our: peer_id={}, our_network={}, peer_network={}",
            peer_id,
                self.my_metadata.network,
                network
            );
            self.events
                .push_back(NetworkBehaviourAction::NotifyHandler {
                    peer_id: peer_id.clone(),
                    handler: NotifyHandler::Any,
                    event: GatekeeperSendEvent::Send(GatekeeperMessage::PermitReply {
                        connection_allowed: false,
                        reason: format!(
                            "Network is different from other, expected={}, got={}.",
                            self.my_metadata.network, network
                        ),
                    }),
                });
            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::BanPeer { peer_id },
            ));
            return;
        }
    }

    fn handle_challenge_reply(
        &mut self,
        peer_id: PeerId,
        challenge: Vec<u8>,
        difficulty: u64,
        metadata: Option<Metadata>,
        _cid: ConnectionId,
    ) {
        debug!(target: "stegos_network::gatekeeper", "received challenge: peer_id={}", peer_id);
        if !self.pending_out_peers.contains_key(&peer_id) {
            debug!(target: "stegos_network::gatekeeper", "challenge from peer we are not going to connect to, ignoring: peer_id={}", peer_id);
            return;
        }
        self.register_metadata(peer_id.clone(), metadata);

        let challenge = VDFChallenge {
            challenge,
            difficulty,
        };
        if let Some(p) = self.solved_vdfs.get(&peer_id.clone().into()) {
            if p.0.challenge == challenge.challenge && p.1.is_some() {
                // Already solved this puzzle
                let proof = VDFProof {
                    challenge: p.0.challenge.clone(),
                    difficulty: p.0.difficulty,
                    proof: p.1.clone().expect("Checked for Some earlier"),
                };
                self.events
                    .push_back(NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer_id.clone(),
                        handler: NotifyHandler::Any,
                        event: GatekeeperSendEvent::Send(GatekeeperMessage::UnlockRequest {
                            proof: Some(proof),
                            metadata: self.my_metadata.clone().into(),
                        }),
                    });
                self.pending_out_peers
                    .insert(peer_id, DialerPeerState::UnlockRequestSent);
                return;
            }
        }
        self.solved_vdfs
            .insert(peer_id.clone().into(), (challenge, None));
        self.pending_out_peers
            .insert(peer_id.clone(), DialerPeerState::SolvingVDF);
        // put peer into the queue to be solved.
        self.challenges_queue.push_back(peer_id);
    }
}

impl NetworkBehaviour for Gatekeeper {
    type ProtocolsHandler = GatekeeperHandler;
    type OutEvent = GatekeeperOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        GatekeeperHandler::new()
    }

    fn addresses_of_peer(&mut self, _peer: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _id: &PeerId) {}

    fn inject_connection_established(
        &mut self,
        id: &PeerId,
        cid: &ConnectionId,
        cp: &ConnectedPoint,
    ) {
        self.connected_peers.insert(id.clone());
        debug!(target: "stegos_network::gatekeeper", "peer connected: peer_id={}, endpoint={}", id, cp.display());
        // FIXME: use LRU cache for dialing addresses/peers
        match cp {
            ConnectedPoint::Dialer { address } => {
                if self.desired_addesses.contains(&address) {
                    self.desired_peers.insert(id.clone());
                }
                if let Some(ListenerPeerState::PublicIpResolving) = self.pending_in_peers.get(id) {
                    debug!(target: "stegos_network::gatekeeper", "back-connected to peer: peer_id={}, endpoint={}", id, cp.display());
                    self.events
                        .push_back(NetworkBehaviourAction::NotifyHandler {
                            peer_id: id.clone(),
                            handler: NotifyHandler::One(*cid),
                            event: GatekeeperSendEvent::Send(GatekeeperMessage::PublicIpUnlock {}),
                        });
                    return;
                }

                self.pending_out_peers
                    .insert(id.clone(), DialerPeerState::Connected);

                if self.desired_peers.contains(id) {
                    self.protocol_updates.push_back(PeerEvent::ConnectedToPeer {
                        peer_id: id.clone(),
                    });
                }
            }
            ConnectedPoint::Listener { send_back_addr, .. } => {
                let peer_entry = self
                    .peers_addresses
                    .entry(id.clone())
                    .or_insert_with(Vec::new);
                for addr in send_back_addr.iter() {
                    match addr {
                        Protocol::Ip4(addr) => {
                            debug!(target: "stegos_network::gatekeeper", "Resolved peer address: peer_id={} addr={}", id, addr);
                            peer_entry.push(addr)
                        }
                        Protocol::Tcp(_) => {} // ignore port
                        addr => {
                            warn!(target: "stegos_network::gatekeeper", "Not supported address {}", addr);
                        }
                    }
                }

                if let Some(DialerPeerState::UnlockRequestSent) = self.pending_out_peers.get(&id) {
                    debug!(target: "stegos_network::gatekeeper", "Detected back-connect of peer, wait for request: peer_id={}", id);
                    return;
                }

                self.protocol_updates.push_back(PeerEvent::PeerConnected {
                    peer_id: id.clone(),
                });
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        _id: &PeerId,
        _: &ConnectionId,
        _endpoint: &ConnectedPoint,
    ) {
    }

    fn inject_disconnected(&mut self, id: &PeerId) {
        if self.desired_peers.contains(id) {
            debug!(target: "stegos_network::gatekeeper", "re-connecting to peer: peer_id={}", id);
            self.events.push_back(NetworkBehaviourAction::DialPeer {
                peer_id: id.clone(),
                condition: DialPeerCondition::Disconnected,
            });
        }

        debug!(target: "stegos_network::gatekeeper", "peer disconnected: peer_id={}", id);
        self.connected_peers.remove(id);
        self.pending_out_peers.remove(&id.clone());
        self.pending_in_peers.remove(&id.clone());
        self.peers_addresses.remove(id);
        self.peers_metadata.remove(id);
    }

    /// Indicates to the behaviour that we tried to reach an address, but failed.
    ///
    /// If we were trying to reach a specific node, its ID is passed as parameter. If this is the
    /// last address to attempt for the given node, then `inject_dial_failure` is called afterwards.
    fn inject_addr_reach_failure(
        &mut self,
        peer_id: Option<&PeerId>,
        addr: &Multiaddr,
        error: &dyn error::Error,
    ) {
        let peer_info = match peer_id {
            None => "None".to_string(),
            Some(p) => p.to_string(),
        };

        debug!(target: "stegos_network::gatekeeper", "failure reaching address: peer_id={}, addr={}, error={}", peer_info, addr, error);
    }

    /// Indicates to the behaviour that we tried to dial all the addresses known for a node, but
    /// failed.
    fn inject_dial_failure(&mut self, peer_id: &PeerId) {
        debug!(target: "stegos_network::gatekeeper", "failure reaching address: peer_id={}", peer_id);
    }

    fn inject_event(
        &mut self,
        propagation_source: PeerId,
        id: ConnectionId,
        event: GatekeeperMessage,
    ) {
        // Process received Gatekeeper message (passed from Handler as Custom(message))
        debug!(target: "stegos_network::gatekeeper", "Received a message: {:?}", event);
        match event {
            GatekeeperMessage::UnlockRequest { proof, metadata } => {
                self.register_metadata(propagation_source.clone(), metadata);
                self.handle_unlock_request(propagation_source, proof)
            }
            GatekeeperMessage::ChallengeReply {
                challenge,
                difficulty,
                metadata,
            } => {
                self.handle_challenge_reply(propagation_source, challenge, difficulty, metadata, id)
            }
            GatekeeperMessage::PermitReply {
                connection_allowed,
                reason,
            } => {
                if connection_allowed {
                    debug!(target: "stegos_network::gatekeeper", "succesfully negotiated VDF handshake: peer_id={}", propagation_source);
                    self.unlocked_peers
                        .insert(propagation_source.clone().into(), ());
                    self.pending_out_peers
                        .insert(propagation_source.clone(), DialerPeerState::WaitingDialer);
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::UnlockedDialer {
                            peer_id: propagation_source,
                        },
                    ));
                    if self.unlocked_peers.len() >= self.readiness_threshold {
                        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                            GatekeeperOutEvent::NetworkReady,
                        ));
                    }
                } else {
                    info!(target: "stegos_network::gatekeeper", "Received permit reply that disallow connection: peer_id={}, reason={}", propagation_source, reason);
                }
            }
            GatekeeperMessage::PublicIpUnlock {} => {
                // send last vdf again
                let challenge = self.solved_vdfs.get(&propagation_source.clone().into());
                let proof = match challenge {
                    Some((p, Some(proof))) => Some(VDFProof {
                        challenge: p.challenge.clone(),
                        difficulty: p.difficulty,
                        proof: proof.clone(),
                    }),
                    Some((_, None)) => None,
                    None => None,
                };
                self.events
                    .push_back(NetworkBehaviourAction::NotifyHandler {
                        peer_id: propagation_source,
                        handler: NotifyHandler::Any,
                        event: GatekeeperSendEvent::Send(GatekeeperMessage::UnlockRequest {
                            proof,
                            metadata: self.my_metadata.clone().into(),
                        }),
                    })
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _poll_parameters: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        match self.solution_stream.poll_next_unpin(cx) {
            Poll::Ready(Some((peer_id, proof, duration))) => {
                self.solvers.remove(&peer_id);
                debug!(target: "stegos_network::gatekeeper", "solved puzzle: peer_id={}, duration={}.{}sec", peer_id, duration.as_secs(), duration.subsec_millis());
                self.protocol_updates
                    .push_back(PeerEvent::VDFSolved { peer_id, proof });
            }
            Poll::Ready(None) => {
                debug!(target: "stegos_network::gatekeeper", "solution stream gone!");
            }
            Poll::Pending => {}
        }

        if self.solvers.len() < self.solver_threads && self.challenges_queue.is_empty() {
            loop {
                if self.challenges_queue.is_empty() {
                    break;
                }
                let peer_id = self.challenges_queue.pop_front().unwrap();
                if let Some(challenge) = self.solved_vdfs.get(&peer_id.clone().into()) {
                    debug!(target: "stegos_network::gatekeeper", "starting thread to solve puzzle: peer_id={}", peer_id);
                    let tx = self.solution_sink.clone();
                    let p = challenge.0.clone();
                    self.solvers.insert(peer_id.clone());
                    thread::spawn(move || {
                        let start = SystemTime::now();
                        let vdf = VDF::new();
                        info!("Solving a VDF puzzle: peer_id={:?}", peer_id);
                        let proof = vdf.solve(&p.challenge, p.difficulty);
                        info!("Solved a VDF puzzle: peer_id={:?}", peer_id);
                        if let Err(e) = tx.unbounded_send((
                            peer_id,
                            proof,
                            start.elapsed().expect("VDF always takes some time"),
                        )) {
                            debug!(target: "stegos_network::gatekeeper", "failed to send VDF proof to the channel: {}", e);
                        }
                    });
                    break;
                }
            }
        }

        if let Some(event) = self.protocol_updates.pop_front() {
            match event {
                PeerEvent::ConnectedToPeer { peer_id } => {
                    debug!(target: "stegos_network::gatekeeper", "peer is connected, enabling listener: peer_id={}", peer_id);
                    self.pending_out_peers
                        .insert(peer_id.clone(), DialerPeerState::WaitingListener);
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::PrepareListener { peer_id },
                    ))
                }
                PeerEvent::PeerConnected { peer_id } => {
                    debug!(target: "stegos_network::gatekeeper", "peer is connected to us, requesting proof: peer_id={}", peer_id);
                    self.send_new_challenge(peer_id);
                }
                PeerEvent::VDFSolved { peer_id, proof } => {
                    if let Some(mut challenge) = self.solved_vdfs.get_mut(&peer_id.clone().into()) {
                        debug!(target: "stegos_network::gatekeeper", "VDF solved, sending proof: peer_id={}", peer_id);
                        self.pending_out_peers
                            .insert(peer_id.clone(), DialerPeerState::UnlockRequestSent);
                        challenge.1 = Some(proof.clone());
                        let vdf_proof = VDFProof {
                            challenge: challenge.0.challenge.clone(),
                            difficulty: challenge.0.difficulty,
                            proof,
                        };
                        if self.connected_peers.contains(&peer_id) {
                            self.events
                                .push_back(NetworkBehaviourAction::NotifyHandler {
                                    peer_id,
                                    handler: NotifyHandler::Any,
                                    event: GatekeeperSendEvent::Send(
                                        GatekeeperMessage::UnlockRequest {
                                            proof: Some(vdf_proof),
                                            metadata: self.my_metadata.clone().into(),
                                        },
                                    ),
                                })
                        } else {
                            debug!(target: "stegos_network::gatekeeper", "peer already gone, trying to reconnect: peer_id={}", peer_id);
                            self.dial_peer(peer_id);
                        }
                    } else {
                        debug!(target: "stegos_network::gatekeeper", "got answer, but puzzle not found: peer_id={}", peer_id);
                    }
                }
            }
        }

        // Expire outbound peer negotiations
        loop {
            match self.pending_out_peers.poll(cx) {
                Poll::Ready(Ok(ref entry)) => {
                    debug!(target: "stegos_network::gatekeeper", "outgoing peer VDF expired: peer_id={}", entry.0);
                    // Do cleanup
                }
                Poll::Ready(Err(e)) => {
                    error!(target: "stegos_network::delivery", "dial_queue timer error: {}", e);
                    break;
                }
                Poll::Pending => break,
            }
        }
        // Expire inbound peers negotiations
        loop {
            match self.pending_in_peers.poll(cx) {
                Poll::Ready(Ok(ref entry)) => {
                    debug!(target: "stegos_network::gatekeeper", "incoming peer VDF expired: peer_id={}", entry.0);
                    // Do cleanup
                }
                Poll::Ready(Err(e)) => {
                    error!(target: "stegos_network::delivery", "dial_queue timer error: {}", e);
                    break;
                }
                Poll::Pending => break,
            }
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

fn local_check_proof(proof: &VDFProof, difficulty: u64) -> bool {
    let vdf = VDF::new();
    if vdf
        .verify(&proof.challenge, difficulty, &proof.proof)
        .is_err()
    {
        return false;
    }
    true
}

fn generate_challenge(_peer_id: &PeerId) -> Vec<u8> {
    (0..256).map(|_| rand::random::<u8>()).collect::<Vec<_>>()
}

// to be extended?
#[derive(Debug)]
pub enum GatekeeperOutEvent {
    PrepareDialer { peer_id: PeerId, version: u64 },
    PrepareListener { peer_id: PeerId },
    UnlockedDialer { peer_id: PeerId },
    BanPeer { peer_id: PeerId },
    NetworkReady,
}

type Solution = (PeerId, Vec<u8>, Duration);

#[derive(Clone)]
struct VDFChallenge {
    challenge: Vec<u8>,
    difficulty: u64,
}

pub enum PeerEvent {
    ConnectedToPeer { peer_id: PeerId },
    PeerConnected { peer_id: PeerId },
    VDFSolved { peer_id: PeerId, proof: Vec<u8> },
}

pub enum DialerPeerState {
    Connected,
    WaitingListener,
    SolvingVDF,
    UnlockRequestSent,
    WaitingDialer,
}

pub enum ListenerPeerState {
    WaitingDialer,
    WaitingProof,
    PublicIpResolving,
}

// Trait for debugging external types
trait StegosDisplay {
    fn display(&self) -> String;
}

impl StegosDisplay for ConnectedPoint {
    fn display(&self) -> String {
        match self {
            ConnectedPoint::Dialer { address } => format!("Dialer({})", address),
            ConnectedPoint::Listener {
                local_addr,
                send_back_addr,
            } => format!("Listener(listen={},advert={}", local_addr, send_back_addr),
        }
    }
}

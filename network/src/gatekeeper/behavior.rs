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
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use libp2p::core::{
    protocols_handler::ProtocolsHandler,
    swarm::{ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters},
    Multiaddr, PeerId,
};
use log::*;
use lru_time_cache::LruCache;
use rand::{seq::SliceRandom, thread_rng};
use std::time::{Duration, SystemTime};
use std::{
    collections::{HashSet, VecDeque},
    marker::PhantomData,
    thread,
};
use stegos_crypto::hashcash::{self, HashCashProof};
use tokio::io::{AsyncRead, AsyncWrite};

use super::handler::{GatekeeperHandler, GatekeeperSendEvent};
use super::protocol::GatekeeperMessage;
use crate::config::NetworkConfig;
use crate::utils::{ExpiringQueue, PeerIdKey};

// Dialout timeout
const DIAL_TIMEOUT: Duration = Duration::from_secs(60);
// How long to wait for remote peer to connect
const HASH_CASH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
// How long proof/puzzle are considered valid
const HASH_CASH_PROOF_TTL: Duration = Duration::from_secs(365 * 24 * 60 * 60);
// How long to wait for next event
const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(30);
// Nuber of concurrent solver threads
const SOLVER_THREADS: usize = 4;
// Unlocked peers threshold (how many peers should be unlock to treat network as ready)
const NETWORK_READY_THRESHOLD: usize = 2;

/// Network behavior to handle initial nodes handshake
pub struct Gatekeeper<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>>,
    /// List of connected peers
    connected_peers: HashSet<PeerId>,
    /// Peers we are trying to connect to
    connecting_peers: HashSet<PeerId>,
    /// Addresses we are trying to connect to
    connecting_addresses: HashSet<Multiaddr>,
    /// Peers we are trying to negotiate with
    pending_out_peers: ExpiringQueue<PeerId, DialerPeerState>,
    /// Incoming peers tring to negotiate with us
    pending_in_peers: ExpiringQueue<PeerId, ListenerPeerState>,
    /// Unlocked peers (passed HashCash handshake)
    unlocked_peers: LruCache<PeerIdKey, ()>,
    /// HshCash puzzle geneated by us
    our_puzzles: LruCache<PeerIdKey, HashCashPuzzle>,
    /// Incommming puzzles (with solutions)
    input_puzzles: LruCache<PeerIdKey, (HashCashPuzzle, Option<i64>)>,
    /// Upstream events when Dialer/Listeners are ready
    protocol_updates: VecDeque<PeerEvent>,
    /// Channel used to send solutions for HashCash puzzles
    solution_sink: UnboundedSender<Solution>,
    /// Output channel with HashCash solutions
    solution_stream: UnboundedReceiver<Solution>,
    /// Solvers - set of currently running solvers
    solvers: HashSet<PeerId>,
    /// Queue of puzzles, waiting to be solved
    puzzles_queue: VecDeque<PeerId>,
    /// Hashcash complexity
    hashcash_nbits: usize,
    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Gatekeeper<TSubstream> {
    /// Creates a NetworkBehaviour for Gatekeeper.
    pub fn new(config: &NetworkConfig) -> Self {
        let mut connecting_addresses: HashSet<Multiaddr> = HashSet::new();
        let mut events: VecDeque<NetworkBehaviourAction<GatekeeperSendEvent, GatekeeperOutEvent>> =
            VecDeque::new();

        // Randomize seed nodes array
        let mut rng = thread_rng();
        let mut addrs = config.seed_nodes.clone();
        addrs.shuffle(&mut rng);

        for addr in addrs.iter() {
            debug!(target: "stegos_network::gatekeeper", "dialing peer with address {}", addr);
            match addr.parse::<Multiaddr>() {
                Ok(maddr) => {
                    events.push_back(NetworkBehaviourAction::DialAddress {
                        address: maddr.clone(),
                    });
                    connecting_addresses.insert(maddr);
                }
                Err(e) => {
                    error!(target: "stegos_network::gatekeeper", "failed to parse address: {}, error: {}", addr, e)
                }
            }
        }

        let (solution_sink, solution_stream) = unbounded::<Solution>();

        Gatekeeper {
            events,
            connected_peers: HashSet::new(),
            connecting_peers: HashSet::new(),
            connecting_addresses,
            pending_out_peers: ExpiringQueue::new(HANDSHAKE_STEP_TIMEOUT),
            pending_in_peers: ExpiringQueue::new(HANDSHAKE_STEP_TIMEOUT),
            unlocked_peers: LruCache::<PeerIdKey, ()>::with_expiry_duration(HASH_CASH_PROOF_TTL),
            our_puzzles: LruCache::<PeerIdKey, HashCashPuzzle>::with_expiry_duration(
                HASH_CASH_PROOF_TTL,
            ),
            input_puzzles:
                LruCache::<PeerIdKey, (HashCashPuzzle, Option<i64>)>::with_expiry_duration(
                    HASH_CASH_PROOF_TTL,
                ),
            protocol_updates: VecDeque::new(),
            solution_sink,
            solution_stream,
            solvers: HashSet::new(),
            puzzles_queue: VecDeque::new(),
            hashcash_nbits: config.hashcash_nbits,
            marker: PhantomData,
        }
    }

    pub fn is_network_ready(&self) -> bool {
        self.unlocked_peers.len() >= NETWORK_READY_THRESHOLD
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

    pub fn notify(&mut self, event: PeerEvent) {
        self.protocol_updates.push_back(event);
    }

    fn send_new_puzlle(&mut self, peer_id: PeerId) {
        let seed = generate_puzzle(&peer_id);
        self.our_puzzles.insert(
            peer_id.clone().into(),
            HashCashPuzzle {
                seed: seed.clone(),
                nbits: self.hashcash_nbits,
            },
        );
        self.pending_in_peers
            .insert(peer_id.clone(), ListenerPeerState::WaitingProof);
        self.events.push_back(NetworkBehaviourAction::SendEvent {
            peer_id,
            event: GatekeeperSendEvent::Send(GatekeeperMessage::ChallengeReply {
                seed,
                nbits: self.hashcash_nbits,
            }),
        })
    }

    fn handle_unlock_request(&mut self, peer_id: PeerId, proof: Option<HashCashProof>) {
        if self.unlocked_peers.contains_key(&peer_id.clone().into()) {
            debug!(target: "stegos_network::gatekeeper", "unlock request from already unlocked peer: peer_id={}", peer_id.to_base58());
            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);
            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer { peer_id },
            ));
            return;
        }

        if self.pending_out_peers.contains_key(&peer_id) {
            debug!(target: "stegos_network::gatekeeper", "unlock request from the peer we are interested in, let in without puzzle solving: peer_id={}", peer_id.to_base58());
            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);
            self.unlocked_peers.insert(peer_id.clone().into(), ());
            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer { peer_id },
            ));
            return;
        }

        let proof = match proof {
            Some(p) => p,
            None => {
                debug!(target: "stegos_network::gatekeeper", "unlock request without proof: peer_id={}", peer_id.to_base58());
                self.send_new_puzlle(peer_id);
                return;
            }
        };

        let puzzle = match self.our_puzzles.get(&peer_id.clone().into()) {
            Some(p) => p,
            None => {
                debug!(target: "stegos_network::gatekeeper", "unlock request with proof, but no puzzle, sending new puzzle: peer_id={}", peer_id.to_base58());
                self.send_new_puzlle(peer_id);
                return;
            }
        };

        if proof.seed == puzzle.seed
            && proof.nbits == puzzle.nbits
            && local_check_proof(&proof, self.hashcash_nbits)
        {
            debug!(target: "stegos_network::gatekeeper", "unlock request with valid proof, peer_id={}", peer_id.to_base58());
            self.unlocked_peers.insert(peer_id.clone().into(), ());
            self.pending_in_peers
                .insert(peer_id.clone(), ListenerPeerState::WaitingDialer);
            self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                GatekeeperOutEvent::PrepareDialer { peer_id },
            ));
            if self.unlocked_peers.len() >= NETWORK_READY_THRESHOLD {
                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                    GatekeeperOutEvent::NetworkReady,
                ));
            }
        } else {
            debug!(target: "stegos_network::gatekeeper", "unlock request with invalid proof, sending new puzzle: peer_id={}", peer_id.to_base58());
            self.send_new_puzlle(peer_id);
        }
    }

    fn handle_challenge_reply(&mut self, peer_id: PeerId, seed: Vec<u8>, nbits: usize) {
        debug!(target: "stegos_network::gatekeeper", "received puzzle: peer_id={}", peer_id.to_base58());
        if !self.pending_out_peers.contains_key(&peer_id) {
            debug!(target: "stegos_network::gatekeeper", "puzzle from peer we are not going to connect to, ignoring: peer_id={}", peer_id.to_base58());
            return;
        }
        let puzzle = HashCashPuzzle {
            seed: seed.clone(),
            nbits,
        };
        if let Some(p) = self.input_puzzles.get(&peer_id.clone().into()) {
            if p.0.seed == seed && p.1.is_some() {
                // Already solved this puzzle
                let proof = HashCashProof {
                    seed: p.0.seed.clone(),
                    nbits: p.0.nbits,
                    count: p.1.expect("checked for Some earlier"),
                };
                self.events.push_back(NetworkBehaviourAction::SendEvent {
                    peer_id: peer_id.clone(),
                    event: GatekeeperSendEvent::Send(GatekeeperMessage::UnlockRequest {
                        proof: Some(proof),
                    }),
                });
                self.pending_out_peers
                    .insert(peer_id, DialerPeerState::UnlockRequestSent);
                return;
            }
        }
        self.input_puzzles
            .insert(peer_id.clone().into(), (puzzle.clone(), None));
        self.pending_out_peers
            .insert(peer_id.clone(), DialerPeerState::SolvingPuzzle);
        // put peer into the queue to be solved.
        self.puzzles_queue.push_back(peer_id);
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
        // FIXME: use LRU cache for dialing addresses/peers
        if let ConnectedPoint::Dialer { address } = cp {
            if self.connecting_addresses.contains(&address) {
                self.connecting_peers.contains(&id);
                self.pending_out_peers
                    .insert(id.clone().into(), DialerPeerState::Connected);
                self.protocol_updates
                    .push_back(PeerEvent::Connected { peer_id: id });
                return;
            }
        }

        if self.connecting_peers.contains(&id) {
            self.pending_out_peers
                .insert(id.clone().into(), DialerPeerState::Connected);
            self.protocol_updates
                .push_back(PeerEvent::Connected { peer_id: id });
        }
    }

    fn inject_disconnected(&mut self, id: &PeerId, _cp: ConnectedPoint) {
        debug!(target: "stegos_network::gatekeeper", "peer disconnected: peer_id={}", id.to_base58());
        self.connected_peers.remove(id);
        self.pending_out_peers.remove(&id.clone().into());
        self.pending_in_peers.remove(&id.clone().into());
        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
            GatekeeperOutEvent::Disconnected {
                peer_id: id.clone(),
            },
        ));
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: GatekeeperMessage) {
        // Process received Gatekeeper message (passed from Handler as Custom(message))
        debug!(target: "stegos_network::gatekeeper", "Received a message: {:?}", event);
        match event {
            GatekeeperMessage::UnlockRequest { proof } => {
                self.handle_unlock_request(propagation_source, proof)
            }
            GatekeeperMessage::ChallengeReply { seed, nbits } => {
                self.handle_challenge_reply(propagation_source, seed, nbits)
            }
            GatekeeperMessage::PermitReply { connection_allowed } => {
                if connection_allowed {
                    debug!(target: "stegos_network::gatekeeper", "succesfully negotiated hashcash: peer_id={}", propagation_source.to_base58());
                    self.unlocked_peers
                        .insert(propagation_source.clone().into(), ());
                    self.pending_out_peers
                        .insert(propagation_source.clone(), DialerPeerState::WaitingDialer);
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::Finished {
                            peer_id: propagation_source,
                        },
                    ));
                    if self.unlocked_peers.len() >= NETWORK_READY_THRESHOLD {
                        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                            GatekeeperOutEvent::NetworkReady,
                        ));
                    }
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
        match self.solution_stream.poll() {
            Ok(Async::Ready(Some((peer_id, proof, duration)))) => {
                debug!(target: "stegos_network::gatekeeper", "solved puzzle: peer_id={}, duration={}.{}sec", peer_id.to_base58(), duration.as_secs(), duration.subsec_millis());
                self.solvers.remove(&peer_id);
                self.protocol_updates.push_back(PeerEvent::PuzzleSolved {
                    peer_id: peer_id.clone(),
                    answer: proof.count,
                });
            }
            Ok(Async::Ready(None)) => {
                debug!(target: "stegos_network::gatekeeper", "solution stream gone!");
            }
            Ok(Async::NotReady) => {}
            Err(_e) => {
                debug!(target: "stegos_network::gatekeeper", "error pollion solution_stream channel!");
            }
        }

        if self.solvers.len() < SOLVER_THREADS && self.puzzles_queue.len() > 0 {
            loop {
                if self.puzzles_queue.is_empty() {
                    break;
                }
                let peer_id = self.puzzles_queue.pop_front().unwrap();
                if let Some(puzzle) = self.input_puzzles.get(&peer_id.clone().into()) {
                    debug!(target: "stegos_network::gatekeeper", "starting thread to solve puzzle: peer_id={}", peer_id.to_base58());
                    let tx = self.solution_sink.clone();
                    let p = puzzle.0.clone();
                    let peer_id = peer_id.clone();
                    self.solvers.insert(peer_id.clone());
                    thread::spawn(move || {
                        let start = SystemTime::now();
                        info!("Solving a hashcash puzzle: peer_id={:?}", peer_id);
                        let proof = hashcash::delay(p.nbits, &p.seed);
                        info!("Solved a hashcash puzzle: peer_id={:?}", peer_id);
                        if let Err(e) = tx.unbounded_send((
                            peer_id,
                            proof,
                            start.elapsed().expect("hashcash always takes some time"),
                        )) {
                            debug!(target: "stegos_network::gatekeeper", "failed to send hashcash solution to the channel: {}", e);
                        }
                    });
                    break;
                }
            }
        }

        if let Some(event) = self.protocol_updates.pop_front() {
            match event {
                PeerEvent::Connected { peer_id } => {
                    debug!(target: "stegos_network::gatekeeper", "peer is connected, enabling listener: peer_id={}", peer_id.to_base58());
                    self.pending_out_peers
                        .insert(peer_id.clone().into(), DialerPeerState::WaitingListener);
                    self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                        GatekeeperOutEvent::PrepareListener { peer_id },
                    ))
                }
                PeerEvent::EnabledListener { peer_id } => {
                    let puzzle = self.input_puzzles.get(&peer_id.clone().into()).clone();
                    let proof = match puzzle {
                        Some((p, Some(count))) => Some(HashCashProof {
                            seed: p.seed.clone(),
                            nbits: p.nbits,
                            count: *count,
                        }),
                        Some((_, None)) => None,
                        None => None,
                    };
                    debug!(target: "stegos_network::gatekeeper", "listener enabled, sending unlock request: peer_id={}, with_proof={}", peer_id.to_base58(), proof.is_some());
                    self.pending_out_peers
                        .insert(peer_id.clone().into(), DialerPeerState::UnlockRequestSent);
                    self.events.push_back(NetworkBehaviourAction::SendEvent {
                        peer_id,
                        event: GatekeeperSendEvent::Send(GatekeeperMessage::UnlockRequest {
                            proof,
                        }),
                    })
                }
                PeerEvent::EnabledDialer { peer_id } => {
                    if self.pending_in_peers.contains_key(&peer_id) {
                        debug!(target: "stegos_network::gatekeeper", "dialer enabled, sending permit reply: peer_id={}", peer_id.to_base58());
                        self.pending_in_peers.remove(&peer_id);
                        self.events.push_back(NetworkBehaviourAction::SendEvent {
                            peer_id,
                            event: GatekeeperSendEvent::Send(GatekeeperMessage::PermitReply {
                                connection_allowed: true,
                            }),
                        });
                    } else {
                        debug!(target: "stegos_network::gatekeeper", "dialer enabled, peer fully negotiated: peer_id={}", peer_id.to_base58());
                        self.pending_out_peers.remove(&peer_id);
                    }
                }
                PeerEvent::PuzzleSolved { peer_id, answer } => {
                    if let Some(mut puzzle) = self.input_puzzles.get_mut(&peer_id.clone().into()) {
                        debug!(target: "stegos_network::gatekeeper", "puzzle solved, sending proof: peer_id={}", peer_id.to_base58());
                        self.pending_out_peers
                            .insert(peer_id.clone().into(), DialerPeerState::ProofSent);
                        puzzle.1 = Some(answer);
                        let proof = HashCashProof {
                            seed: puzzle.0.seed.clone(),
                            nbits: puzzle.0.nbits,
                            count: answer,
                        };
                        if self.connected_peers.contains(&peer_id) {
                            self.events.push_back(NetworkBehaviourAction::SendEvent {
                                peer_id,
                                event: GatekeeperSendEvent::Send(
                                    GatekeeperMessage::UnlockRequest { proof: Some(proof) },
                                ),
                            })
                        } else {
                            debug!(target: "stegos_network::gatekeeper", "peer already gone, trying to reconnect: peer_id={}", peer_id.to_base58());
                            self.dial_peer(peer_id);
                        }
                    } else {
                        debug!(target: "stegos_network::gatekeeper", "got answer, but puzzle not found: peer_id={}", peer_id.to_base58());
                    }
                }
            }
        }

        // Expire outbound peer negotiations
        loop {
            match self.pending_out_peers.poll() {
                Ok(Async::Ready(ref entry)) => {
                    debug!(target: "stegos_network::gatekeeper", "peer hashcash expired: peer_id={}", entry.clone().0.to_base58());
                    // Do cleanup
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!(target: "stegos_network::delivery", "dial_queue timer error: {}", e);
                    break;
                }
            }
        }
        // Expire inbound peers negotiations
        loop {
            match self.pending_in_peers.poll() {
                Ok(Async::Ready(ref entry)) => {
                    debug!(target: "stegos_network::gatekeeper", "peer hashcash expired: peer_id={}", entry.clone().0.to_base58());
                    // Do cleanup
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    error!(target: "stegos_network::delivery", "dial_queue timer error: {}", e);
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

fn local_check_proof(proof: &HashCashProof, nbits: usize) -> bool {
    hashcash::check_proof(proof, nbits)
}

fn generate_puzzle(_peer_id: &PeerId) -> Vec<u8> {
    let key = (0..256).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
    key
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
    Solve {
        peer_id: PeerId,
        seed: Vec<u8>,
        nbits: usize,
    },
    Finished {
        peer_id: PeerId,
    },
    NetworkReady,
}

type Solution = (PeerId, HashCashProof, Duration);

#[derive(Clone)]
struct HashCashPuzzle {
    seed: Vec<u8>,
    nbits: usize,
}

pub enum PeerEvent {
    Connected { peer_id: PeerId },
    EnabledListener { peer_id: PeerId },
    PuzzleSolved { peer_id: PeerId, answer: i64 },
    EnabledDialer { peer_id: PeerId },
}

pub enum DialerPeerState {
    Connected,
    WaitingListener,
    WaitingDialer,
    UnlockRequestSent,
    SolvingPuzzle,
    ProofSent,
    Unlocked,
}

pub enum ListenerPeerState {
    WaitingDialer,
    WaitingProof,
    Unlocked,
}

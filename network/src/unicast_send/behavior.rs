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
    PeerId,
};
use log::*;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
    time::Duration,
};
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::{delay_queue, DelayQueue};

use crate::unicast_send::handler::UnicastHandler;
use crate::unicast_send::{
    UnicastDataMessage, UnicastOutEvent, UnicastSendError, UnicastSendMessage,
};
use crate::PeerStore;

/// HashMap (used as HashSet) with TTL of peers
struct PeersQueue {
    ttl: Duration,
    entries: HashMap<PeerId, delay_queue::Key>,
    expirations: DelayQueue<PeerId>,
}

/// One minute dialout timeout
const DIAL_OUT_TIMEOUT: u64 = 60;

impl PeersQueue {
    fn new(ttl: Duration) -> Self {
        PeersQueue {
            ttl,
            entries: HashMap::new(),
            expirations: DelayQueue::new(),
        }
    }

    fn insert(&mut self, key: PeerId) {
        let delay = self.expirations.insert(key.clone(), self.ttl);

        self.entries.insert(key, delay);
    }

    fn contains(&self, key: &PeerId) -> bool {
        self.entries.contains_key(key)
    }

    fn remove(&mut self, key: &PeerId) {
        if let Some(cache_key) = self.entries.remove(key) {
            self.expirations.remove(&cache_key);
        }
    }
}

pub struct UnicastSend<TSubstream> {
    /// Events that need to be yielded to the outside when polling.
    events: VecDeque<UnicastBehaviorEvent>,

    /// List of connected peers
    connected_peers: HashSet<PeerId>,

    /// List of peers with timeouts we are currently trying to connect to
    dialouts: PeersQueue,

    /// Map PeerId to pbc::secure::PublicKey
    peers_pkeys: HashMap<PeerId, secure::PublicKey>,

    /// Per Peer queues for sending messages
    sending_queues: HashMap<PeerId, VecDeque<UnicastDataMessage>>,

    /// pbc::secure Public key of this node
    local_pkey: secure::PublicKey,

    /// pbc::secure SecretKey of this node
    local_skey: secure::SecretKey,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> UnicastSend<TSubstream> {
    /// Creates a Unicast network behaviour (to be combined with other behaviours to form Swarm)
    pub fn new(keychain: &KeyChain) -> Self {
        UnicastSend {
            events: VecDeque::new(),
            connected_peers: HashSet::new(),
            dialouts: PeersQueue::new(Duration::from_secs(DIAL_OUT_TIMEOUT)),
            sending_queues: HashMap::new(),
            peers_pkeys: HashMap::new(),
            local_pkey: keychain.network_pkey.clone(),
            local_skey: keychain.network_skey.clone(),
            marker: PhantomData,
        }
    }

    /// Enqueue message for delivery.
    /// Assumes upper level did its job to make sure Peer is not known as dead
    pub fn send_message(&mut self, peer_id: PeerId, message: UnicastDataMessage) {
        self.peers_pkeys.insert(peer_id.clone(), message.to.clone());
        if self.connected_peers.contains(&peer_id) {
            self.events
                .push_back(UnicastBehaviorEvent::Deliver { peer_id, message });
        } else {
            self.sending_queues
                .entry(peer_id.clone())
                .or_insert(VecDeque::new())
                .push_back(message);

            if !self.dialouts.contains(&peer_id) {
                self.dialouts.insert(peer_id.clone());
                self.events
                    .push_back(UnicastBehaviorEvent::DialPeer { peer_id });
            }
        }
    }
}

impl<TSubstream, TTopology> NetworkBehaviour<TTopology> for UnicastSend<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
    TTopology: PeerStore,
{
    type ProtocolsHandler = UnicastHandler<TSubstream>;
    type OutEvent = UnicastOutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        UnicastHandler::new(self.local_pkey.clone(), self.local_skey.clone())
    }

    fn inject_connected(&mut self, id: PeerId, _: ConnectedPoint) {
        debug!("Peer connected: {:#?}", id);
        self.dialouts.remove(&id);
        // Store peer in the connected list, so we can start sending messages to it.
        self.connected_peers.insert(id.clone());
        if let Some(mut queue) = self.sending_queues.remove(&id) {
            for msg in queue.drain(..).into_iter() {
                self.events.push_back(UnicastBehaviorEvent::Deliver {
                    peer_id: id.clone(),
                    message: msg,
                });
            }
        }
    }

    fn inject_disconnected(&mut self, id: &PeerId, _: ConnectedPoint) {
        debug!("Peer disconnected: {:#?}", id);
        self.connected_peers.remove(id);
    }

    fn inject_node_event(&mut self, propagation_source: PeerId, event: UnicastSendMessage) {
        // Process received message (passed from Handler as Custom(message))
        // It can be either Data message, if we are receiving side, or
        // Success/Error if we are sending side.
        // Here we just propagate received event upstream
        debug!("Received a message: {:?}", event);
        self.events.push_back(UnicastBehaviorEvent::DataOrResult {
            peer_id: propagation_source,
            event,
        });
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
        trace!("Unicast poll function");
        // Purge failed dialouts
        loop {
            match self.dialouts.expirations.poll() {
                Ok(Async::Ready(Some(entry))) => {
                    let peer_id = entry.get_ref().clone();
                    debug!("Peer {} dialout timeout!", peer_id.to_base58());
                    // Drop sending queue for the peer
                    self.sending_queues.remove(&peer_id);
                    self.dialouts.remove(&peer_id);
                    self.events.push_back(UnicastBehaviorEvent::DataOrResult {
                        peer_id: peer_id.clone(),
                        event: UnicastSendMessage::Error(UnicastSendError::DialoutTimeout),
                    });
                    let topology = poll_parameters.topology();
                    topology.mark_as_failed(&peer_id);
                }
                Ok(Async::Ready(None)) => {
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
                UnicastBehaviorEvent::DialPeer { peer_id } => {
                    debug!("Dialing peer: {:#?}", peer_id);
                    let topology = poll_parameters.topology();
                    if !topology.known_failed(&peer_id) {
                        debug!("Peer is not failing");
                        let addresses = topology.addresses_of_peer(&peer_id);
                        debug!("Peer known addresses: {:#?}", addresses);
                        return Async::Ready(NetworkBehaviourAction::DialPeer { peer_id });
                    } else {
                        // remove peer from dialout queue and clear its queue
                        self.dialouts.remove(&peer_id);
                        self.sending_queues.remove(&peer_id);
                    }
                }
                UnicastBehaviorEvent::Deliver { peer_id, message } => {
                    // Are we still connected to the peer?
                    if self.connected_peers.contains(&peer_id) {
                        return Async::Ready(NetworkBehaviourAction::SendEvent {
                            peer_id,
                            event: message,
                        });
                    }
                    // Peer is gone, can't deliver
                    // TODO: try to reconnect?
                    error!("Peer is gone, can't deliver. Peer: {}", message.to);
                }
                UnicastBehaviorEvent::DataOrResult { peer_id, event } => match event {
                    UnicastSendMessage::Data(msg) => {
                        debug!("Received data message from node: {:?}", msg.from);
                        return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                            UnicastOutEvent::Data(msg),
                        ));
                    }
                    UnicastSendMessage::Success(pkey) => {
                        debug!("Successfully sent message to node: {:?}", pkey);
                        return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                            UnicastOutEvent::Success(pkey),
                        ));
                    }
                    UnicastSendMessage::Error(e) => {
                        if let Some(pkey) = self.peers_pkeys.get(&peer_id) {
                            return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                                UnicastOutEvent::Error(Some(pkey.clone()), e),
                            ));
                        } else {
                            return Async::Ready(NetworkBehaviourAction::GenerateEvent(
                                UnicastOutEvent::Error(None, e),
                            ));
                        }
                    }
                },
            }
        }
        trace!("Finished Unicast poll");
        Async::NotReady
    }
}

/// Event that can happen on the floodsub behaviour.
#[derive(Debug)]
pub enum UnicastBehaviorEvent {
    /// Initiate connection to the peer
    DialPeer { peer_id: PeerId },
    /// Send message to the protocol handler for connected peer
    Deliver {
        peer_id: PeerId,
        message: UnicastDataMessage,
    },
    /// Message received from the protocol handler
    DataOrResult {
        peer_id: PeerId,
        event: UnicastSendMessage,
    },
}

#[cfg(test)]
mod tests {
    use crate::peerstore::MemoryPeerstore;
    use crate::unicast_send::{UnicastDataMessage, UnicastOutEvent, UnicastSend};
    use futures::prelude::*;
    use futures::task;
    use libp2p::{secio, Swarm};
    use stegos_keychain::KeyChain;
    use tokio::runtime::Runtime;

    #[test]
    #[ignore]
    fn single_unicast_send() {
        let keychain1 = KeyChain::new_mem();
        let keychain2 = KeyChain::new_mem();

        let (secp256k1_key1, _) = keychain1
            .generate_secp256k1_keypair()
            .expect("Couldn't generate secp256k1 keypair for network communications");
        let local_key1 = secio::SecioKeyPair::secp256k1_raw_key(&secp256k1_key1[..])
            .expect("converting from raw key shoyld never fail");
        let local_pub_key1 = local_key1.to_public_key();
        let peer_id1 = local_pub_key1.clone().into_peer_id();

        let (secp256k1_key2, _) = keychain2
            .generate_secp256k1_keypair()
            .expect("Couldn't generate secp256k1 keypair for network communications");
        let local_key2 = secio::SecioKeyPair::secp256k1_raw_key(&secp256k1_key2[..])
            .expect("converting from raw key shoyld never fail");
        let local_pub_key2 = local_key2.to_public_key();
        let peer_id2 = local_pub_key2.clone().into_peer_id();

        let transport1 = libp2p::build_development_transport(local_key1);
        let transport2 = libp2p::build_development_transport(local_key2);

        let topology1 = MemoryPeerstore::empty(peer_id1.clone(), local_pub_key1.clone());
        let mut topology2 = MemoryPeerstore::empty(peer_id2.clone(), local_pub_key2.clone());

        let mut swarm1 = {
            let behaviour = UnicastSend::new(&keychain1);
            Swarm::new(transport1, behaviour, topology1)
        };

        let addr =
            libp2p::Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        topology2.add_address(peer_id1.clone(), addr.clone());

        let mut swarm2 = {
            let behaviour = UnicastSend::new(&keychain2);
            Swarm::new(transport2, behaviour, topology2)
        };

        let msg = UnicastDataMessage {
            to: keychain1.network_pkey.clone(),
            from: keychain2.network_pkey.clone(),
            protocol_id: "testing".to_string(),
            data: b"Sunt est voluptate mollit duis elit excepteur do ad minim et exercitation. Duis nostrud veniam commodo labore ut. Voluptate magna laboris Lorem ullamco. Et irure consectetur qui quis aliquip excepteur. Aute elit commodo in laboris proident eu adipisicing pariatur do velit excepteur duis irure. Consectetur pariatur cillum et sit aliquip sit pariatur minim sint et duis.".to_vec(),
        };
        let msg2 = msg.clone();
        swarm2.send_message(peer_id1.clone(), msg);

        let mut swarm1_done = false;
        let mut swarm2_done = false;

        // Kick it off
        let future = futures::future::poll_fn(move || -> Poll<_, ()> {
            println!("future polled!");
            loop {
                if !swarm1_done {
                    println!("poll f1");
                    match swarm1.poll().expect("Error while polling swarm1") {
                        Async::Ready(Some(msg)) => {
                            println!("Swarm 1 got message: {:#?}", msg);
                            if let UnicastOutEvent::Data(new_msg) = msg {
                                assert_eq!(msg2, new_msg);
                            } else {
                                assert!(false, "expected data message");
                            }
                            swarm1_done = true;
                            if swarm2_done {
                                break;
                            }
                        }
                        Async::Ready(None) | Async::NotReady => (),
                    }
                }
                if !swarm2_done {
                    println!("poll f2");
                    match swarm2.poll().expect("Error while polling swarm2") {
                        Async::Ready(Some(msg)) => {
                            println!("Swarm 2 got message: {:#?}", msg);
                            swarm2_done = true;
                            break;
                        }
                        Async::Ready(None) | Async::NotReady => break,
                    }
                }
            }
            if swarm1_done && swarm2_done {
                println!("Both swarms are done!");
                task::current().notify();
                Ok(Async::Ready(()))
            } else {
                Ok(Async::NotReady)
            }
        });

        let mut rt = Runtime::new().unwrap();
        if let Ok(res) = rt.block_on(future) {
            println!("Future finished with result: {:#?}", res);
            return;
        }
        return;
    }
}

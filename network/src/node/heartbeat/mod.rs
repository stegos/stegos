//
// MIT License
//
// Copyright (c) 2018 Stegos
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

#![allow(dead_code)]

use super::{broker::Broker, Inner};
use failure::format_err;
use failure::Error;
use futures::sync::mpsc;
use futures::{Async, Future, Poll, Stream};
use libp2p::peerstore::{PeerAccess, Peerstore};
use libp2p::Multiaddr;
use log::*;
use parking_lot::RwLock;
use protobuf::{self, Message};
use std::cmp::{Eq, PartialEq};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stegos_crypto::hash::{Hashable as StegosHasheable, Hasher as StegosHasher};
use stegos_crypto::pbc::secure::{self, Signature};
pub use stegos_crypto::pbc::secure::{PublicKey as NodePublicKey, SecretKey as NodeSecretKey};
use tokio::timer::Interval;

mod heartbeat_proto;

const HEARTBEAT_TOPIC: &'static str = "stegos-heartbeat";

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HeartbeatUpdateMessage {
    public_key: NodePublicKey,
}

#[derive(Debug, Clone)]
pub enum HeartbeatUpdate {
    Update(HeartbeatUpdateMessage),
    Delete(NodePublicKey),
}

#[derive(Debug, Clone)]
pub(crate) struct Heartbeat {
    tx: mpsc::UnboundedSender<HeartbeatControlMsg>,
}

impl Heartbeat {
    /// Create a new Heartbeat Service.
    pub fn new(
        inner: Arc<RwLock<Inner>>,
    ) -> Result<(impl Future<Item = (), Error = ()>, Self), Error> {
        let (control_tx, control_rx) = mpsc::unbounded();
        let service = HeartbeatService::new(inner, control_rx)?;
        let handle = Heartbeat { tx: control_tx };

        Ok((service, handle))
    }

    pub fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<HeartbeatUpdate>, Error> {
        let (tx, rx) = mpsc::unbounded();
        self.tx.unbounded_send(HeartbeatControlMsg::Subscribe(tx))?;
        Ok(rx)
    }
}

pub(crate) type ExtraInfo = Vec<u8>;

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

#[derive(Debug)]
struct NodeInfo {
    node_public_key: NodePublicKey,
    advertised_ips: Vec<Multiaddr>,
    last_seen: Instant,
    extra_info: ExtraInfo,
}

impl Hash for NodeInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.node_public_key, state);
    }
}

impl PartialEq for NodeInfo {
    fn eq(&self, other: &NodeInfo) -> bool {
        self.node_public_key == other.node_public_key
    }
}

impl Eq for NodeInfo {}

impl StegosHasheable for NodeInfo {
    fn hash(&self, state: &mut StegosHasher) {
        stegos_crypto::hash::Hashable::hash(&self.node_public_key, state);
        for a in self.advertised_ips.iter() {
            stegos_crypto::hash::Hashable::hash(&a.clone().into_bytes(), state);
        }
        stegos_crypto::hash::Hashable::hash(&self.extra_info, state);
    }
}

fn sign_node_info(node_info: &NodeInfo, key: &NodeSecretKey) -> Signature {
    let h = stegos_crypto::hash::Hash::digest(node_info);
    secure::sign_hash(&h, key)
}

#[derive(Debug)]
enum HeartbeatControlMsg {
    Subscribe(mpsc::UnboundedSender<HeartbeatUpdate>),
    Tick,
    Heartbeat(Vec<u8>),
}

struct HeartbeatService {
    me: NodeInfo,
    my_skey: NodeSecretKey,
    active_nodes: HashSet<NodeInfo>,
    input: Box<dyn Stream<Item = HeartbeatControlMsg, Error = ()> + Send>,
    consumers: Vec<mpsc::UnboundedSender<HeartbeatUpdate>>,
    ttl: u64,
    broker: Broker,
}

impl HeartbeatService {
    fn new(
        inner: Arc<RwLock<Inner>>,
        control_rx: mpsc::UnboundedReceiver<HeartbeatControlMsg>,
    ) -> Result<Self, Error> {
        let inner = inner.clone();
        let broker_ = inner.read().broker_handle.clone();
        if let Some(broker) = broker_ {
            let config = inner.read().config.clone();
            let heartbeat_rx = broker
                .subscribe(&HEARTBEAT_TOPIC)?
                .map(|m| HeartbeatControlMsg::Heartbeat(m));

            let ticker = Interval::new(
                Instant::now(),
                Duration::from_secs(config.heartbeat_interval),
            )
            .map(|_| HeartbeatControlMsg::Tick)
            .map_err(|e| {
                error!("Timer error: {}", e);
            });

            let addresses = {
                let inner = inner.read();
                let peerstore = (&*inner).peer_store.clone();
                let mut addresses = vec![];
                if let Some(peer_id) = &inner.peer_id {
                    for addr in peerstore.peer_or_create(peer_id).addrs() {
                        addresses.push(addr);
                    }
                    addresses
                } else {
                    unreachable!();
                }
            };

            let input = control_rx.select(heartbeat_rx).select(ticker);

            let me = NodeInfo {
                node_public_key: inner.read().public_key.clone(),
                advertised_ips: addresses,
                extra_info: inner.read().extra_info.clone(),
                last_seen: Instant::now(),
            };
            let heartbeat_service = HeartbeatService {
                me,
                my_skey: inner.read().secret_key.clone(),
                active_nodes: HashSet::default(),
                input: Box::new(input),
                consumers: vec![],
                ttl: config.heartbeat_interval,
                broker: broker.clone(),
            };

            Ok(heartbeat_service)
        } else {
            Err(format_err!("Broadcast broker is not yes initialized!"))
        }
    }
}

#[must_use = "futures do nothing unless polled"]
impl Future for HeartbeatService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.input.poll() {
                Ok(Async::Ready(Some(msg))) => {
                    debug!("Got heartbeat message: {:?}", msg);
                    match msg {
                        HeartbeatControlMsg::Tick => {
                            // Send heartbeat
                            let msg = msg_to_proto(&self.me, &self.my_skey);
                            if let Ok(proto_msg) = msg.write_to_bytes() {
                                if let Err(e) = self.broker.publish(&HEARTBEAT_TOPIC, proto_msg) {
                                    error!("Error sending message to network: {}", e);
                                };
                            }
                            // Do cleanup
                            let ttl = self.ttl;
                            // FInd dead nodes
                            let mut dead_nodes: HashSet<NodePublicKey> = HashSet::default();
                            for n in self.active_nodes.iter() {
                                if (Instant::now() - n.last_seen) > Duration::from_secs(ttl) {
                                    let msg = HeartbeatUpdate::Delete(n.node_public_key.clone());
                                    self.consumers.retain({
                                        let m = msg.clone();
                                        move |c| {
                                            if let Err(e) = c.unbounded_send(m.clone()) {
                                                error!("Error sending data to consumer: {}", e);
                                                false
                                            } else {
                                                true
                                            }
                                        }
                                    });
                                    dead_nodes.insert(n.node_public_key.clone());
                                }
                            }

                            let dead_pool = &dead_nodes;
                            self.active_nodes
                                .retain({ |n| !dead_pool.contains(&n.node_public_key) })
                        }
                        HeartbeatControlMsg::Subscribe(tx) => {
                            self.consumers.push(tx);
                        }
                        HeartbeatControlMsg::Heartbeat(m) => {
                            if let Ok(proto_msg) = protobuf::parse_from_bytes(&m) {
                                let node_info = match proto_to_msg(proto_msg) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        error!("Error in Hearbeat message: {}", e);
                                        continue;
                                    }
                                };
                                let msg = HeartbeatUpdate::Update(HeartbeatUpdateMessage {
                                    public_key: node_info.node_public_key.clone(),
                                });
                                if None == self.active_nodes.replace(node_info) {
                                    self.consumers.retain({
                                        let m = msg.clone();
                                        move |c| {
                                            if let Err(e) = c.unbounded_send(m.clone()) {
                                                error!("Error sending data to consumer: {}", e);
                                                false
                                            } else {
                                                true
                                            }
                                        }
                                    });
                                };
                            }
                        }
                    };
                }
                Ok(Async::Ready(None)) => {
                    debug!("All streams are closed. Bailing out");
                    return Ok(Async::Ready(()));
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    error!("Error in heartbeat event loop: {:?}", e);
                    return Err(());
                }
            }
        }
    }
}

// Turns a type-safe Heartbeat message into the corresponding row protobuf message.
fn msg_to_proto(hb_msg: &NodeInfo, key: &NodeSecretKey) -> heartbeat_proto::Message {
    let mut msg = heartbeat_proto::Message::new();
    msg.set_public_key(hb_msg.node_public_key.into_bytes().to_vec());
    msg.set_extra_info((&*hb_msg.extra_info).to_vec());
    for a in (&*hb_msg.advertised_ips).into_iter() {
        msg.mut_addrs().push(a.clone().into_bytes());
    }
    msg.set_signature(sign_node_info(&hb_msg, key).into_bytes().to_vec());
    msg
}

/// Turns a raw Heartbeat message into a type-safe message.
fn proto_to_msg(message: heartbeat_proto::Message) -> Result<NodeInfo, Error> {
    let pkey = NodePublicKey::try_from_bytes(&message.get_public_key())?;
    let mut node_info = NodeInfo {
        node_public_key: pkey.clone(),
        extra_info: message.get_extra_info().to_vec(),
        last_seen: Instant::now(),
        advertised_ips: vec![],
    };

    for addr in message.get_addrs().into_iter() {
        match Multiaddr::from_bytes(addr.to_vec()) {
            Ok(m_addr) => node_info.advertised_ips.push(m_addr),
            Err(e) => error!("Error parsing multiaddr: {}", e),
        }
    }

    let sig = Signature::try_from_bytes(message.get_signature())?;
    let h = stegos_crypto::hash::Hash::digest(&node_info);
    if secure::check_hash(&h, &sig, &pkey) {
        return Ok(node_info);
    } else {
        return Err(format_err!("Invalid message signature"));
    }
}

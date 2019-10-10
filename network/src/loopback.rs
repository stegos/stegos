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
#![allow(dead_code)]
use crate::replication::ReplicationEvent;
use crate::{Network, NetworkProvider, UnicastMessage};
use failure::Error;
use futures::sync::mpsc;
use libp2p_core::identity::ed25519;
use libp2p_core::{identity, PeerId};
use log::*;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::mem;
use std::sync::{Arc, Mutex};
use stegos_crypto::pbc;
use stegos_serialization::traits::ProtoConvert;

const IGNORED_UNICAST_PROTOCOLS: [&'static str; 1] = ["chain-loader"];

#[derive(Debug, Clone)]
pub struct LoopbackNetwork {
    state: Arc<Mutex<LoopbackState>>,
}

impl NetworkProvider for LoopbackNetwork {
    fn subscribe(&self, stopic: &str) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let topic: String = stopic.to_string();
        let (tx, rx) = mpsc::unbounded();
        self.state
            .lock()
            .unwrap()
            .consumers
            .entry(topic)
            .or_default()
            .push(tx);
        Ok(rx)
    }

    fn subscribe_unicast(
        &self,
        stopic: &str,
    ) -> Result<mpsc::UnboundedReceiver<UnicastMessage>, Error> {
        let topic: String = stopic.to_string();
        let (tx, rx) = mpsc::unbounded::<UnicastMessage>();
        self.state
            .lock()
            .unwrap()
            .unicast_consumers
            .entry(topic)
            .or_default()
            .push(tx);
        Ok(rx)
    }

    fn send(&self, to: pbc::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error> {
        let msg = MessageFromNode::SendUnicast {
            to,
            protocol_id: protocol_id.to_string(),
            data,
        };
        self.state.lock().unwrap().queue.push_back(msg);
        Ok(())
    }

    fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), Error> {
        trace!("Received publish for topic = {}", topic);
        let topic: String = topic.to_string();
        let msg = MessageFromNode::Publish { topic, data };
        self.state.lock().unwrap().queue.push_back(msg);
        Ok(())
    }

    fn replication_connect(&self, _peer_id: PeerId) -> Result<(), Error> {
        Ok(())
    }

    fn replication_disconnect(&self, _peer_id: PeerId) -> Result<(), Error> {
        Ok(())
    }

    fn change_network_keys(
        &self,
        _new_pkey: pbc::PublicKey,
        _new_skey: pbc::SecretKey,
    ) -> Result<(), Error> {
        Ok(())
    }

    // Clone self as a box
    fn box_clone(&self) -> Network {
        Box::new((*self).clone())
    }
}

#[derive(Debug, Clone)]
struct LoopbackState {
    consumers: HashMap<String, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    unicast_consumers: HashMap<String, Vec<mpsc::UnboundedSender<UnicastMessage>>>,
    queue: VecDeque<MessageFromNode>,
    replication_tx: mpsc::UnboundedSender<ReplicationEvent>,
}

#[derive(Debug, Clone)]
pub struct Loopback {
    state: Arc<Mutex<LoopbackState>>,
}

impl Loopback {
    pub fn new() -> (
        Loopback,
        Network,
        PeerId,
        mpsc::UnboundedReceiver<ReplicationEvent>,
    ) {
        let keypair = ed25519::Keypair::generate();
        let local_key = identity::Keypair::Ed25519(keypair);
        let local_pub_key = local_key.public();
        let peer_id = local_pub_key.clone().into_peer_id();
        let consumers = HashMap::new();
        let unicast_consumers = HashMap::new();
        let (replication_tx, replication_rx) = mpsc::unbounded::<ReplicationEvent>();
        let queue = VecDeque::new();
        let state = LoopbackState {
            consumers,
            unicast_consumers,
            replication_tx,
            queue,
        };
        let state = Arc::new(Mutex::new(state));
        let network = LoopbackNetwork {
            state: state.clone(),
        };
        let service = Loopback { state };
        (service, Box::new(network), peer_id, replication_rx)
    }

    pub fn assert_empty_queue(&self) {
        let ref mut state = self.state.lock().unwrap();
        let mut result = Vec::new();
        for data in &state.queue {
            match data {
                MessageFromNode::SendUnicast { protocol_id, .. }
                    if IGNORED_UNICAST_PROTOCOLS.contains(&protocol_id.as_str()) =>
                {
                    continue
                }
                MessageFromNode::SendUnicast {
                    protocol_id: topic, ..
                }
                | MessageFromNode::Publish { topic, .. } => result.push(topic),
            }
        }

        if !result.is_empty() {
            panic!("Found not processed messages: {:?}", result);
        }
    }

    pub fn assert_broadcast<M: ProtoConvert + Debug + PartialEq>(&mut self, topic: &str, data: M) {
        let ref mut state = self.state.lock().unwrap();
        if let MessageFromNode::Publish {
            topic: msg_topic,
            data: msg_data,
        } = state.queue.pop_front().expect("contains messages")
        {
            assert_eq!(topic, &msg_topic);
            let msg_data = M::from_buffer(&msg_data).unwrap();
            assert_eq!(data, msg_data);
        }
    }

    pub fn get_unicast_to_peer<M: ProtoConvert>(
        &mut self,
        topic: &str,
        peer: &pbc::PublicKey,
    ) -> M {
        let (msg, msg_peer) = self.get_unicast(topic);
        assert_eq!(peer, &msg_peer);
        msg
    }

    pub fn get_unicast<M: ProtoConvert>(&mut self, topic: &str) -> (M, pbc::PublicKey) {
        let (msg, msg_peer) = self.try_get_unicast_raw(topic).expect("Expected message");
        (M::from_buffer(&msg).unwrap(), msg_peer)
    }

    pub fn get_broadcast<M: ProtoConvert>(&mut self, topic: &str) -> M {
        let msg = self.try_get_broadcast_raw(topic).expect("Expected message");
        M::from_buffer(&msg).unwrap()
    }

    pub fn try_get_broadcast_raw(&mut self, topic: &str) -> Option<Vec<u8>> {
        let ref mut state = self.state.lock().unwrap();
        loop {
            match state.queue.pop_front() {
                Some(MessageFromNode::SendUnicast {
                    ref protocol_id, ..
                }) if IGNORED_UNICAST_PROTOCOLS.contains(&protocol_id.as_str()) => continue,
                Some(MessageFromNode::Publish {
                    topic: msg_topic,
                    data: msg_data,
                }) => {
                    assert_eq!(topic, &msg_topic);
                    return Some(msg_data.clone());
                }
                Some(x) => {
                    panic!("Other message in queue = {:?}", x);
                }
                None => return None,
            }
        }
    }

    pub fn try_get_unicast_raw(&mut self, protocol_id: &str) -> Option<(Vec<u8>, pbc::PublicKey)> {
        let ref mut state = self.state.lock().unwrap();
        loop {
            match state.queue.pop_front() {
                Some(MessageFromNode::SendUnicast {
                    ref protocol_id, ..
                }) if IGNORED_UNICAST_PROTOCOLS.contains(&protocol_id.as_str()) => continue,
                Some(MessageFromNode::SendUnicast {
                    protocol_id: msg_protocol_id,
                    to: msg_peer,
                    data: msg_data,
                }) => {
                    assert_eq!(protocol_id, &msg_protocol_id);
                    return Some((msg_data.clone(), msg_peer.clone()));
                }
                Some(x) => {
                    panic!("Other message in queue = {:?}", x);
                }
                None => return None,
            }
        }
    }

    /// Filter out messages with protocol_ids in the following list.
    pub fn filter_unicast(&mut self, protocols: &[&str]) {
        let ref mut state = self.state.lock().unwrap();
        let queue = mem::replace(&mut state.queue, VecDeque::new());
        state.queue = queue
            .into_iter()
            .filter(move |msg| match msg {
                MessageFromNode::SendUnicast {
                    protocol_id: topic, ..
                } => protocols.iter().find(|i| *i == &topic).is_none(),
                _ => true,
            })
            .collect()
    }

    /// Filter out messages from topics in the following list.
    pub fn filter_broadcast(&mut self, topic_list: &[&str]) {
        let ref mut state = self.state.lock().unwrap();
        let queue = mem::replace(&mut state.queue, VecDeque::new());
        state.queue = queue
            .into_iter()
            .filter(|msg| match msg {
                MessageFromNode::Publish { topic, .. } => {
                    topic_list.iter().find(|i| *i == &topic).is_none()
                }

                _ => true,
            })
            .collect()
    }

    pub fn assert_unicast<M: ProtoConvert + Debug + PartialEq>(
        &mut self,
        to: pbc::PublicKey,
        protocol_id: &str,
        data: M,
    ) {
        let ref mut state = self.state.lock().unwrap();
        if let MessageFromNode::SendUnicast {
            to: msg_to,
            protocol_id: msg_protocol_id,
            data: msg_data,
        } = state.queue.pop_front().unwrap()
        {
            assert_eq!(to, msg_to);
            assert_eq!(protocol_id, &msg_protocol_id);
            let msg_data = M::from_buffer(&msg_data).unwrap();
            assert_eq!(data, msg_data);
        }
    }

    pub fn receive_broadcast_raw(&mut self, topic: &str, data: Vec<u8>) {
        let ref mut state = self.state.lock().unwrap();
        let ref mut nodes = state
            .consumers
            .get_mut(topic)
            .expect("Node didn't subscribe to broadcast");

        nodes.retain(move |tx| tx.unbounded_send(data.clone()).is_ok());
    }

    pub fn receive_broadcast<M: ProtoConvert>(&mut self, topic: &str, msg: M) {
        self.receive_broadcast_raw(topic, msg.into_buffer().unwrap());
    }

    pub fn receive_unicast_raw(&mut self, peer: pbc::PublicKey, topic: &str, data: Vec<u8>) {
        let ref mut state = self.state.lock().unwrap();
        let ref mut nodes = state
            .unicast_consumers
            .get_mut(topic)
            .expect("Node didn't subscribe to unicast");
        let message = UnicastMessage { from: peer, data };
        nodes.retain(move |tx| tx.unbounded_send(message.clone()).is_ok());
    }

    pub fn receive_unicast<M: ProtoConvert>(&mut self, peer: pbc::PublicKey, topic: &str, msg: M) {
        self.receive_unicast_raw(peer, topic, msg.into_buffer().unwrap());
    }
}

#[derive(Debug, Clone)]
pub enum MessageFromNode {
    SendUnicast {
        to: pbc::PublicKey,
        protocol_id: String,
        data: Vec<u8>,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
    },
}

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
use crate::{Network, NetworkProvider, UnicastMessage};
use failure::Error;
use futures::sync::mpsc;
use log::*;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::mem;
use std::sync::{Arc, Mutex};
use stegos_crypto::pbc::secure;
use stegos_serialization::traits::ProtoConvert;

#[derive(Debug, Clone)]
pub struct LoopbackNetwork {
    state: Arc<Mutex<LoopbackState>>,
}

impl NetworkProvider for LoopbackNetwork {
    fn subscribe(&self, stopic: &str) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let topic: String = stopic.to_string();
        let (tx, rx) = mpsc::unbounded();
        assert!(
            self.state
                .lock()
                .unwrap()
                .consumers
                .insert(topic, tx)
                .is_none(),
            format!("multiple subscribe to topic {}", stopic)
        );
        Ok(rx)
    }

    fn subscribe_unicast(
        &self,
        stopic: &str,
    ) -> Result<mpsc::UnboundedReceiver<UnicastMessage>, Error> {
        let topic: String = stopic.to_string();
        let (tx, rx) = mpsc::unbounded::<UnicastMessage>();
        assert!(
            self.state
                .lock()
                .unwrap()
                .unicast_consumers
                .insert(topic, tx)
                .is_none(),
            format!("multiple unicast subscribe to topic {}", stopic)
        );
        Ok(rx)
    }

    fn send(&self, to: secure::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error> {
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

    // Clone self as a box
    fn box_clone(&self) -> Network {
        Box::new((*self).clone())
    }
}

#[derive(Debug, Clone)]
struct LoopbackState {
    consumers: HashMap<String, mpsc::UnboundedSender<Vec<u8>>>,
    unicast_consumers: HashMap<String, mpsc::UnboundedSender<UnicastMessage>>,
    queue: VecDeque<MessageFromNode>,
}

#[derive(Debug, Clone)]
pub struct Loopback {
    state: Arc<Mutex<LoopbackState>>,
}

impl Loopback {
    pub fn new() -> (Loopback, Network) {
        let consumers = HashMap::new();
        let unicast_consumers = HashMap::new();
        let queue = VecDeque::new();
        let state = LoopbackState {
            consumers,
            unicast_consumers,
            queue,
        };
        let state = Arc::new(Mutex::new(state));
        let network = LoopbackNetwork {
            state: state.clone(),
        };
        let service = Loopback { state };
        (service, Box::new(network))
    }

    pub fn assert_empty_queue(&self) {
        let ref mut state = self.state.lock().unwrap();
        assert!(state.queue.is_empty());
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

    pub fn get_unicast<M: ProtoConvert>(&mut self, topic: &str, peer: &secure::PublicKey) -> M {
        let ref mut state = self.state.lock().unwrap();
        match state.queue.pop_front().unwrap() {
            MessageFromNode::SendUnicast {
                protocol_id: msg_topic,
                to: msg_peer,
                data: msg_data,
            } => {
                assert_eq!(topic, &msg_topic);
                assert_eq!(peer, &msg_peer);
                M::from_buffer(&msg_data).unwrap()
            }
            x => {
                panic!("Unexpected message {:?}", x);
            }
        }
    }

    pub fn get_broadcast<M: ProtoConvert>(&mut self, topic: &str) -> M {
        let ref mut state = self.state.lock().unwrap();
        match state.queue.pop_front().unwrap() {
            MessageFromNode::Publish {
                topic: msg_topic,
                data: msg_data,
            } => {
                assert_eq!(topic, &msg_topic);
                M::from_buffer(&msg_data).unwrap()
            }
            x => {
                panic!("Unexpected message {:?}", x);
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
        to: secure::PublicKey,
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
        let ref mut node = state
            .consumers
            .get(topic)
            .expect("Node didn't subscribe to broadcast");
        node.unbounded_send(data).expect("channel error")
    }

    pub fn receive_broadcast<M: ProtoConvert>(&mut self, topic: &str, msg: M) {
        self.receive_broadcast_raw(topic, msg.into_buffer().unwrap());
    }

    pub fn receive_unicast_raw(&mut self, peer: secure::PublicKey, topic: &str, data: Vec<u8>) {
        let ref mut state = self.state.lock().unwrap();
        let ref mut node = state
            .unicast_consumers
            .get(topic)
            .expect("Node didn't subscribe to unicast");
        let message = UnicastMessage { from: peer, data };
        node.unbounded_send(message).expect("channel error")
    }

    pub fn receive_unicast<M: ProtoConvert>(
        &mut self,
        peer: secure::PublicKey,
        topic: &str,
        msg: M,
    ) {
        self.receive_unicast_raw(peer, topic, msg.into_buffer().unwrap());
    }
}

#[derive(Debug, Clone)]
pub enum MessageFromNode {
    SendUnicast {
        to: secure::PublicKey,
        protocol_id: String,
        data: Vec<u8>,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
    },
}

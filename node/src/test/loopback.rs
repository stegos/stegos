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
use failure::Error;
use futures::sync::mpsc;
use log::*;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use stegos_crypto::pbc::secure;
use stegos_network::{Network, NetworkProvider, UnicastMessage};
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

    pub fn assert_broadcast<M>(&mut self, topic: &str, data: M)
    where
        M: ProtoConvert + Debug + PartialEq,
    {
        let ref mut state = self.state.lock().unwrap();
        if let MessageFromNode::Publish {
            topic: msg_topic,
            data: msg_data,
        } = state.queue.pop_front().expect("No messages in queue")
        {
            assert_eq!(topic, &msg_topic, "Received message from other topic.");
            let msg_data = M::from_buffer(&msg_data).unwrap();
            assert_eq!(
                data, msg_data,
                "Sended message differ from real node sended."
            );
        }
    }

    pub fn assert_broadcast_with<F, M>(&mut self, topic: &str, mut func: F)
    where
        F: FnMut(M) -> bool,
        M: ProtoConvert + Debug + PartialEq,
    {
        let ref mut state = self.state.lock().unwrap();
        if let MessageFromNode::Publish {
            topic: msg_topic,
            data: msg_data,
        } = state.queue.pop_front().expect("No messages in queue")
        {
            assert_eq!(topic, &msg_topic, "Received message from other topic.");
            let msg_data = M::from_buffer(&msg_data).unwrap();
            assert!(
                func(msg_data),
                "Sended message differ from real node sended."
            );
        }
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

    pub fn receive_broadcast(&mut self, topic: &str, data: Vec<u8>) {
        let ref mut state = self.state.lock().unwrap();
        let ref mut node = state
            .consumers
            .get(topic)
            .expect("Node didn't subscribe to broadcast");
        node.unbounded_send(data).expect("channel error")
    }

    pub fn receive_unicast(&mut self, peer: secure::PublicKey, topic: &str, data: Vec<u8>) {
        let ref mut state = self.state.lock().unwrap();
        let ref mut node = state
            .unicast_consumers
            .get(topic)
            .expect("Node didn't subscribe to unicast");
        let message = UnicastMessage { from: peer, data };
        node.unbounded_send(message).expect("channel error")
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

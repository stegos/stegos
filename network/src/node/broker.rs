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
//!
//! Message broker
//!

use failure::Error;
use fnv::FnvHashMap;
use futures::sync::mpsc;
use futures::Stream;
use futures::{Async, Future, Poll};
use libp2p::floodsub::{self, TopicHash};
use log::*;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Manages subscriptions to topics
///
#[derive(Clone, Debug)]
pub struct Broker {
    pub upstream: mpsc::UnboundedSender<PubsubMessage>,
}

impl Broker {
    /// Create a new Broker service
    pub fn new(
        input: floodsub::FloodSubReceiver,
        floodsub_ctl: floodsub::FloodSubController,
    ) -> (impl Future<Item = (), Error = ()>, Broker) {
        let (tx, rx) = mpsc::unbounded();

        let service = BrokerService::new(input, floodsub_ctl, rx);
        let broker = Broker { upstream: tx };
        (service, broker)
    }

    /// Subscribe to topic, returns Stream<Vec<u8>> of messages incoming to topic
    pub fn subscribe<S>(&self, topic: &S) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error>
    where
        S: Into<String> + Clone,
    {
        let topic: String = topic.clone().into();
        let (tx, rx) = mpsc::unbounded();
        let msg = PubsubMessage::Subscribe { topic, handler: tx };
        self.upstream.unbounded_send(msg)?;
        Ok(rx)
    }
    /// Published message to topic
    pub fn publish<S>(&self, topic: &S, data: Vec<u8>) -> Result<(), Error>
    where
        S: Into<String> + Clone,
    {
        let topic: String = topic.clone().into();
        let msg = PubsubMessage::Publish {
            topic: topic.clone().into(),
            data,
        };
        self.upstream.unbounded_send(msg)?;
        Ok(())
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum PubsubMessage {
    Subscribe {
        topic: String,
        handler: mpsc::UnboundedSender<Vec<u8>>,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
    },
}

enum Message {
    Pubsub(PubsubMessage),
    Input(floodsub::Message),
}

struct BrokerService {
    consumers: FnvHashMap<TopicHash, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    pubsub_rx: Box<dyn Stream<Item = Message, Error = ()> + Send>,
    floodsub_ctl: floodsub::FloodSubController,
}

impl BrokerService {
    fn new(
        input: floodsub::FloodSubReceiver,
        floodsub_ctl: floodsub::FloodSubController,
        rx: mpsc::UnboundedReceiver<PubsubMessage>,
    ) -> BrokerService {
        let messages =
            rx.map(|m| Message::Pubsub(m))
                .select(input.map(|m| Message::Input(m)).map_err(|e| {
                    error!("Error reading from floodsub receiver: {}", e);
                }));

        let service = BrokerService {
            consumers: FnvHashMap::default(),
            // input,
            // downstream: rx,
            pubsub_rx: Box::new(messages),
            floodsub_ctl,
        };

        service
    }
}

impl Future for BrokerService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.pubsub_rx.poll() {
                Ok(Async::Ready(msg)) => match msg {
                    Some(Message::Pubsub(m)) => match m {
                        PubsubMessage::Subscribe { topic, handler } => {
                            debug!("Subscribed to topic '{}'*", &topic);
                            let new_topic = floodsub::TopicBuilder::new(topic).build();
                            let topic_hash = new_topic.hash();
                            self.consumers
                                .entry(topic_hash.clone())
                                .or_insert(vec![])
                                .push(handler);
                            self.floodsub_ctl.subscribe(&new_topic);
                        }
                        PubsubMessage::Publish { topic, data } => {
                            let new_topic = floodsub::TopicBuilder::new(topic).build();
                            let topic_hash = new_topic.hash();
                            debug!(
                                "Got publish message from Upstream, publishing to topic {}!",
                                topic_hash.clone().into_string()
                            );
                            self.floodsub_ctl.publish(&new_topic, data);
                        }
                    },
                    Some(Message::Input(m)) => {
                        for t in m.topics.into_iter() {
                            debug!(
                                "Got message for topic {}, sending to consumers",
                                t.clone().into_string()
                            );
                            let consumers = self.consumers.entry(t).or_insert(vec![]);
                            consumers.retain({
                                let data = &m.data;
                                move |c| {
                                    if let Err(e) = c.unbounded_send(data.clone()) {
                                        error!("Error sending data to consumer: {}", e);
                                        false
                                    } else {
                                        true
                                    }
                                }
                            })
                        }
                    }
                    None => return Ok(Async::Ready(())), // All streams are done!
                },
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    error!("Error in Broker Future: {:?}", e);
                    return Err(());
                }
            }
        }
    }
}

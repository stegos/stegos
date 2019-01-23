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

use failure::Error;
use futures::prelude::*;
use futures::sync::mpsc;
use ipnetwork::IpNetwork;
use libp2p::{
    core::swarm::NetworkBehaviourEventProcess, core::topology::Topology, core::PublicKey, floodsub,
    multiaddr::Protocol, multiaddr::ToMultiaddr, secio, Multiaddr, NetworkBehaviour, PeerId,
};
use log::*;
use pnet::datalink;
use protobuf::Message as ProtoMessage;
use smallvec::SmallVec;
use std::collections::HashMap;
use stegos_config::ConfigNetwork;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ncp, MemoryPeerstore, NetworkProvider};

mod unicast_proto;

#[derive(Clone, Debug)]
pub struct Libp2pNetwork {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

const UNICAST_TOPIC: &'static str = "stegos-unicast";

impl Libp2pNetwork {
    pub fn new(
        config: &ConfigNetwork,
        keychain: &KeyChain,
    ) -> Result<(Self, impl Future<Item = (), Error = ()>), Error> {
        let (service, control_tx) = new_service(config, keychain)?;
        let network = Libp2pNetwork { control_tx };
        Ok((network, service))
    }
}

impl NetworkProvider for Libp2pNetwork {
    /// Subscribe to topic, returns Stream<Vec<u8>> of messages incoming to topic
    fn subscribe<S>(&self, topic: &S) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error>
    where
        S: Into<String> + Clone,
    {
        let topic: String = topic.clone().into();
        let (tx, rx) = mpsc::unbounded();
        let msg = ControlMessage::Subscribe { topic, handler: tx };
        self.control_tx.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Published message to topic
    fn publish<S>(&self, topic: &S, data: Vec<u8>) -> Result<(), Error>
    where
        S: Into<String> + Clone,
    {
        let topic: String = topic.clone().into();
        let msg = ControlMessage::Publish {
            topic: topic.clone().into(),
            data,
        };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    // Subscribe to unicast messages
    fn subscribe_unicast(&self) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let (tx, rx) = mpsc::unbounded();
        let msg = ControlMessage::SubscribeUnicast { consumer: tx };
        self.control_tx.unbounded_send(msg)?;
        Ok(rx)
    }

    // Send direct message to public key
    fn send(&self, to: secure::PublicKey, data: Vec<u8>) -> Result<(), Error> {
        let msg = ControlMessage::SendUnicast { to, data };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }
}

fn new_service(
    config: &ConfigNetwork,
    keychain: &KeyChain,
) -> Result<
    (
        impl Future<Item = (), Error = ()>,
        mpsc::UnboundedSender<ControlMessage>,
    ),
    Error,
> {
    // let peer_id = cosi_pkey2peer_id(&keychain.cosi_pkey);
    let local_key = secio::SecioKeyPair::ed25519_generated().unwrap();
    let local_pub_key = local_key.to_public_key();
    let peer_id = local_pub_key.clone().into_peer_id();

    // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key);

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let behaviour =
            Libp2pBehaviour::new(config, keychain, local_pub_key.clone().into_peer_id());

        libp2p::Swarm::new(
            transport,
            behaviour,
            new_peerstore(config, peer_id, local_pub_key),
        )
    };

    let mut bind_ip = Multiaddr::from(Protocol::Ip4(config.bind_ip.clone().parse()?));
    bind_ip.append(Protocol::Tcp(config.bind_port));

    let addr = libp2p::Swarm::listen_on(&mut swarm, bind_ip).unwrap();
    info!("Listening on {:?}", addr);

    let (control_tx, mut control_rx) = mpsc::unbounded::<ControlMessage>();
    let service = futures::future::poll_fn(move || -> Result<_, ()> {
        trace!("Swarm poll fn");
        loop {
            match control_rx.poll() {
                Ok(Async::Ready(Some(msg))) => swarm.process_event(msg),
                Ok(Async::Ready(None)) => return Ok(Async::Ready(())),
                Ok(Async::NotReady) => break,
                Err(_e) => error!("Error in control channel"),
            }
        }

        loop {
            match swarm.poll().expect("Error while polling swarm") {
                Async::Ready(Some(_)) => {}
                Async::Ready(None) | Async::NotReady => break,
            }
        }
        trace!("Finished Swatm poll!");
        Ok(Async::NotReady)
    });

    Ok((service, control_tx))
}

#[derive(NetworkBehaviour)]
pub struct Libp2pBehaviour<TSubstream: AsyncRead + AsyncWrite> {
    floodsub: floodsub::Floodsub<TSubstream>,
    ncp: ncp::Ncp<TSubstream>,
    #[behaviour(ignore)]
    consumers: HashMap<floodsub::TopicHash, SmallVec<[mpsc::UnboundedSender<Vec<u8>>; 3]>>,
    #[behaviour(ignore)]
    unicast_consumers: Vec<mpsc::UnboundedSender<Vec<u8>>>,
    #[behaviour(ignore)]
    my_pkey: secure::PublicKey,
}

impl<TSubstream> Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(config: &ConfigNetwork, keychain: &KeyChain, peer_id: PeerId) -> Self {
        let mut behaviour = Libp2pBehaviour {
            floodsub: floodsub::Floodsub::new(peer_id.clone()),
            ncp: ncp::layer::Ncp::new(config),
            consumers: HashMap::new(),
            unicast_consumers: Vec::new(),
            my_pkey: keychain.cosi_pkey.clone(),
        };
        let unicast_topic = floodsub::TopicBuilder::new(UNICAST_TOPIC).build();
        behaviour.floodsub.subscribe(unicast_topic);
        debug!(
            "Listening for unicast message for key: {}",
            behaviour.my_pkey.clone().to_string()
        );
        behaviour
    }

    pub fn process_event(&mut self, msg: ControlMessage) {
        trace!("Control event: {:#?}", msg);
        match msg {
            ControlMessage::Subscribe { topic, handler } => {
                let floodsub_topic = floodsub::TopicBuilder::new(topic).build();
                let topic_hash = floodsub_topic.hash();
                self.consumers
                    .entry(topic_hash.clone())
                    .or_insert(SmallVec::new())
                    .push(handler);
                self.floodsub.subscribe(floodsub_topic);
            }
            ControlMessage::Publish { topic, data } => {
                let floodsub_topic = floodsub::TopicBuilder::new(topic).build();
                self.floodsub.publish(floodsub_topic, data)
            }
            ControlMessage::SubscribeUnicast { consumer } => {
                self.unicast_consumers.push(consumer);
            }
            ControlMessage::SendUnicast { to, data } => {
                let floodsub_topic = floodsub::TopicBuilder::new(UNICAST_TOPIC).build();
                let msg = encode_unicast(self.my_pkey.clone(), to, data);
                self.floodsub.publish(floodsub_topic, msg);
            }
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<void::Void> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, _ev: void::Void) {
        void::unreachable(_ev)
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<floodsub::FloodsubEvent>
    for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    // Called when `floodsub` produces an event.
    // Send received message to consumers.
    fn inject_event(&mut self, message: libp2p::floodsub::FloodsubEvent) {
        if let libp2p::floodsub::FloodsubEvent::Message(message) = message {
            let floodsub_topic = floodsub::TopicBuilder::new(UNICAST_TOPIC).build();
            let unicast_topic_hash = floodsub_topic.hash();
            if message.topics.iter().any(|t| t == unicast_topic_hash) {
                match decode_unicast(message.data.clone()) {
                    Ok((from, to, data)) => {
                        // send unicast message upstream
                        if to == self.my_pkey {
                            debug!(
                                "Received unicast message from: {}\n\tdata: {}",
                                from,
                                String::from_utf8_lossy(&data)
                            );
                            self.unicast_consumers.retain({
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
                    Err(e) => error!("Failure decoding unicast message: {}", e),
                }
            }
            for t in message.topics.into_iter() {
                debug!(
                    "Got message for topic {}, sending to consumers",
                    t.clone().into_string()
                );
                let consumers = self.consumers.entry(t).or_insert(SmallVec::new());
                consumers.retain({
                    let data = &message.data;
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
    }
}

#[derive(Clone, Debug)]
pub enum ControlMessage {
    Subscribe {
        topic: String,
        handler: mpsc::UnboundedSender<Vec<u8>>,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
    },
    SendUnicast {
        to: secure::PublicKey,
        data: Vec<u8>,
    },
    SubscribeUnicast {
        consumer: mpsc::UnboundedSender<Vec<u8>>,
    },
}

fn new_peerstore(
    config: &ConfigNetwork,
    peer_id: PeerId,
    local_pub_key: PublicKey,
) -> MemoryPeerstore {
    let mut peerstore = MemoryPeerstore::empty(peer_id, local_pub_key);
    let ifaces = datalink::interfaces();
    let mut my_addresses: Vec<Multiaddr> = vec![];

    for addr in config.advertised_addresses.iter() {
        match addr.parse() {
            Ok(maddr) => my_addresses.push(maddr),
            Err(e) => error!("error parsing multiaddr: {} error: {}", addr, e),
        }
    }

    let bind_port = config.bind_port;

    if config.advertise_local_ips {
        let ips = ifaces
            .into_iter()
            .filter(|ref i| i.is_up() && !i.is_loopback())
            .flat_map(|ref i| i.ips.clone())
            .filter(|ref ip| ip.is_ipv4());

        let mut multiaddresses: Vec<Multiaddr> = ips
            .map(|i| match i {
                IpNetwork::V4(net) => net.ip(),
                IpNetwork::V6(_) => unreachable!(),
            })
            .map(|a| a.to_multiaddr().unwrap())
            .map(|mut a| {
                a.append(Protocol::Tcp(bind_port));
                a
            })
            .collect();

        my_addresses.append(&mut multiaddresses);
    }

    debug!("My adverised addresses: {:#?}", my_addresses);
    peerstore.add_local_external_addrs(my_addresses.into_iter());
    peerstore
}

// Encode unicast message
fn encode_unicast(from: secure::PublicKey, to: secure::PublicKey, data: Vec<u8>) -> Vec<u8> {
    let mut msg = unicast_proto::Message::new();
    msg.set_from(from.into_bytes().to_vec());
    msg.set_to(to.into_bytes().to_vec());
    msg.set_data(data);

    msg.write_to_bytes()
        .expect("protobuf encoding should never fail")
}

fn decode_unicast(
    input: Vec<u8>,
) -> Result<(secure::PublicKey, secure::PublicKey, Vec<u8>), Error> {
    let mut msg: unicast_proto::Message = protobuf::parse_from_bytes(&input)?;

    let from = secure::PublicKey::try_from_bytes(&msg.take_from().to_vec())?;
    let to = secure::PublicKey::try_from_bytes(&msg.take_to().to_vec())?;
    let data = msg.take_data().to_vec();

    Ok((from, to, data))
}

#[cfg(test)]
mod tests {
    use stegos_crypto::pbc::secure;

    #[test]
    fn encode_decode() {
        let from = secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap();
        let to = secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap();
        let data = random_vec(1024);

        let encoded = super::encode_unicast(from, to, data.clone());
        let (from_2, to_2, data_2) = super::decode_unicast(encoded).unwrap();

        assert_eq!(from, from_2);
        assert_eq!(to, to_2);
        assert_eq!(data, data_2);
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

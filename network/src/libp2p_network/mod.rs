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

use failure::{format_err, Error};
use futures::prelude::*;
use futures::sync::mpsc;
use ipnetwork::IpNetwork;
use libp2p::{
    core::swarm::NetworkBehaviourEventProcess,
    floodsub::{Floodsub, FloodsubEvent, TopicBuilder, TopicHash},
    kad::KademliaOut,
    multiaddr::Protocol,
    multiaddr::ToMultiaddr,
    multihash, secio, Multiaddr, NetworkBehaviour, PeerId, Swarm,
};
use log::*;
use pnet::datalink;
use protobuf::Message as ProtoMessage;
use smallvec::SmallVec;
use std::collections::HashMap;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::NetworkConfig;
use crate::discovery::{DiscoveryBehaviour, DiscoveryOutEvent};
use crate::{
    ncp::Ncp, Network, NetworkProvider, UnicastDataMessage, UnicastMessage, UnicastOutEvent,
    UnicastSend,
};

mod proto;

use self::proto::unicast_proto;

#[derive(Clone, Debug)]
pub struct Libp2pNetwork {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

const UNICAST_TOPIC: &'static str = "stegos-unicast";

impl Libp2pNetwork {
    pub fn new(
        config: &NetworkConfig,
        keychain: &KeyChain,
    ) -> Result<(Network, impl Future<Item = (), Error = ()>), Error> {
        let (service, control_tx) = new_service(config, keychain)?;
        let network = Libp2pNetwork { control_tx };
        Ok((Box::new(network), service))
    }
}

impl NetworkProvider for Libp2pNetwork {
    /// Subscribe to topic, returns Stream<Vec<u8>> of messages incoming to topic
    fn subscribe(&self, topic: &str) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let topic: String = topic.clone().into();
        let (tx, rx) = mpsc::unbounded();
        let msg = ControlMessage::Subscribe { topic, handler: tx };
        self.control_tx.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Published message to topic
    fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), Error> {
        let topic: String = topic.clone().into();
        let msg = ControlMessage::Publish {
            topic: topic.clone().into(),
            data,
        };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    // Subscribe to unicast messages
    fn subscribe_unicast(
        &self,
        protocol_id: &str,
    ) -> Result<mpsc::UnboundedReceiver<UnicastMessage>, Error> {
        let protocol_id: String = protocol_id.clone().into();
        let (tx, rx) = mpsc::unbounded::<UnicastMessage>();
        let msg = ControlMessage::SubscribeUnicast {
            protocol_id,
            consumer: tx,
        };
        self.control_tx.unbounded_send(msg)?;
        Ok(rx)
    }

    // Send direct message to public key
    fn send(&self, to: secure::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error> {
        let protocol_id: String = protocol_id.clone().into();
        let msg = ControlMessage::SendUnicast {
            to,
            protocol_id,
            data,
        };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    // Clone self as a box
    fn box_clone(&self) -> Network {
        Box::new((*self).clone())
    }
}

fn new_service(
    config: &NetworkConfig,
    keychain: &KeyChain,
) -> Result<
    (
        impl Future<Item = (), Error = ()>,
        mpsc::UnboundedSender<ControlMessage>,
    ),
    Error,
> {
    let (secp256k1_key, _) = keychain
        .generate_secp256k1_keypair()
        .expect("Couldn't generate secp256k1 keypair for network communications");
    let local_key = secio::SecioKeyPair::secp256k1_raw_key(&secp256k1_key[..])
        .expect("converting from raw key should never fail");
    let local_pub_key = local_key.to_public_key();
    let peer_id = local_pub_key.clone().into_peer_id();

    // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key);

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let behaviour =
            Libp2pBehaviour::new(config, keychain, local_pub_key.clone().into_peer_id());

        libp2p::Swarm::new(transport, behaviour, peer_id)
    };

    let mut my_addresses = my_external_address(config);
    for a in my_addresses.drain(..).into_iter() {
        Swarm::add_external_address(&mut swarm, a);
    }

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
        trace!("Finished Swarm poll!");
        Ok(Async::NotReady)
    });

    Ok((service, control_tx))
}

#[derive(NetworkBehaviour)]
pub struct Libp2pBehaviour<TSubstream: AsyncRead + AsyncWrite> {
    floodsub: Floodsub<TSubstream>,
    ncp: Ncp<TSubstream>,
    discovery: DiscoveryBehaviour<TSubstream>,
    unicast_send: UnicastSend<TSubstream>,
    #[behaviour(ignore)]
    consumers: HashMap<TopicHash, SmallVec<[mpsc::UnboundedSender<Vec<u8>>; 3]>>,
    #[behaviour(ignore)]
    unicast_consumers: HashMap<String, SmallVec<[mpsc::UnboundedSender<UnicastMessage>; 3]>>,
    #[behaviour(ignore)]
    my_pkey: secure::PublicKey,
    #[behaviour(ignore)]
    my_skey: secure::SecretKey,
    #[behaviour(ignore)]
    topics_map: HashMap<TopicHash, String>,
}

impl<TSubstream> Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(config: &NetworkConfig, keychain: &KeyChain, peer_id: PeerId) -> Self {
        let mut discovery = DiscoveryBehaviour::new(peer_id.clone());
        discovery.add_providing(network_pkey_to_peer_id(&keychain.network_pkey));
        let mut behaviour = Libp2pBehaviour {
            floodsub: Floodsub::new(peer_id.clone()),
            ncp: Ncp::new(config),
            unicast_send: UnicastSend::new(keychain),
            discovery,
            consumers: HashMap::new(),
            unicast_consumers: HashMap::new(),
            my_pkey: keychain.network_pkey.clone(),
            my_skey: keychain.network_skey.clone(),
            topics_map: HashMap::new(),
        };
        let unicast_topic = TopicBuilder::new(UNICAST_TOPIC).build();
        behaviour.floodsub.subscribe(unicast_topic);
        debug!(target: "stegos_network::floodsub",
            "Listening for unicast message: my_key={:?}",
            behaviour.my_pkey.clone().to_string()
        );
        behaviour
    }

    fn add_providing(&mut self, key: PeerId) {
        self.discovery.add_providing(key);
    }

    fn process_event(&mut self, msg: ControlMessage) {
        trace!("Control event: {:#?}", msg);
        match msg {
            ControlMessage::Subscribe { topic, handler } => {
                let floodsub_topic = TopicBuilder::new(topic.clone()).build();
                let topic_hash = floodsub_topic.hash();
                self.topics_map.insert(topic_hash.clone(), topic);
                self.consumers
                    .entry(topic_hash.clone())
                    .or_insert(SmallVec::new())
                    .push(handler);
                self.floodsub.subscribe(floodsub_topic);
            }
            ControlMessage::Publish { topic, data } => {
                debug!(target: "stegos_network::floodsub",
                    "Sending broadcast message: topic={}, size={}",
                    topic,
                    data.len(),
                );
                let floodsub_topic = TopicBuilder::new(topic).build();
                self.floodsub.publish(floodsub_topic, data)
            }
            ControlMessage::SubscribeUnicast {
                protocol_id,
                consumer,
            } => {
                self.unicast_consumers
                    .entry(protocol_id)
                    .or_insert(SmallVec::new())
                    .push(consumer);
            }
            ControlMessage::SendUnicast {
                to,
                protocol_id,
                data,
            } => {
                debug!(target: "stegos_network::floodsub",
                    "Sending unicast message: to={}, from={}, protocol={}, size={}",
                    to,
                    self.my_pkey,
                    protocol_id,
                    data.len(),
                );

                if to == self.my_pkey {
                    let msg = UnicastMessage {
                        from: to.clone(),
                        data,
                    };
                    self.unicast_consumers
                        .entry(protocol_id)
                        .or_insert(SmallVec::new())
                        .retain({
                            move |c| {
                                if let Err(e) = c.unbounded_send(msg.clone()) {
                                    error!("Error sending data to consumer: {}", e);
                                    false
                                } else {
                                    true
                                }
                            }
                        })
                } else {
                    if cfg!(feature = "unicast_floodsub") {
                        let floodsub_topic = TopicBuilder::new(UNICAST_TOPIC).build();
                        let msg = encode_unicast(
                            self.my_pkey.clone(),
                            to,
                            protocol_id,
                            data,
                            &self.my_skey,
                        );
                        self.floodsub.publish(floodsub_topic, msg);
                    } else {
                        let msg = UnicastDataMessage {
                            from: self.my_pkey.clone(),
                            to,
                            protocol_id,
                            data,
                        };
                        self.discovery.send(msg);
                    }
                }
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

impl<TSubstream> NetworkBehaviourEventProcess<FloodsubEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    // Called when `floodsub` produces an event.
    // Send received message to consumers.
    fn inject_event(&mut self, message: FloodsubEvent) {
        if let FloodsubEvent::Message(message) = message {
            let floodsub_topic = TopicBuilder::new(UNICAST_TOPIC).build();
            let unicast_topic_hash = floodsub_topic.hash();
            if message.topics.iter().any(|t| t == unicast_topic_hash) {
                match decode_unicast(message.data.clone()) {
                    Ok((from, to, protocol_id, data)) => {
                        // send unicast message upstream
                        if to == self.my_pkey {
                            debug!(target: "stegos_network::floodsub",
                                "Received unicast message: from={}, protocol={} size={}",
                                from,
                                protocol_id,
                                data.len()
                            );
                            let msg = UnicastMessage { from, data };
                            self.unicast_consumers
                                .entry(protocol_id)
                                .or_insert(SmallVec::new())
                                .retain({
                                    move |c| {
                                        if let Err(e) = c.unbounded_send(msg.clone()) {
                                            error!(target:"stegos_network::floodsub", "Error sending data to consumer: {}", e);
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
                return;
            }
            for t in message.topics.into_iter() {
                let topic = match self.topics_map.get(&t) {
                    Some(t) => t.clone(),
                    None => "Unknown".to_string(),
                };

                debug!(target: "stegos_network::floodsub",
                    "Received broadcast message: topic={}, size={}",
                    topic,
                    message.data.len(),
                );
                let consumers = self.consumers.entry(t).or_insert(SmallVec::new());
                consumers.retain({
                    let data = &message.data;
                    move |c| {
                        if let Err(e) = c.unbounded_send(data.clone()) {
                            error!(target: "stegos_network::floodsub", "Error sending data to consumer: {}", e);
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

impl<TSubstream> NetworkBehaviourEventProcess<DiscoveryOutEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, out: DiscoveryOutEvent) {
        match out {
            DiscoveryOutEvent::KadEvent(KademliaOut::FindNodeResult { key, closer_peers }) => {
                debug!(
                    target: "stegos_network::discovery",
                    "Kademlia query for {:?} yielded {:?} results",
                    key,
                    closer_peers.len()
                );
            }
            DiscoveryOutEvent::KadEvent(KademliaOut::GetProvidersResult {
                key,
                closer_peers: _,
                provider_peers,
            }) => {
                debug!(target: "stegos_network::discovery", "Got providers: {:#?} for key: {:#?}", provider_peers, key);
            }
            DiscoveryOutEvent::KadEvent(KademliaOut::Discovered { .. }) => {}
            DiscoveryOutEvent::Deliver(peer_id, msg) => {
                debug!(
                    target: "stegos_network::discovery",
                    "Discovery successful, passing to delivery: pkey={}, peer_id={}",
                    msg.to,
                    peer_id.to_base58()
                );
                self.unicast_send.send_message(peer_id, msg);
            }
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<UnicastOutEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, out: UnicastOutEvent) {
        debug!("Got unicast event: {:#?}", out);
        match out {
            UnicastOutEvent::Data(message) => {
                let msg = UnicastMessage {
                    from: message.from,
                    data: message.data,
                };
                self.unicast_consumers
                    .entry(message.protocol_id)
                    .or_insert(SmallVec::new())
                    .retain({
                        move |c| {
                            if let Err(e) = c.unbounded_send(msg.clone()) {
                                error!("Error sending data to consumer: {}", e);
                                false
                            } else {
                                true
                            }
                        }
                    })
            }
            UnicastOutEvent::Success(pkey) => debug!("Successful send to node: {}", pkey),
            UnicastOutEvent::Error(Some(pkey), e) => {
                error!("Unicast send error! Node: {} Error: {}", pkey, e)
            }
            UnicastOutEvent::Error(None, e) => error!("Unicast send error: {}", e),
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
        protocol_id: String,
        data: Vec<u8>,
    },
    SubscribeUnicast {
        protocol_id: String,
        consumer: mpsc::UnboundedSender<UnicastMessage>,
    },
}

fn network_pkey_to_peer_id(key: &secure::PublicKey) -> PeerId {
    let hash =
        multihash::encode(multihash::Hash::SHA2256, &key.to_bytes()).expect("should never fail");
    PeerId::from_multihash(hash).expect("hash is properly formed on prev step")
}

fn my_external_address(config: &NetworkConfig) -> Vec<Multiaddr> {
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
    my_addresses
}

// Encode unicast message
fn encode_unicast(
    from: secure::PublicKey,
    to: secure::PublicKey,
    protocol_id: String,
    data: Vec<u8>,
    sign_key: &secure::SecretKey,
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    from.hash(&mut hasher);
    to.hash(&mut hasher);
    protocol_id.hash(&mut hasher);
    data.hash(&mut hasher);
    let hash = hasher.result();
    let sig = secure::sign_hash(&hash, sign_key);

    let mut msg = unicast_proto::Message::new();
    msg.set_from(from.to_bytes().to_vec());
    msg.set_to(to.to_bytes().to_vec());
    msg.set_protocol_id(protocol_id.into_bytes().to_vec());
    msg.set_data(data);
    msg.set_signature(sig.to_bytes().to_vec());

    msg.write_to_bytes()
        .expect("protobuf encoding should never fail")
}

fn decode_unicast(
    input: Vec<u8>,
) -> Result<(secure::PublicKey, secure::PublicKey, String, Vec<u8>), Error> {
    let mut msg: unicast_proto::Message = protobuf::parse_from_bytes(&input)?;

    let from = secure::PublicKey::try_from_bytes(&msg.take_from().to_vec())?;
    let to = secure::PublicKey::try_from_bytes(&msg.take_to().to_vec())?;
    let sig = secure::Signature::try_from_bytes(&msg.take_signature().to_vec())?;
    let protocol_id_bytes = &msg.get_protocol_id();
    let protocol_id = String::from_utf8(protocol_id_bytes.to_vec())?;
    let data = msg.take_data().to_vec();

    let mut hasher = Hasher::new();
    from.hash(&mut hasher);
    to.hash(&mut hasher);
    protocol_id.hash(&mut hasher);
    data.hash(&mut hasher);
    let hash = hasher.result();

    if secure::check_hash(&hash, &sig, &from) {
        Ok((from, to, protocol_id, data))
    } else {
        Err(format_err!("Bad packet signature."))
    }
}

#[cfg(test)]
mod tests {
    use stegos_crypto::pbc::secure;

    #[test]
    fn encode_decode() {
        let seed = random_vec(128);
        let (from_skey, from, _signature) = secure::make_deterministic_keys(&seed);
        let to = secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap();
        let protocol_id = "the quick brown fox".to_string();
        let data = random_vec(1024);

        let encoded =
            super::encode_unicast(from, to, protocol_id.clone(), data.clone(), &from_skey);
        let (from_2, to_2, protocol_id_2, data_2) = super::decode_unicast(encoded).unwrap();

        assert_eq!(from, from_2);
        assert_eq!(to, to_2);
        assert_eq!(protocol_id, protocol_id_2);
        assert_eq!(data, data_2);
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

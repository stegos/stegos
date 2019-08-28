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
use libp2p;
use libp2p_core::multiaddr::Multiaddr;
use libp2p_core::upgrade::{InboundUpgradeExt, OutboundUpgradeExt};
use libp2p_core::{identity, identity::ed25519, transport::TransportError, PeerId, Transport};
use libp2p_core_derive::NetworkBehaviour;
use libp2p_dns as dns;
use libp2p_secio as secio;
use libp2p_swarm::{NetworkBehaviourEventProcess, Swarm};
use libp2p_tcp as tcp;
use libp2p_yamux as yamux;
use log::*;
use protobuf::Message as ProtoMessage;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};
use std::error;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_crypto::utils::u8v_to_hexstr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::NetworkConfig;
use crate::delivery::{Delivery, DeliveryEvent, DeliveryMessage};
use crate::discovery::{Discovery, DiscoveryOutEvent};
use crate::gatekeeper::{Gatekeeper, GatekeeperOutEvent, PeerEvent};
use crate::ncp::{Ncp, NcpOutEvent};
use crate::pubsub::{Floodsub, FloodsubEvent};
use crate::{Network, NetworkProvider, UnicastMessage};

mod proto;
use self::proto::unicast_proto;
use crate::utils::socket_to_multi_addr;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Libp2pNetwork {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

// Allow connection to terminate after that much idle time
pub const NETWORK_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

pub const NETWORK_STATUS_TOPIC: &'static str = "stegos-network-status";
pub const NETWORK_READY_TOKEN: &'static [u8] = &[1, 0, 0, 0];

const IBE_ID: &'static [u8] = &[105u8, 13, 185, 148, 68, 76, 69, 155];

impl Libp2pNetwork {
    pub fn new(
        config: &NetworkConfig,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
    ) -> Result<(Network, impl Future<Item = (), Error = ()>), Error> {
        let (service, control_tx) = new_service(config, network_skey, network_pkey)?;
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
    fn send(&self, to: pbc::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error> {
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

    // Switch to new network keys
    fn change_network_keys(
        &self,
        new_pkey: pbc::PublicKey,
        new_skey: pbc::SecretKey,
    ) -> Result<(), Error> {
        let msg = ControlMessage::ChangeNetworkKeys { new_pkey, new_skey };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }
}

fn new_service(
    config: &NetworkConfig,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
) -> Result<
    (
        impl Future<Item = (), Error = ()>,
        mpsc::UnboundedSender<ControlMessage>,
    ),
    Error,
> {
    let keypair = ed25519::Keypair::generate();
    let local_key = identity::Keypair::Ed25519(keypair);
    let local_pub_key = local_key.public();
    let peer_id = local_pub_key.clone().into_peer_id();

    // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
    let transport = build_tcp_ws_secio_yamux(local_key);

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let behaviour = Libp2pBehaviour::new(
            config,
            network_skey,
            network_pkey,
            local_pub_key.clone().into_peer_id(),
        );

        Swarm::new(transport, behaviour, peer_id)
    };

    if config.endpoint != "" {
        let endpoint = SocketAddr::from_str(&config.endpoint).expect("Invalid endpoint");
        let endpoint = socket_to_multi_addr(&endpoint);
        Swarm::listen_on(&mut swarm, endpoint).unwrap();
    }

    let (control_tx, mut control_rx) = mpsc::unbounded::<ControlMessage>();
    let mut listening = false;
    let service = futures::future::poll_fn(move || -> Result<_, ()> {
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
                Async::Ready(None) | Async::NotReady => {
                    if !listening {
                        if let Some(a) = Swarm::listeners(&swarm).next() {
                            info!(target: "stegos_network", "Starting Network on {:?}", a);
                            listening = true;
                        }
                    }
                    break;
                }
            }
        }
        Ok(Async::NotReady)
    });

    Ok((service, control_tx))
}

#[derive(NetworkBehaviour)]
pub struct Libp2pBehaviour<TSubstream: AsyncRead + AsyncWrite> {
    floodsub: Floodsub<TSubstream>,
    ncp: Ncp<TSubstream>,
    gatekeeper: Gatekeeper<TSubstream>,
    delivery: Delivery<TSubstream>,
    discovery: Discovery<TSubstream>,
    #[behaviour(ignore)]
    consumers: HashMap<String, SmallVec<[mpsc::UnboundedSender<Vec<u8>>; 3]>>,
    #[behaviour(ignore)]
    unicast_consumers: HashMap<String, SmallVec<[mpsc::UnboundedSender<UnicastMessage>; 3]>>,
    #[behaviour(ignore)]
    my_pkey: pbc::PublicKey,
    #[behaviour(ignore)]
    my_skey: pbc::SecretKey,
    #[behaviour(ignore)]
    connected_peers: HashSet<PeerId>,
}

impl<TSubstream> Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    pub fn new(
        config: &NetworkConfig,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        peer_id: PeerId,
    ) -> Self {
        let relaying = if config.advertised_endpoint == "".to_string() {
            false
        } else {
            true
        };
        let behaviour = Libp2pBehaviour {
            floodsub: Floodsub::new(peer_id.clone(), relaying),
            ncp: Ncp::new(config, network_pkey.clone()),
            gatekeeper: Gatekeeper::new(config),
            delivery: Delivery::new(),
            discovery: Discovery::new(network_pkey.clone()),
            consumers: HashMap::new(),
            unicast_consumers: HashMap::new(),
            my_pkey: network_pkey.clone(),
            my_skey: network_skey.clone(),
            connected_peers: HashSet::new(),
        };
        debug!(target: "stegos_network::delivery", "Network endpoints: node_id={}, peer_id={}", network_pkey, peer_id);
        behaviour
    }

    fn process_event(&mut self, msg: ControlMessage) {
        trace!("Control event: {:#?}", msg);
        match msg {
            ControlMessage::Subscribe { topic, handler } => {
                if topic != NETWORK_STATUS_TOPIC {
                    self.consumers
                        .entry(topic.clone())
                        .or_insert(SmallVec::new())
                        .push(handler);
                    self.floodsub.subscribe(topic);
                    return;
                }
                if self.gatekeeper.is_network_ready() {
                    // Err shouldn't happen, since channel is just subscribed
                    if let Err(e) = handler.clone().unbounded_send(NETWORK_READY_TOKEN.to_vec()) {
                        debug!(target: "stegos_network::gatekeeper", "Error sending Network::Ready event: error={}", e);
                    }
                }
                self.consumers
                    .entry(topic.clone())
                    .or_insert(SmallVec::new())
                    .push(handler);
            }
            ControlMessage::Publish { topic, data } => {
                debug!(target: "stegos_network::pubsub",
                    "Sending broadcast message: topic={}, size={}",
                    topic,
                    data.len(),
                );
                self.floodsub.publish(topic, data)
            }
            ControlMessage::ChangeNetworkKeys { new_pkey, new_skey } => {
                debug!(target: "stegos_network::libp2p_network","changing network key: from={}, to={}", self.my_pkey, new_pkey);
                self.ncp.change_network_key(new_pkey.clone());
                self.discovery.change_network_key(new_pkey.clone());
                self.my_pkey = new_pkey;
                self.my_skey = new_skey;
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
                debug!(target: "stegos_network::delivery",
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
                    let payload = UnicastPayload {
                        from: self.my_pkey.clone(),
                        to: to.clone(),
                        protocol_id,
                        data,
                    };
                    let msg = encode_unicast(payload, &self.my_skey);
                    // self.floodsub.publish(floodsub_topic, msg);
                    self.discovery.deliver_unicast(&to, msg);
                }
            }
        }
    }

    fn shutdown(&mut self, peer_id: &PeerId) {
        self.ncp.terminate(peer_id.clone());
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<NcpOutEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, event: NcpOutEvent) {
        match event {
            NcpOutEvent::DialAddress { address } => {
                self.gatekeeper.dial_address(address);
            }
            NcpOutEvent::DialPeer { peer_id } => {
                self.gatekeeper.dial_peer(peer_id);
            }
            NcpOutEvent::Connected { peer_id } => {
                self.connected_peers.insert(peer_id);
            }
            NcpOutEvent::Disconnected { peer_id } => {
                self.connected_peers.remove(&peer_id);
            }
            NcpOutEvent::DiscoveredPeer {
                node_id,
                peer_id,
                addresses,
            } => {
                debug!(target: "stegos_network::discovery", "discovered node: node_id={}, peer_id={}", node_id, peer_id);
                self.discovery.add_node(node_id.clone(), peer_id.clone());
                if addresses.len() > 0 {
                    self.discovery.set_peer_id(&node_id, peer_id.clone());
                    if self.connected_peers.contains(&peer_id) {
                        for a in addresses.iter() {
                            self.discovery.add_connected_address(&node_id, a.clone());
                        }
                    } else {
                        for a in addresses.iter() {
                            self.discovery
                                .add_not_connected_address(&node_id, a.clone());
                        }
                    }
                }
            }
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<FloodsubEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    // Called when `floodsub` produces an event.
    // Send received message to consumers.
    fn inject_event(&mut self, message: FloodsubEvent) {
        match message {
            FloodsubEvent::Message(message) => {
                // ignore messages with NETWORK_STATUS_TOPIC
                if message.topic == NETWORK_STATUS_TOPIC {
                    return;
                }

                debug!(target: "stegos_network::pubsub",
                       "Received broadcast message: topic={}, size={}",
                       &message.topic,
                       message.data.len(),
                );
                let consumers = self
                    .consumers
                    .entry(message.topic)
                    .or_insert(SmallVec::new());
                consumers.retain({
                    let data = &message.data;
                    move |c| {
                        if let Err(e) = c.unbounded_send(data.clone()) {
                            error!(target: "stegos_network::pubsub", "Error sending data to consumer: {}", e);
                            false
                        } else {
                            true
                        }
                    }
                })
            }
            FloodsubEvent::Subscribed { .. } => {}
            FloodsubEvent::Unsubscribed { .. } => {}
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<GatekeeperOutEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, event: GatekeeperOutEvent) {
        match event {
            GatekeeperOutEvent::PrepareListener { peer_id } => {
                self.floodsub.enable_incoming(&peer_id);
                self.gatekeeper
                    .notify(PeerEvent::EnabledListener { peer_id });
            }
            GatekeeperOutEvent::PrepareDialer { peer_id } => {
                self.floodsub.enable_outgoing(&peer_id);
                self.gatekeeper.notify(PeerEvent::EnabledDialer { peer_id });
            }
            GatekeeperOutEvent::Finished { peer_id } => {
                self.floodsub.enable_outgoing(&peer_id);
            }
            GatekeeperOutEvent::NetworkReady => {
                debug!(target: "stegos_network::gatekeeper", "network is ready");
                let consumers = self
                    .consumers
                    .entry(NETWORK_STATUS_TOPIC.to_string())
                    .or_insert(SmallVec::new());
                consumers.retain(move |c| c.unbounded_send(NETWORK_READY_TOKEN.to_vec()).is_ok());
            }
            GatekeeperOutEvent::Message { .. } => {}
            GatekeeperOutEvent::Connected { .. } => {}
            GatekeeperOutEvent::Disconnected { .. } => {}
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<DiscoveryOutEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, event: DiscoveryOutEvent) {
        match event {
            DiscoveryOutEvent::DialPeer { peer_id } => {
                debug!(target: "stegos_network::kad", "connecting to closest peer: {}", peer_id);
                self.gatekeeper.dial_peer(peer_id);
            }
            DiscoveryOutEvent::Route { next_hop, message } => {
                debug!(target: "stegos_network::delivery", "delivering paylod: node_id={}, peer_id={}", message.to, next_hop);
                self.delivery.deliver_unicast(&next_hop, message);
            } // _ => {}
            DiscoveryOutEvent::KadEvent { .. } => {}
        }
    }
}

impl<TSubstream> NetworkBehaviourEventProcess<DeliveryEvent> for Libp2pBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn inject_event(&mut self, event: DeliveryEvent) {
        match event {
            DeliveryEvent::Message(msg) => match msg {
                DeliveryMessage::UnicastMessage(unicast) => {
                    debug!(target: "stegos_network::delivery", "received message: dest={}", unicast.to);
                    // Check for duplicate
                    if self.discovery.is_duplicate(&unicast) {
                        debug!(target: "stegos_network::delivery", "got duplicate unicast message: seq_no={}", u8v_to_hexstr(&unicast.seq_no));
                        return;
                    }
                    if unicast.to == self.my_pkey {
                        // Unicast message to us, deliver
                        debug!(target: "stegos_network::delivery", "message for us, delivering");
                        match decode_unicast(unicast.payload.clone()) {
                            Ok((payload, signature, rval)) => {
                                // send unicast message upstream
                                if payload.to == self.my_pkey {
                                    let payload = match decrypt_message(
                                        &self.my_skey,
                                        payload,
                                        signature,
                                        rval,
                                    ) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            debug!(target: "stegos_network::delivery", "bad unicast message received: {}", e);
                                            return;
                                        }
                                    };
                                    debug!(target: "stegos_network::delivery",
                                        "Received unicast message: from={}, protocol={} size={}",
                                        payload.from,
                                        payload.protocol_id,
                                        payload.data.len()
                                    );
                                    let msg = UnicastMessage {
                                        from: payload.from,
                                        data: payload.data,
                                    };
                                    self.unicast_consumers
                                        .entry(payload.protocol_id)
                                        .or_insert(SmallVec::new())
                                        .retain({
                                            move |c| {
                                                if let Err(e) = c.unbounded_send(msg.clone()) {
                                                    error!(target:"stegos_network::delivery", "Error sending data to consumer: {}", e);
                                                    false
                                                } else {
                                                    true
                                                }
                                            }
                                        })
                                }
                            }
                            Err(e) => error!(target:"stegos_network::delivery", "Failure decoding unicast message: {}", e),
                        }
                        return;
                    }
                    // Mesage to somebody else, try to route again...
                    let dest = unicast.to.clone();
                    self.discovery.route(&dest, unicast);
                }
                DeliveryMessage::BroadcastMessage(_) => unimplemented!(),
            },
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
        to: pbc::PublicKey,
        protocol_id: String,
        data: Vec<u8>,
    },
    SubscribeUnicast {
        protocol_id: String,
        consumer: mpsc::UnboundedSender<UnicastMessage>,
    },
    ChangeNetworkKeys {
        new_pkey: pbc::PublicKey,
        new_skey: pbc::SecretKey,
    },
}

#[derive(Clone, Debug)]
pub struct UnicastPayload {
    from: pbc::PublicKey,
    to: pbc::PublicKey,
    protocol_id: String,
    data: Vec<u8>,
}

// Encode unicast message
fn encode_unicast(payload: UnicastPayload, sign_key: &pbc::SecretKey) -> Vec<u8> {
    let mut msg = unicast_proto::Message::new();

    // NOTE: ibe_encrypt() can fail if payload.to is an invalid PublicKey
    // It should be checked ahead of this place, using PublicKey::decompress()?
    let enc_packet = pbc::ibe_encrypt(&payload.data, &payload.to, IBE_ID).expect("ok");

    let mut hasher = Hasher::new();
    payload.from.hash(&mut hasher);
    payload.to.hash(&mut hasher);
    payload.protocol_id.hash(&mut hasher);
    enc_packet.rval().hash(&mut hasher);
    enc_packet.cmsg().hash(&mut hasher);
    let hash = hasher.result();
    let sig = pbc::sign_hash(&hash, sign_key);

    msg.set_data(enc_packet.cmsg().to_vec());
    msg.set_rval(enc_packet.rval().to_bytes().to_vec());
    msg.set_from(payload.from.to_bytes().to_vec());
    msg.set_to(payload.to.to_bytes().to_vec());
    msg.set_protocol_id(payload.protocol_id.into_bytes().to_vec());
    msg.set_signature(sig.to_bytes().to_vec());

    msg.write_to_bytes()
        .expect("protobuf encoding should never fail")
}

fn decode_unicast(input: Vec<u8>) -> Result<(UnicastPayload, pbc::Signature, pbc::RVal), Error> {
    let mut msg: unicast_proto::Message = protobuf::parse_from_bytes(&input)?;

    let from = pbc::PublicKey::try_from_bytes(&msg.take_from().to_vec())?;
    let to = pbc::PublicKey::try_from_bytes(&msg.take_to().to_vec())?;
    let signature = pbc::Signature::try_from_bytes(&msg.take_signature().to_vec())?;
    let protocol_id_bytes = &msg.get_protocol_id();
    let protocol_id = String::from_utf8(protocol_id_bytes.to_vec())?;
    let data = msg.take_data().to_vec();
    let rval = pbc::RVal::try_from_bytes(&msg.take_rval().to_vec())?;

    let payload = UnicastPayload {
        from,
        to,
        protocol_id,
        data,
    };

    Ok((payload, signature, rval))
}

fn decrypt_message(
    my_skey: &pbc::SecretKey,
    mut payload: UnicastPayload,
    signature: pbc::Signature,
    rval: pbc::RVal,
) -> Result<UnicastPayload, Error> {
    let enc_packet = pbc::EncryptedPacket::new(&payload.to, IBE_ID, &rval, &payload.data);

    let mut hasher = Hasher::new();
    payload.from.hash(&mut hasher);
    payload.to.hash(&mut hasher);
    payload.protocol_id.hash(&mut hasher);
    rval.hash(&mut hasher);
    payload.data.hash(&mut hasher);
    let hash = hasher.result();

    if let Err(_e) = pbc::check_hash(&hash, &signature, &payload.from) {
        return Err(format_err!("Bad packet signature."));
    }

    if let Ok(data) = pbc::ibe_decrypt(&enc_packet, my_skey) {
        // if decrypted fine, check the signature
        payload.data = data;
        Ok(payload)
    } else {
        Err(format_err!("Packet failed to decrypt."))
    }
}

/// Builds an implementation of `Transport` that is suitable for usage with the `Swarm`.
///
/// The implementation supports TCP/IP, WebSockets over TCP/IP, secio as the encryption layer,
/// and mplex or yamux as the multiplexing layer.
///
/// > **Note**: If you ever need to express the type of this `Transport`.
pub fn build_tcp_ws_secio_yamux(
    keypair: identity::Keypair,
) -> impl Transport<
    Output = (
        PeerId,
        impl libp2p_core::muxing::StreamMuxer<
                OutboundSubstream = impl Send,
                Substream = impl Send,
                Error = impl Into<io::Error>,
            > + Send
            + Sync,
    ),
    Error = impl error::Error + Send,
    Listener = impl Send,
    Dial = impl Send,
    ListenerUpgrade = impl Send,
> + Clone {
    CommonTransport::new()
        .with_upgrade(secio::SecioConfig::new(keypair))
        .and_then(move |output, endpoint| {
            let peer_id = output.remote_key.into_peer_id();
            let peer_id2 = peer_id.clone();
            let upgrade = yamux::Config::default()
                // TODO: use a single `.map` instead of two maps
                .map_inbound(move |muxer| (peer_id, muxer))
                .map_outbound(move |muxer| (peer_id2, muxer));
            libp2p_core::upgrade::apply(output.stream, upgrade, endpoint)
                .map(|(id, muxer)| (id, libp2p_core::muxing::StreamMuxerBox::new(muxer)))
        })
        .with_timeout(Duration::from_secs(20))
}

/// Implementation of `Transport` that supports the most common protocols.
///
/// The list currently is TCP/IP, DNS, and WebSockets. However this list could change in the
/// future to get new transports.
#[derive(Debug, Clone)]
struct CommonTransport {
    // The actual implementation of everything.
    inner: CommonTransportInner,
}

type InnerImplementation = dns::DnsConfig<tcp::TcpConfig>;

#[derive(Debug, Clone)]
struct CommonTransportInner {
    inner: InnerImplementation,
}

impl CommonTransport {
    /// Initializes the `CommonTransport`.
    pub fn new() -> CommonTransport {
        let tcp = tcp::TcpConfig::new().nodelay(true);
        let transport = dns::DnsConfig::new(tcp);

        CommonTransport {
            inner: CommonTransportInner { inner: transport },
        }
    }
}

impl Transport for CommonTransport {
    type Output = <InnerImplementation as Transport>::Output;
    type Error = <InnerImplementation as Transport>::Error;
    type Listener = <InnerImplementation as Transport>::Listener;
    type ListenerUpgrade = <InnerImplementation as Transport>::ListenerUpgrade;
    type Dial = <InnerImplementation as Transport>::Dial;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        self.inner.inner.listen_on(addr)
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.inner.inner.dial(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::UnicastPayload;
    use stegos_crypto::pbc;

    #[test]
    fn encode_decode() {
        let (from_skey, from) = pbc::make_random_keys();
        let (to_skey, to) = pbc::make_random_keys();
        let protocol_id = "the quick brown fox".to_string();
        let data = random_vec(1024);

        let payload = UnicastPayload {
            from,
            to,
            protocol_id,
            data,
        };

        let encoded = super::encode_unicast(payload.clone(), &from_skey);
        let (enc_payload, signature, rval) = super::decode_unicast(encoded).unwrap();
        let enc_data = enc_payload.data.clone();
        let payload_2 = super::decrypt_message(&to_skey, enc_payload, signature, rval).unwrap();

        assert_eq!(payload.from, payload_2.from);
        assert_eq!(payload.to, payload_2.to);
        assert_eq!(payload.protocol_id, payload_2.protocol_id);
        assert_eq!(payload.data, payload_2.data);
        assert_ne!(payload.data, enc_data);
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }
}

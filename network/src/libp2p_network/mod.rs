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

use crate::utils;
use std::time::Duration;

use failure::Error;
use futures::channel::{mpsc, oneshot};
use futures::future;
use futures::stream::StreamExt;

pub use libp2p::gossipsub::Topic;
use libp2p::gossipsub::{self, Gossipsub, GossipsubMessage, MessageId};
use libp2p::gossipsub::{GossipsubEvent, TopicHash};
pub use libp2p_core::multiaddr::Multiaddr;
pub use libp2p_core::PeerId;
use libp2p_core::{identity, transport::TransportError, Transport};
use libp2p_core_derive::NetworkBehaviour;
use libp2p_dns as dns;
use libp2p_secio as secio;
use libp2p_swarm::{NetworkBehaviourEventProcess, Swarm, SwarmBuilder};
use libp2p_tcp as tcp;
use log::*;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};
use stegos_crypto::pbc;

use std::net::{SocketAddr, SocketAddrV4};

use std::future::Future;
use std::task::{Context, Poll};

// use protobuf::Message as ProtoMessage;
use crate::config::NetworkConfig;
use std::error;
use std::io;

// use std::time::Duration;
use stegos_crypto::utils::u8v_to_hexstr;
pub mod proto;

use crate::gatekeeper::{Gatekeeper, GatekeeperOutEvent};
use crate::old_protos::delivery::{Delivery, DeliveryEvent, DeliveryMessage};
use crate::old_protos::discovery::{Discovery, DiscoveryOutEvent};
use crate::old_protos::ncp::{Ncp, NcpOutEvent};
use crate::old_protos::pubsub::{Floodsub, FloodsubEvent};

use crate::gatekeeper::{Metadata, NetworkName};
use crate::replication::{Replication, ReplicationEvent};
use crate::{Network, NetworkProvider, NetworkResponse, UnicastMessage};
use libp2p_swarm::PollParameters;
use libp2p_swarm::{
    IntoProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, ProtocolsHandler,
};
use std::collections::VecDeque;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Libp2pNetwork {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

pub const NETWORK_STATUS_TOPIC: &str = "stegos-network-status";
pub const VERSION: u64 = 1;
pub const GOSSIP_VERSION: u64 = 1;
// Max number of topic for one floodsub message.

pub const NETWORK_READY_TOKEN: &[u8] = &[1, 0, 0, 0];
use crate::utils::{encode_unicast, UnicastPayload};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BehaviourEvent {
    BanPeer { peer_id: PeerId },
}

impl Libp2pNetwork {
    pub async fn new(
        mut config: NetworkConfig,
        network_name: NetworkName,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
    ) -> Result<
        (
            Network,
            impl Future<Output = ()>,
            PeerId,
            mpsc::UnboundedReceiver<ReplicationEvent>,
        ),
        Error,
    > {
        // Resolve network.seed_pool.
        config.seed_nodes.extend_from_slice(
            &utils::resolve_seed_nodes(&config.seed_pool, &config.dns_servers).await?,
        );

        let (service, control_tx, peer_id, replication_rx) =
            new_service(&config, network_name, network_skey, network_pkey)?;
        let network = Libp2pNetwork { control_tx };
        Ok((Box::new(network), service, peer_id, replication_rx))
    }
}

impl NetworkProvider for Libp2pNetwork {
    /// Subscribe to topic, returns Stream<Vec<u8>> of messages incoming to topic
    fn subscribe(&self, topic: &str) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let topic = topic.to_owned();
        let (tx, rx) = mpsc::unbounded();
        let msg = ControlMessage::Subscribe { topic, handler: tx };
        self.control_tx.unbounded_send(msg)?;
        Ok(rx)
    }

    /// Published message to topic
    fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), Error> {
        let topic = topic.to_owned();
        let msg = ControlMessage::Publish { topic, data };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    // Subscribe to unicast messages
    fn subscribe_unicast(
        &self,
        protocol_id: &str,
    ) -> Result<mpsc::UnboundedReceiver<UnicastMessage>, Error> {
        let protocol_id: String = protocol_id.into();
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
        let protocol_id: String = protocol_id.into();
        let msg = ControlMessage::SendUnicast {
            to,
            protocol_id,
            data,
        };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    fn replication_connect(&self, peer_id: PeerId) -> Result<(), Error> {
        let msg = ControlMessage::EnableReplicationUpstream { peer_id };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    fn replication_disconnect(&self, peer_id: PeerId) -> Result<(), Error> {
        let msg = ControlMessage::DisableReplicationUpstream { peer_id };
        self.control_tx.unbounded_send(msg)?;
        Ok(())
    }

    fn list_connected_nodes(&self) -> Result<oneshot::Receiver<NetworkResponse>, Error> {
        let (tx, rx) = oneshot::channel::<NetworkResponse>();
        self.control_tx
            .unbounded_send(ControlMessage::ConnectedNodesRequest { tx })?;
        Ok(rx)
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
    network_name: NetworkName,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
) -> Result<
    (
        impl Future<Output = ()>,
        mpsc::UnboundedSender<ControlMessage>,
        PeerId,
        mpsc::UnboundedReceiver<ReplicationEvent>,
    ),
    Error,
> {
    let keypair = utils::ed25519_from_pbc(&network_skey);
    let local_key = identity::Keypair::Ed25519(keypair);
    let local_pub_key = local_key.public();
    let peer_id = local_pub_key.into_peer_id();

    let (replication_tx, replication_rx) = mpsc::unbounded();

    // Set up a an encrypted DNS-enabled TCP Transport over the Mplex and Yamux protocols
    // let transpor t = build_tcp_ws_secio_yamux(local_key);
    let transport = build_tcp_ws_secio_yamux(local_key);
    // Create a Swarm to manage peers and events
    let behaviour = Libp2pBehaviour::new(
        config,
        network_name,
        network_skey,
        network_pkey,
        peer_id.clone(),
        replication_tx,
    );

    let mut swarm = SwarmBuilder::new(transport, behaviour, peer_id.clone())
        .peer_connection_limit(2)
        .build();

    if config.endpoint != "" {
        let endpoint = SocketAddr::from_str(&config.endpoint).expect("Invalid endpoint");
        let endpoint = utils::socket_to_multi_addr(&endpoint);
        info!("Listening addr {}", endpoint);
        Swarm::listen_on(&mut swarm, endpoint).unwrap();
    }

    let (control_tx, mut control_rx) = mpsc::unbounded::<ControlMessage>();
    let mut listening = false;
    for peer in &config.seed_nodes {
        info!("Connecting to peer {}", peer);
        let addr =
            utils::socket_to_multi_addr(&SocketAddr::from_str(&peer).expect("Invalid seed_nodes"));
        Swarm::dial_addr(&mut swarm, addr)?;
    }
    let service = future::poll_fn(move |cx: &mut Context| {
        loop {
            match control_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => swarm.process_event(msg),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }

        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(e)) => match e {
                    BehaviourEvent::BanPeer { peer_id } => {
                        info!(target: "stegos_network", "Ban peer: peer_id={}", peer_id);
                        Swarm::ban_peer_id(&mut swarm, peer_id)
                    }
                },
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {
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

        Poll::Pending
    });

    Ok((service, control_tx, peer_id, replication_rx))
}

#[derive(NetworkBehaviour)]
#[behaviour(poll_method = "poll")]
#[behaviour(out_event = "BehaviourEvent")]
pub struct Libp2pBehaviour {
    // gossipsub: Gossipsub,
    gatekeeper: Gatekeeper, // handshake
    replication: Replication,
    gossipsub: Gossipsub,

    // OLD PROTOS BEGIN
    floodsub: Floodsub,

    ncp: Ncp, // Peer sharing, ping (should be merged with discovery)
    discovery: Discovery,
    delivery: Delivery,

    #[behaviour(ignore)]
    unicast_consumers: HashMap<String, SmallVec<[mpsc::UnboundedSender<UnicastMessage>; 3]>>,
    // OLD PROTOS END
    #[behaviour(ignore)]
    replication_tx: mpsc::UnboundedSender<ReplicationEvent>,
    #[behaviour(ignore)]
    gossip_consumers: HashMap<TopicHash, SmallVec<[mpsc::UnboundedSender<Vec<u8>>; 3]>>,

    #[behaviour(ignore)]
    floodsub_consumers: HashMap<String, SmallVec<[mpsc::UnboundedSender<Vec<u8>>; 3]>>,
    #[behaviour(ignore)]
    my_pkey: pbc::PublicKey,
    #[behaviour(ignore)]
    my_skey: pbc::SecretKey,
    #[behaviour(ignore)]
    connected_peers: HashSet<PeerId>,

    #[behaviour(ignore)]
    events: VecDeque<BehaviourEvent>,

    #[behaviour(ignore)]
    banned_peers: HashSet<PeerId>,
}

impl Libp2pBehaviour {
    pub fn new(
        config: &NetworkConfig,
        network_name: NetworkName,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        peer_id: PeerId,
        replication_tx: mpsc::UnboundedSender<ReplicationEvent>,
    ) -> Self {
        let relaying = config.advertised_endpoint != "";
        let port = if config.endpoint != "" {
            let endpoint = SocketAddrV4::from_str(&config.endpoint).expect("Invalid endpoint");
            endpoint.port()
        } else {
            0
        };
        let metadata = Metadata {
            network: network_name.to_string(),
            version: VERSION,
            port,
        };
        debug!("Network metadata = {:?}", metadata);

        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId(s.finish().to_string())
        };

        // set custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::new()
            .heartbeat_interval(Duration::from_secs(10))
            .public_topics(vec![Topic::new("tx".to_string())]) // TODO: use config based aproach
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
            .max_transmit_size(2048 * 1024) // 2MB;
            //same content will be propagated.
            .build();

        let behaviour = Libp2pBehaviour {
            gossipsub: Gossipsub::new(peer_id.clone(), gossipsub_config),
            gossip_consumers: HashMap::new(),
            my_pkey: network_pkey,
            my_skey: network_skey,
            connected_peers: HashSet::new(),

            ncp: Ncp::new(config, network_pkey),
            floodsub: Floodsub::new(relaying),
            floodsub_consumers: HashMap::new(),
            gatekeeper: Gatekeeper::new(config, metadata),
            delivery: Delivery::new(),
            discovery: Discovery::new(network_pkey),
            replication: Replication::new(),
            replication_tx,
            unicast_consumers: HashMap::new(),
            events: VecDeque::new(),
            banned_peers: HashSet::new(),
        };
        debug!(target: "stegos_network::delivery", "Network endpoints: node_id={}, peer_id={}", network_pkey, peer_id);
        behaviour
    }

    fn process_event(&mut self, msg: ControlMessage) {
        trace!("Control event: {:#?}", msg);
        match msg {
            ControlMessage::Subscribe { topic, handler } => {
                if topic != NETWORK_STATUS_TOPIC {
                    debug!(target: "stegos_network::pubsub",
                        "Subscribing: topic={}",
                        topic,
                    );
                    let gossipsub_topic = Topic::new(topic.clone());
                    self.gossip_consumers
                        .entry(gossipsub_topic.no_hash())
                        .or_insert_with(SmallVec::new)
                        .push(handler.clone());
                    self.floodsub_consumers
                        .entry(topic.clone())
                        .or_insert_with(SmallVec::new)
                        .push(handler);
                    self.gossipsub.subscribe(gossipsub_topic);
                    self.floodsub.subscribe(topic);
                    return;
                }
            }
            ControlMessage::Publish { topic, data } => {
                debug!(target: "stegos_network::pubsub",
                    "Sending broadcast message: topic={}, size={}",
                    topic,
                    data.len(),
                );
                let gossipsub_topic = Topic::new(topic.clone());
                self.gossipsub.publish(&gossipsub_topic, data.clone());
                self.floodsub.publish(topic, data);
            }
            ControlMessage::ChangeNetworkKeys { new_pkey, new_skey } => {
                debug!(target: "stegos_network::libp2p_network","changing network key: from={}, to={}", self.my_pkey, new_pkey);
                error!("Not implemented");
                let _new_pkey = new_pkey;
                let _new_skey = new_skey;
                // unimplemented!();
                // self.ncp.change_network_key(new_pkey.clone());
                // self.discovery.change_network_key(new_pkey.clone());
                // self.my_pkey = new_pkey;
                // self.my_skey = new_skey;
            }
            ControlMessage::SubscribeUnicast {
                protocol_id,
                consumer,
            } => {
                self.unicast_consumers
                    .entry(protocol_id)
                    .or_insert_with(SmallVec::new)
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
                    let msg = UnicastMessage { from: to, data };
                    self.unicast_consumers
                        .entry(protocol_id)
                        .or_insert_with(SmallVec::new)
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
                        from: self.my_pkey,
                        to,
                        protocol_id,
                        data,
                    };
                    let msg = encode_unicast(payload, &self.my_skey);
                    self.discovery.deliver_unicast(&to, msg);
                }
            }
            ControlMessage::EnableReplicationUpstream { peer_id } => {
                self.replication.connect(peer_id);
            }
            ControlMessage::DisableReplicationUpstream { peer_id } => {
                self.replication.disconnect(peer_id);
            }
            ControlMessage::ConnectedNodesRequest { tx } => {
                let nodes = self.ncp.get_connected_nodes();
                if let Err(_v) = tx.send(NetworkResponse::ConnectedNodes { nodes }) {
                    warn!(target: "stegos_network", "Failed send API response for connected nodes");
                }
            }
        }
    }

    fn poll(&mut self,
        _cx: &mut Context,
        _poll_parameters: &mut impl PollParameters) -> Poll<NetworkBehaviourAction<
        <<<Self as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::InEvent, <Self as NetworkBehaviour>::OutEvent>,>
    {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
        }

        Poll::Pending
    }

    // fn shutdown(&mut self, peer_id: &PeerId) {
    //     self.ncp.terminate(peer_id.clone());
    // }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Libp2pBehaviour {
    // Called when `floodsub` produces an event.
    // Send received message to consumers.
    fn inject_event(&mut self, message: GossipsubEvent) {
        match message {
            GossipsubEvent::Message(_peer_id, _message_id, message) => {
                debug!("Receiving floodsub message {:?}", message);
                // ignore messages with NETWORK_STATUS_TOPIC or if use send to many topics
                if message.topics.len() > 1
                    || message
                        .topics
                        .iter()
                        .any(|t| t.as_str() == NETWORK_STATUS_TOPIC)
                {
                    return;
                }
                let topic = message.topics[0].clone();
                debug!(target: "stegos_network::gossip",
                       "Received broadcast message: topic={}, size={}",
                       topic.as_str(),
                       message.data.len(),
                );
                let consumers = self
                    .gossip_consumers
                    .entry(topic)
                    .or_insert_with(SmallVec::new);
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
            GossipsubEvent::Subscribed { .. } => info!("Subsribed"),
            GossipsubEvent::Unsubscribed { .. } => info!("UnSubsribed"),
        }
    }
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for Libp2pBehaviour {
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
                    .floodsub_consumers
                    .entry(message.topic)
                    .or_insert_with(SmallVec::new);
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

#[derive(Debug)]
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
    EnableReplicationUpstream {
        peer_id: PeerId,
    },
    DisableReplicationUpstream {
        peer_id: PeerId,
    },
    ConnectedNodesRequest {
        tx: oneshot::Sender<NetworkResponse>,
    },
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
    let mut mplex_config = libp2p_mplex::MplexConfig::new();
    mplex_config.max_buffer_len_behaviour(libp2p_mplex::MaxBufferBehaviour::Block);
    mplex_config.max_substreams(256);
    // let mut yamux_config = yamux::Config::default();
    // yamux_config.set_window_update_mode(yamux::WindowUpdateMode::OnRead);
    // yamux_config.set_read_after_close(true);
    // let yamux_config = libp2p_yamux::Config::new(yamux_config);
    CommonTransport::new()
        .upgrade(libp2p_core::upgrade::Version::V1)
        .authenticate(secio::SecioConfig::new(keypair))
        .multiplex(mplex_config)
        // .multiplex(yamux_config)
        .map(|(peer, muxer), _| (peer, libp2p_core::muxing::StreamMuxerBox::new(muxer)))
        .timeout(Duration::from_secs(20))
}

impl NetworkBehaviourEventProcess<NcpOutEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: NcpOutEvent) {
        match event {
            NcpOutEvent::DialAddress { address } => {
                self.gatekeeper.dial_address(address);
            }
            NcpOutEvent::DialPeer { peer_id } => {
                debug!(target: "stegos_network::ncp", "ncp request connect to peer: {}", peer_id);
                if self.banned_peers.contains(&peer_id) {
                    debug!(target: "stegos_network::ncp", "peer banned, dont connect: {}", peer_id);
                } else {
                    self.gatekeeper.dial_peer(peer_id);
                }
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
                if !addresses.is_empty() {
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

impl NetworkBehaviourEventProcess<GatekeeperOutEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: GatekeeperOutEvent) {
        match event {
            GatekeeperOutEvent::PrepareListener { peer_id } => {
                self.gatekeeper.enable_listener(peer_id);
            }
            GatekeeperOutEvent::PrepareDialer { peer_id, version } => {
                if version < GOSSIP_VERSION {
                    self.floodsub.enable_incoming(&peer_id);
                    self.floodsub.enable_outgoing(&peer_id);
                }

                if version >= GOSSIP_VERSION {
                    self.gossipsub.add_peer_whitelist(peer_id.clone());
                }

                self.gatekeeper.enable_dialer(peer_id);
            }
            GatekeeperOutEvent::UnlockedDialer { peer_id } => {
                self.floodsub.enable_outgoing(&peer_id);
            }
            GatekeeperOutEvent::NetworkReady => {
                debug!(target: "stegos_network::gatekeeper", "network is ready");
                let consumers = self
                    .floodsub_consumers
                    .entry(NETWORK_STATUS_TOPIC.to_string())
                    .or_insert_with(SmallVec::new);
                consumers.retain(move |c| c.unbounded_send(NETWORK_READY_TOKEN.to_vec()).is_ok());
            }

            GatekeeperOutEvent::BanPeer { peer_id } => {
                self.events.push_back(BehaviourEvent::BanPeer { peer_id })
            }
        }
    }
}

impl NetworkBehaviourEventProcess<DiscoveryOutEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: DiscoveryOutEvent) {
        match event {
            DiscoveryOutEvent::DialPeer { peer_id } => {
                debug!(target: "stegos_network::kad", "connecting to closest peer: {}", peer_id);
                if self.banned_peers.contains(&peer_id) {
                    debug!(target: "stegos_network::kad", "peer banned, dont connect: {}", peer_id);
                } else {
                    self.gatekeeper.dial_peer(peer_id);
                }
            }
            DiscoveryOutEvent::Route { next_hop, message } => {
                debug!(target: "stegos_network::delivery", "delivering paylod: node_id={}, peer_id={}", message.to, next_hop);
                self.delivery.deliver_unicast(&next_hop, message);
            } // _ => {}
            DiscoveryOutEvent::KadEvent { .. } => {}
        }
    }
}

impl NetworkBehaviourEventProcess<DeliveryEvent> for Libp2pBehaviour {
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
                        match utils::decode_unicast(unicast.payload) {
                            Ok((payload, signature, rval)) => {
                                // send unicast message upstream
                                if payload.to == self.my_pkey {
                                    let payload = match utils::decrypt_message(
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
                                        .or_insert_with(SmallVec::new)
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
                            Err(e) => {
                                error!(target:"stegos_network::delivery", "Failure decoding unicast message: {}", e)
                            }
                        }
                        return;
                    }
                    // Mesage to somebody else, try to route again...
                    let dest = unicast.to;
                    self.discovery.route(&dest, unicast);
                }
                DeliveryMessage::BroadcastMessage(_) => unimplemented!(),
            },
        }
    }
}

impl NetworkBehaviourEventProcess<ReplicationEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: ReplicationEvent) {
        trace!(target: "stegos_network::replication", "Received event: event={:?}", event);
        if let Err(_e) = self.replication_tx.unbounded_send(event) {
            error!("Failed to send replication event");
        }
    }
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
        let transport = dns::DnsConfig::new(tcp).expect("cannot init dns.");

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
        let (enc_payload, signature, rval) = crate::utils::decode_unicast(encoded).unwrap();
        let enc_data = enc_payload.data.clone();
        let payload_2 =
            crate::utils::decrypt_message(&to_skey, enc_payload, signature, rval).unwrap();

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

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

use failure::{format_err, Error, Fail};
use fnv::FnvHashMap;
use futures::future::{select_all, Either, Future};
use futures::sync::mpsc;
use futures::Stream;
use ipnetwork::IpNetwork;
use libp2p::core::{either::EitherOutput, swarm, upgrade};
use libp2p::core::{Multiaddr, Transport};
use libp2p::floodsub;
use libp2p::mplex;
use libp2p::multiaddr::{Protocol, ToMultiaddr};
use libp2p::peerstore::{memory_peerstore, PeerAccess, PeerId, Peerstore};
use libp2p::secio::{SecioConfig, SecioKeyPair, SecioOutput};
use libp2p::tcp::TcpConfig;
use log::*;
use parking_lot::RwLock;
use pnet::datalink;
use std::collections::HashSet;
use std::io::Error as IoError;
use std::sync::Arc;
use std::time::Duration;
use stegos_config::ConfigNetwork;
use stegos_keychain::KeyChain;
use tokio::timer::Interval;

pub mod broker;
pub mod heartbeat;

use self::heartbeat::HeartbeatUpdate;
use super::ncp::{handler::ncp_handler, protocol::NcpProtocolConfig};

#[derive(Clone)]
pub struct Network {
    pub(crate) inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Fail)]
pub enum NetworkError {
    #[fail(display = "Broker not yet initialized")]
    NoBroker,
    #[fail(display = "Heartbeat not yet initialized")]
    NoHeartbeat,
}

pub(crate) struct Inner {
    // Our config
    pub(crate) config: ConfigNetwork,
    // FloodSubController refernce for message publishing
    floodsub_ctl: Option<floodsub::FloodSubController>,
    // Channel for outbound dial
    dial_tx: Option<mpsc::UnboundedSender<Multiaddr>>,
    // Channel for outbound NCP dial
    dial_ncp_tx: Option<mpsc::UnboundedSender<Multiaddr>>,
    // Active floodsub connections with a remote.
    pub(crate) floodsub_connections: HashSet<PeerId>,
    // All remote connections
    pub(crate) remote_connections: FnvHashMap<Multiaddr, RemoteInfo>,
    // Node's PeerId
    pub(crate) peer_id: PeerId,
    // PeerStore for known Peers
    pub(crate) peer_store: Arc<memory_peerstore::MemoryPeerstore>,
    // BrokerHandle to create subscriptions to new Protocols.
    pub(crate) broker_handle: Option<broker::Broker>,
    // Heartbeat Handle to create susbcriptions to Heartbeat Updates
    pub(crate) heartbeat_handle: Option<heartbeat::Heartbeat>,
    // This node's public key
    pub(crate) public_key: heartbeat::NodePublicKey,
    // This node's public key
    pub(crate) secret_key: heartbeat::NodeSecretKey,
    // Extra info
    pub(crate) extra_info: heartbeat::ExtraInfo,
}

// TODO
pub(crate) struct RemoteInfo {
    pub(crate) peer_id: PeerId,
}

impl Network {
    pub fn new(
        cfg: &ConfigNetwork,
        keychain: &KeyChain,
    ) -> Result<(Network, impl Future<Item = (), Error = ()>, broker::Broker), Error> {
        let sec_secret_key = keychain.generate_secp256k1_keypair()?.0;
        // Generate new key on startup, and init peer_id.
        let keypair = SecioKeyPair::secp256k1_raw_key(&sec_secret_key[..])
            .map_err(|e| format_err!("Couldn't produce SecioKeyPair key, reason = {}", e))?;
        let my_id = keypair.to_peer_id();

        let inner = Arc::new(RwLock::new(Inner {
            config: cfg.clone(),
            floodsub_ctl: None,
            dial_tx: None,
            dial_ncp_tx: None,
            floodsub_connections: HashSet::new(),
            remote_connections: FnvHashMap::default(),
            peer_id: my_id,
            peer_store: Arc::new(memory_peerstore::MemoryPeerstore::empty()),
            broker_handle: None,
            heartbeat_handle: None,
            public_key: keychain.cosi_pkey.clone(),
            secret_key: keychain.cosi_skey.clone(),
            extra_info: heartbeat::ExtraInfo::default(),
        }));

        let node = Network { inner };
        let (service, broker) = node.run(keypair)?;
        Ok((node, service, broker))
    }

    pub fn dial(&self, target: Multiaddr) -> Result<(), Error> {
        let inner2 = &self.inner.clone();
        let inner = inner2.read();
        debug!("*Dialing FloodSub {}*", target);
        if let Some(dial_tx) = inner.dial_tx.clone() {
            dial_tx.unbounded_send(target)?;
        };
        Ok(())
    }

    pub fn dial_ncp(&self, target: Multiaddr) -> Result<(), Error> {
        let inner2 = &self.inner.clone();
        let inner = inner2.read();
        debug!("*Dialing NCP {}*", target);
        if let Some(dial_tx) = inner.dial_ncp_tx.clone() {
            dial_tx.unbounded_send(target)?;
        };
        Ok(())
    }

    pub fn subscribe_heartbeat(&self) -> Result<mpsc::UnboundedReceiver<HeartbeatUpdate>, Error> {
        let inner_ = &self.inner.clone();
        let inner = inner_.read();
        if inner.heartbeat_handle.is_none() {
            return Err(Error::from(NetworkError::NoHeartbeat));
        }
        // None case is out of the way, can unwrap safely
        inner.heartbeat_handle.clone().unwrap().subscribe()
    }

    /// Creates node futures.
    /// Accept node keypair in libp2p_secio format.
    ///
    /// Returns tuple (node_future, broker_handler)
    /// * node_future should be run to completion for network machinery to work
    /// * broker_handler manages subscriptions to topics
    ///
    fn run(
        &self,
        keypair: SecioKeyPair,
    ) -> Result<(impl Future<Item = (), Error = ()>, broker::Broker), Error> {
        let inner = self.inner.clone();
        let (config, my_id) = {
            let inner = inner.read();
            (inner.config.clone(), inner.peer_id.clone())
        };
        let mut bind_ip = Multiaddr::from(Protocol::Ip4(config.bind_ip.clone().parse()?));
        bind_ip.append(Protocol::Tcp(config.bind_port));

        let listen_addr = bind_ip;

        // We start by creating a `TcpConfig` that indicates that we want TCP/IP.
        let transport = TcpConfig::new()
            .with_upgrade({
                let secio = SecioConfig::new(keypair);

                upgrade::map_with_addr(secio, {
                    let inner = inner.clone();
                    move |out: SecioOutput<_>, addr| {
                        let peer_info = RemoteInfo {
                            peer_id: out.remote_key.into_peer_id(),
                        };
                        debug!(
                            "new connection with peer: {}. addr: {}",
                            peer_info.peer_id.to_base58(),
                            addr.to_string()
                        );
                        let mut inner = inner.write();
                        inner.remote_connections.insert(addr.clone(), peer_info);
                        out.stream
                    }
                })
            })
            // On top of secio, we will use the multiplex protocol.
            .with_upgrade(mplex::MplexConfig::new())
            // The object returned by the call to `with_upgrade(MplexConfig::new())` can't be used as a
            // `Transport` because the output of the upgrade is not a stream but a controller for
            // muxing. We have to explicitly call `into_connection_reuse()` in order to turn this into
            // a `Transport`.
            .map(|val, _| ((), val))
            .into_connection_reuse()
            .map(|((), val), _| val);

        // We now have a `transport` variable that can be used either to dial nodes or listen to
        // incoming connections, and that will automatically apply secio and multiplex on top
        // of any opened stream.

        // We now prepare the protocol that we are going to negotiate with nodes that open a connection
        // or substream to our server.

        populate_peerstore(inner.clone())?;
        {
            // Only for testing, will go away when we have proper protocol for peer info exchange
            let inner = inner.read();
            dump_peerstore(&*inner.peer_store)?;
        }
        let (floodsub_upgrade, floodsub_rx) = floodsub::FloodSubUpgrade::new(my_id);

        // Prepare transports for muxing
        let flood_upgrade = upgrade::map(floodsub_upgrade.clone(), |fs| EitherOutput::First(fs));
        let ncp_upgrade = upgrade::map(NcpProtocolConfig {}, |ncp| EitherOutput::Second(ncp));

        let muxed_transport = transport
            .clone()
            .with_upgrade(upgrade::or(flood_upgrade.clone(), ncp_upgrade.clone()));

        // Let's put this `transport` into a *swarm*. The swarm will handle all the incoming and
        // outgoing connections for us.
        let (swarm_controller, swarm_future) = swarm(muxed_transport.clone(), {
            let inner = inner.clone();
            move |socket, addr| {
                let inner = inner.clone();
                match socket {
                    EitherOutput::First(floodsub) => Either::A(
                        addr.and_then(move |addr| floodsub_handler(floodsub, addr, inner)),
                    ),
                    EitherOutput::Second(ncp) => {
                        debug!("Successfully negotiated NCP protocol");
                        debug!("Endpoint: {:?}", ncp.0);
                        Either::B(addr.and_then(move |addr| ncp_handler(ncp.1, ncp.0, addr, inner)))
                    }
                }
            }
        });

        let address = swarm_controller.listen_on(listen_addr);
        debug!("Now listening on {:?}", address);

        let floodsub_ctl = floodsub::FloodSubController::new(&floodsub_upgrade);

        for addr in config.seed_nodes.iter() {
            debug!("Dialing peer with address {}", addr);
            match addr.parse::<Multiaddr>() {
                Ok(maddr) => {
                    if let Err(e) = swarm_controller
                        .dial(maddr, transport.clone().with_upgrade(flood_upgrade.clone()))
                    {
                        error!("failed to floodsub dial node: {}", e);
                    }
                }
                Err(e) => error!("failed to parse address: {}, error: {}", addr, e),
            }
        }

        let (dial_tx, dial_rx) = mpsc::unbounded();
        let dialer = dial_rx.for_each({
            let swarm_controller2 = swarm_controller.clone();
            let transport2 = transport.clone();
            move |msg| {
                debug!("inner: *Dialing FloodSub: {}*", msg);
                if let Err(e) = swarm_controller2
                    .dial(msg, transport2.clone().with_upgrade(flood_upgrade.clone()))
                {
                    error!("failed to dial node: {}", e);
                }
                Ok(())
            }
        });

        let (dial_ncp_tx, dial_ncp_rx) = mpsc::unbounded();
        let dialer_ncp = dial_ncp_rx.for_each({
            let swarm_controller2 = swarm_controller.clone();
            let transport2 = transport.clone();
            move |msg| {
                debug!("inner: *Dialing NCP: {}*", msg);
                if let Err(e) = swarm_controller2
                    .dial(msg, transport2.clone().with_upgrade(ncp_upgrade.clone()))
                {
                    error!("failed to dial node: {}", e);
                }
                Ok(())
            }
        });

        let local_pkey = inner.read().public_key.clone();
        let (broker_service, broker) =
            broker::Broker::new(local_pkey, floodsub_rx, floodsub_ctl.clone());
        {
            let mut inner = inner.write();
            inner.dial_ncp_tx = Some(dial_ncp_tx);
            inner.dial_tx = Some(dial_tx);
            inner.floodsub_ctl = Some(floodsub_ctl.clone());
            inner.broker_handle = Some(broker.clone());
        }
        let (heartbeat_service, heartbeat) = heartbeat::Heartbeat::new(inner.clone())?;
        inner.write().heartbeat_handle = Some(heartbeat.clone());

        let monitor = Interval::new_interval(Duration::from_secs(config.monitoring_interval))
            .for_each({
                let inner = inner.clone();
                move |_| {
                    if let Err(e) = connection_monitor(inner.clone()) {
                        debug!("Error from connection monitorng: {}", e);
                    };
                    Ok(())
                }
            });

        // TODO: handle intenal errors properly
        let mut services: Vec<Box<dyn Future<Item = (), Error = ()> + Send>> = vec![];
        services.push(Box::new(dialer) as Box<dyn Future<Item = (), Error = ()> + Send>);
        services.push(Box::new(dialer_ncp) as Box<dyn Future<Item = (), Error = ()> + Send>);
        services.push(
            Box::new(monitor.map_err(|_| ())) as Box<dyn Future<Item = (), Error = ()> + Send>
        );
        services.push(Box::new(broker_service) as Box<dyn Future<Item = (), Error = ()> + Send>);
        services.push(Box::new(heartbeat_service) as Box<dyn Future<Item = (), Error = ()> + Send>);
        let service_future = select_all(services).map(|(_, _, _)| ());

        let final_fut = swarm_future
            .for_each(|_| Ok(()))
            .select(service_future.map_err(|_| unreachable!()))
            .map(|_| ())
            .map_err(|_| ());

        Ok((final_fut, broker))
    }
}

fn floodsub_handler(
    socket: floodsub::FloodSubFuture,
    addr: Multiaddr,
    node: Arc<RwLock<Inner>>,
) -> Box<dyn Future<Item = (), Error = IoError> + Send> {
    let inner = node.clone();
    {
        let mut inner = inner.write();
        let peer_id = inner.remote_connections.get(&addr).unwrap().peer_id.clone();
        inner.floodsub_connections.insert(peer_id);
    }
    debug!("Successfully negotiated floodsub protocol with: {}", addr);
    // Request peers list from remote
    //
    {
        let inner = inner.read();
        if let Some(ref dial_tx) = inner.dial_ncp_tx {
            if let Err(e) = dial_tx.unbounded_send(addr.clone()) {
                error!("Error trying to dial NCP to {}, error: {}", addr, e);
            };
        }
    }
    let socket = socket.then({
        let inner = inner.clone();
        move |res| {
            let mut inner = inner.write();
            let peer_id = inner.remote_connections.get(&addr).unwrap().peer_id.clone();
            inner.floodsub_connections.remove(&peer_id);
            match res {
                Ok(_) => {
                    debug!("Floodsub successfully finished with: {}", addr);
                    Ok(())
                }
                Err(e) => {
                    debug!("Floodsub with {} finished with error: {}", addr, e);
                    Ok(())
                }
            }
        }
    });

    Box::new(socket) as Box<dyn Future<Item = (), Error = IoError> + Send>
}

pub(crate) fn populate_peerstore(node: Arc<RwLock<Inner>>) -> Result<(), Error> {
    let inner = node.clone();
    let config = {
        let inner = inner.read();
        inner.config.clone()
    };

    let ifaces = datalink::interfaces();
    let mut my_addresses: Vec<Multiaddr> = vec![];

    for addr in config.advertised_addresses.into_iter() {
        match addr.parse() {
            Ok(maddr) => my_addresses.push(maddr),
            Err(e) => error!("error parsing multiaddr: {} error: {}", addr, e),
        }
    }

    let bind_port = config.bind_port;

    if config.advertise_local_ips {
        let ips: Vec<IpNetwork> = ifaces
            .into_iter()
            .filter(|ref i| i.is_up() && !i.is_loopback())
            .flat_map(|ref i| i.ips.clone())
            .filter(|ref ip| ip.is_ipv4())
            .collect();

        let mut multiaddresses: Vec<Multiaddr> = ips
            .clone()
            .into_iter()
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

    // Add addresses to peer store
    {
        let inner = inner.read();
        // TODO: setup reasonable duration
        let ttl = Duration::from_secs(100 * 365 * 24 * 3600);

        let peer_id = inner.peer_id.clone();
        let peer_store = &inner.peer_store;
        let mut peer = peer_store.peer_or_create(&peer_id);
        peer.add_addrs(my_addresses, ttl)
    }

    Ok(())
}

fn dump_peerstore<T>(peerstore: T) -> Result<(), Error>
where
    T: Peerstore + Clone,
{
    debug!("Peerstore dump:");
    let peers = peerstore.clone();

    for peer in peers.peers() {
        debug!("\tPeerID: {}", peer.to_base58());
        let peer_store = peerstore.clone();
        for addr in peer_store.peer_or_create(&peer).addrs() {
            debug!("\t\tAddress: {}", addr)
        }
    }
    Ok(())
}

fn connection_monitor(node: Arc<RwLock<Inner>>) -> Result<(), Error> {
    let inner = node.clone();
    let config = {
        let inner = node.read();
        inner.config.clone()
    };
    debug!("Monitoring TICK!");
    {
        let inner = inner.read();
        if inner.floodsub_connections.len() < config.min_connections {
            let peers = inner.peer_store.clone();

            for p in peers.peers().into_iter() {
                if inner.peer_id == p {
                    continue;
                };

                for a in peers.peer_or_create(&p).addrs().into_iter() {
                    let a_ = a.clone();
                    if !inner.floodsub_connections.contains(&p) {
                        // When floodsub connection is established, it will also be queried for peers
                        if let Some(ref dial_tx) = inner.dial_tx {
                            dial_tx.unbounded_send(a)?;
                        }
                    } else {
                        if let Some(ref dial_tx) = inner.dial_ncp_tx {
                            dial_tx.unbounded_send(a_)?;
                        }
                    }
                }
            }
        };
    }
    Ok(())
}

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

// #![deny(warnings)]

use failure::Error;
use fnv::FnvHashMap;
use futures::future::{loop_fn, Either, Future, Loop};
use futures::sync::mpsc;
use futures::{IntoFuture, Sink, Stream};
use ipnetwork::IpNetwork;
use libp2p::core::{either::EitherOutput, swarm, upgrade};
use libp2p::core::{Multiaddr, PublicKey, Transport};
use libp2p::floodsub;
use libp2p::mplex;
use libp2p::multiaddr::{Protocol, ToMultiaddr};
use libp2p::peerstore::{memory_peerstore, PeerAccess, PeerId, Peerstore};
use libp2p::secio::{SecioConfig, SecioKeyPair, SecioOutput};
use libp2p::tcp::TcpConfig;
use parking_lot::RwLock;
use pnet::datalink;
use slog::Logger;
use std::fs::File;
use std::io::Error as IoError;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use stegos_config::ConfigNetwork;

// use super::{echo::handler::handler as echo_handler, EchoUpgrade};
use super::ncp::protocol::{NcpMsg, NcpProtocolConfig};

#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<RwLock<Inner>>,
}

pub(crate) struct Inner {
    // Our config
    pub(crate) config: ConfigNetwork,
    // FloodSubController refernce for message publishing
    floodsub_ctl: Option<floodsub::FloodSubController>,
    // FloodSub topic used for communications
    floodsub_topic: Option<floodsub::Topic>,
    // Channel for outbound dial
    dial_tx: Option<mpsc::UnboundedSender<Multiaddr>>,
    // Active floodsub connections with a remote.
    pub(crate) floodsub_connections: Vec<Multiaddr>,
    // All remote connections
    pub(crate) remote_connections: FnvHashMap<Multiaddr, RemoteInfo>,
    // Node's PeerId
    peer_id: Option<PeerId>,
    // PeerStore for known Peers
    peer_store: Arc<memory_peerstore::MemoryPeerstore>,
    // Logger for the Node
    pub(crate) logger: Logger,
}

// TODO
pub(crate) struct RemoteInfo {
    pub(crate) peer_id: PeerId,
}

impl Node {
    pub fn new(cfg: &ConfigNetwork, logger: &Logger) -> Self {
        let inner = Arc::new(RwLock::new(Inner {
            config: cfg.clone(),
            floodsub_ctl: None,
            floodsub_topic: None,
            dial_tx: None,
            floodsub_connections: Vec::new(),
            remote_connections: FnvHashMap::default(),
            peer_id: None,
            peer_store: Arc::new(memory_peerstore::MemoryPeerstore::empty()),
            logger: logger.new(o!("module" => "node")),
        }));

        let node = Node { inner };
        node
    }

    pub fn dial(&self, target: Multiaddr) -> Result<(), Error> {
        let inner2 = &self.inner.clone();
        let inner = inner2.read();
        debug!(inner.logger, "*Dialing {}*", target);
        if let Some(dial_tx) = inner.dial_tx.clone() {
            dial_tx.unbounded_send(target)?;
        };
        Ok(())
    }

    pub fn publish(&self, data: Vec<u8>) -> Result<(), Error> {
        let inner2 = &self.inner.clone();
        let inner = inner2.read();
        debug!(
            inner.logger,
            "publishing message: {}*",
            String::from_utf8_lossy(&data)
        );
        if let Some(topic) = &inner.floodsub_topic {
            if let Some(floodsub_ctl) = &inner.floodsub_ctl {
                floodsub_ctl.publish(topic, data)
            }
        }
        Ok(())
    }

    pub fn set_id<S>(&self, id: &S)
    where
        S: Into<String> + Clone,
    {
        let id: String = id.clone().into();
        let topic = floodsub::TopicBuilder::new(id).build();
        let inner = self.inner.read();
        if let Some(floodsub_ctl) = inner.floodsub_ctl.clone() {
            floodsub_ctl.subscribe(&topic);
        }
    }

    pub fn send_to_id<S>(&self, id: &S, data: Vec<u8>) -> Result<(), Error>
    where
        S: Into<String> + Clone,
    {
        let id: String = id.clone().into();
        let topic = floodsub::TopicBuilder::new(id).build();
        let inner = self.inner.read();
        if let Some(floodsub_ctl) = inner.floodsub_ctl.clone() {
            floodsub_ctl.publish(&topic, data);
        }
        Ok(())
    }

    pub fn run(
        &self,
    ) -> Result<
        (
            Box<Future<Item = (), Error = ()> + Send + 'static>,
            Box<Stream<Item = Vec<u8>, Error = ()> + Send>,
        ),
        Error,
    > {
        let inner = self.inner.clone();
        let config = {
            let inner = inner.read();
            inner.config.clone()
        };
        let mut bind_ip = Multiaddr::from(Protocol::Ip4(config.bind_ip.clone().parse()?));
        bind_ip.append(Protocol::Tcp(config.bind_port));

        let listen_addr = bind_ip;
        let private_key = key_from_file(&config.private_key)?;
        let public_key = key_from_file(&config.public_key)?;
        let netlog = {
            let inner = inner.read();
            &inner.logger.clone()
        };

        // We start by creating a `TcpConfig` that indicates that we want TCP/IP.
        let transport = TcpConfig::new()
            .with_upgrade({
                let secio = {
                    let keypair =
                        SecioKeyPair::rsa_from_pkcs8(private_key.as_slice(), public_key.clone())
                            .unwrap();
                    SecioConfig::new(keypair)
                };

                upgrade::map_with_addr(secio, {
                    let nl2 = netlog.clone();
                    let inner = inner.clone();
                    move |out: SecioOutput<_>, addr| {
                        let peer_info = RemoteInfo {
                            peer_id: out.remote_key.into_peer_id(),
                        };
                        debug!(nl2, "new connection";
                                "remote_peer_id" => peer_info.peer_id.to_base58(),
                                "remote_addr" => addr.to_string());
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
        // let my_id = PeerId::from_public_key(PublicKey::Rsa(key_from_file(&cfg.public_key)?))
        let my_id = PeerId::from_public_key(PublicKey::Rsa(public_key));
        {
            let mut inner = inner.write();
            inner.peer_id = Some(my_id.clone());
        }

        populate_peerstore(inner.clone())?;
        {
            // Only for testing, will go away when we have proper protocol for peer info exchange
            let inner = inner.read();
            dump_peerstore(&*inner.peer_store)?;
        }
        let (floodsub_upgrade, floodsub_rx) = floodsub::FloodSubUpgrade::new(my_id);

        // Prepare transports for muxing
        let flood_upgrade = upgrade::map(floodsub_upgrade.clone(), |fs| EitherOutput::First(fs));
        let echo_upgrade = upgrade::map(NcpProtocolConfig {}, |echo| EitherOutput::Second(echo));

        let muxed_transport = transport
            .clone()
            .with_upgrade(upgrade::or(flood_upgrade.clone(), echo_upgrade.clone()));

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
                    EitherOutput::Second(echo) => {
                        println!("Successfully negotiated echo protocol");
                        println!("Endpoint: {:?}", echo.0);
                        Either::B(loop_fn(echo.1, move |socket| {
                            socket
                                .into_future()
                                .map_err(|(e, _)| e)
                                .and_then(move |(msg, rest)| {
                                    if let Some(msg) = msg {
                                        // One message has been received. We send it back to the client.
                                        println!(
                                            "Received a message: {:?}\n => Sending back \
                                             identical message to remote",
                                            msg
                                        );
                                        match msg {
                                            NcpMsg::Ping { ping_data } => {
                                                let resp = NcpMsg::Pong { ping_data };
                                                Box::new(rest.send(resp).map(|m| Loop::Continue(m)))
                                                    as Box<Future<Item = _, Error = _> + Send>
                                            }
                                            _ => unimplemented!(),
                                        }
                                    } else {
                                        // End of stream. Connection closed. Breaking the loop.
                                        println!("Received EOF\n => Dropping connection");
                                        Box::new(Ok(Loop::Break(())).into_future())
                                            as Box<Future<Item = _, Error = _> + Send>
                                    }
                                })
                        }))
                    }
                }
            }
        });

        let address = swarm_controller.listen_on(listen_addr);
        debug!(netlog, "Now listening on {:?}", address);

        let topic = floodsub::TopicBuilder::new(config.broadcast_topic.as_str()).build();

        let floodsub_ctl = floodsub::FloodSubController::new(&floodsub_upgrade);
        floodsub_ctl.subscribe(&topic);
        {
            let mut inner = inner.write();
            inner.floodsub_ctl = Some(floodsub_ctl.clone());
            inner.floodsub_topic = Some(topic.clone());
        }

        for addr in config.seed_nodes.iter() {
            debug!(netlog, "Dialing peer"; "address" => addr);
            match addr.parse() {
                Ok(maddr) => if let Err(e) = swarm_controller
                    .dial(maddr, transport.clone().with_upgrade(flood_upgrade.clone()))
                {
                    error!(netlog, "failed to dial node!"; "Error" => e.to_string());
                },
                Err(e) => {
                    error!(netlog, "failed to parse address: {}", addr; "Error" => e.to_string())
                }
            }
        }

        let (dial_tx, dial_rx) = mpsc::unbounded();
        let dialer = dial_rx.for_each({
            let nl2 = netlog.clone();
            move |msg| {
                debug!(nl2, "inner: *Dialing {}*", msg);
                if let Err(e) = swarm_controller
                    .dial(msg, transport.clone().with_upgrade(flood_upgrade.clone()))
                {
                    error!(nl2, "failed to dial node!"; "Error" => e.to_string());
                }
                Ok(())
            }
        });
        {
            let mut inner = inner.write();
            inner.dial_tx = Some(dial_tx);
        }

        // TODO: handle intenal errors properly
        let final_fut = swarm_future
            .for_each(|_| Ok(()))
            .select(dialer.map_err(|_| unreachable!()))
            .map(|_| ())
            .map_err(|_| ());

        let node_rx = Box::new(floodsub_rx.map(|msg| msg.data).map_err({
            let netlog = netlog.clone();
            move |e| {
                error!(&netlog, "error receiving message"; "Error" => e.to_string());
            }
        }));
        let boxed_future =
            Box::new(final_fut) as Box<Future<Item = (), Error = ()> + Send + 'static>;
        Ok((boxed_future, node_rx))
    }
}

fn floodsub_handler(
    socket: floodsub::FloodSubFuture,
    addr: Multiaddr,
    node: Arc<RwLock<Inner>>,
) -> Box<Future<Item = (), Error = IoError> + Send> {
    let inner = node.clone();
    let netlog = {
        let inner = inner.read();
        inner.logger.new(o!("submodule" => "floodsub"))
    };

    {
        let mut inner = inner.write();
        inner.floodsub_connections.push(addr.clone());
    }
    debug!(
        netlog,
        "Successfully negotiated floodsub protocol with: {}", addr
    );
    let socket = socket.then({
        let inner = inner.clone();
        move |res| {
            let mut inner = inner.write();
            inner.floodsub_connections.retain(|a| *a != addr);
            match res {
                Ok(_) => {
                    debug!(netlog, "Floodsub successfully finished with: {}", addr);
                    Ok(())
                }
                Err(e) => {
                    debug!(netlog, "Floodsub with {} finished with error: {}", addr, e);
                    Ok(())
                }
            }
        }
    });

    Box::new(socket) as Box<Future<Item = (), Error = IoError> + Send>
}

pub(crate) fn populate_peerstore(node: Arc<RwLock<Inner>>) -> Result<(), Error> {
    let inner = node.clone();
    let logger = {
        let inner = inner.read();
        inner.logger.clone()
    };
    let config = {
        let inner = inner.read();
        inner.config.clone()
    };

    let ifaces = datalink::interfaces();
    let mut my_addresses: Vec<Multiaddr> = vec![];

    for addr in config.advertised_addresses.into_iter() {
        match addr.parse() {
            Ok(maddr) => my_addresses.push(maddr),
            Err(e) => error!(logger, "error parsing multiaddr: {}", addr; "Error" => e.to_string()),
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
            }).map(|a| a.to_multiaddr().unwrap())
            .map(|mut a| {
                a.append(Protocol::Tcp(bind_port));
                a
            }).collect();

        my_addresses.append(&mut multiaddresses);
    }

    // Add addresses to peer store
    {
        let inner = inner.read();
        // TODO: setup reasonable duration
        let ttl = Duration::from_secs(100 * 365 * 24 * 3600);

        if let Some(peer_id) = inner.peer_id.clone() {
            let peer_store = &inner.peer_store;
            peer_store
                .peer_or_create(&peer_id)
                .add_addrs(my_addresses, ttl)
        }
    }

    Ok(())
}

fn key_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut f = File::open(file_path)?;
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn dump_peerstore<T>(peerstore: T) -> Result<(), Error>
where
    T: Peerstore + Clone,
{
    println!("Peerstore dump:");
    let peers = peerstore.clone();

    for peer in peers.peers() {
        println!("\tPeerID: {}", peer.to_base58());
        let peer_store = peerstore.clone();
        for addr in peer_store.peer_or_create(&peer).addrs() {
            println!("\t\tAddress: {}", addr)
        }
    }
    Ok(())
}

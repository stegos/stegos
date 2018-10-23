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
use futures::future::Future;
use futures::sync::mpsc;
use futures::Stream;
use libp2p::core::{swarm, upgrade};
use libp2p::core::{Multiaddr, PublicKey, Transport};
use libp2p::floodsub;
use libp2p::mplex;
use libp2p::peerstore::PeerId;
use libp2p::secio::{SecioConfig, SecioKeyPair, SecioOutput};
use libp2p::tcp::TcpConfig;
use parking_lot::RwLock;
use slog::Logger;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use stegos_config::ConfigNetwork;

pub struct Node {
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    // Our config
    config: ConfigNetwork,
    // FloodSubController refernce for message publishing
    floodsub_ctl: Option<floodsub::FloodSubController>,
    // FloodSub topic used for communications
    floodsub_topic: Option<floodsub::Topic>,
    // Channel for outbound dial
    dial_tx: Option<mpsc::UnboundedSender<Multiaddr>>,
    // Active floodsub connections with a remote.
    floodsub_connections: RwLock<Vec<Multiaddr>>,
    // All remote connections
    remote_connections: RwLock<FnvHashMap<Multiaddr, RemoteInfo>>,
    // Logger for the Node
    logger: Logger,
}

// TODO
struct RemoteInfo {
    peer_id: PeerId,
}

impl Node {
    pub fn new(cfg: ConfigNetwork, logger: &Logger) -> Self {
        let inner = Arc::new(RwLock::new(Inner {
            config: cfg,
            floodsub_ctl: None,
            floodsub_topic: None,
            dial_tx: None,
            floodsub_connections: RwLock::new(Vec::new()),
            remote_connections: RwLock::new(FnvHashMap::default()),
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

    pub fn run(
        &self,
    ) -> Result<
        (
            Box<Future<Item = (), Error = ()> + Send + 'static>,
            // floodsub::FloodSubReceiver,
            Box<Stream<Item = Vec<u8>, Error = ()> + Send>,
        ),
        Error,
    > {
        let inner = self.inner.clone();
        let config = {
            let inner = inner.read();
            inner.config.clone()
        };
        let listen_addr = &config.listen_address;
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
                    let keypair = SecioKeyPair::rsa_from_pkcs8(private_key.as_slice(), public_key.clone()).unwrap();
                    SecioConfig::new(keypair)
                };

                upgrade::map_with_addr(secio, {
                    let nl2 = netlog.clone();
                    let inner = inner.clone();
                    move |out: SecioOutput<_>, addr| {
                        let peer_info = RemoteInfo { peer_id: out.remote_key.into_peer_id() };
                        debug!(nl2, "new connection";
                                "remote_peer_id" => peer_info.peer_id.to_base58(),
                                "remote_addr" => addr.to_string());
                        let inner = inner.write();
                        inner.remote_connections.write().insert(addr.clone(), peer_info);
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

        let (floodsub_upgrade, floodsub_rx) = floodsub::FloodSubUpgrade::new(my_id);

        // Let's put this `transport` into a *swarm*. The swarm will handle all the incoming and
        // outgoing connections for us.
        let (swarm_controller, swarm_future) =
            swarm(transport.clone().with_upgrade(floodsub_upgrade.clone()), {
                let nl2 = netlog.clone();
                let inner = inner.clone();
                move |socket, addr| {
                    let nl2 = nl2.clone();
                    let inner = inner.clone();
                    addr.and_then(move |addr| {
                        {
                            let inner = inner.read();
                            inner.floodsub_connections.write().push(addr.clone());
                        }
                        debug!(
                            nl2,
                            "Successfully negotiated floodsub protocol with: {}", addr
                        );
                        socket.then({
                            let inner = inner.clone();
                            move |res| {
                                let inner = inner.read();
                                inner.floodsub_connections.write().retain(|a| *a != addr);
                                match res {
                                    Ok(_) => {
                                        debug!(
                                            nl2,
                                            "Floodsub successfully finished with: {}", addr
                                        );
                                        Ok(())
                                    }
                                    Err(e) => {
                                        debug!(
                                            nl2,
                                            "Floodsub with {} finished with error: {}", addr, e
                                        );
                                        Ok(())
                                    }
                                }
                            }
                        })
                    })
                }
            });

        let listen_addr = listen_addr.parse()?;
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
                Ok(maddr) => if let Err(e) = swarm_controller.dial(
                    maddr,
                    transport.clone().with_upgrade(floodsub_upgrade.clone()),
                ) {
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
                if let Err(e) = swarm_controller.dial(
                    msg,
                    transport.clone().with_upgrade(floodsub_upgrade.clone()),
                ) {
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

fn key_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut f = File::open(file_path)?;
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

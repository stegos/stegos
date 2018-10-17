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

#![deny(warnings)]

use failure::Error;
use futures::future::Future;
use futures::sync::mpsc;
use futures::{Sink, Stream};
use libp2p::core::{swarm, upgrade};
use libp2p::core::{Multiaddr, PublicKey, Transport};
use libp2p::floodsub;
use libp2p::mplex;
use libp2p::peerstore::PeerId;
use libp2p::secio::{SecioConfig, SecioKeyPair, SecioOutput};
use libp2p::tcp::TcpConfig;
use slog::Logger;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use stegos_config::ConfigNetwork;
use tokio::runtime::Runtime;

use super::types::{FloodSubHandler, Node};

pub fn init(cfg: ConfigNetwork, log: Logger, rt: &mut Runtime) -> Result<Node, Error> {
    // Determine which address to listen to.
    let listen_addr = &cfg.listen_address;
    let private_key = key_from_file(&cfg.private_key)?;
    let public_key = key_from_file(&cfg.public_key)?;
    let netlog = log.new(o!("module" => "network"));

    // We start by creating a `TcpConfig` that indicates that we want TCP/IP.
    let transport = TcpConfig::new()
        .with_upgrade({
            let secio = {
                let keypair = SecioKeyPair::rsa_from_pkcs8(private_key.as_slice(), public_key.clone()).unwrap();
                SecioConfig::new(keypair)
            };

            upgrade::map_with_addr(secio, {
                let nl2 = netlog.clone();
                move |out: SecioOutput<_>, addr| {
                    debug!(nl2, "new connection";
                            "remote_peer_id" => out.remote_key.into_peer_id().to_base58(),
                            "remote_addr" => addr.to_string());
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
            move |socket, _| {
                debug!(nl2, "Successfully negotiated protocol");
                socket
            }
        });

    let listen_addr = listen_addr.parse()?;
    let address = swarm_controller.listen_on(listen_addr);
    debug!(netlog, "Now listening on {:?}", address);

    let topic = floodsub::TopicBuilder::new(cfg.broadcast_topic.as_str()).build();

    let floodsub_ctl = floodsub::FloodSubController::new(&floodsub_upgrade);
    floodsub_ctl.subscribe(&topic);

    let (tx, rx) = mpsc::channel(1);

    let floodsub_rx = floodsub_rx.for_each({
        let nl2 = netlog.clone();
        move |msg| {
            if let Ok(msg) = String::from_utf8(msg.data) {
                let tx2 = tx.clone();
                debug!(nl2, "< {}", msg);
                debug!(nl2, "passing upstream");
                if let Err(e) = tx2.send(msg).wait() {
                    error!(log, "failure delivering received message!"; "Error" => e.to_string());
                }
            }
            Ok(())
        }
    });

    let (input_tx, input_rx) = mpsc::channel::<String>(1);
    let floodsub_ctl2 = floodsub_ctl.clone();
    let sender = input_rx.for_each(move |msg| {
        floodsub_ctl2.publish(&topic, msg.into_bytes());
        Ok(())
    });

    for addr in cfg.seed_nodes.iter() {
        debug!(netlog, "Dialing peer"; "address" => addr);
        match addr.parse() {
            Ok(maddr) => if let Err(e) = swarm_controller.dial(
                maddr,
                transport.clone().with_upgrade(floodsub_upgrade.clone()),
            ) {
                error!(netlog, "failed to dial node!"; "Error" => e.to_string());
            },
            Err(e) => error!(netlog, "failed to parse address: {}", addr; "Error" => e.to_string()),
        }
    }

    let (dialer_tx, dialer_rx) = mpsc::channel::<Multiaddr>(1);
    let dialer = dialer_rx.for_each({
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

    // TODO: handle intenal errors properly
    let final_fut = swarm_future
        .for_each(|_| Ok(()))
        .select(floodsub_rx)
        .map(|_| ())
        .map_err(|e| e.0)
        .select(dialer.map_err(|_| unreachable!()))
        .map(|_| ())
        .map_err(|e| e.0)
        .select(sender.map_err(|_| unreachable!()))
        .map(|_| ())
        .map_err(|e| e.0);

    rt.spawn(final_fut.map_err(|_| ()));

    Ok(Node {
        floodsub: FloodSubHandler {
            rx,
            tx: input_tx,
            dialer: dialer_tx,
        },
    })
}

fn key_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut f = File::open(file_path)?;
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

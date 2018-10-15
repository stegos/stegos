// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate libp2p;
extern crate rand;
extern crate tokio;
extern crate tokio_current_thread;
extern crate tokio_io;
extern crate tokio_stdin;

use futures::future::Future;
use futures::sync::mpsc;
use futures::{Sink, Stream};
use libp2p::core::upgrade;
use libp2p::core::{Multiaddr, PublicKey, Transport};
use libp2p::peerstore::PeerId;
use libp2p::secio::SecioOutput;
use libp2p::tcp::TcpConfig;
use libp2p::websocket::WsConfig;
use std::{env, mem};
use tokio::runtime::Runtime;

pub struct FloodSubHandler {
    pub rx: mpsc::Receiver<String>,
    pub tx: mpsc::Sender<String>,
    pub dialer: mpsc::Sender<Multiaddr>,
}

pub struct Node {
    pub floodsub: FloodSubHandler,
}

fn run_node(rt: &mut Runtime) -> Node {
    env_logger::init();

    // Determine which address to listen to.
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or("/ip4/0.0.0.0/tcp/10050".to_owned());

    // We start by creating a `TcpConfig` that indicates that we want TCP/IP.
    let transport = TcpConfig::new()
        // In addition to TCP/IP, we also want to support the Websockets protocol on top of TCP/IP.
        // The parameter passed to `WsConfig::new()` must be an implementation of `Transport` to be
        // used for the underlying multiaddress.
        .or_transport(WsConfig::new(TcpConfig::new()))

        // On top of TCP/IP, we will use either the plaintext protocol or the secio protocol,
        // depending on which one the remote supports.
        .with_upgrade({
            let secio = {
                let private_key = include_bytes!("test-rsa-private-key.pk8");
                let public_key = include_bytes!("test-rsa-public-key.der").to_vec();
                let keypair = libp2p::secio::SecioKeyPair::rsa_from_pkcs8(private_key, public_key).unwrap();
                libp2p::secio::SecioConfig::new(keypair)
            };

            upgrade::map_with_addr(secio,
             |out: SecioOutput<_>, addr| {
               println!("Remote key: {:?}", out.remote_key);
               println!("Remote addr: {:?}", addr);
               out.stream
             })
        })

        // On top of plaintext or secio, we will use the multiplex protocol.
        .with_upgrade(libp2p::mplex::MplexConfig::new())
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
    let my_id = {
        let key = (0..2048).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        PeerId::from_public_key(PublicKey::Rsa(key))
    };

    let (floodsub_upgrade, floodsub_rx) = libp2p::floodsub::FloodSubUpgrade::new(my_id);

    // Let's put this `transport` into a *swarm*. The swarm will handle all the incoming and
    // outgoing connections for us.
    let (swarm_controller, swarm_future) = libp2p::core::swarm(
        transport.clone().with_upgrade(floodsub_upgrade.clone()),
        |socket, _| {
            println!("Successfully negotiated protocol");
            socket
        },
    );

    let address = swarm_controller
        .listen_on(listen_addr.parse().expect("invalid multiaddr"))
        .expect("unsupported multiaddr");
    println!("Now listening on {:?}", address);

    let topic = libp2p::floodsub::TopicBuilder::new("chat").build();

    let floodsub_ctl = libp2p::floodsub::FloodSubController::new(&floodsub_upgrade);
    floodsub_ctl.subscribe(&topic);

    let (tx, rx) = mpsc::channel(1);

    let floodsub_rx = floodsub_rx.for_each({
        move |msg| {
            if let Ok(msg) = String::from_utf8(msg.data) {
                let tx2 = tx.clone();
                println!("< {}", msg);
                println!("passing upstream");
                tx2.send(msg).wait().unwrap();
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

    let (dialer_tx, dialer_rx) = mpsc::channel::<Multiaddr>(1);
    let dialer = dialer_rx.for_each(move |msg| {
        println!("inner: *Dialing {}*", msg);
        swarm_controller
            .dial(
                msg,
                transport.clone().with_upgrade(floodsub_upgrade.clone()),
            ).unwrap();
        Ok(())
    });

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
    // rt.spawn(futures::future::ok(ct_rt.run().unwrap()));

    Node {
        floodsub: FloodSubHandler {
            rx,
            tx: input_tx,
            dialer: dialer_tx,
        },
    }
}

fn main() {
    let mut rt = Runtime::new().unwrap();
    let node: Node = run_node(&mut rt);

    let sender = node.floodsub.tx.clone();
    let dialer = node.floodsub.dialer.clone();

    let floodsub_rx = node.floodsub.rx.for_each(|msg| {
        println!("<<< {}", msg);
        Ok(())
    });

    let stdin = {
        let mut buffer = Vec::new();
        tokio_stdin::spawn_stdin_stream_unbounded().for_each({
            move |msg| {
                let dialer2 = dialer.clone();
                let sender2 = sender.clone();
                if msg != b'\r' && msg != b'\n' {
                    buffer.push(msg);
                    return Ok(());
                } else if buffer.is_empty() {
                    return Ok(());
                }

                let msg = String::from_utf8(mem::replace(&mut buffer, Vec::new())).unwrap();
                if msg.starts_with("/dial ") {
                    let target: Multiaddr = msg[6..].parse().unwrap();
                    println!("main: *Dialing {}*", target);
                    dialer2.send(target).wait().unwrap();
                } else {
                    sender2.send(msg).wait().unwrap();
                }
                Ok(())
            }
        })
    };

    rt.spawn(stdin);

    rt.block_on_all(floodsub_rx).unwrap();
}

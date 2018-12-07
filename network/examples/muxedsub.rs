//! Floodsub example based on libp2p

//
// Copyright (c) 2017 Parity Technologies (UK) Ltd
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

use bytes::Bytes;
use env_logger;
use futures::future::{Either, Future};
use futures::sync::mpsc;
use futures::{future, Poll, Sink, Stream};
use libp2p;
use libp2p::core::{either::EitherOutput, upgrade};
use libp2p::core::{ConnectionUpgrade, Endpoint, Multiaddr, PublicKey, Transport};
use libp2p::peerstore::PeerId;
use libp2p::secio::SecioOutput;
use libp2p::tcp::TcpConfig;
use libp2p::websocket::WsConfig;
use log::*;
use rand;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::{env, fmt, iter, mem};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use tokio_codec::{BytesCodec, Framed};
use tokio_stdin;

pub struct FloodSubHandler {
    pub rx: mpsc::Receiver<String>,
    pub tx: mpsc::Sender<String>,
    pub dialer: mpsc::Sender<Multiaddr>,
}

pub struct Node {
    pub floodsub: FloodSubHandler,
}

/// Implementation of the `ConnectionUpgrade` for the echo protocol.
#[derive(Debug, Clone)]
pub struct EchoUpgrade;

impl EchoUpgrade {
    pub fn new() -> Self {
        EchoUpgrade {}
    }
}

/// Implementation of `Future` that must be driven to completion in order for echo protocol to work.
#[must_use = "futures do nothing unless polled"]
pub struct EchoFuture {
    inner: Box<dyn Future<Item = (), Error = IoError> + Send>,
}

impl Future for EchoFuture {
    type Item = ();
    type Error = IoError;

    #[inline]
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

impl fmt::Debug for EchoFuture {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EchoFuture").finish()
    }
}

impl<C, Maf> ConnectionUpgrade<C, Maf> for EchoUpgrade
where
    C: AsyncRead + AsyncWrite + Send + 'static,
    Maf: Future<Item = Multiaddr, Error = IoError> + Send + 'static,
{
    type NamesIter = iter::Once<(Bytes, Self::UpgradeIdentifier)>;
    type UpgradeIdentifier = ();

    #[inline]
    fn protocol_names(&self) -> Self::NamesIter {
        iter::once(("/echo/1.0.0".into(), ()))
    }

    type Output = EchoFuture;
    type MultiaddrFuture = future::FutureResult<Multiaddr, IoError>;
    type Future =
        Box<dyn Future<Item = (Self::Output, Self::MultiaddrFuture), Error = IoError> + Send>;

    #[inline]
    fn upgrade(
        self,
        socket: C,
        _: Self::UpgradeIdentifier,
        _: Endpoint,
        remote_addr: Maf,
    ) -> Self::Future {
        debug!("Upgrading connection as echo");
        let future = remote_addr.and_then(move |remote_addr| {
            // Split the socket into writing and reading parts.
            // let (echo_sink, echo_stream) = Framed::new(socket, codec::UviBytes::default())
            let (echo_sink, echo_stream) = Framed::new(socket, BytesCodec::new())
                .sink_map_err(|err| IoError::new(IoErrorKind::InvalidData, err))
                .map_err(|err| IoError::new(IoErrorKind::InvalidData, err))
                .split();

            let remote_addr_ret = future::ok(remote_addr.clone());
            let future = future::loop_fn((echo_sink, echo_stream), move |(echo_sink, messages)| {
                let _remote_addr = remote_addr.clone();

                messages
                    .into_future()
                    .map_err(|(err, _)| err)
                    .and_then(move |(input, rest)| {
                        match input {
                            Some(bytes) => {
                                // Received a packet from the remote.
                                // Need to send a message to remote.
                                println!("Got message: {:?}, sending back", bytes);
                                let future = echo_sink
                                    .send(bytes.freeze())
                                    .map(|echo_sink| future::Loop::Continue((echo_sink, rest)));
                                Box::new(future) as Box<_>
                            }

                            None => {
                                // Both the connection stream and `rx` are empty, so we break
                                // the loop.
                                println!("Got EOF from remote, closing connection!");
                                let future = future::ok(future::Loop::Break(()));
                                Box::new(future) as Box<dyn Future<Item = _, Error = _> + Send>
                            }
                        }
                    })
            });
            future::ok((
                EchoFuture {
                    inner: Box::new(future) as Box<_>,
                },
                remote_addr_ret,
            ))
        });
        Box::new(future) as Box<_>
    }
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
                let keypair =
                    libp2p::secio::SecioKeyPair::rsa_from_pkcs8(private_key, public_key).unwrap();
                libp2p::secio::SecioConfig::new(keypair)
            };

            upgrade::map_with_addr(secio, |out: SecioOutput<_>, addr| {
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

    let flood_upgrade = upgrade::map(floodsub_upgrade.clone(), |fs| EitherOutput::First(fs));

    let echo_upgrade = upgrade::map(EchoUpgrade::new(), |echo| EitherOutput::Second(echo));
    let transport = transport.with_upgrade(upgrade::or(flood_upgrade, echo_upgrade));

    // Let's put this `transport` into a *swarm*. The swarm will handle all the incoming and
    // outgoing connections for us.
    let (swarm_controller, swarm_future) =
        libp2p::core::swarm(transport.clone(), |out, _| match out {
            EitherOutput::First(socket) => {
                println!("Successfully negotiated floodsub protocol");
                Either::A(socket)
            }
            EitherOutput::Second(socket) => {
                println!("Successfully negotiated echo protocol");
                Either::B(socket)
            }
        });

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
        swarm_controller.dial(msg, transport.clone()).unwrap();
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

//! Echo Server based on libp2p

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
use futures::future::Future;
use futures::{future, Poll, Sink, Stream};
use libp2p;
use libp2p::core::upgrade;
use libp2p::core::{ConnectionUpgrade, Endpoint, Multiaddr, Transport};
use libp2p::secio::SecioOutput;
use libp2p::tcp::TcpConfig;
use log::*;
use std::env;
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::iter;
use tokio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_codec::Framed;
use unsigned_varint::codec;

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
            let (echo_sink, echo_stream) = Framed::new(socket, codec::UviBytes::default())
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

fn main() {
    env_logger::init();

    // Determine which address to listen to.
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or("/ip4/0.0.0.0/tcp/10333".to_owned());

    // We start by creating a `TcpConfig` that indicates that we want TCP/IP.
    let transport = TcpConfig::new()
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

    // Let's put this `transport` into a *swarm*. The swarm will handle all the incoming and
    // outgoing connections for us.
    let (swarm_controller, swarm_future) = libp2p::core::swarm(
        transport.clone().with_upgrade(EchoUpgrade::new()),
        |socket, client_addr| {
            client_addr.and_then(|addr| {
                println!("Successfully negotiated protocol");
                println!("Remote address is: {}", addr);
                socket
            })
        },
    );

    // We now use the controller to listen on the address.
    let address = swarm_controller
        .listen_on(listen_addr.parse().expect("invalid multiaddr"))
        // If the multiaddr protocol exists but is not supported, then we get an error containing
        // the original multiaddress.
        .expect("unsupported multiaddr");
    // The address we actually listen on can be different from the address that was passed to
    // the `listen_on` function. For example if you pass `/ip4/0.0.0.0/tcp/0`, then the port `0`
    // will be replaced with the actual port.
    println!("Now listening on {:?}", address);

    // `swarm_future` is a future that contains all the behaviour that we want, but nothing has
    // actually started yet. Because we created the `TcpConfig` with tokio, we need to run the
    // future through the tokio core.
    // tokio_current_thread::block_on_all(swarm_future.for_each(|_| Ok(()))).unwrap();
    tokio::run(swarm_future.for_each(|_| Ok(())).map_err(|_| ()))
}

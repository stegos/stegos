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
#![allow(dead_code)]

use super::node::Inner;
use super::protocol::EchoMiddleware;
use futures::future::{loop_fn, Future, IntoFuture, Loop};
use futures::{Sink, Stream};
use libp2p::core::{Endpoint, Multiaddr};
use parking_lot::RwLock;
use std::io::Error as IoError;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) fn handler<S>(
    ncp_out: (Endpoint, EchoMiddleware<S>),
    addr: Multiaddr,
    node: Arc<RwLock<Inner>>,
) -> Box<Future<Item = (), Error = IoError> + Send>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let inner = node.clone();
    let netlog = {
        let inner = inner.read();
        inner.logger.new(o!("submodule" => "ncp"))
    };

    debug!(
        netlog,
        "Successfully negotiated NCP protocol with: {}", addr
    );

    let (_endpoint, socket) = ncp_out;

    let fut = loop_fn(socket, move |socket| {
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
                    Box::new(rest.send(msg.freeze()).map(|m| Loop::Continue(m)))
                        as Box<Future<Item = _, Error = _> + Send>
                } else {
                    // End of stream. Connection closed. Breaking the loop.
                    println!("Received EOF\n => Dropping connection");
                    Box::new(Ok(Loop::Break(())).into_future())
                        as Box<Future<Item = _, Error = _> + Send>
                }
            })
    });

    Box::new(fut) as Box<Future<Item = (), Error = IoError> + Send>
}

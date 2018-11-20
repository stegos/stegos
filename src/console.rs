///! Console - command-line interface.
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
use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::{Async, Future, Poll, Stream};
use libp2p::Multiaddr;
use std::mem;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_network::{Broker, Network};
use stegos_node::Node;
use tokio_stdin;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Console - command-line interface.
pub struct Console {}

impl Console {
    /// Create a new Console Service.
    pub fn new(
        network: Network,
        broker: Broker,
        node: Node,
    ) -> Result<impl Future<Item = (), Error = ()>, Error> {
        ConsoleService::new(network, broker, node)
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// Console (stdin) service.
struct ConsoleService {
    /// Network node.
    network: Network,
    /// Network message broker.
    broker: Broker,
    /// Blockchain Node.
    node: Node,
    /// A channel to receive message from stdin thread.
    stdin: UnboundedReceiver<u8>,
    /// Input buffer.
    buf: Vec<u8>,
    /// A channel to receive notification about balance changes.
    balance_rx: UnboundedReceiver<i64>,
}

impl ConsoleService {
    /// Constructor.
    fn new(network: Network, broker: Broker, node: Node) -> Result<ConsoleService, Error> {
        let stdin = tokio_stdin::spawn_stdin_stream_unbounded();
        let buf = Vec::<u8>::new();
        let balance_rx = node.subscribe_balance()?;
        let service = ConsoleService {
            network,
            broker,
            node,
            stdin,
            buf,
            balance_rx,
        };
        Ok(service)
    }

    /// Called when char is typed in standard input.
    fn on_input(&mut self, ch: u8) {
        if ch != b'\r' && ch != b'\n' {
            self.buf.push(ch);
            return;
        } else if self.buf.is_empty() {
            return;
        }

        let msg = String::from_utf8(mem::replace(&mut self.buf, Vec::new())).unwrap();
        if msg.starts_with("/dial ") {
            let target: Multiaddr = msg[6..].parse().unwrap();
            info!("main: *Dialing {}*", target);
            self.network.dial(target).unwrap();
        } else if msg.starts_with("/publish ") {
            // TODO: rewrite this buggy parser
            let sep_pos = msg[9..].find(' ').unwrap_or(0);
            let topic: String = msg[9..9 + sep_pos].to_string();
            let msg: String = msg[9 + sep_pos + 1..].to_string();
            info!("main: *Publishing to topic '{}': {} *", topic, msg);
            self.broker
                .publish(&topic, msg.as_bytes().to_vec())
                .unwrap();
        } else if msg.starts_with("/pay ") {
            // TODO: rewrite this buggy parser
            let sep_pos = msg[5..].find(' ').unwrap_or(0);
            let recipient: String = msg[5..5 + sep_pos].to_string();
            let amount: String = msg[5 + sep_pos + 1..].to_string();

            let recipient = match PublicKey::from_str(&recipient) {
                Ok(r) => r,
                Err(e) => {
                    error!("Invalid public key: {}", e);
                    return;
                }
            };
            let amount = match amount.parse::<i64>() {
                Ok(r) => r,
                Err(e) => {
                    error!("Invalid amount: {}", e);
                    return;
                }
            };

            info!("Requesting payment: to={}, amount={}", recipient, amount);
            if let Err(e) = self.node.pay(recipient, amount) {
                error!("Request failed: {}", e);
            }
        } else {
            eprintln!("Usage:");
            eprintln!("/dial multiaddr");
            eprintln!("/publish topic message");
            eprintln!("/pay publickey amount");
        }
    }

    fn on_balance_changed(&self, balance: i64) {
        info!("Balance => {}", balance);
    }
}

// Event loop.
impl Future for ConsoleService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.stdin.poll() {
                Ok(Async::Ready(Some(ch))) => self.on_input(ch),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!(),
            }
        }

        loop {
            match self.balance_rx.poll() {
                Ok(Async::Ready(Some(balance))) => self.on_balance_changed(balance),
                Ok(Async::Ready(None)) => unreachable!(),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(()) => panic!("Wallet failure"),
            }
        }
    }
}

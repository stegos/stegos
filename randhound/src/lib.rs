//! Randhound++ Implementation.

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

extern crate failure;
extern crate futures;
extern crate lazy_static;
extern crate parking_lot;
extern crate rand;
extern crate stegos_crypto;
extern crate stegos_network;
extern crate tokio;
extern crate tokio_timer;
#[macro_use]
extern crate log;

use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::{Async, Future, Poll, Stream};
use std::thread;
use std::thread::ThreadId;
use std::time::Duration;
use stegos_network::Broker;
use tokio::timer::Interval;

mod randhound;

const TOPIC: &'static str = "randhound";

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// RandHound++ - distributed randomness.
pub struct RandHound {}

impl RandHound {
    /// Create a new RandHound service.
    pub fn new(
        broker: Broker,
        my_id: &String,
    ) -> Result<impl Future<Item = (), Error = ()>, Error> {
        RandHoundService::new(broker, my_id)
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// RandHound++ network service.
struct RandHoundService {
    /// Network message broker.
    broker: Broker,
    /// Timer
    timer: Interval,
    /// Unicast Input Messages.
    unicast_rx: UnboundedReceiver<Vec<u8>>,
    /// Broadcast Input Messages.
    broadcast_rx: UnboundedReceiver<Vec<u8>>,
    /// Network node id.
    my_id: String,
    /// Thread Id (just for debug).
    thread_id: ThreadId,
}

impl RandHoundService {
    /// Send an unicast message to RandHound peer.
    fn unicast(&self, node_id: &String, data: Vec<u8>) -> Result<(), Error> {
        self.broker.publish(&format!("{}-{}", node_id, TOPIC), data)
    }

    /// Send a broadcast message to RandHound peer.
    fn broadcast(&self, data: Vec<u8>) -> Result<(), Error> {
        self.broker.publish(&TOPIC.to_string(), data)
    }

    /// Called on a new unitcast message.
    fn on_unicast(&mut self, msg: Vec<u8>) {
        debug!(
            "received unicast message: {}*",
            String::from_utf8_lossy(msg.as_slice())
        );
    }

    /// Called on a new broadcast message.
    fn on_broadcast(&mut self, msg: Vec<u8>) {
        debug!(
            "received broadcast message: {}*",
            String::from_utf8_lossy(msg.as_slice())
        );
    }

    /// Called on timer event.
    fn on_timer(&mut self) {
        debug!("timer");

        let hello_msg1 = format!("hello from: {} to node01", &self.my_id);
        let hello_msg2 = format!("hello from: {} to node02", &self.my_id);
        let hello_msg3 = format!("hello from: {} to node03", &self.my_id);
        let hello_broadcast = format!("broadcast hello from: {}", &self.my_id);

        self.unicast(&"node01".to_string(), hello_msg1.as_bytes().to_vec())
            .unwrap();
        self.unicast(&"node02".to_string(), hello_msg2.as_bytes().to_vec())
            .unwrap();
        self.unicast(&"node03".to_string(), hello_msg3.as_bytes().to_vec())
            .unwrap();

        self.broadcast(hello_broadcast.as_bytes().to_vec()).unwrap();
    }
}

// Event loop.
impl Future for RandHoundService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        assert_eq!(self.thread_id, thread::current().id());

        // Process incoming messages
        loop {
            match self.unicast_rx.poll() {
                Ok(Async::Ready(Some(msg))) => self.on_unicast(msg),
                Ok(Async::Ready(None)) => unreachable!(), // never happens
                Ok(Async::NotReady) => break,             // fall through
                Err(()) => panic!("Network failure"),
            }
        }
        loop {
            match self.broadcast_rx.poll() {
                Ok(Async::Ready(Some(msg))) => self.on_broadcast(msg),
                Ok(Async::Ready(None)) => unreachable!(), // never happens
                Ok(Async::NotReady) => break,             // fall through
                Err(()) => panic!("Network failure"),
            }
        }

        // Process timer events
        loop {
            match self.timer.poll() {
                Ok(Async::Ready(Some(_instant))) => self.on_timer(),
                Ok(Async::Ready(None)) => unreachable!(), // never happens
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => panic!("Timer failure: {}", e),
            };
        }
    }
}

impl RandHoundService {
    /// Constructor.
    fn new(broker: Broker, my_id: &String) -> Result<Self, Error> {
        let my_id = my_id.clone();

        // Subscribe to unicast topic.
        let unicast_rx = broker.subscribe(&format!("{}-{}", my_id, TOPIC))?;

        // Subscribe to broadcast topic.
        let broadcast_rx = broker.subscribe(&TOPIC.to_string())?;

        // Set up timer event.
        let timer = Interval::new_interval(Duration::from_secs(10));

        let thread_id = thread::current().id();
        let randhound = RandHoundService {
            broker,
            my_id,
            timer,
            unicast_rx,
            broadcast_rx,
            thread_id,
        };

        Ok(randhound)
    }
}

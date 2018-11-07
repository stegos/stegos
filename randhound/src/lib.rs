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

use failure::Error;
use futures::{Async, Future, Poll, Stream};
use std::thread;
use std::thread::ThreadId;
use std::time::Duration;
use stegos_network::Node;
use tokio::timer::Interval;

mod randhound;

const TOPIC: &'static str = "randhound";

/// RandHound++ network service.
pub struct RandHoundService {
    /// Network node
    node: Node,
    /// Timer
    timer: Interval,
    /// Input Messages.
    inbox: Box<Stream<Item = Vec<u8>, Error = ()>>,
    /// Network node id.
    my_id: String,
    /// Thread Id (just for debug).
    thread_id: ThreadId,
}

impl RandHoundService {
    /// Send an unicast message to RandHound peer.
    fn unicast(&self, node_id: &String, data: Vec<u8>) -> Result<(), Error> {
        self.node.publish(&format!("{}-{}", node_id, TOPIC), data)
    }

    /// Send a broadcast message to RandHound peer.
    fn broadcast(&self, data: Vec<u8>) -> Result<(), Error> {
        self.node.publish(&TOPIC.to_string(), data)
    }

    /// Called on a new message.
    fn on_message(&mut self, msg: Vec<u8>) {
        println!(
            "randhound: *message: {}*",
            String::from_utf8_lossy(msg.as_slice())
        );
    }

    /// Called on timer event.
    fn on_timer(&mut self) {
        // println!("randhound: *timer*");
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

/// Tokio boilerplate.
impl Future for RandHoundService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        assert_eq!(self.thread_id, thread::current().id());

        // Process incoming messages
        loop {
            match self.inbox.poll() {
                Ok(Async::Ready(Some(msg))) => self.on_message(msg),
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
    pub fn new(node: Node, my_id: &String, inbox: Box<Stream<Item = Vec<u8>, Error = ()>>) -> Self {
        let my_id = my_id.clone();

        // Subscribe to unicast topic.
        node.subscribe(&format!("{}-{}", my_id, TOPIC));
        // Subscribe to broadcast topic.
        node.subscribe(&TOPIC.to_string());
        // Set up timer event.
        let timer = Interval::new_interval(Duration::from_secs(10));

        let thread_id = thread::current().id();
        RandHoundService {
            node,
            my_id,
            timer,
            inbox,
            thread_id,
        }
    }
}

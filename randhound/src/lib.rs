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
// #[macro_use]
// extern crate lazy_static;
extern crate parking_lot;
extern crate protobuf;
extern crate rand;
extern crate state;
extern crate stegos_config;
extern crate stegos_crypto;
extern crate stegos_keychain;
extern crate stegos_network;
extern crate tokio;
extern crate tokio_timer;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure_derive;

use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::{Async, Future, Poll, Stream};
use std::sync::Arc;
use std::time::Duration;
use stegos_config::Config;
use stegos_crypto::hash::{Hash, Hashable};
use stegos_keychain::KeyChain;
use stegos_network::Broker;
use tokio::timer::Interval;

mod randhound;
mod randhound_proto;

use randhound::GlobalState;

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
        cfg: &Config,
        keychain: &KeyChain,
    ) -> Result<impl Future<Item = (), Error = ()>, Error> {
        RandHoundService::new(broker, cfg, keychain)
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

/// RandHound++ network service.
struct RandHoundService {
    /// Network message broker.
    // broker: Broker,
    /// Timer
    timer: Interval,
    /// Unicast Input Messages.
    unicast_rx: UnboundedReceiver<Vec<u8>>,
    /// Broadcast Input Messages.
    broadcast_rx: UnboundedReceiver<Vec<u8>>,
    /// Is Randhound started??
    randhound_started: bool,
    /// Randhound state
    state: Arc<GlobalState>,
}

impl RandHoundService {
    /// Constructor.
    fn new(broker: Broker, cfg: &Config, keychain: &KeyChain) -> Result<Self, Error> {
        // Subscribe to unicast topic.
        debug!(
            "subscribed to topic: {}",
            node_id_from_hashable(&keychain.cosi_pkey)
        );
        let unicast_rx = broker.subscribe(&node_id_from_hashable(&keychain.cosi_pkey))?;

        // Subscribe to broadcast topic.
        let broadcast_rx = broker.subscribe(&TOPIC.to_string())?;

        // Set up timer event.
        let timer = Interval::new_interval(Duration::from_secs(15));

        let state = randhound::init_state(cfg, &keychain, broker)?;

        let randhound = RandHoundService {
            // broker: broker.clone(),
            timer,
            unicast_rx,
            broadcast_rx,
            randhound_started: false,
            state: Arc::new(state),
        };

        Ok(randhound)
    }
    /// Send an unicast message to RandHound peer.
    // fn unicast(&self, node_id: &String, data: Vec<u8>) -> Result<(), Error> {
    //     self.broker.publish(node_id, data)
    // }

    /// Send a broadcast message to RandHound peer.
    // fn broadcast(&self, data: Vec<u8>) -> Result<(), Error> {
    //     self.broker.publish(&TOPIC.to_string(), data)
    // }

    /// Called on a new unitcast message.
    fn on_unicast(&mut self, msg: Vec<u8>) {
        self.process_msg(msg);
    }

    /// Called on a new broadcast message.
    fn on_broadcast(&mut self, msg: Vec<u8>) {
        self.process_msg(msg);
    }

    /// Called on timer event.
    fn on_timer(&mut self) {
        debug!("timer");
        // if self.randhound_started {
        //     debug!("Randhound already started!");
        //     self.state.maybe_transition_from_init_phase();
        // } else {
        //     debug!("Starting Randhound!");
        //     self.randhound_started = true;
        //     self.state.start_randhound_round();
        // }
    }

    fn process_msg(&self, msg: Vec<u8>) {
        let proto_msg = match protobuf::parse_from_bytes(&msg) {
            Ok(msg) => {
                debug!("*received unicast protobuf message: {:#?}*", msg);
                msg
            }
            Err(e) => {
                error!("Bad protobuf message received: {}", e);
                return;
            }
        };
        match randhound::proto_to_msg(proto_msg) {
            Ok(m) => {
                debug!("*received randhound message: {:#?}", m);
                if let Err(e) = self.state.dispatch_incoming_message(&m) {
                    error!("Error processing randhound message: {}", e);
                }
            }
            Err(e) => {
                error!("failed to decode protobuf message: {}", e);
                return;
            }
        };
    }
}

// Event loop.
impl Future for RandHoundService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
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

#[inline]
pub fn node_id_from_hashable(id: &Hashable) -> String {
    Hash::digest(id).into_hex()
}

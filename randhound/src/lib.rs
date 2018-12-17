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

mod randhound;
mod randhound_proto;

use crate::randhound::{EpochInfo, GlobalState};

use failure::{Error, Fail};
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{self, Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use protobuf;
use std::time::{Duration, Instant};
use stegos_crypto::hash::{Hash, Hashable};
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_keychain::KeyChain;
use stegos_network::{Broker, HeartbeatUpdate, Network};
use tokio::runtime::TaskExecutor;
use tokio::timer::{Delay, Interval};

const TOPIC: &'static str = "randhound";

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// RandHound++ - distributed randomness.
///
#[derive(Clone, Debug)]
pub struct RandHound {
    control: UnboundedSender<RandHoundEvent>,
}

#[derive(Clone, Debug)]
pub struct Randomness {
    pub value: Hash,
}

#[derive(Clone, Debug)]
pub struct RandhoundEpoch {
    pub epoch: u64,
    pub leader: SecurePublicKey,
    pub witnesses: Vec<SecurePublicKey>,
}

impl RandHound {
    /// Create a new RandHound service.
    pub fn new(
        broker: Broker,
        network: Network,
        keychain: &KeyChain,
        runtime: TaskExecutor,
    ) -> Result<(impl Future<Item = (), Error = ()>, Self), Error> {
        let (service, channel) = RandHoundService::new(broker, network, keychain, runtime)?;
        let handle = RandHound { control: channel };
        Ok((service, handle))
    }

    pub fn on_epoch(rh: &Self, msg: RandhoundEpoch) -> Result<(), Error> {
        rh.control.unbounded_send(RandHoundEvent::Epoch(msg))?;
        Ok(())
    }

    pub fn start_round(rh: &Self) -> Result<(), Error> {
        rh.control.unbounded_send(RandHoundEvent::NewRound)?;
        Ok(())
    }

    pub fn subscribe(rh: &Self) -> Result<UnboundedReceiver<Option<Randomness>>, Error> {
        let (tx, rx) = mpsc::unbounded();
        rh.control.unbounded_send(RandHoundEvent::Subscribe(tx))?;
        Ok(rx)
    }

    pub fn dummy() -> (impl Future<Item = (), Error = ()>, Self) {
        let (tx, rx) = mpsc::unbounded();
        let fut = rx.for_each(|_| Ok(())).map_err(|_| ());
        let rh = RandHound { control: tx };
        (fut, rh)
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) enum RandHoundEvent {
    Timer(Instant),
    Unicast(Vec<u8>),
    Broadcast(Vec<u8>),
    Epoch(RandhoundEpoch),
    Heartbeat(HeartbeatUpdate),
    Subscribe(UnboundedSender<Option<Randomness>>),
    NewRound,
}

#[derive(Debug, Fail)]
enum RandHoundInputError {
    #[fail(display = "Timer error: {:#?}", _0)]
    Timer(tokio_timer::Error),
    #[fail(display = "Unreachable")]
    NoError, // To wrap Error = () from network streams
}

/// RandHound++ network service.
pub struct RandHoundService {
    /// event sender
    send: UnboundedSender<RandHoundEvent>,
    /// event receiver
    recv: Box<Stream<Item = RandHoundEvent, Error = RandHoundInputError> + Send>,
    /// Randhound state
    state: GlobalState,
    /// Tokio Runtime,
    runtime: TaskExecutor,
}

impl RandHoundService {
    /// Constructor.
    fn new(
        broker: Broker,
        network: Network,
        keychain: &KeyChain,
        runtime: TaskExecutor,
    ) -> Result<(Self, UnboundedSender<RandHoundEvent>), Error> {
        // Subscribe to unicast topic.
        debug!(
            "subscribed to topic: {}",
            node_id_from_hashable(&keychain.cosi_pkey)
        );

        let mut inputs: Vec<
            Box<Stream<Item = RandHoundEvent, Error = RandHoundInputError> + Send>,
        > = vec![];

        let heartbeat_rx = network
            .subscribe_heartbeat()?
            .map(|m| RandHoundEvent::Heartbeat(m))
            .map_err(|_| RandHoundInputError::NoError);

        inputs.push(Box::new(heartbeat_rx));

        let unicast_rx = broker
            .subscribe(&node_id_from_hashable(&keychain.cosi_pkey))?
            .map(|m| RandHoundEvent::Unicast(m))
            .map_err(|_| RandHoundInputError::NoError);

        inputs.push(Box::new(unicast_rx));

        let broadcast_rx = broker
            .subscribe(&TOPIC.to_string())?
            .map(|m| RandHoundEvent::Broadcast(m))
            .map_err(|_| RandHoundInputError::NoError);

        inputs.push(Box::new(broadcast_rx));

        let (send, recv) = mpsc::unbounded();

        inputs.push(Box::new(recv.map_err(|_| RandHoundInputError::NoError)));

        // Set up timer event.
        let timer = Interval::new_interval(Duration::from_secs(15))
            .map(|i| RandHoundEvent::Timer(i))
            .map_err(|e| RandHoundInputError::Timer(e));

        inputs.push(Box::new(timer));

        let recv = select_all(inputs);

        let state = randhound::init_state(&keychain, broker, send.clone());

        let randhound = RandHoundService {
            // broker: broker.clone(),
            send: send.clone(),
            recv,
            state,
            runtime,
        };

        Ok((randhound, send))
    }

    /// Called on a new unitcast message.
    fn on_unicast(&mut self, msg: Vec<u8>) {
        self.process_msg(msg);
    }

    /// Called on a new broadcast message.
    fn on_broadcast(&mut self, msg: Vec<u8>) {
        self.process_msg(msg);
    }

    fn on_epoch(&mut self, msg: RandhoundEpoch) {
        debug!("Epoch notification received: {:#?}", msg);
        let mut epoch = EpochInfo::default();
        epoch.leader = msg.leader.clone();
        epoch.beacon = msg.leader.clone();
        for w in msg.witnesses.iter() {
            self.state.add_witness(w);
        }
        self.state.set_next_epoch(epoch);
        // TODO: remove this in favor Node service orchestrating RandHound
        // Remove this, when appropriate code is present in Node
        if self.state.get_pkey() == msg.leader {
            debug!("I'm beacon! Schedule Randhound round ");
            self.runtime.spawn({
                let delayed = Delay::new(
                    Instant::now() + Duration::from_secs(self.state.witnesses_size() as u64 + 10),
                )
                .and_then({
                    let send = self.send.clone();
                    move |()| {
                        debug!("Kabooom!");
                        if let Err(e) = send.unbounded_send(RandHoundEvent::NewRound) {
                            error!("Timer error, scheduling Randhound round: {}", e)
                        }
                        Ok(())
                    }
                });
                delayed.map_err(|_| ())
            });
        }
    }

    fn on_heartbeat(&mut self, msg: HeartbeatUpdate) {
        debug!("Heartbeat notification received: {:#?}", msg);
    }

    fn on_new_round(&mut self) {
        debug!("Starting Randhound!");
        self.state.start_randhound_round();
    }

    fn on_timer(&self) {
        debug!("Tick!");
    }

    fn on_deadline(&mut self, session: Hash) {
        info!("Deadline triggered for session: {}", session);
        if session != self.state.get_current_session() {
            error!("Stray deadline, current session is: {}", session);
        } else {
            self.state.maybe_transition_from_init_phase();
        }
    }

    fn process_msg(&mut self, msg: Vec<u8>) {
        let proto_msg = match protobuf::parse_from_bytes(&msg) {
            Ok(msg) => {
                trace!("*received protobuf message: {:#?}*", msg);
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
        loop {
            let deadline_poll = self.state.poll_deadline();
            match deadline_poll {
                Ok(Async::Ready(Some(session))) => self.on_deadline(session),
                Ok(Async::Ready(None)) => (),
                Ok(Async::NotReady) => (),
                Err(e) => {
                    error!("Error in DelayQueue: {}", e);
                    return Err(());
                }
            }
            match self.recv.poll() {
                Ok(Async::Ready(Some(evt))) => match evt {
                    RandHoundEvent::Unicast(msg) => self.on_unicast(msg),
                    RandHoundEvent::Broadcast(msg) => self.on_broadcast(msg),
                    RandHoundEvent::Epoch(msg) => self.on_epoch(msg),
                    RandHoundEvent::Heartbeat(msg) => self.on_heartbeat(msg),
                    RandHoundEvent::Timer(_i) => self.on_timer(),
                    RandHoundEvent::NewRound => self.on_new_round(),
                    RandHoundEvent::Subscribe(tx) => self.state.subscribe(tx),
                },
                Ok(Async::Ready(None)) => unreachable!(), // never should happen
                Ok(Async::NotReady) => {
                    let deadline_result = deadline_poll.unwrap();
                    if deadline_result == Async::NotReady || deadline_result == Async::Ready(None) {
                        return Ok(Async::NotReady);
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    error!("Error in Randhound event loop: {:#?}", e);
                    return Err(());
                }
            }
        }
    }
}

#[inline]
pub fn node_id_from_hashable(id: &dyn Hashable) -> String {
    Hash::digest(id).into_hex()
}

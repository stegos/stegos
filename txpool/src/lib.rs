use stegos_crypto::pbc::secure::{self, G2};
use stegos_keychain::KeyChain;
use stegos_network::NetworkProvider;

use std::time::{Duration, Instant};

pub use crate::api::{PoolEvent, PoolFeedback, TransactionPool};
use crate::messages::{Message, PoolInfo};
use failure::Error;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{task, Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::{debug, error, info};
use stegos_serialization::traits::*;
use tokio_timer::Delay;
pub mod api;
mod messages;
pub mod protos;
//TODO: on Drop, unsubscribe for messages topics.
//TODO: introduce session id for splitting different pools.

const BROADCAST_POOL_MESSAGES: &'static str = "broadcast-transaction-pool";

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

struct FacilitatorState {
    accumulator: Vec<Message>,
}

impl FacilitatorState {
    fn new() -> Self {
        FacilitatorState {
            accumulator: Vec::new(),
        }
    }

    fn add_message(&mut self, message: Message) {
        self.accumulator.push(message)
    }

    fn take_pool(&self) -> Vec<Message> {
        self.accumulator.clone()
    }
}

enum NodeRole {
    Facilitator(FacilitatorState),
    Regular,
}

pub struct TransactionPoolService<Network> {
    facilitator_pkey: secure::PublicKey,
    pkey: secure::PublicKey,
    skey: secure::SecretKey,
    broker: Network,
    role: NodeRole,
    timer: Option<Delay>,

    _sender: UnboundedSender<PoolFeedback>,
    events: Box<Stream<Item = PoolEvent, Error = ()> + Send>,
}

impl<Network: NetworkProvider> TransactionPoolService<Network> {
    /// Crates new TransactionPool.
    pub fn new(
        keychain: &KeyChain,
        broker: Network,
        receiver: UnboundedReceiver<PoolEvent>,
        sender: UnboundedSender<PoolFeedback>,
    ) -> Self {
        let pkey = keychain.cosi_pkey.clone();
        let skey = keychain.cosi_skey.clone();
        let facilitator_pkey: secure::PublicKey = G2::generator().into(); // some fake key
        let events = || -> Result<_, Error> {
            let mut streams = Vec::<Box<Stream<Item = PoolEvent, Error = ()> + Send>>::new();

            // Broadcast messages from facilitator
            let broadcast_message = broker
                .subscribe(&BROADCAST_POOL_MESSAGES)?
                .map(|m| PoolEvent::PoolInfo(m));
            streams.push(Box::new(broadcast_message));

            //TODO: unsubscribe unicast.
            // Unicast messages from other nodes
            let unicast_message = broker.subscribe_unicast()?.map(|m| PoolEvent::Message(m));
            streams.push(Box::new(unicast_message));

            // Messages from console
            streams.push(Box::new(receiver));

            Ok(select_all(streams))
        }()
        .expect("Error when aggregating streams");

        TransactionPoolService {
            facilitator_pkey,
            role: NodeRole::Regular,
            broker,
            pkey,
            skey,
            _sender: sender,
            timer: None,
            events,
        }
    }

    /// Creates TransactionPool with TransactionPoolManager
    pub fn with_manager(keychain: &KeyChain, broker: Network) -> (Self, TransactionPool) {
        let (events_sender, events_receiver) = mpsc::unbounded();
        let (feedback_sender, feedback_receiver) = mpsc::unbounded();
        let manager = TransactionPool {
            feedback_receiver,
            events_sender,
        };
        (
            Self::new(keychain, broker, events_receiver, feedback_sender),
            manager,
        )
    }

    fn change_facilitator(&mut self, facilitator_pkey: secure::PublicKey) -> Result<(), Error> {
        debug!("Changing facilitator.");
        let role = if facilitator_pkey == self.pkey {
            info!("I am facilitator.");
            self.timer = Some(Delay::new(Instant::now() + MESSAGE_TIMEOUT));
            task::current().notify();

            NodeRole::Facilitator(FacilitatorState::new())
        } else {
            self.timer = None;
            NodeRole::Regular
        };
        self.role = role;
        self.facilitator_pkey = facilitator_pkey;
        Ok(())
    }

    pub fn handle_timer(&mut self) -> Result<(), Error> {
        match &mut self.role {
            NodeRole::Facilitator(state) => {
                // after timeout facilitator should broadcast message to each node.
                let accumulator = state.take_pool();
                let pool = PoolInfo::new(accumulator, self.pkey, &self.skey);
                //TODO:: remove clone
                let data = pool.clone().into_buffer()?;
                self.broker.publish(&BROADCAST_POOL_MESSAGES, data)?;
                self.handle_receive_pool_info(pool)?;
            }
            NodeRole::Regular => {
                unreachable!();
            }
        }
        Ok(())
    }

    pub fn handle_receive_pool_info(&mut self, message: PoolInfo) -> Result<(), Error> {
        // TODO: After node receive pool info, it should start to communicate with other nodes?
        debug!("Received pool info message {:?}", message);
        message.validate()
    }

    /// Receive message of other nodes from unicast channel.
    pub fn handle_receive_message(&mut self, message: Message) -> Result<(), Error> {
        debug!("Receiving new message = {:?}", message);
        // TODO: message.validate()
        match self.role {
            NodeRole::Regular => {}
            NodeRole::Facilitator(ref mut state) => {
                debug!("Add message = {:?}, into pool.", message);
                state.add_message(message);
            }
        }
        Ok(())
    }

    /// Receive message of other nodes from unicast channel.
    pub fn handle_internal_message(&mut self, message: Message) -> Result<(), Error> {
        debug!("Trying to add message into pool = {:?}.", message);
        match self.role {
            NodeRole::Regular => {
                debug!("Send message to facilitator = {:?}.", self.facilitator_pkey);
                let buffer = message.into_buffer()?;
                self.broker.send(self.facilitator_pkey, buffer)?;
            }
            NodeRole::Facilitator(ref mut state) => {
                debug!("Add message = {:?}, into pool.", message);
                state.add_message(message);
            }
        }
        Ok(())
    }
}

impl<Network: NetworkProvider> Future for TransactionPoolService<Network> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match (self.poll_events(), self.poll_timer()) {
                // stop when both sources are not ready
                (Async::NotReady, Async::NotReady) => return Ok(Async::NotReady),
                _ => continue,
            }
        }
    }
}

impl<Network: NetworkProvider> TransactionPoolService<Network> {
    /// Polls event queue, stop on errors
    fn poll_events(&mut self) -> Async<()> {
        match self.events.poll().expect("all errors are already handled") {
            Async::Ready(Some(event)) => {
                let result = match event {
                    PoolEvent::Message(data) => Message::from_buffer(&data)
                        .and_then(|data| self.handle_receive_message(data)),
                    PoolEvent::InternalMessage(msg) => self.handle_internal_message(msg),
                    PoolEvent::PoolInfo(data) => PoolInfo::from_buffer(&data)
                        .and_then(|data| self.handle_receive_pool_info(data)),
                    PoolEvent::ChangeFacilitator(pk) => self.change_facilitator(pk),
                };

                if let Err(e) = result {
                    error!("Error: {}", e);
                }
                return Async::Ready(());
            }
            Async::Ready(None) => unreachable!(), // never happens
            Async::NotReady => {}
        }
        Async::NotReady
    }

    fn poll_timer(&mut self) -> Async<()> {
        if self.timer.is_none() {
            // we don't need to call `notify`, there,
            // because this timer is oneshot, and cannot recover.
            return Async::NotReady;
        }

        let timer = self.timer.as_mut().unwrap();
        match timer.poll().expect("timer fails") {
            Async::Ready(()) => {
                if let Err(e) = self.handle_timer() {
                    error!("Error: {}", e);
                }
                self.timer = None;
            }
            _ => {}
        }
        Async::NotReady
    }
}

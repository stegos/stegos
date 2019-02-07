mod messages;
pub use crate::messages::*;

pub mod protos;

use failure::Error;
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use std::collections::HashSet;
use std::time::Duration;
use stegos_crypto::pbc::secure::{self, G2};
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_node::EpochNotification;
use stegos_node::Node;
use stegos_serialization::traits::*;
use tokio_timer::Interval;

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

struct FacilitatorState {
    participants: HashSet<secure::PublicKey>,
    timer: Interval,
}

impl FacilitatorState {
    fn new() -> Self {
        let mut timer = Interval::new_interval(MESSAGE_TIMEOUT);
        // register new timer to the current task.
        let _ = timer.poll();
        FacilitatorState {
            participants: HashSet::new(),
            timer,
        }
    }

    fn add_participant(&mut self, pkey: secure::PublicKey) -> bool {
        self.participants.insert(pkey)
    }

    fn take_pool(&mut self) -> HashSet<secure::PublicKey> {
        std::mem::replace(&mut self.participants, HashSet::new())
    }
}

enum NodeRole {
    Facilitator(FacilitatorState),
    Regular,
}

#[derive(Debug)]
pub(crate) enum PoolEvent {
    //
    // Public API.
    //
    Join(secure::PublicKey, Vec<u8>),

    //
    // Internal events.
    //
    EpochChanged(EpochNotification),
}

pub struct TransactionPoolService {
    facilitator_pkey: secure::PublicKey,
    pkey: secure::PublicKey,
    network: Network,
    role: NodeRole,

    events: Box<Stream<Item = PoolEvent, Error = ()> + Send>,
}

impl TransactionPoolService {
    /// Crates new TransactionPool.
    pub fn new(keychain: &KeyChain, network: Network, node: Node) -> TransactionPoolService {
        let pkey = keychain.cosi_pkey.clone();
        let facilitator_pkey: secure::PublicKey = G2::generator().into(); // some fake key

        let events = || -> Result<_, Error> {
            let mut streams = Vec::<Box<Stream<Item = PoolEvent, Error = ()> + Send>>::new();

            // Unicast messages from other nodes
            let unicast_message = network
                .subscribe_unicast(POOL_JOIN_TOPIC)?
                .map(|m| PoolEvent::Join(m.from, m.data));
            streams.push(Box::new(unicast_message));

            // Epoch Changes
            let node_outputs = node.subscribe_epoch()?.map(|m| PoolEvent::EpochChanged(m));
            streams.push(Box::new(node_outputs));

            Ok(select_all(streams))
        }()
        .expect("Error when aggregating streams");

        TransactionPoolService {
            facilitator_pkey,
            role: NodeRole::Regular,
            network,
            pkey,
            events,
        }
    }

    fn handle_epoch(&mut self, epoch: EpochNotification) -> Result<(), Error> {
        debug!("Changed facilitator: facilitator={:?}", epoch.facilitator);
        let role = if epoch.facilitator == self.pkey {
            info!("I am facilitator.");
            NodeRole::Facilitator(FacilitatorState::new())
        } else {
            NodeRole::Regular
        };
        self.role = role;
        self.facilitator_pkey = epoch.facilitator;
        Ok(())
    }

    pub fn handle_timer(&mut self) -> Result<(), Error> {
        match &mut self.role {
            NodeRole::Facilitator(state) => {
                // after timeout facilitator should broadcast message to each node.
                let participants: Vec<secure::PublicKey> = state.take_pool().into_iter().collect();
                if participants.is_empty() {
                    debug!("No requests received, skipping pool formation");
                    return Ok(());
                }
                let info = PoolInfo { participants };
                info!("Formed a new pool: participants={:?}", &info.participants);
                let data = info.into_buffer()?;
                for pkey in info.participants {
                    self.network.send(pkey, POOL_ANNOUNCE_TOPIC, data.clone())?;
                }
            }
            NodeRole::Regular => {
                unreachable!();
            }
        }
        Ok(())
    }

    /// Receive message of other nodes from unicast channel.
    pub fn handle_join_message(&mut self, from: secure::PublicKey) -> Result<(), Error> {
        match self.role {
            NodeRole::Regular => {
                error!(
                    "Received a join request on non-faciliator: from={:?}, facilitator={:?}",
                    from, self.facilitator_pkey
                );
            }
            NodeRole::Facilitator(ref mut state) => {
                if state.add_participant(from) {
                    info!("Added a new member: pkey={:?}", from);
                }
            }
        }
        Ok(())
    }
}

impl Future for TransactionPoolService {
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

impl TransactionPoolService {
    /// Polls event queue, stop on errors
    fn poll_events(&mut self) -> Async<()> {
        match self.events.poll().expect("all errors are already handled") {
            Async::Ready(Some(event)) => {
                let result = match event {
                    PoolEvent::Join(from, data) => {
                        debug!("Received join message: from={:?}", from);
                        PoolJoin::from_buffer(&data).and_then(|_| self.handle_join_message(from))
                    }
                    PoolEvent::EpochChanged(epoch) => self.handle_epoch(epoch),
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
        let timer = match self.role {
            NodeRole::Facilitator(ref mut state) => &mut state.timer,
            NodeRole::Regular => return Async::NotReady,
        };
        match timer.poll().expect("timer fails") {
            Async::Ready(Some(_)) => {
                if let Err(e) = self.handle_timer() {
                    error!("Error: {}", e);
                }
            }
            Async::Ready(None) => panic!("Timer fails."),
            _ => {}
        }
        Async::NotReady
    }
}

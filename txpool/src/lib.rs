mod messages;
pub use crate::messages::*;

pub mod protos;

use failure::Error;
use futures::{Async, Future, Poll, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::PaymentOutput;
use stegos_crypto::curve1174;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_network::Network;
use stegos_node::EpochChanged;
use stegos_node::Node;
use stegos_serialization::traits::*;
use tokio_timer::Interval;

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

type TXIN = Hash;
type UTXO = PaymentOutput;
type SchnorrSig = curve1174::SchnorrSig;
type ParticipantID = pbc::PublicKey;

struct FacilitatorState {
    participants: HashMap<ParticipantID, (Vec<TXIN>, Vec<UTXO>, SchnorrSig)>,
    timer: Interval,
}

impl FacilitatorState {
    fn new() -> Self {
        let mut timer = Interval::new_interval(MESSAGE_TIMEOUT);
        // register new timer to the current task.
        let _ = timer.poll();
        FacilitatorState {
            participants: HashMap::new(),
            timer,
        }
    }

    fn add_participant(&mut self, pkey: ParticipantID, data: PoolJoin) -> bool {
        match self
            .participants
            .insert(pkey, (data.txins, data.utxos, data.ownsig))
        {
            None => true,
            _ => false,
        }
    }

    fn take_pool(&mut self) -> HashMap<ParticipantID, (Vec<TXIN>, Vec<UTXO>, SchnorrSig)> {
        if self.participants.len() >= 3 {
            std::mem::replace(&mut self.participants, HashMap::new())
        } else {
            HashMap::new()
        }
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
    Join(ParticipantID, Vec<u8>),

    //
    // Internal events.
    //
    EpochChanged(EpochChanged),
}

pub struct TransactionPoolService {
    facilitator_pkey: ParticipantID,
    pkey: ParticipantID,
    network: Network,
    role: NodeRole,

    events: Box<Stream<Item = PoolEvent, Error = ()> + Send>,
}

impl TransactionPoolService {
    /// Crates new TransactionPool.
    pub fn new(
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
    ) -> TransactionPoolService {
        let facilitator_pkey: ParticipantID = ParticipantID::dum();

        let events = || -> Result<_, Error> {
            let mut streams = Vec::<Box<Stream<Item = PoolEvent, Error = ()> + Send>>::new();

            // Unicast messages from other nodes
            let unicast_message = network
                .subscribe_unicast(POOL_JOIN_TOPIC)?
                .map(|m| PoolEvent::Join(m.from, m.data));
            streams.push(Box::new(unicast_message));

            // Epoch Changes
            let epoch_changes = node
                .subscribe_epoch_changed()
                .map(|m| PoolEvent::EpochChanged(m));
            streams.push(Box::new(epoch_changes));

            Ok(select_all(streams))
        }()
        .expect("Error when aggregating streams");

        TransactionPoolService {
            facilitator_pkey,
            role: NodeRole::Regular,
            network,
            pkey: network_pkey,
            events,
        }
    }

    fn handle_epoch(&mut self, epoch: EpochChanged) -> Result<(), Error> {
        debug!("Changed facilitator: facilitator={}", epoch.facilitator);
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
                let parts = state.take_pool();
                if parts.is_empty() {
                    debug!("No requests received, skipping pool formation");
                    return Ok(());
                }
                let mut participants = Vec::<ParticipantTXINMap>::new();
                for (participant, (txins, utxos, ownsig)) in &parts {
                    /*
                    let mut utxos = Vec::<UTXO>::new();
                    for txin in txins {
                        utxos.push(get_utxo(txin)?);
                    }
                    */
                    participants.push(ParticipantTXINMap {
                        participant: participant.clone(),
                        txins: txins.clone(),
                        utxos: utxos.clone(),
                        ownsig: ownsig.clone(),
                    })
                }
                let session_id = Hash::random();
                let info = PoolInfo {
                    participants: participants.clone(),
                    session_id,
                };
                info!("Formed a new pool: participants={:?}", &info.participants);
                let data = info.into_buffer()?;
                for part in info.participants {
                    self.network
                        .send(part.participant, POOL_ANNOUNCE_TOPIC, data.clone())?;
                }
            }
            NodeRole::Regular => {
                unreachable!();
            }
        }
        Ok(())
    }

    /// Receive message of other nodes from unicast channel.
    pub fn handle_join_message(
        &mut self,
        data: PoolJoin,
        from: ParticipantID,
    ) -> Result<(), Error> {
        match self.role {
            NodeRole::Regular => {
                error!(
                    "Received a join request on non-faciliator: from={:?}, facilitator={:?}",
                    from, self.facilitator_pkey
                );
            }
            NodeRole::Facilitator(ref mut state) => {
                if state.add_participant(from, data) {
                    info!("Added a new member: pkey={}", from);
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
                        debug!("Received join message: from={}", from);
                        PoolJoin::from_buffer(&data)
                            .and_then(|pj_rec| self.handle_join_message(pj_rec, from))
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

#![deny(warnings)]

pub mod messages;
pub use self::messages::*;

use crate::Node;
use failure::Error;
use futures::sync::mpsc;
use futures::{Async, Future, Poll, Stream};
use log::*;
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::PaymentOutput;
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;
use stegos_network::{Network, UnicastMessage};
use stegos_serialization::traits::*;
use tokio_timer::Interval;

pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_PARTICIPANTS: usize = 3;
pub const MAX_PARTICIPANTS: usize = 20;

type TXIN = Hash;
type UTXO = PaymentOutput;
type SchnorrSig = scc::SchnorrSig;
type ParticipantID = dicemix::ParticipantID;

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

    fn add_participant(&mut self, pkey: pbc::PublicKey, data: PoolJoin) -> bool {
        match self.participants.insert(
            ParticipantID::new(pkey, data.seed),
            (data.txins, data.utxos, data.ownsig),
        ) {
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

pub struct TransactionPoolService {
    facilitator_pkey: pbc::PublicKey,
    pkey: pbc::PublicKey,
    network: Network,
    role: NodeRole,
    pool_join_rx: mpsc::UnboundedReceiver<UnicastMessage>,
}

impl TransactionPoolService {
    /// Crates new TransactionPool.
    pub fn new(
        network_pkey: pbc::PublicKey,
        network: Network,
        _node: Node,
    ) -> TransactionPoolService {
        let facilitator_pkey: pbc::PublicKey = pbc::PublicKey::dum();

        // Unicast messages from other nodes
        let pool_join_rx = network.subscribe_unicast(POOL_JOIN_TOPIC).unwrap();

        TransactionPoolService {
            facilitator_pkey,
            role: NodeRole::Regular,
            network,
            pkey: network_pkey,
            pool_join_rx,
        }
    }

    pub fn change_facilitator(&mut self, facilitator: pbc::PublicKey) {
        debug!("Changed facilitator: facilitator={}", facilitator);
        let role = if facilitator == self.pkey {
            info!("I am facilitator.");
            NodeRole::Facilitator(FacilitatorState::new())
        } else {
            // we was facilitator, send notify to everybody, that pool was not formed, or form pool.
            if let NodeRole::Facilitator(_) = self.role {
                if let Err(e) = self.notify_cancel() {
                    error!("Error during notify participants: error={}", e)
                }
            }
            NodeRole::Regular
        };

        self.role = role;
        self.facilitator_pkey = facilitator;
    }

    fn notify_cancel(&mut self) -> Result<(), Error> {
        match &mut self.role {
            NodeRole::Facilitator(ref mut state) => {
                if state.participants.len() < MIN_PARTICIPANTS {
                    let info = PoolNotification::Canceled;
                    let data = info.into_buffer()?;
                    for part in &state.take_pool() {
                        self.network
                            .send(part.0.pkey, POOL_ANNOUNCE_TOPIC, data.clone())?;
                    }
                } else {
                    self.try_notify_participants()?
                }
            }
            NodeRole::Regular => unreachable!(),
        }
        Ok(())
    }

    pub fn try_notify_participants(&mut self) -> Result<(), Error> {
        match &mut self.role {
            NodeRole::Facilitator(state) => {
                if state.participants.len() < MIN_PARTICIPANTS {
                    debug!(
                        "Found no enough participants, skipping pool formation: \
                         pool_len={}, min_len={}",
                        state.participants.len(),
                        MIN_PARTICIPANTS
                    );
                    return Ok(());
                }
                // after timeout facilitator should broadcast message to each node.
                let parts = state.take_pool();

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
                info!(
                    "Formed a new pool: session_id={}, participants={:?}",
                    session_id, &participants
                );
                let info = PoolInfo {
                    participants: participants.clone(),
                    session_id,
                };
                let msg: PoolNotification = info.into();
                let data = msg.into_buffer()?;
                for part in participants {
                    self.network
                        .send(part.participant.pkey, POOL_ANNOUNCE_TOPIC, data.clone())?;
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
        from: pbc::PublicKey,
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

                    if state.participants.len() >= MAX_PARTICIPANTS {
                        self.try_notify_participants()?
                    }
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
        //
        // Poll PoolJoin messages.
        //
        loop {
            match self
                .pool_join_rx
                .poll()
                .expect("all errors are already handled")
            {
                Async::Ready(Some(msg)) => {
                    debug!("Received join message: from={}", msg.from);
                    let result = PoolJoin::from_buffer(&msg.data)
                        .and_then(|pj_rec| self.handle_join_message(pj_rec, msg.from));
                    if let Err(e) = result {
                        error!("Error: {}", e);
                    }
                    continue;
                }
                Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                Async::NotReady => break,
            }
        }

        //
        // Poll timer.
        //
        match self.role {
            NodeRole::Facilitator(ref mut state) => {
                match state.timer.poll().expect("timer fails") {
                    Async::Ready(Some(_)) => {
                        if let Err(e) = self.try_notify_participants() {
                            error!("Error: {}", e);
                        }
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())), // shutdown.
                    Async::NotReady => {}
                }
            }
            NodeRole::Regular => {}
        }

        Ok(Async::NotReady)
    }
}

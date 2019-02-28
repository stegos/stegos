//
// MIT License
//
// Copyright (c) 2018 Stegos AG
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

use stegos_blockchain::Escrow;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_crypto::pbc::secure::VRF;
use stegos_serialization::traits::ProtoConvert;

use lazy_static::lazy_static;

use crate::election::{self, ConsensusGroup, StakersGroup};
use crate::NodeService;

use failure::{Error, Fail};
use log::{debug, info, trace};
use std::time::{Duration, Instant};
use std::{collections::HashMap, mem};
use tokio_timer::clock;

///
/// Constants
///

/// Topic used for vrf system.
pub const VRF_TICKETS_TOPIC: &'static str = "vrf_tickets";

/// How often to check VRF system state.
pub const TIMER: Duration = Duration::from_secs(5);

lazy_static! {
    /// If no new block was provided between this interval - we should start vrf system.
    pub static ref RESTART_CONSENSUS_TIMER: Duration = crate::MESSAGE_TIMEOUT * 4 + // 4 consensus message
                                          crate::BLOCK_VALIDATION_TIME * 2 + // form block on leader and
                                                                              // validate on validator
                                          crate::TX_WAIT_TIMEOUT; // Propose timeout
}
/// How long we should collect the tickets.
/// This value represent initial timeout, at view_change timeout exponentialy increasing.
pub const COLLECTING_TICKETS_TIMER: Duration = crate::MESSAGE_TIMEOUT;

///
/// Data types
///

/// Represent VRFTicket message
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct VRFTicket {
    /// Random value that can be verified.
    pub random: VRF,
    /// Height of blockchain at start of current voting process,
    /// used to identify is this ticket is actual or not.
    pub height: u64,
    /// Count of retries.
    pub view_change: u32,
    /// Sender public key.
    pub pkey: secure::PublicKey,
    /// Signature of the message.
    pub sig: secure::Signature,
}

/// Possible Ticket System errors.
#[derive(Debug, Fail, PartialEq, Eq)]
pub enum TicketsError {
    #[fail(display = "Trying to start new TicketsSystem when working on other.")]
    StartingWhileWork,
    #[fail(display = "Received invalid ticket: {:?}.", _0)]
    InvalidTicket(VRFTicket),
    #[fail(display = "No tickets was received in time.")]
    NoTickets,
    #[fail(
        display = "Trying to process tickets but tickets count is smaller that LOWER_TICKETS_COUNT."
    )]
    NotEnoughTicketsCount,
    #[fail(display = "Stakers majority group more then testnet hard limit.")]
    TooManyStakers,
    #[fail(display = "Receiving multiple tickets from {:?}.", _0)]
    MultipleTickets(secure::PublicKey),
}

///
/// States
///

/// Collecting ticket state.
#[derive(Debug)]
struct CollectingState {
    //TODO: Probably later we can keep in memory only lowest VRF ticket.
    tickets: HashMap<secure::PublicKey, VRF>,
    seed: Hash,
}

/// All possible VRF system state.
#[derive(Debug)]
enum State {
    /// Wait for starting trigger.
    /// It could be timeout of block, or epoch ending.
    Sleeping(Instant),
    /// TicketsSystem started, waiting for tickets.
    CollectingTickets(CollectingState, Instant),
}

/// Ticket system module.
/// VRF ticket system should produce random
/// value in case of epoch change or in case of consensus failure.
/// In VRF ticket system every node should try to reach "consensus" by exchanging a `Tickets`.
/// Each `Ticket` represent random value.
/// After `COLLECTING_TICKETS_TIMER` timeout node choose the lowest possible random value,
/// and start `election` lottery with this value as seed.
/// The new group should start and reach consensus.
/// If consensus was succesfully reached the system keep going.
/// If new consensus group is failed too, then Ticket system restarts, with new `view_change` value,
/// and `COLLECTING_TICKETS_TIMER` increased.
pub struct TicketsSystem {
    /// Maximum possible elected group size.
    max_group_size: usize,
    /// Represent current number of retry.
    view_change: u32,
    /// Debug value, could be removed.
    height: u64,
    /// Secret key of the current node. Used to create new Tickets.
    skey: secure::SecretKey,
    /// Public key of the current node. Used to create new Tickets.
    pkey: secure::PublicKey,
    /// State of the Ticket system
    state: State,
    /// Queue of out-of-order messages.
    queue: HashMap<secure::PublicKey, VRFTicket>,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Feedback {
    BroadcastTicket(VRFTicket),
    ChangeGroup(ConsensusGroup),
    Nothing,
}

impl TicketsSystem {
    pub fn new(
        max_group_size: usize,
        view_change: u32,
        height: u64,
        pkey: secure::PublicKey,
        skey: secure::SecretKey,
    ) -> TicketsSystem {
        TicketsSystem {
            max_group_size,
            view_change,
            height,
            pkey,
            skey,
            queue: HashMap::new(),
            state: State::default(),
        }
    }

    /// Handle eventloop ticks.
    pub fn handle_tick(
        &mut self,
        time: Instant,
        escrow: &Escrow,
        last_block_hash: Hash,
    ) -> Result<Feedback, TicketsError> {
        trace!("Handle vrf system tick");
        match self.state {
            State::Sleeping(start) if time.duration_since(start) >= *RESTART_CONSENSUS_TIMER => {
                let ticket = self.on_view_change(last_block_hash);
                Ok(Feedback::BroadcastTicket(ticket))
            }
            State::CollectingTickets(_, start)
                if time.duration_since(start) >= COLLECTING_TICKETS_TIMER * self.view_change =>
            {
                let stakers: StakersGroup = escrow.get_stakers_majority().into_iter().collect();
                self.on_collection_end(stakers).map(Feedback::ChangeGroup)
            }
            _ => Ok(Feedback::Nothing),
        }
    }

    /// On epoch change, restart vrf system.
    pub fn handle_epoch_end(&mut self, last_block_hash: Hash) -> VRFTicket {
        self.on_view_change(last_block_hash)
    }

    /// On receiving valid block, trying to restart VRF system.
    pub fn handle_sealed_block(&mut self) {
        if let State::CollectingTickets(..) = self.state {
            debug!("Stoping old ticket processing");
        }

        self.view_change = 0;
        self.height += 1;
        self.state = State::default();
    }

    /// Receive ticket from other nodes.
    pub fn handle_process_ticket(&mut self, ticket: VRFTicket) -> Result<(), TicketsError> {
        debug!(
            "Receiving new ticket: from={:?}, ticket_view_change={}, \
             our_view_change={}",
            ticket.pkey, ticket.view_change, self.view_change
        );

        if ticket.height != self.height && ticket.height != self.height + 1 {
            debug!(
                "Skipping out of order ticket: our_height={}, ticket_height={}",
                self.height, ticket.height
            );
            return Ok(());
        }

        match &mut self.state {
            State::CollectingTickets(ref mut state, _)
                if ticket.view_change == self.view_change =>
            {
                state.process_ticket(ticket)?;
            }
            _ => {
                debug!("Received out of order: ticket={:?}", ticket);
                if let Some(found) = self.queue.get(&ticket.pkey) {
                    trace!("Ignoring duplicate ticket: from={:?}", ticket.pkey);

                    // keep only latest ticket.
                    if ticket.view_change > found.view_change {
                        debug!(
                            "Found ticket with greater view_change: user={:?}  \
                             view_change={}, old_view_change={}",
                            ticket.pkey, ticket.view_change, found.view_change
                        );
                        self.queue.insert(ticket.pkey, ticket);
                    }
                } else {
                    self.queue.insert(ticket.pkey, ticket);
                }
            }
        };
        Ok(())
    }

    fn on_view_change(&mut self, last_block_hash: Hash) -> VRFTicket {
        info!(
            "Trying to start new ticket collecting: height={}, block_hash={}",
            self.height, last_block_hash
        );
        self.view_change += 1;
        let seed = mix(last_block_hash, self.view_change);
        debug!(
            "Starting new ticket system: seed={:?}, retry={}",
            seed, self.view_change
        );
        let mut collecting = CollectingState::new(seed);
        let ticket =
            collecting.produce_ticket(self.height, self.view_change, self.pkey, &self.skey);
        let hm = mem::replace(&mut self.queue, HashMap::new());
        for (k, out_of_order_ticket) in hm.into_iter() {
            trace!("Processing out of order ticket {:?}", out_of_order_ticket);
            if self.view_change == out_of_order_ticket.view_change {
                if let Err(e) = collecting.process_ticket(out_of_order_ticket) {
                    debug!("Error out of order ticket looks outdated: error={:?}", e);
                }
            } else if self.view_change < out_of_order_ticket.view_change {
                self.queue
                    .insert(k, out_of_order_ticket)
                    .expect("no duplicates");
            }
        }
        self.state = State::CollectingTickets(collecting, clock::now());
        ticket
    }

    fn on_collection_end(&mut self, stakers: StakersGroup) -> Result<ConsensusGroup, TicketsError> {
        info!("Collecting tickets stoped, producing new group");
        match mem::replace(&mut self.state, State::default()) {
            State::CollectingTickets(state, _) => {
                let stakers_majority_count = 2 * stakers.len() / 3;
                // Cannot produce reliable group with low count of tickets, so just restart system.
                if state.tickets_count() < stakers_majority_count {
                    return Err(TicketsError::NotEnoughTicketsCount);
                }
                if stakers.len() > self.max_group_size {
                    return Err(TicketsError::TooManyStakers);
                }
                let (pk, ticket) = state.lowest()?;
                debug!("New random calculated: random={:?}, pkey={:?}", ticket, pk);
                let group =
                    election::choose_consensus_group(stakers, pk, ticket.rand, self.max_group_size);
                debug!("Obtaining new group: group={:?}.", group);
                Ok(group)
            }
            _ => unreachable!(),
        }
    }

    /// Returns number of retries for the electing new group.
    pub fn view_change(&self) -> u32 {
        self.view_change
    }
}

///Node service extension for VrfTicketSystem
impl NodeService {
    pub(crate) fn broadcast_vrf_ticket(&mut self, ticket: VRFTicket) -> Result<(), Error> {
        if self.chain.escrow.get(&self.keys.network_pkey) < stegos_blockchain::MIN_STAKE_AMOUNT {
            debug!("Trying to broadcast ticket but our node is not staker");
            return Ok(());
        }
        self.vrf_system.handle_process_ticket(ticket).unwrap();
        let data = ticket.into_buffer()?;
        self.network.publish(&VRF_TICKETS_TOPIC, data)?;
        Ok(())
    }

    pub(crate) fn handle_vrf_message(&mut self, msg: VRFTicket) -> Result<(), Error> {
        if self.chain.escrow.get(&msg.pkey) >= stegos_blockchain::MIN_STAKE_AMOUNT {
            self.vrf_system.handle_process_ticket(msg)?;
        } else {
            debug!(
                "Received message from peer that is not known staker: pkey={:?}",
                msg.pkey
            );
        }
        Ok(())
    }

    pub(crate) fn handle_vrf_timer(&mut self) -> Result<(), Error> {
        let previous_hash = Hash::digest(self.chain.last_block());
        let result =
            self.vrf_system
                .handle_tick(clock::now(), &self.chain.escrow, previous_hash)?;
        match result {
            Feedback::BroadcastTicket(ticket) => self.broadcast_vrf_ticket(ticket),
            Feedback::ChangeGroup(group) => self.on_change_group(group),
            Feedback::Nothing => Ok(()),
        }
    }
}

///
/// Helpers
///

/// Mix seed hash with round value to produce new hash.
fn mix(random: Hash, round: u32) -> Hash {
    let mut hasher = Hasher::new();
    random.hash(&mut hasher);
    round.hash(&mut hasher);
    hasher.result()
}

impl VRFTicket {
    pub fn new(
        seed: Hash,
        height: u64,
        view_change: u32,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> Self {
        let random = secure::make_VRF(&skey, &seed);
        let msg_hash = Self::hash(&random, &pkey);
        let sig = secure::sign_hash(&msg_hash, skey);

        VRFTicket {
            random,
            height,
            view_change,
            pkey,
            sig,
        }
    }

    fn hash(random: &VRF, pkey: &secure::PublicKey) -> Hash {
        let mut hasher = Hasher::new();
        random.hash(&mut hasher);
        pkey.hash(&mut hasher);
        hasher.result()
    }

    fn validate(&self, seed: Hash) -> Result<(), TicketsError> {
        let hash = Self::hash(&self.random, &self.pkey);
        let msg_valid = secure::check_hash(&hash, &self.sig, &self.pkey);
        let vrf_checked = secure::validate_VRF_source(&self.random, &self.pkey, &seed);
        if msg_valid && vrf_checked {
            Ok(())
        } else {
            Err(TicketsError::InvalidTicket(self.clone()))
        }
    }

    fn random(&self) -> VRF {
        self.random
    }
}

impl CollectingState {
    /// Creates new collecting state
    fn new(last_block_hash: Hash) -> Self {
        CollectingState {
            tickets: HashMap::new(),
            seed: last_block_hash,
        }
    }

    /// Returns count of tickets that we collect.
    fn tickets_count(&self) -> usize {
        self.tickets.len()
    }

    /// Creates new tickets
    /// Panics if we failed to process new ticket.
    fn produce_ticket(
        &mut self,
        height: u64,
        view_change: u32,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> VRFTicket {
        VRFTicket::new(self.seed, height, view_change, pkey, skey)
    }

    /// Process ticket, return error if ticket was invalid, or some node produce multiple tickets.
    fn process_ticket(&mut self, ticket: VRFTicket) -> Result<(), TicketsError> {
        trace!("Processing ticket from={:?}", ticket.pkey);
        ticket.validate(self.seed)?;
        let random = ticket.random();
        if let Some(old_random) = self.tickets.insert(ticket.pkey, random.clone()) {
            if old_random != random {
                return Err(TicketsError::MultipleTickets(ticket.pkey));
            }
        }
        Ok(())
    }

    /// Returns lowest VRF.
    /// Returns error if no ticket was collected during collection phase.
    fn lowest(self) -> Result<(secure::PublicKey, VRF), TicketsError> {
        self.tickets
            .into_iter()
            .min_by_key(|item| item.1.rand)
            .ok_or(TicketsError::NoTickets)
    }
}

impl Default for State {
    fn default() -> Self {
        State::Sleeping(clock::now())
    }
}

impl Hashable for VRFTicket {
    fn hash(&self, state: &mut Hasher) {
        self.random.hash(state);
        self.pkey.hash(state);
        self.sig.hash(state);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use stegos_crypto::pbc::secure;

    //
    // Possible OOM checks:
    //
    // We have two collections for tickets system:
    // 1. is queue for future messages,
    // 2. map for collected tickets.
    // Both collections should have hard limit of size, which is depend on stakers count.
    //

    // TEST Case:
    // Emulating timer asynchronity.
    // Receive many tickets from other node, with single height.
    // We should only save a one message per staker.
    #[test]
    fn test_vrf_oom_queue() {
        let block_hash = Hash::digest("test");
        let height = 1;
        let view_change = 0;
        let (s, p, _sign) = secure::make_random_keys();
        let mut tickets_system = TicketsSystem::new(100, view_change, height, p, s.clone());

        for i in 0..100 {
            let view_change = view_change + i;
            let seed = mix(block_hash, view_change);
            let ticket = VRFTicket::new(seed, height, view_change, p, &s);
            let _ = tickets_system.handle_process_ticket(ticket);
        }

        assert_eq!(tickets_system.queue.len(), 1);
    }

    // TEST Case:
    // Start collecting tickets.
    // Receive many tickets from other node, with single height.
    // We should only save a one message per staker.
    #[test]
    fn test_vrf_oom_collecting() {
        let _ = simple_logger::init_with_level(log::Level::Trace);
        let block_hash = Hash::digest("test");
        let height = 1;
        let view_change = 0;
        let (s, p, _sign) = secure::make_random_keys();
        let mut tickets_system = TicketsSystem::new(100, view_change, height, p, s.clone());
        let ticket = tickets_system.on_view_change(block_hash);
        let _ = tickets_system.handle_process_ticket(ticket);
        // receive self ticket
        if let State::CollectingTickets(ref s, _) = tickets_system.state {
            assert_eq!(s.tickets.len(), 1);
        } else {
            panic!("Other state")
        }
        for i in 0..10 {
            let view_change = view_change + i;
            let seed = mix(block_hash, view_change);
            let ticket = VRFTicket::new(seed, height, view_change, p, &s);
            let _ = tickets_system.handle_process_ticket(ticket);
        }

        if let State::CollectingTickets(ref s, _) = tickets_system.state {
            assert_eq!(s.tickets.len(), 1);
            assert_eq!(s.tickets.iter().next().unwrap().1, &ticket.random);
        } else {
            panic!("Other state")
        }
    }

    // TEST case:
    // Received duplicate of ticket, should be ignored.
    #[test]
    fn test_vrf_duplicate_ticket() {
        let _ = simple_logger::init_with_level(log::Level::Trace);
        let block_hash = Hash::digest("test");
        let height = 1;
        let view_change = 0;
        let (s, p, _sign) = secure::make_random_keys();
        let mut tickets_system = TicketsSystem::new(100, view_change, height, p, s.clone());
        let old_ticket = tickets_system.on_view_change(block_hash);

        // receive self ticket
        if let State::CollectingTickets(ref s, _) = tickets_system.state {
            assert_eq!(s.tickets.len(), 0);
        } else {
            panic!("Other state.")
        }
        let view_change = view_change + 1;

        let seed = mix(block_hash, view_change);
        let ticket = VRFTicket::new(seed, height, view_change, p, &s);

        let _ = tickets_system.handle_process_ticket(ticket.clone());
        // receive self ticket
        if let State::CollectingTickets(ref s, _) = tickets_system.state {
            assert_eq!(s.tickets.len(), 1);
        } else {
            panic!("Other state.")
        }
        assert_eq!(old_ticket, ticket);
        let (s, p, _sign) = secure::make_random_keys();

        for i in 0..10 {
            let view_change = view_change + i;
            let seed = mix(block_hash, view_change);
            let ticket = VRFTicket::new(seed, height, view_change, p, &s);
            let _ = tickets_system.handle_process_ticket(ticket.clone());
            // duplicate creation and receiving
            let _ = tickets_system.handle_process_ticket(ticket);
        }

        if let State::CollectingTickets(ref s, _) = tickets_system.state {
            assert_eq!(s.tickets.len(), 2);
        } else {
            panic!("Other state.")
        }
    }
}

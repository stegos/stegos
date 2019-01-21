//
// MIT License
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

use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::{
    self, PublicKey as SecurePublicKey, SecretKey as SecureSecretKey, Signature as SecureSignature,
    VRF,
};

use lazy_static::lazy_static;

use crate::election::{self, ConsensusGroup, StakersGroup};
use crate::protos::{self, FromProto, IntoProto};
use crate::NodeService;
use protobuf::Message;

use failure::{Error, Fail};
use log::{debug, info, trace};
use std::{
    collections::HashMap,
    mem,
    time::{Duration, Instant},
};

///
/// Constants
///

/// Topic used for vrf system.
pub const VRF_TICKETS_TOPIC: &'static str = "vrf_tickets";

/// How often to check VRF system state.
pub const TIMER: Duration = Duration::from_secs(5);

lazy_static! {
    /// If no new block was provided between this interval - we should start vrf system.
    static ref RESTART_CONSENSUS_TIMER: Duration = crate::MESSAGE_TIMEOUT * 4 + // 4 consensus message
                                          crate::BLOCK_VALIDATION_TIME * 2 + // form block on leader and
                                                                              // validate on witness
                                          crate::TX_WAIT_TIMEOUT; // Propose timeout
}
/// How long we should collect the tickets.
/// This value represent initial timeout, at view_change timeout exponentialy increasing.
const COLLECTING_TICKETS_TIMER: Duration = crate::MESSAGE_TIMEOUT;

/// Minumum count of tickets that we need to collect.
const LOWER_TICKETS_COUNT: usize = 3;

///
/// Data types
///

/// Represent VRFTicket message
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct VRFTicket {
    /// Random value that can be verifyed.
    pub random: VRF,
    /// Height of blockchain at start of current voting process,
    /// used to identify is this ticket is actual or not.
    pub height: u64,
    /// Sender public key.
    pub pkey: SecurePublicKey,
    /// Signature of the message.
    pub sig: SecureSignature,
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
    #[fail(display = "Trying to process tickets not in collection phase.")]
    OutOfOrderTicketsProcessing,
    #[fail(display = "Receiving multiple tickets from {:?}.", _0)]
    MultipleTickets(SecurePublicKey),
}

///
/// States
///

/// Collecting ticket state.
struct CollectingState {
    //TODO: Probably later we can keep in memory only lowest VRF ticket.
    tickets: HashMap<SecurePublicKey, VRF>,
    seed: Hash,
}

/// All possible VRF system state.
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
    skey: SecureSecretKey,
    /// Public key of the current node. Used to create new Tickets.
    pkey: SecurePublicKey,
    /// State of the Ticket system
    state: State,
    // TODO: Don't collect tickets from older state.
    /// Queue of out-of-order messages.
    queue: Vec<VRFTicket>,
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
        pkey: SecurePublicKey,
        skey: SecureSecretKey,
    ) -> TicketsSystem {
        TicketsSystem {
            max_group_size,
            view_change,
            height,
            pkey,
            skey,
            queue: Vec::new(),
            state: State::default(),
        }
    }

    /// Handle eventloop ticks.
    pub fn handle_tick(
        &mut self,
        time: Instant,
        stakers: StakersGroup,
        last_block_hash: Hash,
    ) -> Result<Feedback, TicketsError> {
        trace!("Handle vrf system tick");

        match self.state {
            State::Sleeping(start) if time.duration_since(start) > *RESTART_CONSENSUS_TIMER => {
                let ticket = self.on_view_change(last_block_hash);
                Ok(Feedback::BroadcastTicket(ticket))
            }
            State::CollectingTickets(ref state, start)
                if state.tickets_count() >= LOWER_TICKETS_COUNT
                    && time.duration_since(start) > COLLECTING_TICKETS_TIMER * self.view_change =>
            {
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
            debug!("Stoping old ticket processing.");
        }

        self.view_change = 0;
        self.height += 1;
        self.state = State::default();
    }

    /// Receive ticket from other nodes.
    pub fn hanle_process_ticket(&mut self, ticket: VRFTicket) -> Result<(), TicketsError> {
        trace!("Receiving new ticket from = {:?}.", ticket.pkey);

        if ticket.height != self.height && ticket.height != self.height + 1 {
            debug!(
                "Skipping out of order ticket, our height = {}, ticket height = {}",
                self.height, ticket.height
            );
            return Ok(());
        }

        match &mut self.state {
            State::CollectingTickets(ref mut state, _) => {
                state.process_ticket(ticket)?;
            }
            _ => {
                debug!("Received out of order ticket = {:?}", ticket);
                self.queue.push(ticket);
            }
        };
        Ok(())
    }

    fn on_view_change(&mut self, last_block_hash: Hash) -> VRFTicket {
        info!(
            "Trying to start new ticket collecting, on height = {}, with hash = {:?}",
            self.height, last_block_hash
        );
        self.view_change += 1;
        let seed = mix(last_block_hash, self.view_change);
        debug!(
            "Starting new ticket system seed = {:?}, retry = {}",
            seed, self.view_change
        );
        let mut collecting = CollectingState::new(seed);
        let ticket = collecting.produce_ticket(self.height, self.pkey, &self.skey);
        for out_of_order_ticket in self.queue.drain(..) {
            trace!("Processing out of order ticket {:?}", out_of_order_ticket);
            if let Err(e) = collecting.process_ticket(out_of_order_ticket) {
                debug!("Error out of order ticket looks outdated {:?}", e);
            }
        }
        self.state = State::CollectingTickets(collecting, Instant::now());
        ticket
    }

    fn on_collection_end(&mut self, stakers: StakersGroup) -> Result<ConsensusGroup, TicketsError> {
        info!("Collecting tickets stoped, producing new group.");
        match mem::replace(&mut self.state, State::default()) {
            State::CollectingTickets(state, _) => {
                let ticket = state.lowest()?;
                debug!("New random calculated = {:?}.", ticket);
                let group = election::choose_validators(stakers, ticket.rand, self.max_group_size);
                debug!("Obtaining new group = {:?}.", group);
                Ok(group)
            }
            _ => Err(TicketsError::OutOfOrderTicketsProcessing),
        }
    }
}

///Node service extension for VrfTicketSystem
impl NodeService {
    pub(crate) fn broadcast_vrf_ticket(&mut self, ticket: VRFTicket) -> Result<(), Error> {
        if !self.stakes.contains_key(&self.keys.cosi_pkey) {
            debug!("Trying to broadcast ticket but our node is not staker.");
            return Ok(());
        }
        let proto = ticket.into_proto();
        let data = proto.write_to_bytes()?;
        self.broker.publish(&VRF_TICKETS_TOPIC.to_string(), data)?;
        Ok(())
    }

    pub(crate) fn handle_vrf_message(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        // Decode incoming message.
        let msg: protos::node::VRFTicket = protobuf::parse_from_bytes(&msg)?;
        let msg = VRFTicket::from_proto(&msg)?;
        if self.stakes.get(&msg.pkey).is_some() {
            self.vrf_system.hanle_process_ticket(msg)?;
        } else {
            debug!("Received message from unknown peer = {:?}", msg.pkey);
        }
        Ok(())
    }

    pub(crate) fn handle_vrf_timer(&mut self) -> Result<(), Error> {
        let previous_hash = Hash::digest(self.chain.last_block());
        let all_stakers = self.active_stakers();
        let result = self
            .vrf_system
            .handle_tick(Instant::now(), all_stakers, previous_hash)?;
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
    pub fn new(seed: Hash, height: u64, pkey: SecurePublicKey, skey: &SecureSecretKey) -> Self {
        let random = secure::make_VRF(&skey, &seed);
        let msg_hash = Self::hash(&random, &pkey);
        let sig = secure::sign_hash(&msg_hash, skey);

        VRFTicket {
            random,
            height,
            pkey,
            sig,
        }
    }

    fn hash(random: &VRF, pkey: &SecurePublicKey) -> Hash {
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
            Err(TicketsError::InvalidTicket(*self))
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
        pkey: SecurePublicKey,
        skey: &SecureSecretKey,
    ) -> VRFTicket {
        let ticket = VRFTicket::new(self.seed, height, pkey, skey);
        self.process_ticket(ticket).unwrap();
        ticket
    }

    /// Process ticket, return error if ticket was invalid, or some node produce multiple tickets.
    fn process_ticket(&mut self, ticket: VRFTicket) -> Result<(), TicketsError> {
        debug!("Processing ticket from = {:?}.", ticket.pkey);
        ticket.validate(self.seed)?;
        let random = ticket.random();
        if let Some(old_random) = self.tickets.insert(ticket.pkey, random) {
            if old_random != random {
                return Err(TicketsError::MultipleTickets(ticket.pkey));
            }
        }
        Ok(())
    }

    /// Returns lowest VRF.
    /// Returns error if no ticket was collected during collection phase.
    fn lowest(self) -> Result<VRF, TicketsError> {
        self.tickets
            .into_iter()
            .map(|(_k, v)| v)
            .fold(None, |acc: Option<VRF>, item| {
                let value = if let Some(acc) = acc {
                    if item.rand < acc.rand {
                        item
                    } else {
                        acc
                    }
                } else {
                    item
                };
                Some(value)
            })
            .ok_or(TicketsError::NoTickets)
    }
}

impl Default for State {
    fn default() -> Self {
        State::Sleeping(Instant::now())
    }
}

impl Hashable for VRFTicket {
    fn hash(&self, state: &mut Hasher) {
        self.random.hash(state);
        self.pkey.hash(state);
        self.sig.hash(state);
    }
}

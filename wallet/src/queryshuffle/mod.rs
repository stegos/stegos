//! mod.rs - QueryShuffle Protocol for secure and anonymous transaction construction

//
// Copyright (c) 2019 Stegos AG
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
//

// ========================================================================
// When a wallet wants to participate in a QueryShuffle session,
// it should advertise its desire by sending a message to the Facilitator
// node, along with its network ID (currently a pbc::pbc::PublicKey).
//
// When the Facilitator has accumulated a sufficient number of requestor
// nodes, it collects those ID's and sends a message to each of them, to
// start a QueryShuffle session. The Facilitator should send that list of
// node ID's along with an initial unique session ID (sid).
//
// Each wallet will then assemble their list of TXINs and proposed UTXO output
// details (uncloaked recipient pkey, amount, data). Wallet should then call
// start() with the list of all participant node ID's, their own node ID,
// the list of TXINs, the list of proposed spending, and the session ID (sid)
// provided by the Facilitator node.
//
// Since wallets are free to advertise different recipient public keys for
// every transaction, the list of TXINs must be accompanied by the secret key
// corresponding to the uncloaked public key used in the formation of the
// blockchain UTXO.
//
// At the start of the first round of QueryShuffle, these TXINs are checked
// by forming ownership signatures, and verifying that these signatures check.
//
// If all TXIN are good, the TXIN hash values and ownership signatures are
// sent to all other QueryShuffle participants, and they will also perform
// the signature check. If other participants have problems with any TXIN,
// the sender wallet will be excluded from further participation without
// warning.
//
// The proposeed spending, plus fee, is also checked for zero balance against
// the TXINs. If not zero balance, then the session is aborted for the wallet.
//
// During the session, the wallets will be asked to construct UTXOs from the
// list of proposed spending. Each request for UTXO's should make use of
// fresh randomness in choosing the cloaking factors, gamma and delta.
//
// The arguments to start() are checked for validity:
//
//  1. No more than MAX_SHARING_TXOUTS can be indicated by the proposed spending list
//     (Currently MAX_SHARING_TXOUTS = 5). If fewer UTXOs will be produced, then the
//     DiceMix sharing matrix will be zero-filled and cloaked up to this maximum.
//
//  2. Each TXIN must refer to a blockchain UTXO that can be proven to be
//     owned by the wallet. We do that by checking that the hash of the UTXO
//     can be signed by the cloaked recipient key shown in the UTXO.
//
// ========================================================================

#![allow(non_snake_case)]
#![allow(unused)]

use super::MAX_SHARING_TXOUTS;

mod error;
pub use error::*;

pub mod message;
use message::*;

mod protos;

use crate::queryshuffle::message::QueryShuffleMessage;
use crate::storage::{OutputValue, PaymentValue};
use failure::format_err;
use failure::Error;
use futures::task::current;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use futures_stream_select_all_send::select_all;
use log::*;
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use std::mem;
use std::time::Duration;
use stegos_blockchain::PaymentTransaction;
use stegos_blockchain::{Output, Timestamp};
use stegos_blockchain::{PaymentOutput, PaymentPayloadData};
use stegos_crypto::bulletproofs::{simple_commit, validate_range_proof};
use stegos_crypto::dicemix;
use stegos_crypto::dicemix::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher, HASH_SIZE};
use stegos_crypto::pbc;
use stegos_crypto::scc::{
    make_deterministic_keys, sign_hash, validate_sig, Fr, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_network::Network;
use stegos_node::txpool::QueryPoolJoin;
use stegos_node::txpool::QueryPoolNotification;
use stegos_node::txpool::QUERYPOOL_ANNOUNCE_TOPIC;
use stegos_node::txpool::QUERYPOOL_JOIN_TOPIC;
use stegos_node::Node;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::{clock, Delay};

/// A topic used for QueryShuffle unicast communication.
pub const QUERYSHUFFLE_TOPIC: &'static str = "queryshuffle";

pub const QUERYSHUFFLE_TIMER: Duration = Duration::from_secs(60); // recurring 1sec events

pub const MSG_FLOOD_LIMIT: usize = 5; // max nbr of pending messages from one participant

const QUERY_FEE: i64 = 1_000; // 0.001 STG

// ==============================================================

macro_rules! sdebug {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Debug, concat!("[QS{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}
macro_rules! sinfo {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Info, concat!("[QS{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}
macro_rules! swarn {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Warn, concat!("[QS{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}
macro_rules! serror {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Error, concat!("[QS{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}

type ParticipantID = dicemix::ParticipantID;
type UTXO = Hash;

#[derive(Debug)]
/// QueryShuffle Events.
enum QueryShuffleEvent {
    PoolFormed(pbc::PublicKey, Vec<u8>),
    MessageReceived(pbc::PublicKey, Vec<u8>),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Snowball Finite State Machine state.
pub enum State {
    Start,
    PoolWait,
    SharedKeying,
    Commitment,
    CloakedVals,
    Finish,
}

impl State {
    /// Enum to string.
    fn name(&self) -> &'static str {
        match *self {
            State::Start => "Start",
            State::PoolWait => "PoolWait",
            State::SharedKeying => "SharedKeying",
            State::Commitment => "Commitment",
            State::CloakedVals => "CloakedVals",
            State::Finish => "Finish",
        }
    }
}

#[derive(Debug)]
/// Possible outcomes of QueryShuffle
pub struct QueryShuffleOutput {
    pub participants: Vec<ParticipantID>,
    pub queries: Vec<UTXO>,
    pub fee: i64,
    pub is_leader: bool,
}

impl Hashable for QueryShuffleOutput {
    fn hash(&self, state: &mut Hasher) {
        self.participants.iter().for_each(|part| part.hash(state));
        self.queries.iter().for_each(|cutxo| cutxo.hash(state));
        self.fee.hash(state);
        self.is_leader.hash(state);
    }
}

#[derive(Debug, Clone)]
pub enum QueryShuffleTestPlan {
    // StopCommunication -- stop communications with other participants
    // before sending messages pertaining to the next state
    // State here must be the current state which is about to
    // transition to a next state.
    //
    // If second arg is None, don't send message to anyone,
    // else, don't send message to indicated participants
    StopCommunication(State, Option<Vec<ParticipantID>>),
}

/// QueryShuffle implementation.
pub struct QueryShuffle {
    // -------------------------------------------
    // Startup Info - known at time of QueryShuffle::new()
    /// Account Secret Key.
    account_pkey: PublicKey,

    /// Account Secret Key.
    account_skey: SecretKey,

    /// My public txpool's key.
    my_participant_id: ParticipantID,

    /// Faciliator's PBC public key
    facilitator: pbc::PublicKey,

    /// Query Server PBC public key
    server_pkey: pbc::PublicKey,

    /// Public keys of txpool's members,
    participants: Vec<ParticipantID>,

    /// Network API.
    network: Network,

    /// Timeout timer.
    timer: Option<Delay>,

    /// Incoming events.
    events: Box<dyn Stream<Item = QueryShuffleEvent, Error = ()> + Send>,

    /// FSM.
    state: State,

    // --------------------------------------------
    // Items computed from TXINS before joining pool

    // list of my UTXO queries
    my_utxos: Vec<UTXO>,

    // fee paid for query
    my_fee: i64,

    // FIFO queue of incoming messages not yet processed
    msg_queue: VecDeque<(ParticipantID, Hash, QueryShufflePayload)>,

    // --------------------------------------------
    // After facilitator launches our session.
    // Items computed in start()

    // session_round - init to zero, incremented in each round
    session_round: u16,

    /// Session ID, based on prior session_id, session_round, list of participants
    session_id: Hash,

    // Session round keying
    sess_pkey: PublicKey, // my public key
    sess_skey: SecretKey, // my secret key

    // public keys from other participants
    sess_pkeys: HashMap<ParticipantID, PublicKey>,

    // --------------------------------------------
    // Items compupted in commit()

    // size of serialized UTXO for retrieval
    serialized_cutxo_size: Option<usize>,

    // nbr of DiceMix chunks per UTXO
    dicemix_nbr_cutxo_chunks: Option<usize>,

    // cloaking hash value used between me and each other participant
    k_cloaks: HashMap<ParticipantID, Hash>,

    // cloaked matrices from each participant
    matrices: HashMap<ParticipantID, DcMatrix>,

    // commitments from each participant = hash(matrix, gamma_adj, fee)
    commits: HashMap<ParticipantID, Hash>,

    commit_phase_participants: Vec<ParticipantID>,

    // list of participants that did not send us matrices
    // but to whom we sent our matrix,
    // and for whom we computed sharing cloaks
    excl_participants: Vec<ParticipantID>,

    // dictionary by participantID of the cloaking factors
    // used for the missing participants.
    excl_cloaks: HashMap<ParticipantID, Hash>,

    // table of participant cloaking hashes used with excluded participants
    // one of these from each remaining participant during blame discovery
    all_excl_cloaks: HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,

    // --------------------------------------------
    // Items computed in make_superquery()

    // --------------------------------------------
    // Send/Receieve - we start by sending to all participants,
    // then move all but myself over to pending participants.
    // Upon hearing valid responses from expected participants
    // they get moved back to participants list. Remaining pending_participants
    // is the list of participants that dropped out during this exchange
    pending_participants: HashSet<ParticipantID>,

    // QueryShuffle test-plan
    test_plan: Option<QueryShuffleTestPlan>,
}

impl QueryShuffle {
    // ----------------------------------------------------------------------------------------------
    // Public API.
    // ----------------------------------------------------------------------------------------------

    /// Create a new QueryShuffle instance.
    pub fn new(
        account_skey: SecretKey,
        account_pkey: PublicKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        _node: Node,
        facilitator: pbc::PublicKey,
        server: pbc::PublicKey,
        my_utxos: Vec<UTXO>,
        my_fee: i64,
    ) -> QueryShuffle {
        // check the maximal number of UTXOs.
        assert!(my_utxos.len() <= MAX_SHARING_TXOUTS);
        assert!(my_fee == QUERY_FEE * (MAX_SHARING_TXOUTS as i64));

        let participants: Vec<ParticipantID> = Vec::new();
        let session_id: Hash = Hash::random();
        let state = State::Start;
        let mut rng = thread_rng();
        let seed = rng.gen::<[u8; 32]>();
        let my_participant_id = dicemix::ParticipantID::new(network_pkey, seed);

        //
        // Events.
        //
        let mut events: Vec<Box<dyn Stream<Item = QueryShuffleEvent, Error = ()> + Send>> =
            Vec::new();

        // Network.
        let pool_formed = network
            .subscribe_unicast(QUERYSHUFFLE_TOPIC)
            .expect("connected")
            .map(|m| QueryShuffleEvent::MessageReceived(m.from, m.data));
        events.push(Box::new(pool_formed));

        // Pool formation.
        let pool_formed = network
            .subscribe_unicast(QUERYPOOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| QueryShuffleEvent::PoolFormed(m.from, m.data));
        events.push(Box::new(pool_formed));

        // SbTimeout timer events
        let timer = None;

        let events = select_all(events);

        let mut sb = QueryShuffle {
            account_skey,
            account_pkey,
            sess_pkey: PublicKey::zero(), // just a dummy placeholder for now
            my_participant_id,
            facilitator,
            state,
            server_pkey: server,
            participants,
            session_id,
            network,
            timer,
            events,
            my_utxos,
            my_fee,
            sess_skey: SecretKey::zero(), // dummy placeholder for now
            // these are all empty participant lists
            session_round: 0,
            sess_pkeys: HashMap::new(),
            k_cloaks: HashMap::new(),
            excl_cloaks: HashMap::new(),
            all_excl_cloaks: HashMap::new(),
            commits: HashMap::new(),
            matrices: HashMap::new(),
            pending_participants: HashSet::new(),
            excl_participants: Vec::new(),
            msg_queue: VecDeque::new(),
            serialized_cutxo_size: None,
            dicemix_nbr_cutxo_chunks: None,
            commit_phase_participants: Vec::new(),
            test_plan: None,
        };
        sb.send_pool_join();
        sb
    }

    // for debug - set up a test plan
    pub fn set_test_plan(&mut self, plan: QueryShuffleTestPlan) {
        self.test_plan = Some(plan.clone());
    }

    // ----------------------------------------------------------
    // QueryShuffle Internals

    /// Change state.
    fn change_state(&mut self, state: State) {
        swarn!(self, "=> ({})", state.name());
        self.state = state;
        if self.state == State::Finish {
            return;
        }
        let timer = Delay::new(clock::now() + QUERYSHUFFLE_TIMER);
        self.timer = Some(timer);
        current().notify();
    }

    // ----------------------------------------------------------------------------------------------
    // TxPool Membership
    // ----------------------------------------------------------------------------------------------

    // When a wallet wants to participate in a QueryShuffle session,
    // it should advertise its desire by sending a message to the Facilitator
    // node, along with its network ID (currently a pbc::pbc::PublicKey).
    //
    // When the Facilitator has accumulated a sufficient number of requestor
    // nodes, it collects those ID's and sends a message to each of them, to
    // start a QueryShuffle session. The Facilitator should send that list of
    // node ID's along with an initial unique session ID (sid).

    /// Called when facilitator has been changed.
    pub fn change_facilitator(&mut self, facilitator: pbc::PublicKey) {
        self.facilitator = facilitator;
        sinfo!(self, "Change facilitator to {}", &facilitator);
        if self.state == State::PoolWait {
            self.send_pool_join();
        }
    }

    /// Sends a request to join tx pool.
    fn send_pool_join(&mut self) {
        sdebug!(
            self,
            "Sending pool join request: to_facilitator={}",
            self.facilitator
        );
        // To join a session we must send our list of TXINS, along with
        // our proof of ownership signature on all of them.

        let msg = QueryPoolJoin {
            seed: self.my_participant_id.seed,
        };
        let msg = msg.into_buffer().unwrap();
        self.network
            .send(self.facilitator, QUERYPOOL_JOIN_TOPIC, msg)
            .expect("Connected");

        self.msg_queue.clear();
        self.session_round = 0;
        self.change_state(State::PoolWait);
    }

    /// Called when a new txpool is formed.
    fn on_pool_notification(
        &mut self,
        from: pbc::PublicKey,
        pool_info: QueryPoolNotification,
    ) -> HandlerResult {
        if from != self.facilitator {
            swarn!(
                self,
                "Ignore pool notification from a non-facilitator: expected={}, got={}",
                self.facilitator,
                from
            );
            return Ok(Async::NotReady);
        }

        if self.state != State::PoolWait {
            swarn!(
                self,
                "Ignore pool notification in current state: msg={:?}",
                pool_info
            );
            return Ok(Async::NotReady);
        }

        let pool_info = match pool_info {
            QueryPoolNotification::Canceled => {
                swarn!(
                    self,
                    "Pool has been cancelled, waiting for the next facilitator."
                );
                // Wait until self.change_facilitator() is called by timer.
                assert!(self.timer.is_some(), "timer is active");
                return Ok(Async::NotReady);
            }
            QueryPoolNotification::Started(info) => info,
        };

        if !pool_info.participants.contains(&self.my_participant_id) {
            swarn!(self, "We aren't a participant");
            // Wait until self.change_facilitator() is called by timer.
            assert!(self.timer.is_some(), "timer is active");
            return Ok(Async::NotReady);
        }

        self.session_id = pool_info.session_id;
        self.participants = pool_info.participants.clone();

        self.participants.sort();
        self.participants.dedup();

        sinfo!(self, "Formed a pool");
        for pkey in &self.participants {
            sinfo!(self, "Member {:?}", pkey);
        }

        // start processing queued transactions....
        self.start()
    }
}

type HandlerResult = Poll<QueryShuffleOutput, QueryShuffleError>;

impl Future for QueryShuffle {
    type Item = QueryShuffleOutput;
    type Error = QueryShuffleError;

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        assert_ne!(self.state, State::Finish, "poll() after finish");
        match self.timer.poll().expect("Should be no error in timer") {
            Async::Ready(Some(_)) => match self.handle_timer() {
                Ok(Async::NotReady) => (),
                result => return result,
            },
            Async::NotReady | Async::Ready(None) => (),
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: HandlerResult = match event {
                        QueryShuffleEvent::PoolFormed(from, pool_info) => {
                            let pool_info = match QueryPoolNotification::from_buffer(&pool_info) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    serror!(self, "Invalid PoolInfo message: {}", e);
                                    continue;
                                }
                            };
                            self.on_pool_notification(from, pool_info)
                        }
                        QueryShuffleEvent::MessageReceived(from, msg) => {
                            let msg = match QueryShuffleMessage::from_buffer(&msg) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    serror!(self, "Ignore invalid message: {}", e);
                                    continue;
                                }
                            };
                            if msg.source.pkey != from {
                                swarn!(
                                    self,
                                    "Ignore a message with invalid source: expected={}, got={}",
                                    from,
                                    msg.source.pkey
                                );
                                continue;
                            }
                            if msg.destination != self.my_participant_id {
                                sdebug!(
                                    self,
                                    "Ignore a message to other participant: msg_id={}, my_id={}",
                                    msg.destination,
                                    self.my_participant_id
                                );
                                continue;
                            }
                            self.on_message_received(&msg.source, &msg.sid, &msg.payload)
                        }
                    };

                    match result {
                        Ok(Async::Ready(r)) => {
                            // Finish.
                            return Ok(Async::Ready(r));
                        }
                        Ok(Async::NotReady) => {
                            continue;
                        }
                        Err(error) => {
                            serror!(self, "{:?}", error);
                            return Err(error);
                        }
                    }
                }
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

// -------------------------------------------------
// Event Handlers

#[derive(Debug)]
enum MsgHandlerResponse {
    Discard,
    ReEnqueue,
    Accept,
}

impl QueryShuffle {
    /*
    So the protocol could be written as state machine, called by scheduler
    on receipt of events. Events are obtained by the scheduler polling for them.
    Two events are of interest here:
     1. periodic timer events, occurring at 1sec intervals, and
     2. messages arriving from other participants.

     fn event_handler(&mut self, event: Event) -> Result<QueryShuffleOutput, QueryShuffleError> {
         match event.kind {
             Event::TimerTic(tic) => {
                 // increment our timer,
                 // check for timeout im pending reads
                 // if not timeout then return NotReady
                 // else perform next session phase
             },
             Event::Message(msg) => {
                 // check if msg is expected type
                 // if not, just enqueue for later
                 // else validate message and enqueue its information
                 // If all participants have responded, perform the next
                 // session phase,
                 // else, return NoReady
             }
         }
     }

     Messages could be of two broad categories:

     1. Out-of-band messages - direct the scheduler to perform
        some action, which might include aborting the current session,
        possibly restarting with supervision from a different facilitator.

     2. In-band inter-phase messages from other participants -

       a) Some of these might arrive in apparent out-of-order delivery, as
          might happen when one participant has progressed further than we have.
          These should be enqueued for later use.

       b) Other messages might pertain to our next anticipated phase of the session.
          Their payloads must be validated, and if valid, enqueued into a response queue
          from other participants. If invalid, then responder is considered
          to have failed to respond and will be considered missing in the next phase.

       c) Other messages might arrive that are irrelevant or noise messages, which
          should be discarded. Examples would be messages from participants that are not
          in our session group, or from participants we wish to exclude.

    The message handler is a state machine within the scheduler state machine. Messages
    directed to the session are identified by session ID. Messages for other sessions
    should be enqueued because we might also end up in that session later.

    fn message_handler(&mut self, message: Message) -> Result<QueryShuffleOutput, QueryShuffleError> {
        match message.category() {
            Message::OutOfBand(info) => {
                // handle out of band message
                // which might include altering the state
            }
            Message::InBand(info) => {
                // handle in-band message
                // which might discard this message,
                // enueue it for later use,
                // perform validation of information and
                // enqueue for this session next phase,
                // if all participants have responded for the next phase
                // then we perform that phase and end by setting up the
                // state machine for its following phase.
            }
        }
    }
    */

    fn handle_timer(&mut self) -> HandlerResult {
        assert_ne!(self.state, State::Finish, "poll() after finish");
        // reset state to indicate done waiting for this kind of message
        // whichever participants have responded are now held in self.participants.
        // whichever participants did not respond are in self.pending_participants.
        self.timer = None;
        swarn!(self, "Timed out");
        if self.state == State::PoolWait {
            self.send_pool_join();
            return Ok(Async::NotReady);
        }

        if !self.pending_participants.is_empty() {
            sdebug!(
                self,
                "Missing participants: {:?}",
                self.pending_participants
            );
        }
        self.perform_next_phase()
    }

    fn from_msg_count(&self, from: &ParticipantID) -> usize {
        let mut ct = 0;
        for (f, _, _) in self.msg_queue.clone() {
            if f == *from {
                ct += 1;
            }
        }
        ct
    }

    fn on_message_received(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &QueryShufflePayload,
    ) -> HandlerResult {
        sdebug!(
            self,
            "Message: from={}, sid={}, msg={}",
            *from,
            *sid,
            *payload
        );

        // insert new message at head of queue
        if self.from_msg_count(from) < MSG_FLOOD_LIMIT {
            self.msg_queue.push_front((*from, *sid, payload.clone()));
        }

        if self.state == State::PoolWait || self.pending_participants.is_empty() {
            // if messages arrive while we aren't waiting (yet),
            // just enqueue them.
            return Ok(Async::NotReady);
        }

        // Scan the message queue and process each message
        // look for actionable messages, while also cleaning out
        // the queue.

        // If actionable message found, then peform action,
        // and rescan from the top of the queue again.
        //
        // Otherwise, if no actionable messages, just return to event handler
        //
        // This is the only place where actions are dispatched.
        loop {
            let queue = mem::replace(&mut self.msg_queue, VecDeque::new());
            let mut ready_to_run = false; // true if we found something to do...
                                          // process each message in the queue
            for (from, sid, payload) in queue {
                if ready_to_run {
                    // stuff message back on tail of queue for next pass
                    self.msg_queue.push_back((from, sid, payload));
                } else {
                    // handle one message, filtering out the queue
                    match self.handle_message(&from, &sid, &payload) {
                        MsgHandlerResponse::Discard => { /* discard by default */ }
                        MsgHandlerResponse::ReEnqueue => {
                            // guard against message flooding attacks
                            if self.from_msg_count(&from) < MSG_FLOOD_LIMIT {
                                // put message back on queue for later
                                self.msg_queue.push_back((from, sid, payload));
                            }
                        }
                        MsgHandlerResponse::Accept => {
                            // message will be removed from queue by default
                            self.pending_participants.remove(&from);
                            self.participants.push(from);
                            // we are actionable if no more pending participants
                            ready_to_run = self.pending_participants.is_empty();
                        }
                    }
                }
            }
            if ready_to_run {
                let ans = self.perform_next_phase();
                match ans {
                    Ok(Async::Ready(_)) => {
                        return ans;
                    }
                    Err(_) => {
                        return ans;
                    }
                    _ => { /* go around again */ }
                }
            } else {
                // we processed all messages, and no actions happened
                break;
            }
        }
        Ok(Async::NotReady)
    }

    fn handle_message(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &QueryShufflePayload,
    ) -> MsgHandlerResponse {
        // If message matches what would be expected for a given msg_state,
        // then process the message.
        //
        // Otherwise, perhaps a participant is ahead of us and we see their
        // message for the next phase, so re-enqueue the message for later
        // processing.
        //
        // It is possible for messages to have arrived from other participants,
        // even when our own state is Start. They might be ahead of us.
        match (self.state, payload) {
            (State::SharedKeying, QueryShufflePayload::SharedKeying { pkey, fee }) => {
                self.handle_shared_keying(from, sid, pkey, *fee)
            }
            (State::Commitment, QueryShufflePayload::Commitment { cmt }) => {
                self.handle_commitment(from, sid, cmt)
            }
            (State::CloakedVals, QueryShufflePayload::CloakedVals { matrix, cloaks }) => {
                self.handle_cloaked_vals(from, sid, matrix, cloaks)
            }
            _ => MsgHandlerResponse::ReEnqueue,
        }
    }

    fn perform_next_phase(&mut self) -> HandlerResult {
        self.timer = None; // cancel any pending timeout timer
        match self.state {
            State::Start | State::Finish | State::PoolWait => {
                panic!(
                    "There should be no processing in {} state.",
                    self.state.name()
                );
            }
            State::SharedKeying => self.commit(),
            State::Commitment => self.share_cloaked_data(),
            State::CloakedVals => self.make_superquery(),
        }
    }

    // message handlers should accept one payload,
    // validate it and enqueue it. Then return one
    // of 3 possible results:
    //  1. Message Accepted and processed
    //  2. Message rejected as invalid
    //  3. Message should be enqueued for later processing
    //
    // In case 1, if no pending_participants remain, the next phase
    // should be initiated. And if so, then all remaining messages
    // in the message queue should be appended to the new queue
    // for later processing.
    //
    // State processing of messages for that state requres:
    //   1. message SID = Session ID
    //      If not, then maybe message is from the next retry,
    //      so re-enqueue. (Could also be spurious, but no way to tell)
    //   2. message From must be among the pending participants
    //      for this session round (same Session ID).
    //      Otherwise it is a spurious message.
    //
    //  Checking must be performed in this order, because the actual
    //  pending participants may be different for other session ID's.

    // --- Prep for communications and transition to next phase ---

    fn handle_shared_keying(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        pkey: &PublicKey,
        fee: i64,
    ) -> MsgHandlerResponse {
        if *sid == self.session_id {
            if self.pending_participants.contains(from)
                && fee == QUERY_FEE * (MAX_SHARING_TXOUTS as i64)
            {
                // debug!("In handle_shared_keying()");
                sdebug!(self, "received shared keying {:?}", pkey);
                self.sess_pkeys.insert(*from, *pkey);
                MsgHandlerResponse::Accept
            } else {
                MsgHandlerResponse::Discard
            }
        } else {
            MsgHandlerResponse::ReEnqueue
        }
    }

    // --- Commitments to DiceMix Matries ----

    fn handle_commitment(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        cmt: &Hash,
    ) -> MsgHandlerResponse {
        // debug!("In handle_commitment()");
        if *sid == self.session_id {
            if self.pending_participants.contains(from) {
                sdebug!(self, "saving commitment {}", cmt);
                self.commits.insert(*from, *cmt);
                MsgHandlerResponse::Accept
            } else {
                MsgHandlerResponse::Discard
            }
        } else {
            MsgHandlerResponse::ReEnqueue
        }
    }

    // --- Exchange of Cloaked DiceMix Matrices ---

    fn same_exclusions(&self, cloaks: &HashMap<ParticipantID, Hash>) -> bool {
        // We won't be able to form the same supertransaction as others
        // unless they have exactly the same missing participants that we do
        self.excl_participants
            .iter()
            .all(|p| cloaks.contains_key(p))
            && cloaks.keys().all(|p| self.excl_participants.contains(p))
    }

    fn handle_cloaked_vals(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        matrix: &DcMatrix,
        cloaks: &HashMap<ParticipantID, Hash>,
    ) -> MsgHandlerResponse {
        // debug!("In handle_cloaked_vals()");
        if *sid == self.session_id {
            if self.pending_participants.contains(from) {
                let cmt = self.commits.get(from).expect("Can't access commit");
                sdebug!(self, "Checking commitment {}", cmt);
                // DiceMix expects to be able to find all missing
                // participant cloaking values
                if *cmt == hash_data(matrix) && self.same_exclusions(cloaks) {
                    sdebug!(self, "Commitment check passed {}", cmt);
                    sdebug!(self, "Saving cloaked data");
                    self.matrices.insert(*from, matrix.clone());
                    self.all_excl_cloaks.insert(*from, cloaks.clone());
                    MsgHandlerResponse::Accept
                } else {
                    // participant has wrong impression, or we are
                    // under attack...
                    swarn!(self, "Commitment check failed {}", cmt);
                    MsgHandlerResponse::Discard
                }
            } else {
                MsgHandlerResponse::Discard
            }
        } else {
            MsgHandlerResponse::ReEnqueue
        }
    }

    // ----------------------------------------------------------

    fn need_3_participants(&self) -> HandlerResult {
        if self.participants.len() < 3 {
            return Err(QueryShuffleError::TooFewParticipants(
                self.participants.len(),
            ));
        }
        Ok(Async::NotReady)
    }

    // ----------------------------------------------------------
    // The interrim phases of QueryShuffle protocol
    //
    // In each phase, input items from other participants are
    // processed, new items computed, and some are shared with
    // other participants.
    //
    // The phases are split out into basic blocks which run when
    // either all participants have responded, or a timeout occurs.
    // Each phase terminates with a broadcast to other recipients,
    // or a recursive call to start again for a new round.
    //
    // Just before returning to the scheduler, the state machine is
    // set up for receipt of specific items needed for the next phase.

    fn start(&mut self) -> HandlerResult {
        // Possible exits:
        //   - fewer than 3 participants = protocol fail
        //   - normal exit

        self.need_3_participants()?;

        self.participants.sort(); // put into consistent order
        self.session_round += 1;
        self.session_id = {
            let mut state = Hasher::new();
            "sid".hash(&mut state);
            self.session_id.hash(&mut state);
            self.session_round.hash(&mut state);
            self.participants.iter().for_each(|p| p.hash(&mut state));
            state.result()
        };

        // choose a random signature k value, and send along with my
        // session cloaking pkey, as the K = k * G to be used for
        // collective signing in this round.

        // ===============================================================
        // CAUTION: Because we use Schnorr signatures, it is imperative
        // that a different k value be used when the message being signed
        // changes.
        // If, for two different messsages, you did happen to use
        // the same k value, then you immediately lose your secret key
        // to anyone who can do some simple Field arithmetic.
        //
        // This is the Sony Playstation attack, and the reason that
        // our crypto signing primitives utilize deterministic randomness.
        //
        // Ordinarily, if you called our Schnorr signing primitives this
        // would be handled properly for you. But since we are bypassing
        // those primitives to provide a composite Schnorr multi-signature
        // on the super transaction, we must be careful here for ourselves.
        // ===============================================================

        // Generate new cloaked sharing key set and share with others
        // also shares our sigK value at this time.
        let (sess_sk, sess_pk) = make_session_key(&self.account_skey, &self.session_id);
        self.sess_pkey = sess_pk;
        self.sess_skey = sess_sk.clone();

        self.sess_pkeys = HashMap::new();
        self.sess_pkeys.insert(self.my_participant_id, sess_pk);

        self.send_session_pkey(&sess_pk, self.my_fee);

        // Collect cloaked sharing keys from others
        // fill in sess_pkeys and sigK_vals
        self.receive_session_pkeys()
    }

    fn commit(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure

        self.need_3_participants()?;

        // participants at the time of matrix construction
        self.commit_phase_participants = self.participants.clone();

        // Generate shared cloaking factors
        self.k_cloaks = dc_keys(
            &self.commit_phase_participants,
            &self.sess_pkeys,
            &self.my_participant_id,
            &self.sess_skey,
            &self.session_id,
        );

        // set size of serialized UTXO if not already established
        match self.serialized_cutxo_size {
            None => {
                let msg = serialize_utxo(&self.my_utxos[0]);
                self.serialized_cutxo_size = Some(msg.len());
                let row = split_message(&msg, None);
                self.dicemix_nbr_cutxo_chunks = Some(row.len());
            }
            _ => {}
        }

        let my_matrix = Self::encode_matrix(
            &self.commit_phase_participants,
            &self.my_utxos,
            &self.my_participant_id,
            &self.k_cloaks,
            self.dicemix_nbr_cutxo_chunks.unwrap(),
        );
        self.matrices = HashMap::new();
        self.matrices
            .insert(self.my_participant_id, my_matrix.clone());

        // form commitments to our matrix and gamma sum
        let my_commit = hash_data(&my_matrix);

        // Collect and validate commitments from other participants
        self.commits = HashMap::new();
        self.commits.insert(self.my_participant_id, my_commit);

        // send sharing commitment to other participants
        self.send_commitment(&my_commit);

        // fill in commits
        self.receive_commitments()
    }

    fn share_cloaked_data(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure
        //   - .expect() errors - should never happen in proper code

        self.need_3_participants()?;

        // make note of missing participants here
        // so we can furnish decloaking values to other participants
        let mut excl_cloaks = HashMap::new();
        let mut excl_participants = Vec::new();
        let prev_parts = self.commit_phase_participants.clone();
        let cur_parts = self.participants.clone();
        prev_parts
            .iter()
            .filter(|p| !cur_parts.contains(p))
            .for_each(|&p| {
                excl_participants.push(p);
                let cloaks = self.k_cloaks.get(&p).expect("can't get k_cloaks");
                excl_cloaks.insert(p, cloaks.clone());
            });
        self.excl_participants = excl_participants;
        self.excl_cloaks = excl_cloaks;
        self.all_excl_cloaks = HashMap::new();
        self.all_excl_cloaks
            .insert(self.my_participant_id, self.excl_cloaks.clone());

        // send committed and cloaked data to all participants
        let my_matrix = self
            .matrices
            .get(&self.my_participant_id)
            .expect("Can't access my own matrix");

        self.send_cloaked_data(&my_matrix, &self.excl_cloaks);

        // At this point, if we don't hear valid responses from all
        // remaining participants, we abort and start a new session
        // collect cloaked contributions from others

        // fill in matrices, cloaked_gamma_adj, cloaked_fees,
        // and all_excl_k_cloaks, using commits to validate incoming data
        self.receive_cloaked_data()
    }

    fn had_dropouts(&self) -> bool {
        !(self
            .commit_phase_participants
            .iter()
            .all(|p| self.participants.contains(p))
            && self
                .participants
                .iter()
                .all(|p| self.commit_phase_participants.contains(p)))
    }

    fn make_superquery(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in proper code
        //
        self.need_3_participants()?;

        if self.had_dropouts() {
            // if we don't have exactly the same participants as when
            // we shared the cloaked data, then we won't be able to
            // agree on the contents of a supertransaction, and signing
            // will fail. So may as well restart now.
            //
            // An inifinite restart loop is avoided here because we obviously
            // now have fewer participants than before. Either we eventually
            // succeed, or we fail by having fewer than 3 participants.
            swarn!(self, "dropouts occurred - restarting");
            return self.start();
        }

        // -------------------------------------------------------
        // we got valid responses from all participants,
        // get the cloaks we put there for all missing participants
        let total_fees = (self.participants.len() as i64) * QUERY_FEE * (MAX_SHARING_TXOUTS as i64);
        sdebug!(self, "total fees = {}", total_fees);

        let msgs = dc_decode(
            &self.participants,
            &self.matrices,
            &self.my_participant_id,
            MAX_SHARING_TXOUTS,
            self.dicemix_nbr_cutxo_chunks.unwrap(),
            &self.excl_participants, // the excluded participants
            &self.all_excl_cloaks,
        );
        sdebug!(self, "nbr msgs = {}", msgs.len());

        let mut all_utxos = Vec::<UTXO>::new();
        let mut state = Hasher::new();
        msgs.iter().for_each(|msg| {
            // we might have garbage data...
            match deserialize_utxo(msg, self.serialized_cutxo_size.unwrap()) {
                Ok(utxo) => {
                    all_utxos.push(utxo.clone());
                    utxo.hash(&mut state);
                }
                _ => {} // this will cause failure below
            }
        });
        sdebug!(self, "query hash: {}", state.result());
        // --------------------------------------------------------
        // for debugging - ensure that all of our txouts made it
        {
            sdebug!(self, "nbr queries = {}", all_utxos.len());
            self.my_utxos
                .iter()
                .for_each(|utxo| assert!(all_utxos.contains(utxo)));
        }
        // --------------------------------------------------------
        let leader = self.leader_id();
        let superquery = QueryShuffleOutput {
            participants: self.participants.clone(),
            queries: all_utxos,
            fee: total_fees,
            is_leader: self.my_participant_id == leader,
        };

        // for debugging - show the supertransaction hash at this node
        // all nodes should agree on this
        sinfo!(
            self,
            "Created a super query: queryhash={}",
            Hash::digest(&superquery)
        );
        // And... we are finished!
        return Ok(Async::Ready(superquery));
    }

    // -----------------------------------------------------------------

    fn encode_matrix(
        participants: &Vec<ParticipantID>,
        my_utxos: &Vec<UTXO>,
        my_id: &ParticipantID,
        k_cloaks: &HashMap<ParticipantID, Hash>,
        n_chunks: usize,
    ) -> DcMatrix {
        // Encode UTXOs to matrix for cloaked sharing
        let mut matrix = Vec::<DcSheet>::new();
        let mut sheet_id = 0;
        for utxo in my_utxos.clone() {
            sheet_id += 1;
            let msg = serialize_utxo(&utxo);
            let sheet = dc_encode_sheet(sheet_id, n_chunks, &msg, participants, my_id, &k_cloaks);
            matrix.push(sheet);
        }
        // fill out matrix with dummy UTXO messages
        // (sheets containing zero fill plus cloaking factors)
        let n_utxos = my_utxos.len();
        let null_msg = Vec::<u8>::new();
        for _ in n_utxos..MAX_SHARING_TXOUTS {
            sheet_id += 1;
            let sheet = dc_encode_sheet(
                sheet_id,
                n_chunks,
                &null_msg,
                participants,
                my_id,
                &k_cloaks,
            );
            matrix.push(sheet);
        }
        matrix
    }

    // -------------------------------------------------

    fn send_signed_message(&self, payload: &QueryShufflePayload) {
        // for testing - see if we are asked to not send message
        let skip_parts = match self.test_plan.as_ref() {
            None => vec![self.my_participant_id], // dummy, we never send to self anyway
            Some(QueryShuffleTestPlan::StopCommunication(phase, parts)) => {
                if *phase == self.state {
                    match &*parts {
                        Some(part_ids) => part_ids.clone(),
                        None => self.participants.clone(), // send to nobody
                    }
                } else {
                    vec![self.my_participant_id] // dummy, we never send to self anyway
                }
            }
        };
        for pkey in &self.participants {
            if *pkey != self.my_participant_id && !skip_parts.contains(pkey) {
                let msg = QueryShuffleMessage {
                    sid: self.session_id,
                    payload: payload.clone(),
                    source: self.my_participant_id,
                    destination: *pkey,
                };
                let bmsg = msg.into_buffer().expect("serialized");
                sdebug!(self, "sending msg {:?} to {}", &msg, pkey);
                self.network
                    .send(pkey.pkey.clone(), QUERYSHUFFLE_TOPIC, bmsg)
                    .expect("connected");
            }
        }
    }

    fn prep_rx(&mut self, state: State) -> HandlerResult {
        // transfer other participants into pending_participants
        // and set new msg_state for expected kind of messages
        let mut other_participants: HashSet<ParticipantID> = HashSet::new();
        self.participants
            .iter()
            .filter(|&&p| p != self.my_participant_id)
            .for_each(|&p| {
                other_participants.insert(p);
            });
        self.pending_participants = other_participants;
        self.participants = vec![self.my_participant_id];

        sdebug!(self, "In prep_rx(), state = {:?}", state);
        self.change_state(state);
        Ok(Async::NotReady)
    }

    // ------------------------------------------------

    fn send_session_pkey(&self, sess_pkey: &PublicKey, fee: i64) {
        // send our session_pkey and sigK to all participants
        let payload = QueryShufflePayload::SharedKeying {
            pkey: sess_pkey.clone(),
            fee,
        };
        self.send_signed_message(&payload);
    }

    fn receive_session_pkeys(&mut self) -> HandlerResult {
        // collect session pkeys from all participants.
        // If any participant does not answer, add him to the exclusion list, p_excl

        // fills in the global state sess_pkeys and sigK_vals

        // we allow the receive_xxx to specify individual timeout periods
        // in case they need to vary
        self.prep_rx(State::SharedKeying)
    }

    // -------------------------------------------------

    fn send_commitment(&self, commit: &Hash) {
        // send our commitment to cloaked data to all other participants
        let payload = QueryShufflePayload::Commitment { cmt: *commit };
        self.send_signed_message(&payload);
    }

    fn receive_commitments(&mut self) -> HandlerResult {
        // receive commitments from all other participants
        // if any fail to send commitments, add them to exclusion list p_excl

        // fill in commits
        self.prep_rx(State::Commitment)
    }

    // -------------------------------------------------

    fn send_cloaked_data(&self, matrix: &DcMatrix, cloaks: &HashMap<ParticipantID, Hash>) {
        // send matrix, sum, and excl_k_cloaks to all participants
        let payload = QueryShufflePayload::CloakedVals {
            matrix: matrix.clone(),
            cloaks: cloaks.clone(),
        };
        self.send_signed_message(&payload);
    }

    fn receive_cloaked_data(&mut self) -> HandlerResult {
        // receive cloaked data from each participant.
        // If participants don't respond, or respond
        // with invalid data, as per previous commitment,
        // then add them to exclusion list.

        // fill in matrices, cloaked_gamma_adj, cloaked_fees,
        // and all_excl_k_cloaks, using commits to validate incoming data
        self.prep_rx(State::CloakedVals)
    }

    // -------------------------------------------------

    fn leader_id(&mut self) -> ParticipantID {
        // select the leader as the public key hash having the lowest XOR between
        // its key bits and the hash of all participant keys.
        self.participants.sort(); // nodes can't agree on hash unless all keys in same order
        let hash = {
            let mut state = Hasher::new();
            self.participants.iter().for_each(|p| p.hash(&mut state));
            state.result()
        };
        let mut min_part = self.participants[0];
        let mut min_xor = vec![0xffu8; HASH_SIZE];
        self.participants.iter().for_each(|p| {
            let phash = Hash::digest(p);
            let pbits = phash.base_vector();
            let hbits = hash.bits();
            let xor_bits: Vec<u8> = pbits
                .iter()
                .zip(hbits.iter())
                .map(|(p, h)| *p ^ *h)
                .collect();
            for (hp, hm) in xor_bits.iter().zip(min_xor.iter()) {
                if *hp < *hm {
                    min_part = *p;
                    min_xor = xor_bits;
                    break;
                }
            }
        });
        min_part
    }
}

// --------------------------------------------------------------------------
// helper functions

fn hash_data(matrix: &DcMatrix) -> Hash {
    let mut state = Hasher::new();
    "CM".hash(&mut state);
    for sheet in matrix.clone() {
        for row in sheet {
            for cell in row {
                cell.hash(&mut state);
            }
        }
    }
    state.result()
}

fn make_session_key(skey: &SecretKey, sid: &Hash) -> (SecretKey, PublicKey) {
    let seed = {
        let mut state = Hasher::new();
        sid.hash(&mut state);
        skey.hash(&mut state);
        state.result()
    };
    let (skey, pkey) = make_deterministic_keys(&seed.to_bytes());
    (skey, pkey)
}

fn serialize_utxo(utxo: &UTXO) -> Vec<u8> {
    utxo.to_bytes().to_vec()
}

fn deserialize_utxo(msg: &Vec<u8>, ser_size: usize) -> Result<UTXO, String> {
    // DiceMix returns a byte vector whose length is some integral
    // number of Field size. But proto-bufs is very particular about
    // what it is handed, and complains about trailing padding bytes.
    // otherwise, deserialize and return
    UTXO::try_from_bytes(&msg[0..ser_size]).map_err(|e| format!("{:?}", e))
}

// -----------------------------------------------------------------
// Participation helpers...

// ------------------------------------------------------------------

// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::dbg;

    #[test]
    fn tst_hashmap_presentation_order() {
        // the order of readout depends on the order of HashMap construction
        // Beware! - use a sorted keylist for ordered access to HashMaps
        let mut m1: HashMap<u8, u8> = HashMap::new();
        let mut m2: HashMap<u8, u8> = HashMap::new();

        m1.insert(1, 10);
        m1.insert(2, 20);
        m1.insert(3, 30);
        dbg!(&m1);

        m2.insert(2, 20);
        m2.insert(1, 10);
        m2.insert(3, 30);
        dbg!(&m2);

        println!("Showing m1");
        for (k, v) in m1 {
            println!("k {} v {}", k, v);
        }
        println!("Showing m2");
        for (k, v) in m2 {
            println!("k {} v {}", k, v);
        }
    }
}

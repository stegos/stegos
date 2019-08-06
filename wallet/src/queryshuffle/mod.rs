//! mod.rs - QueryShuffle for secure and anonymous databae query construction

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
// node ID's along with an initial unique session ID (sid) and the public
// key of the Database Server (may be a composite shared key if multiple
// servers).
//
// Each wallet will then assemble their list of UTXO ID's. Wallet should then
// call qs_start() with the list of all participant node ID's, their own node ID,
// and the session ID (sid) provided by the Facilitator node.
//
// During the session, the wallets will be asked to construct encrypted queries
// from their list of UTXO ID's. Each request for UTXO's should make use of
// fresh randomness their encryptions, and in choosing the cloaking factors.
//
// The arguments to qs_start() are checked for validity:
//
//  1. No more than MAX_QUERIES can be indicated by the UTXO ID list
//     (Currently MAX_QUERIES = 5). If fewer queries will be produced, then the
//     DiceMix sharing matrix will be zero-filled and cloaked up to this maximum.
//
// ========================================================================

#![allow(non_snake_case)]
#![allow(warnings)]

mod error;
pub use error::*;

pub mod message;
use message::*;

mod protos;

use crate::queryshuffle::message::DirectQMessage;
use failure::Error;
use failure::{bail, format_err};
use futures::sync::mpsc::UnboundedSender;
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
use std::time::{Duration, SystemTime};
use stegos_crypto::dicemix;
use stegos_crypto::dicemix::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher, HASH_SIZE};
use stegos_crypto::pbc;
use stegos_crypto::scc::{make_deterministic_keys, Fr, Pt, PublicKey, SecretKey};
use stegos_network::Network;
use stegos_node::txpool::PoolNotification;
use stegos_node::txpool::QueryPoolJoin;
use stegos_node::txpool::QUERY_POOL_ANNOUNCE_TOPIC;
use stegos_node::txpool::QUERY_POOL_JOIN_TOPIC;
use stegos_node::{Node, NodeNotification};
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::Interval;

/// A topic used for QueryShuffle unicast communication.
pub const QUERY_SHUFFLE_TOPIC: &'static str = "queryshuffle";

const QS_TIMER: Duration = Duration::from_secs(1); // recurring 1sec events
const QS_TIMEOUT: i16 = 60; // sec, default for now

pub const MAX_QUERIES: usize = 5; // max nbr of UTXO queries permitted per participant

// ==============================================================

type ParticipantID = dicemix::ParticipantID;
type ServerID = pbc::PublicKey;
pub type UTXOId = Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperQuery {
    pub serverID: ServerID,
    pub queries: Vec<UTXOId>,
}

// ---------------------------------------------------

impl Hashable for SuperQuery {
    fn hash(&self, state: &mut Hasher) {
        self.serverID.hash(state);
        for query in self.queries.clone() {
            query.hash(state);
        }
    }
}

// ---------------------------------------------------

#[derive(Debug)]
/// QueryShuffle Events.
enum QueryShuffleEvent {
    FacilitatorChanged(pbc::PublicKey),
    PoolFormed(pbc::PublicKey, Vec<u8>),
    MessageReceived(pbc::PublicKey, Vec<u8>),
    QsTimer(SystemTime),
}

#[derive(Debug, PartialEq, Eq)]
/// QueryShuffle State.
enum State {
    Offline,
    PoolWait,
    PoolFormed,
    PoolFinished,
    /// Last session was canceled, waiting for new facilitator.
    PoolRestart,
}

#[derive(Debug)]
/// Possible outcomes of QueryShuffle
pub enum QueryShuffleOutput {
    Failure(Error, Vec<UTXOId>),
}

/// QueryShuffle Service.
pub struct QueryShuffle {
    /// Account Secret Key.
    skey: SecretKey,

    /// Faciliator's PBC public key
    facilitator_pkey: pbc::PublicKey,
    /// Next facilitator's PBC public key.
    /// Used if facilitator was changed during queryshuffle session.
    future_facilitator: Option<pbc::PublicKey>,
    /// Server PBC Public Key
    server_pubkey: pbc::PublicKey,
    /// State.
    state: State,
    /// My public txpool's key.
    participant_key: ParticipantID,
    /// Public keys of txpool's members,
    participants: Vec<ParticipantID>,
    // Sent transaction.
    wallet_query_info: UnboundedSender<(SuperQuery, bool)>,
    /// Network API.
    network: Network,
    /// Incoming events.
    events: Box<dyn Stream<Item = QueryShuffleEvent, Error = ()> + Send>,

    // --------------------------------------------
    // Items computed from TXINS before joining pool

    // Fee for this query
    _my_fee: i64,

    // My UTXO IDs
    my_utxo_ids: Vec<UTXOId>,

    // FIFO queue of incoming messages not yet processed
    msg_queue: VecDeque<(ParticipantID, Hash, QsPayload)>,

    // List of participants that should be excluded on startup
    // normally empty, but could have resulted from restart pool
    // message arriving out of order with respect to pool start message.
    pending_removals: Vec<ParticipantID>,

    // dictionary of all UTXO IDs from all participants
    all_utxo_ids: HashMap<ParticipantID, Vec<UTXOId>>,

    // --------------------------------------------
    // Items computed in qs_start()

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
    // Items compupted in qs_commit()

    // size of serialized UTXO for retrieval
    serialized_query_size: Option<usize>,

    // nbr of DiceMix chunks per UTXO
    dicemix_nbr_query_chunks: Option<usize>,

    // cloaking hash value used between me and each other participant
    k_cloaks: HashMap<ParticipantID, Hash>,

    // cloaked matrices from each participant
    matrices: HashMap<ParticipantID, DcMatrix>,

    // commitments from each participant = hash(matrix, gamma_adj, fee)
    commits: HashMap<ParticipantID, Hash>,

    // --------------------------------------------
    // Items computed in qs_share_cloaked_data()

    // list of participants that did not send us commitments
    // but with whom we sent commitments and computed sharing cloaks
    excl_participants_with_cloaks: Vec<ParticipantID>,

    // table of participant cloaking hashes used with excluded participants
    // one of these from each remaining participant during blame discovery
    all_excl_k_cloaks: HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,

    // --------------------------------------------
    // Items computed in qs_make_superquery()

    // the super-transaction that each remaining participant should have
    // all of us should compute the same body, different individual signatures
    sess_skeys: HashMap<ParticipantID, SecretKey>,

    // --------------------------------------------
    // Send/Receieve - we start by sending to all participants,
    // then move all but myself over to pending participants.
    // Upon hearing valid responses from expected participants
    // they get moved back to participants list. Remaining pending_participants
    // is the list of participants that dropped out during this exchange
    pending_participants: HashSet<ParticipantID>,

    // msg_state - indicates type of expected messages for each
    // Send/Receive exchange. Reset to None at termination of Receive.
    // Receive can terminate either by timeout, or early after receiving
    // from all expected participants.
    msg_state: QsMsgType,

    // Timeout handling - we record the beginning of our timeout
    // period at start of Receive, and decrement waiting on each 1s tick
    // of our VS Timer.
    //
    // Each timer tick carries the instant that it fired. So if tick is earlier
    // than our start time, we simply ignore the tick event.
    waiting: i16,
    wait_start: SystemTime,
}

impl QueryShuffle {
    // ----------------------------------------------------------------------------------------------
    // Public API.
    // ----------------------------------------------------------------------------------------------

    /// Create a new QueryShuffle instance.
    pub fn new(
        skey: SecretKey,
        pkey: PublicKey,
        participant_pkey: pbc::PublicKey,
        server: pbc::PublicKey,
        network: Network,
        node: Node,
        wallet_query_info: UnboundedSender<(SuperQuery, bool)>,
    ) -> QueryShuffle {
        //
        // State.
        //
        let facilitator_pkey: pbc::PublicKey = pbc::PublicKey::dum();
        let future_facilitator = None;
        let participants: Vec<ParticipantID> = Vec::new();
        let session_id: Hash = Hash::random();
        let state = State::Offline;
        let mut rng = thread_rng();
        let seed = rng.gen::<[u8; 32]>();
        let participant_key = dicemix::ParticipantID::new(participant_pkey, seed);
        //
        // Events.
        //
        let mut events: Vec<Box<dyn Stream<Item = QueryShuffleEvent, Error = ()> + Send>> =
            Vec::new();

        // Network.
        let pool_formed = network
            .subscribe_unicast(QUERY_SHUFFLE_TOPIC)
            .expect("connected")
            .map(|m| QueryShuffleEvent::MessageReceived(m.from, m.data));
        events.push(Box::new(pool_formed));

        // Facilitator elections.
        let facilitator_changed = node
            .subscribe()
            .filter_map(|e| match e {
                NodeNotification::NewMacroBlock(b) => Some(b),
                _ => None,
            })
            .map(|epoch| QueryShuffleEvent::FacilitatorChanged(epoch.facilitator));
        events.push(Box::new(facilitator_changed));

        // Pool formation.
        let pool_formed = network
            .subscribe_unicast(QUERY_POOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| QueryShuffleEvent::PoolFormed(m.from, m.data));
        events.push(Box::new(pool_formed));

        // QsTimeout timer events
        let duration = QS_TIMER; // every second
        let timer = Interval::new_interval(duration)
            .map(|_i| QueryShuffleEvent::QsTimer(SystemTime::now()))
            .map_err(|_e| ()); // ignore transient timer errors
        events.push(Box::new(timer));

        let events = select_all(events);

        QueryShuffle {
            wallet_query_info,
            server_pubkey: server,
            skey: skey.clone(),
            facilitator_pkey,
            future_facilitator,
            state,
            participant_key,
            participants: participants.clone(), // empty vector
            session_id,
            network,
            events,

            my_utxo_ids: Vec::new(),
            all_utxo_ids: HashMap::new(),
            sess_skey: skey.clone(),
            sess_pkey: pkey,

            // these are all empty participant lists
            session_round: 0,
            sess_skeys: HashMap::new(),
            sess_pkeys: HashMap::new(),
            k_cloaks: HashMap::new(),
            all_excl_k_cloaks: HashMap::new(),
            commits: HashMap::new(),
            matrices: HashMap::new(),
            pending_participants: HashSet::new(),
            excl_participants_with_cloaks: Vec::new(),
            msg_state: QsMsgType::None,
            wait_start: SystemTime::now(),
            waiting: 0,
            msg_queue: VecDeque::new(),
            serialized_query_size: None,
            dicemix_nbr_query_chunks: None,
            pending_removals: Vec::new(),
            _my_fee: 0,
        }
    }

    /// Called by Wallet.
    pub fn queue_query(&mut self, utxo_ids: &Vec<UTXOId>, fee: i64) -> Result<(), Error> {
        match self.state {
            State::Offline | State::PoolFinished => (),
            _ => {
                return Err(QsError::QsBusy.into());
            }
        }

        // get copies of our own TXIN UTXOs
        self.my_utxo_ids = utxo_ids.clone();
        self._my_fee = fee;

        if utxo_ids.len() > MAX_QUERIES {
            self.zap_state();
            return Err(QsError::QsTooManyUTXO.into());
        }

        // Send PoolJoin on the first request.
        self.state = State::PoolWait;
        self.msg_state = QsMsgType::None;
        self.send_pool_join()
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
    fn on_facilitator_changed(&mut self, facilitator: pbc::PublicKey) -> Result<(), Error> {
        match self.state {
            State::Offline | State::PoolFinished | State::PoolRestart | State::PoolWait => {}
            // in progress some session, keep new facilitator in future facilitator.
            _ => {
                debug!(
                    "Saving new facilitator, for future change: facilitator={}",
                    facilitator
                );
                self.future_facilitator = Some(facilitator);
                return Ok(());
            }
        }
        debug!("Changed facilitator: facilitator={}", facilitator);
        self.facilitator_pkey = facilitator;
        self.future_facilitator = None;
        // Last session was canceled, rejoining to new facilitator.
        if self.state == State::PoolRestart || self.state == State::PoolWait {
            debug!("Found new facilitator, rejoining to new pool.");
            self.send_pool_join()?;
        }

        Ok(())
    }

    fn try_update_facilitator(&mut self) {
        if let Some(facilitator) = self.future_facilitator.take() {
            debug!("Changed facilitator: facilitator={}", facilitator);
            self.facilitator_pkey = facilitator;
        }
    }

    /// Sends a request to join tx pool.
    fn send_pool_join(&mut self) -> Result<(), Error> {
        match self.try_send_pool_join() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state();
                Err(err)
            }
        }
    }

    fn try_send_pool_join(&mut self) -> Result<(), Error> {
        debug!(
            "Sending pool join request: to_facilitator={}",
            self.facilitator_pkey
        );
        let msg = self.form_pooljoin_message()?.into_buffer()?;
        self.network
            .send(self.facilitator_pkey, QUERY_POOL_JOIN_TOPIC, msg)?;
        Ok(())
    }

    fn reset_state(&mut self) {
        self.waiting = 0; // reset timeout counter
        self.state = State::PoolFinished;
        self.msg_state = QsMsgType::None;
        self.try_update_facilitator();
    }

    fn zap_state(&mut self) {
        debug!("Zapping state, trying to restart Snowcrash.");
        self.msg_queue.clear();
        self.waiting = 0;
        self.session_round = 0;
        self.try_update_facilitator();
        self.state = State::PoolWait;
        self.msg_state = QsMsgType::None;
        if let Err(e) = self.try_send_pool_join() {
            debug!("Error joining pool during state zap: error={:?}", e)
        }
    }

    /// Called when a new txpool is formed.
    fn on_pool_notification(
        &mut self,
        from: pbc::PublicKey,
        pool_info: Vec<u8>,
    ) -> Result<(), Error> {
        match self.try_on_pool_notification(from, pool_info) {
            Err(err) => {
                self.zap_state();
                return Err(err);
            }
            _ => {
                return Ok(());
            }
        }
    }

    fn try_on_pool_notification(
        &mut self,
        from: pbc::PublicKey,
        pool_info: Vec<u8>,
    ) -> Result<(), Error> {
        self.ensure_facilitator(from)?;

        let pool_info = PoolNotification::from_buffer(&pool_info)?;
        debug!("pool = {:?}", pool_info);
        let pool_info = match pool_info {
            PoolNotification::Canceled => {
                debug!(
                    "Old facilitator decide to stop forming pool, trying to rejoin to the new one."
                );
                let changed = self.future_facilitator.is_some();
                self.zap_state();
                if changed {
                    debug!("Found new facilitator, rejoining to new pool.");
                    self.send_pool_join()?;
                } else {
                    self.state = State::PoolRestart;
                }
                return Ok(());
            }
            PoolNotification::Started(info) => info,
        };

        if pool_info
            .participants
            .iter()
            .find(|k| k.participant == self.participant_key)
            .is_none()
        {
            debug!("Our key = {:?}", self.participant_key);
            return Err(QsError::QsNotInParticipantList.into());
        }

        self.session_id = pool_info.session_id;
        let part_info = pool_info.participants;
        self.participants = Vec::<ParticipantID>::new();
        for elt in &part_info {
            self.participants.push(elt.participant);
        }

        // handle enqueued requests from possible pool restart
        // messages that arrived before we got the pool start message
        self.exclude_participants(&self.pending_removals.clone());
        self.pending_removals.clear();

        self.participants.sort();
        self.participants.dedup();
        debug!("Formed txpool: members={}", self.participants.len());
        for pkey in &self.participants {
            debug!("{:?}", pkey);
        }

        self.state = State::PoolFormed;

        // start processing queued transactions....
        self.qs_start()
    }

    fn ensure_facilitator(&self, from: pbc::PublicKey) -> Result<(), Error> {
        if from != self.facilitator_pkey {
            Err(format_err!(
                "Invalid facilitator: expected={}, got={}",
                self.facilitator_pkey,
                from
            ))
        } else {
            Ok(())
        }
    }

    fn on_restart_pool(
        &mut self,
        from: ParticipantID,
        without_part: ParticipantID,
        session_id: Hash,
    ) -> Result<(), Error> {
        match self.try_on_restart_pool(from, without_part, session_id) {
            Ok(ans) => Ok(ans),
            Err(err) => {
                self.zap_state();
                self.state = State::PoolWait;
                self.msg_state = QsMsgType::None;
                if let Err(e) = self.send_pool_join() {
                    debug!(
                        "Error attempting to join pool on pool restart: error={:?}",
                        e
                    )
                }
                Err(err)
            }
        }
    }

    fn exclude_participants(&mut self, p_excl: &Vec<ParticipantID>) {
        self.participants.retain(|p| !p_excl.contains(p));
    }

    fn try_on_restart_pool(
        &mut self,
        from: ParticipantID,
        without_part: ParticipantID,
        session_id: Hash,
    ) -> Result<(), Error> {
        // called from facilitator node when it is discovered that "without_part" has submitted
        // a side transaction containing a same TXIN as already submitted to the pool - a bad actor.
        self.ensure_facilitator(from.pkey)?;
        self.session_id = session_id;
        self.session_round = 0;
        let excl = vec![without_part];
        match self.state {
            State::PoolFormed | State::PoolFinished => {
                match self.msg_state {
                    QsMsgType::None => {
                        // We aren't currently running, but we can restart with the
                        // participants left over from previous run.
                        // Facilitator should have already discarded our previous supertransaction.
                        self.exclude_participants(&excl);
                        self.state = State::PoolFormed;
                        return self.qs_start();
                    }
                    _ => {
                        // We are pausing for incoming messages of some kind.
                        // Restart from the combined participants and pending_participants.
                        for p in &self.pending_participants {
                            // copy over pending participants for restart
                            self.participants.push(*p);
                        }
                        self.exclude_participants(&excl);
                        // set state to reflect this division of participants list state
                        // in case we abort qs_start
                        self.msg_state = QsMsgType::None;
                        return self.qs_start();
                    }
                }
            }
            _ => {
                // We haven't yet started. No participants are yet
                // known. If this message arrived out of order with
                // a pending startup message this request must be enqueued
                // for use at startup.
                self.pending_removals.push(without_part);
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------------------------------------
    // QueryPool Communication
    // ----------------------------------------------------------------------------------------------

    /// Sends a message to all txpool members via unicast.
    fn send_message(&self, msg: QMessage) -> Result<(), Error> {
        for pkey in &self.participants {
            if *pkey != self.participant_key {
                let msg = DirectQMessage {
                    destination: *pkey,
                    source: self.participant_key,
                    message: msg.clone(),
                };
                let bmsg = msg.into_buffer()?;
                debug!("sending msg {:?} to {}", &msg, pkey);
                self.network
                    .send(pkey.pkey.clone(), QUERY_SHUFFLE_TOPIC, bmsg)?;
            }
        }
        Ok(())
    }

    /// Called when a new message is received via unicast.
    fn on_message_received(&mut self, from: ParticipantID, msg: QMessage) -> Result<(), Error> {
        match msg {
            QMessage::QsMessage { sid, payload } => {
                self.on_qs_message_received(&from, &sid, &payload)
            }
            QMessage::QsRestart {
                without_part,
                session_id,
            } => self.on_restart_pool(from, without_part, session_id),
        }
    }
}

impl Future for QueryShuffle {
    type Item = ();
    type Error = ();

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        QueryShuffleEvent::FacilitatorChanged(facilitator) => {
                            self.on_facilitator_changed(facilitator)
                        }
                        QueryShuffleEvent::PoolFormed(from, msg) => {
                            self.on_pool_notification(from, msg)
                        }
                        QueryShuffleEvent::MessageReceived(from, msg) => {
                            DirectQMessage::from_buffer(&msg).and_then(|msg| {
                                if msg.source.pkey != from {
                                    bail!(
                                        "Source key was different {} = {}",
                                        msg.source.pkey,
                                        from
                                    );
                                }
                                if msg.destination != self.participant_key {
                                    trace!(
                                        "Message to other account: destination={} = our_key={}",
                                        msg.destination,
                                        self.participant_key
                                    );
                                    return Ok(());
                                }
                                // debug!("in poll() dispatching to on_message_received()");
                                self.on_message_received(msg.source, msg.message)
                            })
                        }
                        QueryShuffleEvent::QsTimer(when) => self.handle_qs_timer(when),
                    };
                    if let Err(error) = result {
                        error!("Error: {:?}", error)
                    }
                }
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

// -------------------------------------------------

type QsFunction = fn(&mut QueryShuffle) -> Result<(), Error>;

impl QueryShuffle {
    fn handle_qs_timer(&mut self, when: SystemTime) -> Result<(), Error> {
        // self.waiting contains the nbr seconds countdown until a timeout
        // specify waiting = 0 for no timeout checking
        if self.waiting > 0 && when > self.wait_start {
            self.waiting -= 1;
            if 0 == self.waiting {
                // reset msg_state to indicate done waiting for this kind of message
                // whichever participants have responded are now held in self.participants.
                // whichever participants did not respond are in self.pending_participants.
                debug!("vs timeout, msg_state: {:?}", self.msg_state);
                let state = self.msg_state;
                self.msg_state = QsMsgType::None;
                match state {
                    QsMsgType::None => {
                        return Ok(());
                    }
                    QsMsgType::SharedKeying => {
                        return self.qs_commit();
                    }
                    QsMsgType::Commitment => {
                        return self.qs_share_cloaked_data();
                    }
                    QsMsgType::CloakedVals => {
                        return self.qs_make_superquery();
                    }
                }
            }
        }
        Ok(())
    }

    fn on_qs_message_received(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &QsPayload,
    ) -> Result<(), Error> {
        debug!("qs message: {}, from: {}, sess: {}", *payload, *from, *sid);
        self.msg_queue.push_front((*from, *sid, payload.clone()));
        self.handle_enqueued_messages()
    }

    fn handle_enqueued_messages(&mut self) -> Result<(), Error> {
        let mut ans = Ok(());
        let queue = self.msg_queue.clone();
        self.msg_queue.clear();
        for (from, sid, payload) in queue {
            if self.state != State::PoolFinished {
                if self.is_acceptable_message(&from, &sid, &payload) {
                    // debug!("is_acceptable_message()");
                    self.pending_participants.remove(&from);
                    debug!("removed from from pending_participants: {}", from);
                    ans = self.handle_message(&from, &payload);
                } else {
                    self.msg_queue.push_back((from, sid, payload));
                }
            }
        }
        ans
    }

    fn is_acceptable_message(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &QsPayload,
    ) -> bool {
        if *sid != self.session_id {
            debug!(
                "SessionID misatch: ours={}, their={}",
                self.session_id, *sid
            );
            return false;
        }
        if !self.pending_participants.contains(from) {
            debug!(
                "Not waiting for messages from this participant: participant={}",
                from
            );
            return false;
        }
        match (self.msg_state, payload) {
            (QsMsgType::SharedKeying, QsPayload::SharedKeying { .. })
            | (QsMsgType::Commitment, QsPayload::Commitment { .. })
            | (QsMsgType::CloakedVals, QsPayload::CloakedVals { .. }) => {
                debug!(
                    "Message accepted: msg_state={:?}, payload={}",
                    self.msg_state, payload
                );
                true
            }
            _ => {
                debug!(
                    "Unexpected message state/payload: msg_state={:?}, payload={}",
                    self.msg_state, payload
                );
                false
            }
        }
    }

    fn handle_message(&mut self, from: &ParticipantID, payload: &QsPayload) -> Result<(), Error> {
        match self.msg_state {
            QsMsgType::None => Err(QsError::QsNotInSession.into()),
            QsMsgType::SharedKeying => self.handle_shared_keying(from, payload),
            QsMsgType::Commitment => self.handle_commitment(from, payload),
            QsMsgType::CloakedVals => self.handle_cloaked_vals(from, payload),
        }
    }

    fn maybe_do(&mut self, from: &ParticipantID, vfn: QsFunction) -> Result<(), Error> {
        self.participants.push(*from);
        if self.pending_participants.is_empty() {
            // Reset state to reflect a full participants list in case
            // we bomb out of the vfn(). We do this in case of any incoming
            // QsRestart messages which are sensitive to the state of the
            // participants list and pending_participants.
            self.msg_state = QsMsgType::None;
            vfn(self)
        } else {
            Ok(())
        }
    }

    fn handle_shared_keying(&mut self, from: &ParticipantID, msg: &QsPayload) -> Result<(), Error> {
        // debug!("In handle_shared_keying()");
        match msg {
            QsPayload::SharedKeying { pkey } => {
                debug!("checking shared keying {:?}", pkey);
                self.sess_pkeys.insert(*from, *pkey);
                return self.maybe_do(from, Self::qs_commit);
            }
            _ => {}
        }
        Err(QsError::QsInvalidMessage.into())
    }

    fn handle_commitment(&mut self, from: &ParticipantID, msg: &QsPayload) -> Result<(), Error> {
        // debug!("In handle_commitment()");
        match msg {
            QsPayload::Commitment { cmt } => {
                debug!("saving commitment {}", cmt);
                self.commits.insert(*from, *cmt);
                return self.maybe_do(from, Self::qs_share_cloaked_data);
            }
            _ => {}
        }
        Err(QsError::QsInvalidMessage.into())
    }

    fn handle_cloaked_vals(&mut self, from: &ParticipantID, msg: &QsPayload) -> Result<(), Error> {
        // debug!("In handle_cloaked_vals()");
        match msg {
            QsPayload::CloakedVals { matrix, cloaks } => {
                let cmt = self.commits.get(from).expect("Can't access commit");
                debug!("Checking commitment {}", cmt);
                if *cmt == hash_data(matrix) {
                    self.matrices.insert(*from, matrix.clone());
                    self.all_excl_k_cloaks.insert(*from, cloaks.clone());
                    return self.maybe_do(from, Self::qs_make_superquery);
                }
            }
            _ => {}
        }
        Err(QsError::QsInvalidMessage.into())
    }

    fn form_pooljoin_message(&mut self) -> Result<QueryPoolJoin, Error> {
        // Possible exits:
        //   - normal exit
        self.all_utxo_ids
            .insert(self.participant_key, self.my_utxo_ids.clone());

        let msg = QueryPoolJoin {
            seed: self.participant_key.seed,
        };
        Ok(msg)
    }

    fn prep_rx(&mut self, msgtype: QsMsgType, timeout: i16) {
        // transfer other participants into pending_participants
        // and set new msg_state for expected kind of messages
        self.pending_participants = HashSet::new();
        for p in &self.participants {
            if *p != self.participant_key {
                self.pending_participants.insert(*p);
            }
        }
        self.participants = Vec::new();
        self.participants.push(self.participant_key);

        // arrange to ignore enqueue timer events unless they
        // are timestamped later than now.
        //
        // Note: This might fail if our system clock is reset
        // after this point, and before a final timeout triggering
        // timer event occurs.
        self.wait_start = SystemTime::now();
        self.waiting = timeout;
        self.msg_state = msgtype;
        debug!("In prep_rx(), state = {:?}", msgtype);
        self.handle_enqueued_messages()
            .expect("Can't handle enqueued messages");
    }

    fn qs_start(&mut self) -> Result<(), Error> {
        match self.try_qs_start() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state();
                Err(err)
            }
        }
    }

    fn try_qs_start(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - fewer than 3 participants = protocol fail
        //   - normal exit

        debug!("In qs_start()");
        if self.participants.len() < 3 {
            return Err(QsError::QsTooFewParticipants(self.participants.len()).into());
        }
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

        // Generate new cloaked sharing key set and share with others
        let (sess_sk, sess_pk) = make_session_key(&self.skey, &self.session_id);
        self.sess_pkey = sess_pk;
        self.sess_skey = sess_sk;

        self.sess_pkeys = HashMap::new();
        self.sess_pkeys.insert(self.participant_key, sess_pk);

        self.send_session_pkey(&sess_pk);

        // Collect cloaked sharing keys from others
        // fill in sess_pkeys and sigK_vals
        self.receive_session_pkeys();

        Ok(())
    }

    fn qs_commit(&mut self) -> Result<(), Error> {
        match self.try_qs_commit() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state();
                Err(err)
            }
        }
    }

    fn try_qs_commit(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure

        debug!("In qs_commit()");
        if self.participants.len() < 3 {
            return Err(QsError::QsTooFewParticipants(self.participants.len()).into());
        }

        // Generate shared cloaking factors
        self.k_cloaks = dc_keys(
            &self.participants,
            &self.sess_pkeys,
            &self.participant_key,
            &self.sess_skey,
            &self.session_id,
        );

        // -------------------------------------------------------------
        // set size of serialized query if not already established
        match self.serialized_query_size {
            None => {
                let msg = serialize_query(self.my_utxo_ids[0]);
                self.serialized_query_size = Some(msg.len());
                let row = split_message(&msg, None);
                self.dicemix_nbr_query_chunks = Some(row.len());
            }
            _ => {}
        }

        // -------------------------------------------------------------

        let my_matrix = Self::encode_matrix(
            &self.participants,
            &self.my_utxo_ids,
            &self.participant_key,
            &self.k_cloaks,
            self.dicemix_nbr_query_chunks.unwrap(),
        );
        self.matrices = HashMap::new();
        self.matrices
            .insert(self.participant_key, my_matrix.clone());

        // form commitments to our matrix and gamma sum
        let my_commit = hash_data(&my_matrix);

        // Collect and validate commitments from other participants
        self.commits = HashMap::new();
        self.commits.insert(self.participant_key, my_commit);

        // send sharing commitment to other participants
        self.send_commitment(&my_commit);

        // fill in commits
        self.receive_commitments();

        Ok(())
    }

    fn qs_share_cloaked_data(&mut self) -> Result<(), Error> {
        match self.try_qs_share_cloaked_data() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state();
                Err(err)
            }
        }
    }

    fn try_qs_share_cloaked_data(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure
        //   - .expect() errors - should never happen in proper code

        debug!("In qs_share_cloaked_data()");
        if self.participants.len() < 3 {
            return Err(QsError::QsFail.into());
        }

        // save the excluded participants at this point
        // they match up with k_cloaks.
        self.excl_participants_with_cloaks = Vec::new();
        for p in &self.pending_participants {
            self.excl_participants_with_cloaks.push(*p);
        }

        // ---------------------------------------------------------------
        // NOTE:
        // from here to end, we keep newly excluded pkeys in a separate list.
        // Those newly excluded keys will have had cloaking factors generated by us for them.
        //
        // If there are no further critical dropouts, then we can still de-cloak the
        // remaining shared data with the keying info we are about to send everyone.
        //
        // If there are further critical dropouts, then we just abort the current
        // round and proceed anew with remaining participants.
        // ---------------------------------------------------------------

        // collect the cloaking factors shared with non-responding participants
        // we share these with all other partipants, along with our cloaked data
        // in case anyone decides that we need a blame discovery session
        self.all_excl_k_cloaks = HashMap::new();
        let mut my_excl_k_cloaks: HashMap<ParticipantID, Hash> = HashMap::new();
        for p in &self.excl_participants_with_cloaks {
            let cloak = self.k_cloaks.get(p).expect("Can't access cloaking");
            my_excl_k_cloaks.insert(*p, *cloak);
        }
        self.all_excl_k_cloaks
            .insert(self.participant_key, my_excl_k_cloaks.clone());

        // send committed and cloaked data to all participants
        let my_matrix = self
            .matrices
            .get(&self.participant_key)
            .expect("Can't access my own matrix");

        self.send_cloaked_data(&my_matrix, &my_excl_k_cloaks);

        // At this point, if we don't hear valid responses from all
        // remaining participants, we abort and start a new session

        // collect cloaked contributions from others

        // fill in matrices and all_excl_k_cloaks,
        // using commits to validate incoming data
        self.receive_cloaked_data();

        Ok(())
    }

    fn qs_make_superquery(&mut self) -> Result<(), Error> {
        match self.try_qs_make_superquery() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state();
                Err(err)
            }
        }
    }

    fn try_qs_make_superquery(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in proper code
        //
        debug!("In qs_make_superquery()");
        if !self.pending_participants.is_empty() {
            // we can't do anything on partial data
            // so merge local exclusions with outer list for
            // next session round
            return self.qs_start();
        }

        // we got valid responses from all participants,
        self.participants.sort();

        let msgs = dc_decode(
            &self.participants,
            &self.matrices,
            &self.participant_key,
            MAX_QUERIES,
            self.dicemix_nbr_query_chunks.unwrap(),
            &self.excl_participants_with_cloaks, // the excluded participants
            &self.all_excl_k_cloaks,
        );
        debug!("nbr msgs = {}", msgs.len());

        let mut all_queries = Vec::<UTXOId>::new();
        let mut state = Hasher::new();
        for msg in msgs {
            // we might have garbage data...
            match deserialize_query(&msg, self.serialized_query_size.unwrap()) {
                Ok(query) => {
                    all_queries.push(query.clone());
                    query.hash(&mut state);
                }
                _ => {} // this will cause failure below
            }
        }
        debug!("queries hash: {}", state.result());
        // --------------------------------------------------------
        // for debugging - ensure that all of our queries made it
        {
            debug!("nbr queries = {}", all_queries.len());
            for query in self.my_utxo_ids.clone() {
                assert!(all_queries.contains(&query));
            }
        }
        // --------------------------------------------------------

        let super_query = SuperQuery {
            serverID: self.server_pubkey.clone(),
            queries: all_queries.clone(),
        };
        {
            // for debugging - show the superquery hash at this node
            // all nodes should agree on this
            let h = Hash::digest(&super_query);
            debug!("hash: {}", h);
        }

        self.execute_super_query(super_query)?;
        self.reset_state(); // indicate nothing more to follow, restartable
        self.msg_queue.clear();
        self.session_round = 0; // for possible restarts
        debug!("Success in QueryShuffle!!");
        return Ok(());
    }

    // -----------------------------------------------------------------

    fn encode_matrix(
        participants: &Vec<ParticipantID>,
        my_queries: &Vec<UTXOId>,
        my_id: &ParticipantID,
        k_cloaks: &HashMap<ParticipantID, Hash>,
        n_chunks: usize,
    ) -> DcMatrix {
        // Encode UTXOs to matrix for cloaked sharing
        let mut matrix = Vec::<DcSheet>::new();
        let mut sheet_id = 0;
        for query in my_queries.clone() {
            sheet_id += 1;
            let msg = serialize_query(query);
            let sheet = dc_encode_sheet(sheet_id, n_chunks, &msg, participants, my_id, &k_cloaks);
            matrix.push(sheet);
        }
        // fill out matrix with dummy UTXO messages
        // (sheets containing zero fill plus cloaking factors)
        let n_queries = my_queries.len();
        let null_msg = Vec::<u8>::new();
        for _ in n_queries..MAX_QUERIES {
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

    fn send_signed_message(&self, payload: &QsPayload) {
        let msg = QMessage::QsMessage {
            payload: payload.clone(),
            sid: self.session_id,
        };
        self.send_message(msg).expect("Can't send message");
    }

    fn send_session_pkey(&self, sess_pkey: &PublicKey) {
        // send our session_pkey and sigK to all participants
        let payload = QsPayload::SharedKeying { pkey: *sess_pkey };
        self.send_signed_message(&payload);
    }

    fn receive_session_pkeys(&mut self) {
        // collect session pkeys from all participants.
        // If any participant does not answer, add him to the exclusion list, p_excl

        // fills in the global state sess_pkeys and sigK_vals

        // we allow the receive_xxx to specify individual timeout periods
        // in case they need to vary
        self.prep_rx(QsMsgType::SharedKeying, QS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_commitment(&self, commit: &Hash) {
        // send our commitment to cloaked data to all other participants
        let payload = QsPayload::Commitment { cmt: *commit };
        self.send_signed_message(&payload);
    }

    fn receive_commitments(&mut self) {
        // receive commitments from all other participants
        // if any fail to send commitments, add them to exclusion list p_excl

        // fill in commits
        self.prep_rx(QsMsgType::Commitment, QS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_cloaked_data(&self, matrix: &DcMatrix, excl_k_cloaks: &HashMap<ParticipantID, Hash>) {
        // send matrix, sum, and excl_k_cloaks to all participants
        let payload = QsPayload::CloakedVals {
            matrix: matrix.clone(),
            cloaks: excl_k_cloaks.clone(),
        };
        self.send_signed_message(&payload);
    }

    fn receive_cloaked_data(&mut self) {
        // receive cloaked data from each participant.
        // If participants don't respond, or respond
        // with invalid data, as per previous commitment,
        // then add them to exclusion list.

        // fill in matrices, cloaked_gamma_adj, cloaked_fees,
        // and all_excl_k_cloaks, using commits to validate incoming data
        self.prep_rx(QsMsgType::CloakedVals, QS_TIMEOUT);
    }

    // -------------------------------------------------

    /// Send super-query to the wallet.
    fn execute_super_query(&mut self, super_query: SuperQuery) -> Result<(), Error> {
        let leader = self.leader_id();
        debug!("Leader = {}", leader);
        let tx = super_query.clone();
        self.wallet_query_info
            .unbounded_send((tx, self.participant_key == leader))?;
        Ok(())
    }

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

fn serialize_query(utxo_id: UTXOId) -> Vec<u8> {
    utxo_id.into_buffer().expect("Can't serialize UTXO ID")
}

fn deserialize_query(msg: &Vec<u8>, ser_size: usize) -> Result<UTXOId, Error> {
    // DiceMix returns a byte vector whose length is some integral
    // number of Field size. But proto-bufs is very particular about
    // what it is handed, and complains about trailing padding bytes.
    match UTXOId::from_buffer(&msg[0..ser_size]) {
        Err(err) => {
            debug!("deserialization error: {:?}", err);
            Err(QsError::QsBadQuery.into())
        }
        Ok(utxo) => Ok(utxo),
    }
}

// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::dbg;

}

//! mod.rs - ValueShuffle for secure and anonymous transaction construction

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
// When a wallet wants to participate in a ValueShuffle session,
// it should advertise its desire by sending a message to the Facilitator
// node, along with its network ID (currently a pbc::pbc::PublicKey).
//
// When the Facilitator has accumulated a sufficient number of requestor
// nodes, it collects those ID's and sends a message to each of them, to
// start a ValueShuffle session. The Facilitator should send that list of
// node ID's along with an initial unique session ID (sid).
//
// Each wallet will then assemble their list of TXINs and proposed UTXO output
// details (uncloaked recipient pkey, amount, data). Wallet should then call
// vs_start() with the list of all participant node ID's, their own node ID,
// the list of TXINs, the list of proposed spending, and the session ID (sid)
// provided by the Facilitator node.
//
// Since wallets are free to advertise different recipient public keys for
// every transaction, the list of TXINs must be accompanied by the secret key
// corresponding to the uncloaked public key used in the formation of the
// blockchain UTXO.
//
// At the start of the first round of ValueShuffle, these TXINs are checked
// by forming ownership signatures, and verifying that these signatures check.
// If any problems arise, the ValueShuffle session is aborted with
// Err(VsError::VsBadTXIN).
//
// If all TXIN are good, the TXIN hash values and ownership signatures are
// sent to all other ValueShuffle participants, and they will also perform
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
// The arguments to vs_start() are checked for validity:
//
//  1. No more than MAX_UTXOS can be indicated by the proposed spending list
//     (Currently MAX_UTXOS = 5). If fewer UTXOs will be produced, then the
//     DiceMix sharing matrix will be zero-filled and cloaked up to this maximum.
//
//  2. Each TXIN must refer to a blockchain UTXO that can be proven to be
//     owned by the wallet. We do that by checking that the hash of the UTXO
//     can be signed by the cloaked recipient key shown in the UTXO.
//
// ========================================================================

#![allow(non_snake_case)]
#![allow(warnings)]

mod error;
pub use error::*;

pub mod message;
use message::*;

mod protos;

use crate::valueshuffle::message::DirectMessage;
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
use stegos_node::txpool::PoolJoin;
use stegos_node::txpool::PoolNotification;
use stegos_node::txpool::POOL_ANNOUNCE_TOPIC;
use stegos_node::txpool::POOL_JOIN_TOPIC;
use stegos_node::{Node, NodeNotification};
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::Interval;

/// A topic used for ValueShuffle unicast communication.
pub const VALUE_SHUFFLE_TOPIC: &'static str = "valueshuffle";

pub const VS_TIMER: Duration = Duration::from_secs(1); // recurring 1sec events
pub const VS_TIMEOUT: i16 = 60; // sec, default for now

pub const MAX_UTXOS: usize = 5; // max nbr of txout UTXO permitted

// ==============================================================

type ParticipantID = dicemix::ParticipantID;
type TXIN = Hash;
type UTXO = PaymentOutput;

#[derive(Clone)]
pub struct ProposedUTXO {
    pub recip: PublicKey, // payee key (uncloaked)
    pub amount: i64,
    pub data: String,
    pub locked_timestamp: Option<Timestamp>,
}

#[derive(Clone)]
struct ValidationData {
    // used to pass extra data to the blame discovery validator fn
    pub all_txins: HashMap<ParticipantID, Vec<(TXIN, UTXO)>>,
    pub signatures: HashMap<ParticipantID, SchnorrSig>,
    pub transaction: PaymentTransaction,
    pub serialized_utxo_size: usize,
}

#[derive(Debug)]
/// ValueShuffle Events.
enum ValueShuffleEvent {
    FacilitatorChanged(pbc::PublicKey),
    PoolFormed(pbc::PublicKey, Vec<u8>),
    MessageReceived(pbc::PublicKey, Vec<u8>),
    VsTimer(SystemTime),
}

#[derive(Debug, PartialEq, Eq)]
/// ValueShuffle State.
enum State {
    Offline,
    PoolWait,
    PoolFormed,
    PoolFinished,
    /// Last session was canceled, waiting for new facilitator.
    PoolRestart,
}

#[derive(Debug)]
/// Possible outcomes of ValueShuffle
pub enum ValueShuffleOutput {
    Failure(Error, Vec<(TXIN, UTXO)>),
    UnsignedTransaction(PaymentTransaction),
    SignedTransaction(PaymentTransaction, bool),
}

/// ValueShuffle Service.
pub struct ValueShuffle {
    /// Account Secret Key.
    skey: SecretKey,

    /// Faciliator's PBC public key
    facilitator_pkey: pbc::PublicKey,
    /// Next facilitator's PBC public key.
    /// Used if facilitator was changed during valueshuffle session.
    future_facilitator: Option<pbc::PublicKey>,
    /// State.
    state: State,
    /// My public txpool's key.
    participant_key: ParticipantID,
    /// Public keys of txpool's members,
    participants: Vec<ParticipantID>,
    // Sent transaction.
    wallet_tx_info: UnboundedSender<ValueShuffleOutput>,
    /// Network API.
    network: Network,
    /// Incoming events.
    events: Box<dyn Stream<Item = ValueShuffleEvent, Error = ()> + Send>,

    // --------------------------------------------
    // Items computed from TXINS before joining pool

    // My TXINs resolved to UTXOs
    my_txins: Vec<(TXIN, UTXO)>,
    my_txouts: Vec<ProposedUTXO>,
    my_fee: i64,

    // sum(gamma_i) for i over TXINs
    txin_gamma_sum: Fr,

    // skey used for Schnorr signature generation
    //   = sum(skey_i + gamma_i * delta_i) for i over TXINs
    my_signing_skey: SecretKey,

    // FIFO queue of incoming messages not yet processed
    msg_queue: VecDeque<(ParticipantID, Hash, VsPayload)>,

    // List of participants that should be excluded on startup
    // normally empty, but could have resulted from restart pool
    // message arriving out of order with respect to pool start message.
    pending_removals: Vec<ParticipantID>,

    // --------------------------------------------
    // Items computed in vs_start()

    // session_round - init to zero, incremented in each round
    session_round: u16,

    /// Session ID, based on prior session_id, session_round, list of participants
    session_id: Hash,

    // random k-value used for Schnorr signature generation
    my_round_k: Fr,

    // K-value (= k * G) for each participant, used for Schnorr signature
    // final signatures will be based on sum of all K from remaining participants
    sigK_vals: HashMap<ParticipantID, Pt>,

    // Session round keying
    sess_pkey: PublicKey, // my public key
    sess_skey: SecretKey, // my secret key

    // public keys from other participants
    sess_pkeys: HashMap<ParticipantID, PublicKey>,

    // (TXIN, UTXO) lists from each participant
    all_txins: HashMap<ParticipantID, Vec<(TXIN, UTXO)>>,

    // --------------------------------------------
    // Items compupted in vs_commit()

    // list of newly constructed txouts
    my_utxos: Vec<Pt>,

    // size of serialized UTXO for retrieval
    serialized_utxo_size: Option<usize>,

    // nbr of DiceMix chunks per UTXO
    dicemix_nbr_utxo_chunks: Option<usize>,

    // cloaking hash value used between me and each other participant
    k_cloaks: HashMap<ParticipantID, Hash>,

    // cloaked matrices from each participant
    matrices: HashMap<ParticipantID, DcMatrix>,

    // cloaked gamma adj from each participant
    cloaked_gamma_adjs: HashMap<ParticipantID, Fr>,

    // cloaked fee from each participant
    // (why cloak fees? Because they may serve to distinguish participants
    // unless all are equal)
    cloaked_fees: HashMap<ParticipantID, Fr>,

    // commitments from each participant = hash(matrix, gamma_adj, fee)
    commits: HashMap<ParticipantID, Hash>,

    commit_phase_participants: Vec<ParticipantID>,

    // --------------------------------------------
    // Items computed in vs_share_cloaked_data()

    // --------------------------------------------
    // Items computed in vs_make_supertransaction()

    // the super-transaction that each remaining participant should have
    // all of us should compute the same body, different individual signatures
    trans: PaymentTransaction,

    // the list of signatures from each remaining participant
    // Individual signatures are based on hash of common transaction body,
    // and sum of all remaining participant K-sig values,
    // and sum of all remaining participant pubkeys
    // Final multi-signature is sum of these individual signatures
    signatures: HashMap<ParticipantID, SchnorrSig>,

    // list of participants that did not send us matrices
    // but to whom we sent our matrix,
    // and for whom we computed sharing cloaks
    excl_participants: Vec<ParticipantID>,

    // dictionary by participantID of the cloaking factors
    // used for the missing participants.
    excl_cloaks: HashMap<ParticipantID, Hash>,

    // --------------------------------------------
    // Items computed in vs_sign_supertransaction()

    // if we enter a blame cycle, we broadcast our session skey
    // and collect those from remaining participants
    sess_skeys: HashMap<ParticipantID, SecretKey>,

    // table of participant cloaking hashes used with excluded participants
    // one of these from each remaining participant during blame discovery
    all_excl_cloaks: HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,

    // supertransaction participant lists from fellow participants
    all_parts_info: HashMap<ParticipantID, Vec<ParticipantID>>,

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
    msg_state: VsMsgExpectedType,

    // Timeout handling - we record the beginning of our timeout
    // period at start of Receive, and decrement waiting on each 1s tick
    // of our VS Timer.
    //
    // Each timer tick carries the instant that it fired. So if tick is earlier
    // than our start time, we simply ignore the tick event.
    waiting: i16,
    wait_start: SystemTime,
}

impl ValueShuffle {
    // ----------------------------------------------------------------------------------------------
    // Public API.
    // ----------------------------------------------------------------------------------------------

    /// Create a new ValueShuffle instance.
    pub fn new(
        skey: SecretKey,
        pkey: PublicKey,
        participant_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        wallet_tx_info: UnboundedSender<ValueShuffleOutput>,
    ) -> ValueShuffle {
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
        let mut events: Vec<Box<dyn Stream<Item = ValueShuffleEvent, Error = ()> + Send>> =
            Vec::new();

        // Network.
        let pool_formed = network
            .subscribe_unicast(VALUE_SHUFFLE_TOPIC)
            .expect("connected")
            .map(|m| ValueShuffleEvent::MessageReceived(m.from, m.data));
        events.push(Box::new(pool_formed));

        // Facilitator elections.
        let facilitator_changed = node
            .subscribe()
            .filter_map(|e| match e {
                NodeNotification::NewMacroBlock(b) => Some(b),
                _ => None,
            })
            .map(|epoch| ValueShuffleEvent::FacilitatorChanged(epoch.facilitator));
        events.push(Box::new(facilitator_changed));

        // Pool formation.
        let pool_formed = network
            .subscribe_unicast(POOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| ValueShuffleEvent::PoolFormed(m.from, m.data));
        events.push(Box::new(pool_formed));

        // VsTimeout timer events
        let duration = VS_TIMER; // every second
        let timer = Interval::new_interval(duration)
            .map(|_i| ValueShuffleEvent::VsTimer(SystemTime::now()))
            .map_err(|_e| ()); // ignore transient timer errors
        events.push(Box::new(timer));

        let events = select_all(events);

        ValueShuffle {
            wallet_tx_info,
            skey: skey.clone(),
            facilitator_pkey,
            future_facilitator,
            state,
            participant_key,
            participants: participants.clone(), // empty vector
            session_id,
            network,
            events,

            my_txins: Vec::new(),
            my_txouts: Vec::new(),
            my_utxos: Vec::new(),
            my_fee: 0,
            sess_skey: skey.clone(),
            sess_pkey: pkey,
            my_signing_skey: skey.clone(),
            txin_gamma_sum: Fr::zero(),

            // these are all empty participant lists
            session_round: 0,
            all_txins: HashMap::new(),
            my_round_k: Fr::zero(),
            sigK_vals: HashMap::new(),
            sess_skeys: HashMap::new(),
            sess_pkeys: HashMap::new(),
            k_cloaks: HashMap::new(),
            excl_cloaks: HashMap::new(),
            all_excl_cloaks: HashMap::new(),
            commits: HashMap::new(),
            matrices: HashMap::new(),
            cloaked_gamma_adjs: HashMap::new(),
            cloaked_fees: HashMap::new(),
            signatures: HashMap::new(),
            pending_participants: HashSet::new(),
            excl_participants: Vec::new(),
            msg_state: VsMsgExpectedType::None,
            trans: PaymentTransaction::dum(),
            wait_start: SystemTime::now(),
            waiting: 0,
            msg_queue: VecDeque::new(),
            serialized_utxo_size: None,
            dicemix_nbr_utxo_chunks: None,
            pending_removals: Vec::new(),
            commit_phase_participants: Vec::new(),
            all_parts_info: HashMap::new(),
        }
    }

    /// Called by Wallet.
    pub fn queue_transaction(
        &mut self,
        txins: &Vec<(TXIN, UTXO)>,
        txouts: &Vec<ProposedUTXO>,
        fee: i64,
    ) -> Result<(), Error> {
        match self.state {
            State::Offline | State::PoolFinished => (),
            _ => {
                return Err(VsError::VsBusy.into());
            }
        }

        // get copies of our own TXIN UTXOs
        self.my_txins = txins.clone();
        self.my_txouts = txouts.clone();
        self.my_fee = fee;

        if txouts.len() > MAX_UTXOS {
            self.reset_state();
            return Err(VsError::VsTooManyUTXO.into());
        }

        // Send PoolJoin on the first request.
        self.state = State::PoolWait;
        self.msg_state = VsMsgExpectedType::None;
        self.send_pool_join()
    }

    /// Terminate ValueShuffle (used when ValueShuffle takes too long)
    pub fn terminate(&mut self) {
        warn!("Resetting ValueShuffle on request from outside.");
        self.reset_state();
    }

    // ----------------------------------------------------------------------------------------------
    // TxPool Membership
    // ----------------------------------------------------------------------------------------------

    // When a wallet wants to participate in a ValueShuffle session,
    // it should advertise its desire by sending a message to the Facilitator
    // node, along with its network ID (currently a pbc::pbc::PublicKey).
    //
    // When the Facilitator has accumulated a sufficient number of requestor
    // nodes, it collects those ID's and sends a message to each of them, to
    // start a ValueShuffle session. The Facilitator should send that list of
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
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
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
            .send(self.facilitator_pkey, POOL_JOIN_TOPIC, msg)?;
        Ok(())
    }

    fn reset_state(&mut self) {
        self.waiting = 0; // reset timeout counter
        self.state = State::PoolFinished;
        self.msg_state = VsMsgExpectedType::None;
        self.msg_queue.clear();
        self.session_round = 0;
        self.try_update_facilitator();
    }

    fn zap_state(&mut self, err: Error) {
        debug!("Zapping state, returning error to upper level.");
        if let Err(e) = self
            .wallet_tx_info
            .unbounded_send(ValueShuffleOutput::Failure(err, self.my_txins.clone()))
        {
            debug!("Error returning error from ValueShuffle: {:?}", e);
        }

        self.msg_queue.clear();
        self.waiting = 0;
        self.session_round = 0;
        self.try_update_facilitator();
        self.state = State::PoolFinished;
        self.msg_state = VsMsgExpectedType::None;
    }

    /// Called when a new txpool is formed.
    fn on_pool_notification(
        &mut self,
        from: pbc::PublicKey,
        pool_info: Vec<u8>,
    ) -> Result<(), Error> {
        match self.try_on_pool_notification(from, pool_info) {
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
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
        if let Err(e) = self.ensure_facilitator(from) {
            warn!("Found different facilitator: e = {}", e);
            return Ok(());
        }

        let pool_info = PoolNotification::from_buffer(&pool_info)?;
        debug!("pool = {:?}", pool_info);
        let pool_info = match pool_info {
            PoolNotification::Canceled => {
                debug!(
                    "Old facilitator decide to stop forming pool, trying to rejoin to the new one."
                );
                let changed = self.future_facilitator.is_some();
                self.reset_state();
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
            return Err(VsError::VsNotInParticipantList.into());
        }

        self.session_id = pool_info.session_id;
        let part_info = pool_info.participants;
        self.participants = Vec::<ParticipantID>::new();
        for elt in &part_info {
            let mut pairs = Vec::<(TXIN, UTXO)>::new();
            for (txin, utxo) in elt.txins.iter().zip(elt.utxos.iter()) {
                pairs.push((txin.clone(), utxo.clone()));
            }
            match validate_ownership(&pairs, &elt.ownsig) {
                Ok(_) => {
                    self.participants.push(elt.participant);
                    self.all_txins.insert(elt.participant, pairs);
                }
                _ => {
                    debug!("Invalid ownership signature");
                }
            }
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
        self.vs_start()
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
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
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
        if let Err(e) = self.ensure_facilitator(from.pkey) {
            warn!("Found different facilitator: e = {}", e);
            return Ok(());
        }
        self.session_id = session_id;
        self.session_round = 0;
        let excl = vec![without_part];
        match self.state {
            State::PoolFormed | State::PoolFinished => {
                match self.msg_state {
                    VsMsgExpectedType::None => {
                        // We aren't currently running, but we can restart with the
                        // participants left over from previous run.
                        // Facilitator should have already discarded our previous supertransaction.
                        self.exclude_participants(&excl);
                        self.state = State::PoolFormed;
                        return self.vs_start();
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
                        // in case we abort vs_start
                        self.msg_state = VsMsgExpectedType::None;
                        return self.vs_start();
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
    // TxPool Communication
    // ----------------------------------------------------------------------------------------------

    /// Sends a message to all txpool members via unicast.
    fn send_message(&self, msg: Message) -> Result<(), Error> {
        for pkey in &self.participants {
            if *pkey != self.participant_key {
                let msg = DirectMessage {
                    destination: *pkey,
                    source: self.participant_key,
                    message: msg.clone(),
                };
                let bmsg = msg.into_buffer()?;
                debug!("sending msg {:?} to {}", &msg, pkey);
                self.network
                    .send(pkey.pkey.clone(), VALUE_SHUFFLE_TOPIC, bmsg)?;
            }
        }
        Ok(())
    }

    /// Called when a new message is received via unicast.
    fn on_message_received(&mut self, from: ParticipantID, msg: Message) -> Result<(), Error> {
        match msg {
            Message::VsMessage { sid, payload } => {
                self.on_vs_message_received(&from, &sid, &payload)
            }
            Message::VsRestart {
                without_part,
                session_id,
            } => self.on_restart_pool(from, without_part, session_id),
        }
    }
}

impl Future for ValueShuffle {
    type Item = ();
    type Error = ();

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        ValueShuffleEvent::FacilitatorChanged(facilitator) => {
                            self.on_facilitator_changed(facilitator)
                        }
                        ValueShuffleEvent::PoolFormed(from, msg) => {
                            self.on_pool_notification(from, msg)
                        }
                        ValueShuffleEvent::MessageReceived(from, msg) => {
                            DirectMessage::from_buffer(&msg).and_then(|msg| {
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
                        ValueShuffleEvent::VsTimer(when) => self.handle_vs_timer(when),
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

fn is_valid_pt(pt: &Pt, ans: &mut Pt) -> bool {
    *ans = *pt;
    true
}

type VsFunction = fn(&mut ValueShuffle) -> Result<(), Error>;

impl ValueShuffle {
    fn handle_vs_timer(&mut self, when: SystemTime) -> Result<(), Error> {
        // self.waiting contains the nbr seconds countdown until a timeout
        // specify waiting = 0 for no timeout checking
        if self.waiting > 0 && when >= self.wait_start {
            self.waiting -= 1;
            if 0 == self.waiting {
                // reset msg_state to indicate done waiting for this kind of message
                // whichever participants have responded are now held in self.participants.
                // whichever participants did not respond are in self.pending_participants.
                debug!("vs timeout, msg_state: {:?}", self.msg_state);
                let state = self.msg_state;
                self.msg_state = VsMsgExpectedType::None;
                match state {
                    VsMsgExpectedType::None => {
                        return Ok(());
                    }
                    VsMsgExpectedType::SharedKeying => {
                        return self.vs_commit();
                    }
                    VsMsgExpectedType::Commitment => {
                        return self.vs_share_cloaked_data();
                    }
                    VsMsgExpectedType::CloakedVals => {
                        return self.vs_make_supertransaction();
                    }
                    VsMsgExpectedType::Signature => {
                        return self.vs_sign_supertransaction();
                    }
                    VsMsgExpectedType::SecretKeying => {
                        return self.vs_blame_discovery();
                    }
                }
            }
        }
        Ok(())
    }

    fn on_vs_message_received(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &VsPayload,
    ) -> Result<(), Error> {
        debug!("vs message: {}, from: {}, sess: {}", *payload, *from, *sid);
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
        payload: &VsPayload,
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
            (VsMsgExpectedType::SharedKeying, VsPayload::SharedKeying { .. })
            | (VsMsgExpectedType::Commitment, VsPayload::Commitment { .. })
            | (VsMsgExpectedType::CloakedVals, VsPayload::CloakedVals { .. })
            | (VsMsgExpectedType::Signature, VsPayload::Signature { .. })
            | (VsMsgExpectedType::SecretKeying, VsPayload::SecretKeying { .. }) => {
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

    fn handle_message(&mut self, from: &ParticipantID, payload: &VsPayload) -> Result<(), Error> {
        match self.msg_state {
            VsMsgExpectedType::None => Err(VsError::VsNotInSession.into()),
            VsMsgExpectedType::SharedKeying => self.handle_shared_keying(from, payload),
            VsMsgExpectedType::Commitment => self.handle_commitment(from, payload),
            VsMsgExpectedType::CloakedVals => self.handle_cloaked_vals(from, payload),
            VsMsgExpectedType::Signature => self.handle_signature(from, payload),
            VsMsgExpectedType::SecretKeying => self.handle_secret_keying(from, payload),
        }
    }

    fn maybe_do(&mut self, from: &ParticipantID, vfn: VsFunction) -> Result<(), Error> {
        self.participants.push(*from);
        if self.pending_participants.is_empty() {
            // Reset state to reflect a full participants list in case
            // we bomb out of the vfn(). We do this in case of any incoming
            // VsRestart messages which are sensitive to the state of the
            // participants list and pending_participants.
            self.msg_state = VsMsgExpectedType::None;
            vfn(self)
        } else {
            Ok(())
        }
    }

    fn handle_shared_keying(&mut self, from: &ParticipantID, msg: &VsPayload) -> Result<(), Error> {
        // debug!("In handle_shared_keying()");
        match msg {
            VsPayload::SharedKeying { pkey, ksig } => {
                debug!("checking shared keying {:?} {:?}", pkey, ksig);
                let mut pt = Pt::inf();
                if is_valid_pt(&ksig, &mut pt) {
                    debug!("shared keying okay {:?}", pkey);
                    self.sigK_vals.insert(*from, pt);
                    self.sess_pkeys.insert(*from, *pkey);
                    return self.maybe_do(from, Self::vs_commit);
                } else {
                    debug!("shared keying bad {:?}", pkey);
                }
            }
            _ => {}
        }
        Err(VsError::VsInvalidMessage.into())
    }

    fn handle_commitment(&mut self, from: &ParticipantID, msg: &VsPayload) -> Result<(), Error> {
        // debug!("In handle_commitment()");
        match msg {
            VsPayload::Commitment { cmt } => {
                debug!("saving commitment {}", cmt);
                self.commits.insert(*from, *cmt);
                return self.maybe_do(from, Self::vs_share_cloaked_data);
            }
            _ => {}
        }
        Err(VsError::VsInvalidMessage.into())
    }

    fn handle_cloaked_vals(&mut self, from: &ParticipantID, msg: &VsPayload) -> Result<(), Error> {
        // debug!("In handle_cloaked_vals()");
        match msg {
            VsPayload::CloakedVals {
                matrix,
                gamma_sum,
                fee_sum,
                cloaks,
            } => {
                let cmt = self.commits.get(from).expect("Can't access commit");
                debug!("Checking commitment {}", cmt);
                if *cmt == hash_data(matrix, gamma_sum, fee_sum)
                // DiceMix expects to be able to find all missing
                // participant cloaking values
                && self.excl_participants.iter().all(|p| cloaks.contains_key(p))
                // and we won't be able to form the same supertransaction as others
                // unless they have exactly the same missing participants that we do
                && cloaks.keys().all(|p| self.excl_participants.contains(p))
                {
                    debug!("Commitment check passed {}", cmt);
                    debug!("Saving cloaked data");
                    self.matrices.insert(*from, matrix.clone());
                    self.cloaked_gamma_adjs.insert(*from, gamma_sum.clone());
                    self.cloaked_fees.insert(*from, fee_sum.clone());
                    self.all_excl_cloaks.insert(*from, cloaks.clone());
                    return self.maybe_do(from, Self::vs_make_supertransaction);
                } else {
                    debug!("Commitment check failed {}", cmt);
                }
            }
            _ => {}
        }
        Err(VsError::VsInvalidMessage.into())
    }

    fn handle_signature(&mut self, from: &ParticipantID, msg: &VsPayload) -> Result<(), Error> {
        // debug!("In handle_signature()");
        match msg {
            VsPayload::Signature { sig } => {
                debug!("saving signature {:?}", sig);
                self.signatures.insert(*from, sig.clone());
                return self.maybe_do(from, Self::vs_sign_supertransaction);
            }
            _ => {}
        }
        Err(VsError::VsInvalidMessage.into())
    }

    fn handle_secret_keying(&mut self, from: &ParticipantID, msg: &VsPayload) -> Result<(), Error> {
        // debug!("In handle_secret_keying()");
        match msg {
            VsPayload::SecretKeying { skey } => {
                debug!("saving skey {:?}", skey);
                self.sess_skeys.insert(*from, skey.clone());
                return self.maybe_do(from, Self::vs_blame_discovery);
            }
            _ => {}
        }
        Err(VsError::VsInvalidMessage.into())
    }

    fn form_pooljoin_message(&mut self) -> Result<PoolJoin, Error> {
        // Possible exits:
        //   - normal exit
        //   - ownership signing failure - can't open TXIN UTXO
        //                               - or signature fails validation
        //   - can't open TXIN UTXO
        //   - assertion failure on zero gamma value

        // validate each TXIN and get my initial signature keying info
        let mut my_signing_skeyF = Fr::zero();
        self.txin_gamma_sum = Fr::zero();
        let utxos = self.my_txins.iter().map(|(_txin, u)| u.clone()).collect();
        // signing error if we can't open the TXIN UTXO
        let own_sig = sign_utxos(&utxos, &self.skey)?;

        // double check our own TXINs
        validate_ownership(&self.my_txins, &own_sig)?;

        let mut amt_in = 0;
        for utxo in utxos.clone() {
            let (gamma, delta, amount) = open_utxo(&utxo, &self.skey)?;
            assert!(gamma != Fr::zero());
            amt_in += amount;
            self.txin_gamma_sum += gamma;
            my_signing_skeyF += Fr::from(self.skey) + gamma * delta;
        }
        self.my_signing_skey = my_signing_skeyF.into();

        // check that we have a zero balance condition
        // might as well abort right now, if not...
        let mut amt_out = 0;
        self.my_txouts.iter().for_each(|rec| amt_out += rec.amount);
        if self.my_fee < 0 || amt_in != amt_out + self.my_fee {
            return Err(VsError::VsBadTransaction.into());
        }

        // To join a session we must send our list of TXINS, along with
        // our proof of ownership signature on all of them.

        self.all_txins
            .insert(self.participant_key, self.my_txins.clone());

        let msg_txins: Vec<TXIN> = self.my_txins.iter().map(|(k, _u)| k.clone()).collect();
        let msg = PoolJoin {
            seed: self.participant_key.seed,
            txins: msg_txins,
            utxos,
            ownsig: own_sig,
        };
        Ok(msg)
    }

    fn prep_rx(&mut self, msgtype: VsMsgExpectedType, timeout: i16) {
        // transfer other participants into pending_participants
        // and set new msg_state for expected kind of messages
        let mut other_participants: HashSet<ParticipantID> = HashSet::new();
        self.participants
            .iter()
            .filter(|&&p| p != self.participant_key)
            .for_each(|&p| {
                other_participants.insert(p);
            });
        self.pending_participants = other_participants;
        self.participants = vec![self.participant_key];

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

    fn vs_start(&mut self) -> Result<(), Error> {
        match self.try_vs_start() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_start(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - fewer than 3 participants = protocol fail
        //   - normal exit

        debug!("In vs_start()");
        if self.participants.len() < 3 {
            return Err(VsError::VsTooFewParticipants(self.participants.len()).into());
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

        let k = {
            // construct a new session dependent secret sig.k val
            // We can't construct k based on hash of transaction to be
            // signed, since we don't have it yet.
            //
            //  But we must never allow the k_val to be the same between
            // rounds. Otherwise we open ourselves to the Sony PS attack,
            // and we could lose secrecy of the signing key.
            let mut state = Hasher::new();
            "kVal".hash(&mut state);
            self.session_id.hash(&mut state);
            self.my_signing_skey.hash(&mut state);
            Fr::from(state.result())
        };
        self.my_round_k = k;
        let my_sigK = times_G(&self.my_round_k); // = my_round_k * G
        let my_sigKcmp = my_sigK;

        self.sigK_vals = HashMap::new();
        self.sigK_vals.insert(self.participant_key, my_sigK);

        // Generate new cloaked sharing key set and share with others
        // also shares our sigK value at this time.
        let (sess_sk, sess_pk) = make_session_key(&self.my_signing_skey, &self.session_id);
        self.sess_pkey = sess_pk;
        self.sess_skey = sess_sk.clone();

        self.sess_pkeys = HashMap::new();
        self.sess_pkeys.insert(self.participant_key, sess_pk);

        self.send_session_pkey(&sess_pk, &my_sigKcmp);

        // Collect cloaked sharing keys from others
        // fill in sess_pkeys and sigK_vals
        self.receive_session_pkeys();

        Ok(())
    }

    fn vs_commit(&mut self) -> Result<(), Error> {
        match self.try_vs_commit() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_commit(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure

        debug!("In vs_commit()");
        if self.participants.len() < 3 {
            return Err(VsError::VsTooFewParticipants(self.participants.len()).into());
        }

        // participants at the time of matrix construction
        self.commit_phase_participants = self.participants.clone();

        // Generate shared cloaking factors
        self.k_cloaks = dc_keys(
            &self.commit_phase_participants,
            &self.sess_pkeys,
            &self.participant_key,
            &self.sess_skey,
            &self.session_id,
        );

        // Construct fresh UTXOS and gamma_adj
        let my_pairs = Self::generate_fresh_utxos(&self.skey, &self.my_txouts);
        let mut my_utxos = Vec::<UTXO>::new();
        let mut my_gamma_adj = self.txin_gamma_sum.clone();
        self.my_utxos = Vec::new();
        my_pairs.iter().for_each(|(utxo, gamma)| {
            my_utxos.push(utxo.clone());
            my_gamma_adj -= gamma.clone();
            self.my_utxos.push(utxo.proof.vcmt);
        });

        // set size of serialized UTXO if not already established
        match self.serialized_utxo_size {
            None => {
                let msg = serialize_utxo(&my_utxos[0]);
                self.serialized_utxo_size = Some(msg.len());
                let row = split_message(&msg, None);
                self.dicemix_nbr_utxo_chunks = Some(row.len());
            }
            _ => {}
        }

        // -------------------------------------------------------------
        // for debugging - check that our contribution produces zero balance
        {
            let cmt_sum = self
                .my_txins
                .iter()
                .fold(Pt::inf(), |sum, (_, u)| sum + u.proof.vcmt);
            let cmt_sum = my_utxos.iter().fold(cmt_sum, |sum, u| sum - u.proof.vcmt);
            assert!(cmt_sum == simple_commit(&my_gamma_adj, &Fr::from(self.my_fee)));
        }
        // -------------------------------------------------------------

        let my_matrix = Self::encode_matrix(
            &self.commit_phase_participants,
            &my_utxos,
            &self.participant_key,
            &self.k_cloaks,
            self.dicemix_nbr_utxo_chunks.unwrap(),
        );
        self.matrices = HashMap::new();
        self.matrices
            .insert(self.participant_key, my_matrix.clone());

        // cloaked gamma_adj for sharing
        self.cloaked_gamma_adjs = HashMap::new();
        let my_cloaked_gamma_adj = dc_encode_scalar(
            my_gamma_adj,
            &self.commit_phase_participants,
            &self.participant_key,
            &self.k_cloaks,
        );
        self.cloaked_gamma_adjs
            .insert(self.participant_key, my_cloaked_gamma_adj.clone());

        self.cloaked_fees = HashMap::new();
        let my_cloaked_fee = dc_encode_scalar(
            Fr::from(self.my_fee),
            &self.commit_phase_participants,
            &self.participant_key,
            &self.k_cloaks,
        );
        self.cloaked_fees
            .insert(self.participant_key, my_cloaked_fee.clone());

        // form commitments to our matrix and gamma sum
        let my_commit = hash_data(&my_matrix, &my_cloaked_gamma_adj, &my_cloaked_fee);

        // Collect and validate commitments from other participants
        self.commits = HashMap::new();
        self.commits.insert(self.participant_key, my_commit);

        // send sharing commitment to other participants
        self.send_commitment(&my_commit);

        // fill in commits
        self.receive_commitments();

        Ok(())
    }

    fn vs_share_cloaked_data(&mut self) -> Result<(), Error> {
        match self.try_vs_share_cloaked_data() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_share_cloaked_data(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure
        //   - .expect() errors - should never happen in proper code

        debug!("In vs_share_cloaked_data()");
        if self.participants.len() < 3 {
            return Err(VsError::VsFail.into());
        }

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
            .insert(self.participant_key, self.excl_cloaks.clone());

        // send committed and cloaked data to all participants
        let my_matrix = self
            .matrices
            .get(&self.participant_key)
            .expect("Can't access my own matrix");
        let my_cloaked_gamma_adj = self
            .cloaked_gamma_adjs
            .get(&self.participant_key)
            .expect("Can't access my own gamma_adj");
        let my_cloaked_fee = self
            .cloaked_fees
            .get(&self.participant_key)
            .expect("Can't access my own fee");

        self.all_parts_info = HashMap::new();
        self.all_parts_info
            .insert(self.participant_key, self.participants.clone());

        self.send_cloaked_data(
            &my_matrix,
            &my_cloaked_gamma_adj,
            &my_cloaked_fee,
            &self.excl_cloaks,
        );

        // At this point, if we don't hear valid responses from all
        // remaining participants, we abort and start a new session
        // collect cloaked contributions from others

        // fill in matrices, cloaked_gamma_adj, cloaked_fees,
        // and all_excl_k_cloaks, using commits to validate incoming data
        self.receive_cloaked_data();

        Ok(())
    }

    fn had_dropouts(&self) -> bool {
        !(self
            .participants
            .iter()
            .all(|p| self.commit_phase_participants.contains(p))
            && (self
                .commit_phase_participants
                .iter()
                .all(|p| self.participants.contains(p))))
    }

    fn vs_make_supertransaction(&mut self) -> Result<(), Error> {
        match self.try_vs_make_supertransaction() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_make_supertransaction(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in proper code
        //
        debug!("In vs_make_supertransaction()");

        if self.participants.len() < 3 {
            debug!("Too few shared participants");
            return Err(VsError::VsFail.into());
        }

        if self.had_dropouts() {
            // if we don't have exactly the same participants as when
            // we shared the cloaked data, then we won't be able to
            // agree on the contents of a supertransaction, and signing
            // will fail. So may as well restart now.
            //
            // An inifinite restart loop is avoided here because we obviously
            // now have fewer participants than before. Either we eventually
            // succeed, or we fail by having fewer than 3 participants.
            debug!("dropouts occurred - restarting");
            return self.vs_start();
        }

        // -------------------------------------------------------
        // we got valid responses from all participants,
        let mut trn_txins = Vec::<UTXO>::new();
        self.commit_phase_participants.sort();
        let mut state = Hasher::new();
        self.commit_phase_participants.iter().for_each(|p| {
            // TXINs have already been checked and
            // these expects should never happen
            self.all_txins
                .get(p)
                .expect("Can't access TXINS")
                .iter()
                .for_each(|(_txin, u)| {
                    trn_txins.push(u.clone());
                    u.hash(&mut state);
                });
        });
        debug!("txin hash: {}", state.result());

        // get the cloaks we put there for all missing participants
        let msgs = dc_decode(
            &self.participants,
            &self.matrices,
            &self.participant_key,
            MAX_UTXOS,
            self.dicemix_nbr_utxo_chunks.unwrap(),
            &self.excl_participants, // the excluded participants
            &self.all_excl_cloaks,
        );
        debug!("nbr msgs = {}", msgs.len());

        let mut all_utxos = Vec::<UTXO>::new();
        let mut all_utxo_cmts = Vec::<Pt>::new();
        let mut state = Hasher::new();
        msgs.iter().for_each(|msg| {
            // we might have garbage data...
            match deserialize_utxo(msg, self.serialized_utxo_size.unwrap()) {
                Ok(utxo) => {
                    all_utxos.push(utxo.clone());
                    utxo.hash(&mut state);
                    all_utxo_cmts.push(utxo.proof.vcmt);
                }
                _ => {} // this will cause failure below
            }
        });
        debug!("txout hash: {}", state.result());
        // --------------------------------------------------------
        // for debugging - ensure that all of our txouts made it
        {
            debug!("nbr txouts = {}", all_utxos.len());
            self.my_utxos
                .iter()
                .for_each(|ucmt| assert!(all_utxo_cmts.contains(ucmt)));
        }
        // --------------------------------------------------------
        let gamma_adj = dc_scalar_open(
            &self.participants,
            &self.cloaked_gamma_adjs,
            &self.excl_participants,
            &self.all_excl_cloaks,
        );
        let total_fees_f = dc_scalar_open(
            &self.participants,
            &self.cloaked_fees,
            &self.excl_participants,
            &self.all_excl_cloaks,
        );
        let total_fees = {
            match total_fees_f.clone().to_i64() {
                Ok(val) => val,
                _ => {
                    debug!("I failed in conversion of total_fees");
                    0 // will probably fail validation...
                }
            }
        };
        debug!("total fees {:?} -> {:?}", total_fees_f.clone(), total_fees);
        debug!("gamma_adj: {:?}", gamma_adj);

        let K_sum = self
            .commit_phase_participants
            .iter()
            .fold(Pt::inf(), |sum, p| {
                sum + *self.sigK_vals.get(p).expect("can't get sigK value")
            });

        self.trans = self.make_super_transaction(
            &self.my_signing_skey,
            &self.my_round_k,
            &K_sum,
            &trn_txins,
            &all_utxos,
            total_fees,
            &gamma_adj,
        );
        {
            // for debugging - show the supertransaction hash at this node
            // all nodes should agree on this
            let h = Hash::digest(&self.trans);
            debug!("hash: {}", h);
        }

        // fill in multi-signature...
        self.signatures = HashMap::new();
        let sig = self.trans.sig.clone();
        self.signatures.insert(self.participant_key, sig.clone());

        self.send_signature(&sig);

        // fill in signatures
        self.receive_signatures();

        Ok(())
    }

    fn vs_sign_supertransaction(&mut self) -> Result<(), Error> {
        match self.try_vs_sign_supertransaction() {
            Ok(()) => Ok(()),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_sign_supertransaction(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in correct code

        debug!("In vs_sign_supertransaction()");
        if !self
            .commit_phase_participants
            .iter()
            .all(|p| self.signatures.contains_key(p))
        {
            // we don't have the requisite signatures,
            // so just start a new session. Could only have happened if
            // fewer participants responded.
            debug!("incorrect number of signaturs obtained - restarting without them");
            return self.vs_start();
        }

        self.trans.sig = self
            .commit_phase_participants
            .iter()
            .filter(|&&p| p != self.participant_key)
            .fold(self.trans.sig, |sig, p| {
                sig + self.signatures.get(p).expect("can't get peer signature")
            });
        debug!("total sig {:?}", self.trans.sig);

        if self.validate_transaction() {
            self.execute_super_transaction()?;
            self.reset_state(); // indicate nothing more to follow, restartable
            self.msg_queue.clear();
            self.session_round = 0; // for possible restarts
            debug!("Success in ValueShuffle!!");
            return Ok(());
        }

        // ------------------------------------------------------
        // Something is wrong with super-transaction:
        // (1) something phony in the transaction
        //    (1a) phony UTXO
        //    (1b) phony gamma_adj
        // (2) not all nodes agreed on its structure
        // (3) someone sent a phony signature

        // Enter blame discovery for retry sans cheater
        // broadcast our session skey and begin a round of blame discovery
        self.sess_skeys = HashMap::new();
        self.sess_skeys
            .insert(self.participant_key, self.sess_skey.clone());

        self.send_session_skey(&self.sess_skey);

        // fill in sess_skeys
        self.receive_session_skeys();
        Ok(())
    }

    fn vs_blame_discovery(&mut self) -> Result<(), Error> {
        match self.try_vs_blame_discovery() {
            Ok(ans) => Ok(ans),
            Err(err) => {
                self.zap_state(format_err!("ValueShuffle error: {:?}", err));
                Err(err)
            }
        }
    }

    fn try_vs_blame_discovery(&mut self) -> Result<(), Error> {
        // Possible exits:
        //   - normal exit

        debug!("In vs_blame_discovery()");
        if self.had_dropouts() {
            // if there were too few session keys received, then
            // someone dropped out, and we restart without them.
            debug!("too few session keys for blame cycle");
        } else {
            // everyone responded with their secret session key

            // let's do blame discovery
            // collect pkeys of cheaters and add to exclusions for next round
            let data = ValidationData {
                transaction: self.trans.clone(),
                signatures: self.signatures.clone(),
                all_txins: self.all_txins.clone(),
                serialized_utxo_size: self.serialized_utxo_size.unwrap(),
            };
            debug!("calling dc_reconstruct()");
            let new_p_excl = dc_reconstruct(
                &self.commit_phase_participants,
                &self.sess_pkeys,
                &self.participant_key,
                &self.sess_skeys,
                &self.matrices,
                &self.cloaked_gamma_adjs,
                &self.cloaked_fees,
                &self.session_id,
                &self.excl_participants,
                &self.all_excl_cloaks,
                Self::validate_uncloaked_contrib,
                &data,
            );
            self.exclude_participants(&new_p_excl);
        }
        // and begin another round
        self.vs_start()
    }

    // -----------------------------------------------------------------

    fn collect_txin_outputs(&self, txins: &Vec<TXIN>) -> Vec<Output> {
        // construct a lookup table TXIN -> UTXO
        let mut tbl: HashMap<TXIN, UTXO> = HashMap::new();
        for p in self.participants.clone() {
            for (txin, utxo) in self.all_txins.get(&p).expect("Can't access txins") {
                tbl.insert(txin.clone(), utxo.clone());
            }
        }
        // convert TXINs to UTXOs
        let mut inputs = Vec::<Output>::new();
        for tx in txins {
            let utxo = tbl.get(tx).expect("Can't access UTXO");
            inputs.push(Output::PaymentOutput(utxo.clone()));
        }
        inputs
    }

    fn make_super_transaction(
        &self,
        my_skey: &SecretKey,
        my_k: &Fr,
        K_val: &Pt, // grand sum K for composite signing
        txins: &Vec<UTXO>,
        utxos: &Vec<UTXO>,
        total_fee: i64,
        gamma_adj: &Fr,
    ) -> PaymentTransaction {
        fn map_to_outputs(v: &Vec<UTXO>) -> Vec<Output> {
            v.iter().map(|u| Output::PaymentOutput(u.clone())).collect()
        }
        let inputs = map_to_outputs(txins);
        let outputs = map_to_outputs(utxos);

        PaymentTransaction::new_super_transaction(
            my_skey, my_k, K_val, &inputs, &outputs, gamma_adj, total_fee,
        )
        .expect("Can't construct the super-transaction")
    }

    fn validate_transaction(&self) -> bool {
        // Check that super-transaction signature validates
        // against transaction contents, just like a validator would do.

        let inputs = self.collect_txin_outputs(&self.trans.txins);
        match self.trans.validate(&inputs) {
            Ok(_) => true,
            Err(err) => {
                debug!("validation error: {:?}", err);
                false
            }
        }
    }

    fn validate_uncloaked_contrib(
        pid: &ParticipantID,
        msgs: &Vec<Vec<u8>>,
        gamma_adj: Fr,
        fee: Fr,
        data: &ValidationData,
    ) -> bool {
        // accept a list of uncloaked messages that belong to pkey, along with gamma sum of his,
        // convert the messages into his UTXOS, and then verify that they satisfy the zero balance
        // condition with his TXIN.

        let mut txin_sum = Pt::inf();
        let mut eff_pkey = Pt::inf();
        for (_txin, utxo) in data.all_txins.get(pid).expect("Can't access TXIN") {
            // all txins have already been checked for validity
            // these expects should never happen
            let pkey_pt = Pt::from(utxo.recipient);
            let cmt_pt = utxo.proof.vcmt;
            txin_sum += cmt_pt;
            eff_pkey += pkey_pt + cmt_pt;
        }
        let mut txout_sum = Pt::inf();
        for msg in msgs {
            let utxo = match deserialize_utxo(msg, data.serialized_utxo_size) {
                Ok(u) => u,
                _ => {
                    return false;
                } // user supplied garbage
            };
            if !validate_range_proof(&utxo.proof) {
                return false; // user had invalid Bulletproof
            }
            // we just passed Bulletproof checking, so the proof.vcmt must be okay
            let cmt_pt = utxo.proof.vcmt;
            txout_sum += cmt_pt;
            eff_pkey -= cmt_pt;
        }

        let adj_cmt = simple_commit(&gamma_adj, &fee);
        // check for zero balance condition
        if txin_sum != txout_sum + adj_cmt {
            return false; // user trying to pull a fast one...
        }

        // All data seems good, so look for invalid signature
        eff_pkey -= adj_cmt;
        let eff_pkey = PublicKey::from(eff_pkey);
        let sig = data.signatures.get(pid).expect("Can't access signature");
        let tx = &data.transaction;
        let hash = Hasher::digest(&tx);

        // check signature on this portion of transaction
        match validate_sig(&hash, &sig, &eff_pkey) {
            Ok(_) => true,
            _ => false,
        }
    }

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
        for _ in n_utxos..MAX_UTXOS {
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

    fn generate_fresh_utxos(
        spender_skey: &SecretKey,
        txouts: &Vec<ProposedUTXO>,
    ) -> Vec<(UTXO, Fr)> {
        // generate a fresh set of UTXOs based on the list of proposed UTXOs
        // Return new UTXOs with fresh randomness, and the sum of all gamma factors

        let mut outs = Vec::<(UTXO, Fr)>::new();
        for txout in txouts.clone() {
            let data = PaymentPayloadData::Comment(txout.data);
            let (output, gamma, _rvalue) = PaymentOutput::with_payload(
                Some(&spender_skey),
                &txout.recip,
                txout.amount,
                data,
                txout.locked_timestamp,
            )
            .expect("Can't produce Payment UTXO");
            outs.push((output, gamma));
        }
        outs
    }

    // -------------------------------------------------

    fn send_signed_message(&self, payload: &VsPayload) {
        let msg = Message::VsMessage {
            payload: payload.clone(),
            sid: self.session_id,
        };
        self.send_message(msg).expect("Can't send message");
    }

    fn send_session_pkey(&self, sess_pkey: &PublicKey, sess_KSig: &Pt) {
        // send our session_pkey and sigK to all participants
        let payload = VsPayload::SharedKeying {
            pkey: *sess_pkey,
            ksig: *sess_KSig,
        };
        self.send_signed_message(&payload);
    }

    fn receive_session_pkeys(&mut self) {
        // collect session pkeys from all participants.
        // If any participant does not answer, add him to the exclusion list, p_excl

        // fills in the global state sess_pkeys and sigK_vals

        // we allow the receive_xxx to specify individual timeout periods
        // in case they need to vary
        self.prep_rx(VsMsgExpectedType::SharedKeying, VS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_commitment(&self, commit: &Hash) {
        // send our commitment to cloaked data to all other participants
        let payload = VsPayload::Commitment { cmt: *commit };
        self.send_signed_message(&payload);
    }

    fn receive_commitments(&mut self) {
        // receive commitments from all other participants
        // if any fail to send commitments, add them to exclusion list p_excl

        // fill in commits
        self.prep_rx(VsMsgExpectedType::Commitment, VS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_cloaked_data(
        &self,
        matrix: &DcMatrix,
        cloaked_gamma_adj: &Fr,
        cloaked_fee: &Fr,
        cloaks: &HashMap<ParticipantID, Hash>,
    ) {
        // send matrix, sum, and excl_k_cloaks to all participants
        let payload = VsPayload::CloakedVals {
            matrix: matrix.clone(),
            gamma_sum: cloaked_gamma_adj.clone(),
            fee_sum: cloaked_fee.clone(),
            cloaks: cloaks.clone(),
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
        self.prep_rx(VsMsgExpectedType::CloakedVals, VS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_signature(&self, sig: &SchnorrSig) {
        // send signature to leader node
        let payload = VsPayload::Signature { sig: sig.clone() };
        self.send_signed_message(&payload);
    }

    fn receive_signatures(&mut self) {
        // collect signatures from all participants
        // should not count as collected unless signature is partially valid.
        //
        // Partial valid = K component is valid ECC point

        // fill in signatures
        self.prep_rx(VsMsgExpectedType::Signature, VS_TIMEOUT);
    }

    // -------------------------------------------------

    fn send_session_skey(&self, skey: &SecretKey) {
        // send the session secret key to all participants
        let payload = VsPayload::SecretKeying { skey: skey.clone() };
        self.send_signed_message(&payload);
    }

    fn receive_session_skeys(&mut self) {
        // non-respondents are added to p_excl

        // fills in sess_skeys
        self.prep_rx(VsMsgExpectedType::SecretKeying, VS_TIMEOUT);
    }

    // -------------------------------------------------

    /// Send transaction to the wallet.
    fn execute_super_transaction(&mut self) -> Result<(), Error> {
        let leader = self.leader_id();
        debug!("Leader = {}", leader);
        let tx = self.trans.clone();
        self.wallet_tx_info
            .unbounded_send(ValueShuffleOutput::SignedTransaction(
                tx,
                self.participant_key == leader,
            ))?;
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

fn hash_data(matrix: &DcMatrix, cloaked_gamma_adj: &Fr, cloaked_fee: &Fr) -> Hash {
    let mut state = Hasher::new();
    "CM".hash(&mut state);
    for sheet in matrix.clone() {
        for row in sheet {
            for cell in row {
                cell.hash(&mut state);
            }
        }
    }
    cloaked_gamma_adj.hash(&mut state);
    cloaked_fee.hash(&mut state);
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

fn open_utxo(utxo: &UTXO, skey: &SecretKey) -> Result<(Fr, Fr, i64), VsError> {
    // decrypt the encrypted payload of the UTXO and
    // return the (gamma, delta, amount)
    match utxo.decrypt_payload(skey) {
        Ok(data) => {
            return Ok((data.gamma, data.delta, data.amount));
        }
        _ => {
            return Err(VsError::VsBadTXIN);
        }
    }
}

fn sign_utxos(utxos: &Vec<UTXO>, skey: &SecretKey) -> Result<SchnorrSig, Error> {
    // sign an (ordered) list of UTXOs to form an ownership signature
    let mut signing_f = Fr::zero();
    let mut state = Hasher::new();
    for utxo in utxos {
        utxo.hash(&mut state);
        let (gamma, delta, _) = open_utxo(utxo, skey)?;
        // decryption can always be performed. But if we don't
        // actually own the UTXO then we get garbage back.
        // This signature would then fail later on validate_ownership().
        assert!(gamma != Fr::zero());
        assert!(delta != Fr::zero());
        signing_f += Fr::from(skey.clone()) + gamma * delta;
    }
    Ok(sign_hash(&state.result(), &SecretKey::from(signing_f)))
}

fn validate_ownership(txins: &Vec<(TXIN, UTXO)>, owner_sig: &SchnorrSig) -> Result<(), Error> {
    let mut p_cmp = Pt::inf();
    let hash = {
        let mut state = Hasher::new();
        for (txin, utxo) in txins {
            let hash = Hash::digest(utxo);
            if hash != *txin {
                return Err(VsError::VsBadTXIN.into());
            }
            p_cmp += Pt::from(utxo.recipient);
            utxo.hash(&mut state);
        }
        state.result()
    };
    match validate_sig(&hash, owner_sig, &PublicKey::from(p_cmp)) {
        Ok(()) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn serialize_utxo(utxo: &UTXO) -> Vec<u8> {
    utxo.into_buffer().expect("Can't serialize UTXO")
}

fn deserialize_utxo(msg: &Vec<u8>, ser_size: usize) -> Result<UTXO, Error> {
    // DiceMix returns a byte vector whose length is some integral
    // number of Field size. But proto-bufs is very particular about
    // what it is handed, and complains about trailing padding bytes.
    // otherwise, deserialize and return
    match UTXO::from_buffer(&msg[0..ser_size]) {
        Err(err) => {
            debug!("deserialization error: {:?}", err);
            Err(VsError::VsBadUTXO.into())
        }
        Ok(utxo) => Ok(utxo),
    }
}

// -------------------------------------------------
// Domain helpers...

fn times_G(val: &Fr) -> Pt {
    // produce Pt = val*G
    *val * Pt::one()
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

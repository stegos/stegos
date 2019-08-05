//! mod.rs - Snowball Protocol for secure and anonymous transaction construction

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
// When a wallet wants to participate in a Snowball session,
// it should advertise its desire by sending a message to the Facilitator
// node, along with its network ID (currently a pbc::pbc::PublicKey).
//
// When the Facilitator has accumulated a sufficient number of requestor
// nodes, it collects those ID's and sends a message to each of them, to
// start a Snowball session. The Facilitator should send that list of
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
// At the start of the first round of Snowball, these TXINs are checked
// by forming ownership signatures, and verifying that these signatures check.
//
// If all TXIN are good, the TXIN hash values and ownership signatures are
// sent to all other Snowball participants, and they will also perform
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

mod error;
pub use error::*;

pub mod message;
use message::*;

mod protos;

use crate::snowball::message::SnowballMessage;
use crate::storage::ExtendedOutputValue;
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
use stegos_node::txpool::PoolJoin;
use stegos_node::txpool::PoolNotification;
use stegos_node::txpool::POOL_ANNOUNCE_TOPIC;
use stegos_node::txpool::POOL_JOIN_TOPIC;
use stegos_node::Node;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::{clock, Delay};

/// A topic used for Snowball unicast communication.
pub const SNOWBALL_TOPIC: &'static str = "snowball";

pub const SNOWBALL_TIMER: Duration = Duration::from_secs(60); // recurring 1sec events

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
    pub is_change: bool,
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
/// Snowball Events.
enum SnowballEvent {
    PoolFormed(pbc::PublicKey, Vec<u8>),
    MessageReceived(pbc::PublicKey, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
/// Pool State.
enum PoolState {
    PoolWait,
    PoolFormed,
    PoolFinished,
    /// Last session was canceled, waiting for new facilitator.
    PoolRestart,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageState {
    // used to indicate what kind of message payloads are wanted
    // in a collection pause between Snowball phases.
    None, // at startup, and after we finished succeessfully
    SharedKeying,
    Commitment,
    CloakedVals,
    Signature,
    SecretKeying,
}

#[derive(Debug)]
/// Possible outcomes of Snowball
pub struct SnowballOutput {
    pub tx: PaymentTransaction,
    pub outputs: Vec<ExtendedOutputValue>,
    pub is_leader: bool,
}

/// Snowball implementation.
pub struct Snowball {
    // -------------------------------------------
    // Startup Info - known at time of Snowball::new()
    /// Account Secret Key.
    account_skey: SecretKey,

    /// PBC Secret key of my node
    my_participant_skey: pbc::SecretKey,

    /// My public txpool's key.
    my_participant_id: ParticipantID,

    /// Faciliator's PBC public key
    facilitator: pbc::PublicKey,

    /// Next facilitator's PBC public key.
    /// Used if facilitator was changed during snowball session.
    future_facilitator: Option<pbc::PublicKey>,

    /// Pool State.
    poll_state: PoolState,

    /// Public keys of txpool's members,
    participants: Vec<ParticipantID>,

    /// Network API.
    network: Network,

    /// Timeout timer.
    timer: Option<Delay>,

    /// Incoming events.
    events: Box<dyn Stream<Item = SnowballEvent, Error = ()> + Send>,

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
    msg_queue: VecDeque<(ParticipantID, Hash, SnowballPayload)>,

    // List of participants that should be excluded on startup
    // normally empty, but could have resulted from restart pool
    // message arriving out of order with respect to pool start message.
    pending_removals: Vec<ParticipantID>,

    // --------------------------------------------
    // After facilitator launches our session.
    // Items computed in start()

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
    // Items compupted in commit()

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
    // Items computed in make_supertransaction()

    // the super-transaction that each remaining participant should have
    // all of us should compute the same body, different individual signatures
    trans: PaymentTransaction,

    // the list of signatures from each remaining participant
    // Individual signatures are based on hash of common transaction body,
    // and sum of all remaining participant K-sig values,
    // and sum of all remaining participant pubkeys
    // Final multi-signature is sum of these individual signatures
    signatures: HashMap<ParticipantID, SchnorrSig>,

    // --------------------------------------------
    // Items computed in sign_supertransaction()

    // if we enter a blame cycle, we broadcast our session skey
    // and collect those from remaining participants
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
    msg_state: MessageState,
}

impl Snowball {
    // ----------------------------------------------------------------------------------------------
    // Public API.
    // ----------------------------------------------------------------------------------------------

    /// Create a new Snowball instance.
    pub fn new(
        account_skey: SecretKey,
        account_pkey: PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        _node: Node,
        facilitator: pbc::PublicKey,
        my_txins: Vec<(TXIN, UTXO)>,
        my_txouts: Vec<ProposedUTXO>,
        my_fee: i64,
    ) -> Snowball {
        // check the maximal number of UTXOs.
        assert!(my_txouts.len() <= MAX_UTXOS);

        // validate each TXIN and get my initial signature keying info
        let utxos = my_txins.iter().map(|(_txin, u)| u.clone()).collect();
        // signing error if we can't open the TXIN UTXO
        let own_sig = sign_utxos(&utxos, &account_skey);

        // double check our own TXINs
        validate_ownership(&my_txins, &own_sig).expect("invalid keys");
        let mut amt_in = 0;
        let mut my_signing_skeyF = Fr::zero();
        let mut txin_gamma_sum = Fr::zero();
        for utxo in utxos.clone() {
            let payload = utxo.decrypt_payload(&account_skey).expect("invalid keys");
            let (gamma, delta, amount) = (payload.gamma, payload.delta, payload.amount);
            assert_ne!(gamma, Fr::zero());
            amt_in += amount;
            txin_gamma_sum += gamma;
            my_signing_skeyF += Fr::from(account_skey.clone()) + gamma * delta;
        }
        let mut amt_out = 0;
        my_txouts.iter().for_each(|rec| amt_out += rec.amount);

        // check that we have a zero balance condition
        if my_fee < 0 || amt_in != amt_out + my_fee {
            panic!("Invalid TX balance");
        }

        let my_signing_skey: SecretKey = my_signing_skeyF.into();
        let future_facilitator = None;
        let participants: Vec<ParticipantID> = Vec::new();
        let session_id: Hash = Hash::random();
        let state = PoolState::PoolWait;
        let mut rng = thread_rng();
        let seed = rng.gen::<[u8; 32]>();
        let my_participant_id = dicemix::ParticipantID::new(network_pkey, seed);

        //
        // Events.
        //
        let mut events: Vec<Box<dyn Stream<Item = SnowballEvent, Error = ()> + Send>> = Vec::new();

        // Network.
        let pool_formed = network
            .subscribe_unicast(SNOWBALL_TOPIC)
            .expect("connected")
            .map(|m| SnowballEvent::MessageReceived(m.from, m.data));
        events.push(Box::new(pool_formed));

        // Pool formation.
        let pool_formed = network
            .subscribe_unicast(POOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| SnowballEvent::PoolFormed(m.from, m.data));
        events.push(Box::new(pool_formed));

        // SbTimeout timer events
        let timer = None;

        let events = select_all(events);

        let mut sb = Snowball {
            account_skey,
            sess_pkey: account_pkey, // just a dummy placeholder for now
            my_participant_skey: network_skey.clone(),
            my_participant_id,
            facilitator,
            future_facilitator,
            poll_state: state,
            participants,
            session_id,
            network,
            timer,
            events,
            my_txins,
            my_txouts,
            my_utxos: Vec::new(),
            my_fee,
            sess_skey: account_skey.clone(), // dummy placeholder for now
            my_signing_skey,
            txin_gamma_sum,
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
            msg_state: MessageState::None,
            trans: PaymentTransaction::dum(),
            msg_queue: VecDeque::new(),
            serialized_utxo_size: None,
            dicemix_nbr_utxo_chunks: None,
            pending_removals: Vec::new(),
            commit_phase_participants: Vec::new(),
        };
        sb.send_pool_join();
        sb
    }

    /// Sets timeout.
    fn start_timer(&mut self) {
        trace!("Start timer.");
        assert!(self.msg_state != MessageState::None);
        current().notify();
        let timer = Delay::new(clock::now() + SNOWBALL_TIMER);
        self.timer = timer.into();
    }

    pub fn is_my_input(&self, input: Hash) -> bool {
        for (hash, _) in &self.my_txins {
            if *hash == input {
                return true;
            }
        }
        false
    }

    // ----------------------------------------------------------------------------------------------
    // TxPool Membership
    // ----------------------------------------------------------------------------------------------

    // When a wallet wants to participate in a Snowball session,
    // it should advertise its desire by sending a message to the Facilitator
    // node, along with its network ID (currently a pbc::pbc::PublicKey).
    //
    // When the Facilitator has accumulated a sufficient number of requestor
    // nodes, it collects those ID's and sends a message to each of them, to
    // start a Snowball session. The Facilitator should send that list of
    // node ID's along with an initial unique session ID (sid).

    /// Called when facilitator has been changed.
    pub fn change_facilitator(&mut self, facilitator: pbc::PublicKey) {
        match self.poll_state {
            PoolState::PoolFinished | PoolState::PoolRestart | PoolState::PoolWait => {}
            // in progress some session, keep new facilitator in future facilitator.
            _ => {
                debug!(
                    "Saving new facilitator, for future change: facilitator={}",
                    facilitator
                );
                self.future_facilitator = Some(facilitator);
            }
        }
        debug!("Changed facilitator: facilitator={}", facilitator);
        self.facilitator = facilitator;
        self.future_facilitator = None;
        // Last session was canceled, rejoining to new facilitator.
        if self.poll_state == PoolState::PoolRestart || self.poll_state == PoolState::PoolWait {
            debug!("Found new facilitator, rejoining to new pool.");
            self.send_pool_join();
        }
    }

    fn try_update_facilitator(&mut self) {
        if let Some(facilitator) = self.future_facilitator.take() {
            debug!("Changed facilitator: facilitator={}", facilitator);
            self.facilitator = facilitator;
        }
    }

    /// Sends a request to join tx pool.
    fn send_pool_join(&mut self) {
        debug!(
            "Sending pool join request: to_facilitator={}",
            self.facilitator
        );
        // To join a session we must send our list of TXINS, along with
        // our proof of ownership signature on all of them.

        self.all_txins
            .insert(self.my_participant_id, self.my_txins.clone());

        let utxos = self.my_txins.iter().map(|(_txin, u)| u.clone()).collect();
        let ownsig = sign_utxos(&utxos, &self.account_skey);
        let msg_txins: Vec<TXIN> = self.my_txins.iter().map(|(k, _u)| k.clone()).collect();
        let msg = PoolJoin {
            seed: self.my_participant_id.seed,
            txins: msg_txins,
            utxos,
            ownsig,
        };
        let msg = msg.into_buffer().unwrap();
        self.network
            .send(self.facilitator, POOL_JOIN_TOPIC, msg)
            .expect("Connected");
    }

    fn reset_state(&mut self) {
        self.poll_state = PoolState::PoolFinished;
        self.msg_state = MessageState::None;
        self.msg_queue.clear();
        self.session_round = 0;
        self.timer = None;
        self.try_update_facilitator();
    }

    /// Called when a new txpool is formed.
    fn on_pool_notification(
        &mut self,
        from: pbc::PublicKey,
        pool_info: PoolNotification,
    ) -> HandlerResult {
        debug!("pool = {:?}", pool_info);
        if let Err(e) = self.ensure_facilitator(from) {
            warn!("Found different facilitator: e = {}", e);
            return Ok(Async::NotReady);
        }
        let pool_info = match pool_info {
            PoolNotification::Canceled => {
                debug!(
                    "Old facilitator decide to stop forming pool, trying to rejoin to the new one."
                );
                let changed = self.future_facilitator.is_some();
                self.reset_state();
                if changed {
                    debug!("Found new facilitator, rejoining to new pool.");
                    self.send_pool_join();
                } else {
                    self.poll_state = PoolState::PoolRestart;
                }
                return Ok(Async::NotReady);
            }
            PoolNotification::Started(info) => info,
        };

        if pool_info
            .participants
            .iter()
            .find(|k| k.participant == self.my_participant_id)
            .is_none()
        {
            debug!("Our key = {:?}", self.my_participant_id);
            return Err(SnowballError::NotInParticipantList);
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
        let removals = mem::replace(&mut self.pending_removals, Vec::new());
        self.exclude_participants(&removals);

        self.participants.sort();
        self.participants.dedup();

        debug!("Formed txpool: members={}", self.participants.len());
        for pkey in &self.participants {
            debug!("{:?}", pkey);
        }

        self.poll_state = PoolState::PoolFormed;

        // start processing queued transactions....
        self.start()
    }

    fn ensure_facilitator(&self, from: pbc::PublicKey) -> Result<(), Error> {
        if from != self.facilitator {
            Err(format_err!(
                "Invalid facilitator: expected={}, got={}",
                self.facilitator,
                from
            ))
        } else {
            Ok(())
        }
    }

    fn exclude_participants(&mut self, p_excl: &Vec<ParticipantID>) {
        self.participants.retain(|p| !p_excl.contains(p));
    }
}

type HandlerResult = Poll<SnowballOutput, SnowballError>;

impl Future for Snowball {
    type Item = SnowballOutput;
    type Error = (SnowballError, Vec<(TXIN, UTXO)>);

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.timer.poll().expect("Should be no error in timer") {
            Async::Ready(Some(_)) => match self.handle_timer() {
                Ok(Async::NotReady) => (),
                result => return result.map_err(|error| (error, self.my_txins.clone())),
            },
            Async::NotReady | Async::Ready(None) => (),
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: HandlerResult = match event {
                        SnowballEvent::PoolFormed(from, pool_info) => {
                            let pool_info = match PoolNotification::from_buffer(&pool_info) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    error!("Invalid PoolInfo message: {}", e);
                                    continue;
                                }
                            };
                            self.on_pool_notification(from, pool_info)
                        }
                        SnowballEvent::MessageReceived(from, msg) => {
                            let msg = match SnowballMessage::from_buffer(&msg) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    error!("Invalid DirectMessage message: {}", e);
                                    continue;
                                }
                            };
                            if msg.source.pkey != from {
                                warn!("Source key was different {} = {}", msg.source.pkey, from);
                                continue;
                            }
                            if msg.destination != self.my_participant_id {
                                trace!(
                                    "Message to other account: destination={} = our_key={}",
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
                            debug!("Done");
                            return Ok(Async::Ready(r));
                        }
                        Ok(Async::NotReady) => {
                            debug!("NotReady");
                            continue;
                        }
                        Err(error) => {
                            error!("Error: {:?}", error);
                            return Err((error, self.my_txins.clone()));
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

impl Snowball {
    /*
    So the protocol could be written as state machine, called by scheduler
    on receipt of events. Events are obtained by the scheduler polling for them.
    Two events are of interest here:
     1. periodic timer events, occurring at 1sec intervals, and
     2. messages arriving from other participants.

     fn event_handler(&mut self, event: Event) -> Result<SnowballOutput, SnowballError> {
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

    fn message_handler(&mut self, message: Message) -> Result<SnowballOutput, SnowballError> {
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
        self.timer = None;
        // reset msg_state to indicate done waiting for this kind of message
        // whichever participants have responded are now held in self.participants.
        // whichever participants did not respond are in self.pending_participants.
        debug!("vs timeout, msg_state: {:?}", self.msg_state);
        if self.poll_state == PoolState::PoolFinished {
            // handle case of left over timer event after we finish
            // should not ever happen...
            return Err(SnowballError::WildTimer);
        } else {
            self.perform_next_phase()
        }
    }

    fn on_message_received(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        payload: &SnowballPayload,
    ) -> HandlerResult {
        debug!("vs message: {}, from: {}, sess: {}", *payload, *from, *sid);

        // insert new message at head of queue
        self.msg_queue.push_front((*from, *sid, payload.clone()));

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
            if self.poll_state == PoolState::PoolFinished {
                break;
            }
            let queue = mem::replace(&mut self.msg_queue, VecDeque::new());
            let mut actionable = false; // true if we found something to do...
                                        // process each message in the queue
            for (from, sid, payload) in queue {
                if actionable {
                    // stuff message back on tail of queue for next pass
                    self.msg_queue.push_back((from, sid, payload.clone()));
                } else {
                    // handle one message, filtering out the queue
                    match self.handle_message(&from, &sid, &payload) {
                        MsgHandlerResponse::Discard => { /* discard by default */ }
                        MsgHandlerResponse::ReEnqueue => {
                            // put message back on queue for later
                            self.msg_queue.push_back((from, sid, payload.clone()));
                        }
                        MsgHandlerResponse::Accept => {
                            // message will be removed from queue by default
                            self.pending_participants.remove(&from);
                            self.participants.push(from);
                            // we are actionable if no more pending participants
                            actionable = self.pending_participants.is_empty();
                        }
                    }
                }
            }
            if actionable {
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
        payload: &SnowballPayload,
    ) -> MsgHandlerResponse {
        match self.msg_state {
            MessageState::None => {
                panic!("There should messages in None state.");
            }
            MessageState::SharedKeying => self.handle_shared_keying(from, sid, payload),
            MessageState::Commitment => self.handle_commitment(from, sid, payload),
            MessageState::CloakedVals => self.handle_cloaked_vals(from, sid, payload),
            MessageState::Signature => self.handle_signature(from, sid, payload),
            MessageState::SecretKeying => self.handle_secret_keying(from, sid, payload),
        }
    }

    fn perform_next_phase(&mut self) -> HandlerResult {
        match self.msg_state {
            MessageState::None => {
                panic!("There should be no processing in None state.");
            }
            MessageState::SharedKeying => self.commit(),
            MessageState::Commitment => self.share_cloaked_data(),
            MessageState::CloakedVals => self.make_supertransaction(),
            MessageState::Signature => self.sign_supertransaction(),
            MessageState::SecretKeying => self.blame_discovery(),
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

    // --- Prep for communications and transition to next phase ---

    fn prep_rx(&mut self, next_state: MessageState) -> HandlerResult {
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

        self.msg_state = next_state;
        self.start_timer();
        debug!("In prep_rx(), state = {:?}", next_state);
        Ok(Async::NotReady)
    }

    // --- Shared Session Keying ---

    fn make_shared_keying(&self, pkey: &PublicKey, ksig: &Pt) -> SnowballPayload {
        let mut state = Hasher::new();
        pkey.hash(&mut state);
        ksig.hash(&mut state);
        self.session_id.hash(&mut state);
        let h = state.result();
        let signature = pbc::sign_hash(&h, &self.my_participant_skey);
        SnowballPayload::SharedKeying {
            pkey: pkey.clone(),
            ksig: ksig.clone(),
            signature,
        }
    }

    fn is_valid_keying(&self, msg: &SnowballPayload, from: &ParticipantID) -> bool {
        // check that signature was from someone who not only knows the
        // secret key, but also knows the correct session ID.
        match msg {
            SnowballPayload::SharedKeying {
                pkey,
                ksig,
                signature,
            } => {
                let mut state = Hasher::new();
                pkey.hash(&mut state);
                ksig.hash(&mut state);
                self.session_id.hash(&mut state);
                let h = state.result();
                pbc::check_hash(&h, signature, &from.pkey).is_ok()
            }
            _ => false, // should never reach here...
        }
    }

    fn handle_shared_keying(
        &mut self,
        from: &ParticipantID,
        _sid: &Hash,
        msg: &SnowballPayload,
    ) -> MsgHandlerResponse {
        // debug!("In handle_shared_keying()");
        match msg {
            SnowballPayload::SharedKeying { pkey, ksig, .. } => {
                debug!("checking shared keying {:?} {:?}", pkey, ksig);
                if self.is_valid_keying(msg, from) {
                    debug!("received shared keying {:?}", pkey);
                    self.sigK_vals.insert(*from, *ksig);
                    self.sess_pkeys.insert(*from, *pkey);
                    MsgHandlerResponse::Accept
                } else {
                    // message might have arrived from attacker
                    // trying to impersonate the participant
                    // so allow for another try from participant
                    debug!("shared keying bad {:?}", pkey);
                    MsgHandlerResponse::Discard
                }
            }
            _ => MsgHandlerResponse::ReEnqueue,
        }
    }

    // --- Commitments to DiceMix Matries ----

    fn handle_commitment(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        msg: &SnowballPayload,
    ) -> MsgHandlerResponse {
        // debug!("In handle_commitment()");
        if *sid != self.session_id {
            return MsgHandlerResponse::ReEnqueue;
        }
        match msg {
            SnowballPayload::Commitment { cmt } => {
                debug!("saving commitment {}", cmt);
                self.commits.insert(*from, *cmt);
                MsgHandlerResponse::Accept
            }
            _ => MsgHandlerResponse::ReEnqueue,
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
        msg: &SnowballPayload,
    ) -> MsgHandlerResponse {
        // debug!("In handle_cloaked_vals()");
        if *sid != self.session_id {
            return MsgHandlerResponse::ReEnqueue;
        }
        match msg {
            SnowballPayload::CloakedVals {
                matrix,
                gamma_sum,
                fee_sum,
                cloaks,
            } => {
                let cmt = self.commits.get(from).expect("Can't access commit");
                debug!("Checking commitment {}", cmt);
                // DiceMix expects to be able to find all missing
                // participant cloaking values
                if *cmt == hash_data(matrix, gamma_sum, fee_sum) && self.same_exclusions(cloaks) {
                    debug!("Commitment check passed {}", cmt);
                    debug!("Saving cloaked data");
                    self.matrices.insert(*from, matrix.clone());
                    self.cloaked_gamma_adjs.insert(*from, gamma_sum.clone());
                    self.cloaked_fees.insert(*from, fee_sum.clone());
                    self.all_excl_cloaks.insert(*from, cloaks.clone());
                    MsgHandlerResponse::Accept
                } else {
                    // participant has wrong impression, or we are
                    // under attack...
                    debug!("Commitment check failed {}", cmt);
                    MsgHandlerResponse::Discard
                }
            }
            _ => MsgHandlerResponse::ReEnqueue,
        }
    }

    // --- Signature exchange for pending supertransaction ---

    fn handle_signature(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        msg: &SnowballPayload,
    ) -> MsgHandlerResponse {
        // debug!("In handle_signature()");
        if *sid != self.session_id {
            return MsgHandlerResponse::ReEnqueue;
        }
        match msg {
            SnowballPayload::Signature { sig } => {
                debug!("saving signature {:?}", sig);
                self.signatures.insert(*from, sig.clone());
                MsgHandlerResponse::Accept
            }
            _ => MsgHandlerResponse::ReEnqueue,
        }
    }

    // --- Session secret key exchange for blame discovery ---

    fn handle_secret_keying(
        &mut self,
        from: &ParticipantID,
        sid: &Hash,
        msg: &SnowballPayload,
    ) -> MsgHandlerResponse {
        // debug!("In handle_secret_keying()");
        if *sid != self.session_id {
            return MsgHandlerResponse::ReEnqueue;
        }
        match msg {
            SnowballPayload::SecretKeying { skey } => {
                debug!("saving skey {:?}", skey);
                self.sess_skeys.insert(*from, skey.clone());
                MsgHandlerResponse::Accept
            }
            _ => MsgHandlerResponse::ReEnqueue,
        }
    }

    fn need_3_participants(&self) -> HandlerResult {
        if self.participants.len() < 3 {
            return Err(SnowballError::TooFewParticipants(self.participants.len()));
        }
        Ok(Async::NotReady)
    }

    // ----------------------------------------------------------
    // The interrim phases of Snowball protocol
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

        debug!("In start()");
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
        self.sigK_vals.insert(self.my_participant_id, my_sigK);

        // Generate new cloaked sharing key set and share with others
        // also shares our sigK value at this time.
        let (sess_sk, sess_pk) = make_session_key(&self.my_signing_skey, &self.session_id);
        self.sess_pkey = sess_pk;
        self.sess_skey = sess_sk.clone();

        self.sess_pkeys = HashMap::new();
        self.sess_pkeys.insert(self.my_participant_id, sess_pk);

        self.send_session_pkey(&sess_pk, &my_sigKcmp);

        // Collect cloaked sharing keys from others
        // fill in sess_pkeys and sigK_vals
        self.receive_session_pkeys()
    }

    fn commit(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - fewer than 3 participants = protocol failure

        debug!("In commit()");
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

        // Construct fresh UTXOS and gamma_adj
        // We should store fresh UTXOS into `my_utxos` with the same order as it was in `my_txouts`.
        let my_pairs = Self::generate_fresh_utxos(&self.account_skey, &self.my_txouts);
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
            &self.my_participant_id,
            &self.k_cloaks,
            self.dicemix_nbr_utxo_chunks.unwrap(),
        );
        self.matrices = HashMap::new();
        self.matrices
            .insert(self.my_participant_id, my_matrix.clone());

        // cloaked gamma_adj for sharing
        self.cloaked_gamma_adjs = HashMap::new();
        let my_cloaked_gamma_adj = dc_encode_scalar(
            my_gamma_adj,
            &self.commit_phase_participants,
            &self.my_participant_id,
            &self.k_cloaks,
        );
        self.cloaked_gamma_adjs
            .insert(self.my_participant_id, my_cloaked_gamma_adj.clone());

        self.cloaked_fees = HashMap::new();
        let my_cloaked_fee = dc_encode_scalar(
            Fr::from(self.my_fee),
            &self.commit_phase_participants,
            &self.my_participant_id,
            &self.k_cloaks,
        );
        self.cloaked_fees
            .insert(self.my_participant_id, my_cloaked_fee.clone());

        // form commitments to our matrix and gamma sum
        let my_commit = hash_data(&my_matrix, &my_cloaked_gamma_adj, &my_cloaked_fee);

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

        debug!("In share_cloaked_data()");
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
        let my_cloaked_gamma_adj = self
            .cloaked_gamma_adjs
            .get(&self.my_participant_id)
            .expect("Can't access my own gamma_adj");
        let my_cloaked_fee = self
            .cloaked_fees
            .get(&self.my_participant_id)
            .expect("Can't access my own fee");

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

    fn make_supertransaction(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in proper code
        //
        debug!("In make_supertransaction()");
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
            debug!("dropouts occurred - restarting");
            return self.start();
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
            &self.my_participant_id,
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
        self.signatures.insert(self.my_participant_id, sig.clone());

        self.send_signature(&sig);

        // fill in signatures
        self.receive_signatures()
    }

    fn sign_supertransaction(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit
        //   - .expect() errors -> should never happen in correct code

        debug!("In sign_supertransaction()");
        if !self
            .commit_phase_participants
            .iter()
            .all(|p| self.signatures.contains_key(p))
        {
            // we don't have the requisite signatures,
            // so just start a new session. Could only have happened if
            // fewer participants responded.
            debug!("incorrect number of signaturs obtained - restarting without them");
            return self.start();
        }

        self.trans.sig = self
            .commit_phase_participants
            .iter()
            .filter(|&&p| p != self.my_participant_id)
            .fold(self.trans.sig, |sig, p| {
                sig + self.signatures.get(p).expect("can't get peer signature")
            });
        debug!("total sig {:?}", self.trans.sig);

        if self.validate_transaction() {
            let leader = self.leader_id();
            debug!("Leader = {}", leader);
            let tx = self.trans.clone();
            self.reset_state(); // indicate nothing more to follow, restartable
            self.msg_queue.clear();
            self.session_round = 0; // for possible restarts

            assert_eq!(self.my_txouts.len(), self.my_utxos.len());
            let utxos: Vec<_> = self
                .my_utxos
                .iter()
                .map(|o| {
                    for (id, output) in self.trans.txouts.iter().enumerate() {
                        if let Ok(c) = output.pedersen_commitment() {
                            if c == *o {
                                return id;
                            }
                        }
                    }
                    panic!("Can't find utxo by Pedersen commitment.");
                })
                .collect();

            let outputs = utxos
                .into_iter()
                .zip(&self.my_txouts)
                .map(|(id, output)| {
                    ExtendedOutputValue {
                        id: id as u64,
                        recipient: output.recip.clone(),
                        amount: output.amount,
                        //TODO: add certificate to snowball.
                        rvalue: None,
                        data: Some(PaymentPayloadData::Comment(output.data.clone())),
                        is_change: output.is_change,
                    }
                })
                .collect();

            debug!("Success in Snowball!");
            return Ok(Async::Ready(SnowballOutput {
                tx,
                outputs,
                is_leader: self.my_participant_id == leader,
            }));
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
            .insert(self.my_participant_id, self.sess_skey.clone());

        self.send_session_skey(&self.sess_skey);

        // fill in sess_skeys
        self.receive_session_skeys()
    }

    fn blame_discovery(&mut self) -> HandlerResult {
        // Possible exits:
        //   - normal exit

        debug!("In blame_discovery()");
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
                &self.my_participant_id,
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
        self.start()
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

    fn send_signed_message(&self, payload: &SnowballPayload) {
        for pkey in &self.participants {
            if *pkey != self.my_participant_id {
                let msg = SnowballMessage {
                    sid: self.session_id,
                    payload: payload.clone(),
                    source: self.my_participant_id,
                    destination: *pkey,
                };
                let bmsg = msg.into_buffer().expect("serialized");
                debug!("sending msg {:?} to {}", &msg, pkey);
                self.network
                    .send(pkey.pkey.clone(), SNOWBALL_TOPIC, bmsg)
                    .expect("connected");
            }
        }
    }

    fn send_session_pkey(&self, sess_pkey: &PublicKey, sess_KSig: &Pt) {
        // send our session_pkey and sigK to all participants
        let payload = self.make_shared_keying(sess_pkey, sess_KSig);
        self.send_signed_message(&payload);
    }

    fn receive_session_pkeys(&mut self) -> HandlerResult {
        // collect session pkeys from all participants.
        // If any participant does not answer, add him to the exclusion list, p_excl

        // fills in the global state sess_pkeys and sigK_vals

        // we allow the receive_xxx to specify individual timeout periods
        // in case they need to vary
        self.prep_rx(MessageState::SharedKeying)
    }

    // -------------------------------------------------

    fn send_commitment(&self, commit: &Hash) {
        // send our commitment to cloaked data to all other participants
        let payload = SnowballPayload::Commitment { cmt: *commit };
        self.send_signed_message(&payload);
    }

    fn receive_commitments(&mut self) -> HandlerResult {
        // receive commitments from all other participants
        // if any fail to send commitments, add them to exclusion list p_excl

        // fill in commits
        self.prep_rx(MessageState::Commitment)
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
        let payload = SnowballPayload::CloakedVals {
            matrix: matrix.clone(),
            gamma_sum: cloaked_gamma_adj.clone(),
            fee_sum: cloaked_fee.clone(),
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
        self.prep_rx(MessageState::CloakedVals)
    }

    // -------------------------------------------------

    fn send_signature(&self, sig: &SchnorrSig) {
        // send signature to leader node
        let payload = SnowballPayload::Signature { sig: sig.clone() };
        self.send_signed_message(&payload);
    }

    fn receive_signatures(&mut self) -> HandlerResult {
        // collect signatures from all participants
        // should not count as collected unless signature is partially valid.
        //
        // Partial valid = K component is valid ECC point

        // fill in signatures
        self.prep_rx(MessageState::Signature)
    }

    // -------------------------------------------------

    fn send_session_skey(&self, skey: &SecretKey) {
        // send the session secret key to all participants
        let payload = SnowballPayload::SecretKeying { skey: skey.clone() };
        self.send_signed_message(&payload);
    }

    fn receive_session_skeys(&mut self) -> HandlerResult {
        // non-respondents are added to p_excl

        // fills in sess_skeys
        self.prep_rx(MessageState::SecretKeying)
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

fn sign_utxos(utxos: &Vec<UTXO>, skey: &SecretKey) -> SchnorrSig {
    // sign an (ordered) list of UTXOs to form an ownership signature
    let mut signing_f = Fr::zero();
    let mut state = Hasher::new();
    for utxo in utxos {
        utxo.hash(&mut state);
        let payload = utxo.decrypt_payload(skey).expect("invalid keys");
        let (gamma, delta) = (payload.gamma, payload.delta);
        // decryption can always be performed. But if we don't
        // actually own the UTXO then we get garbage back.
        // This signature would then fail later on validate_ownership().
        assert_ne!(gamma, Fr::zero());
        assert_ne!(delta, Fr::zero());
        signing_f += Fr::from(skey.clone()) + gamma * delta;
    }
    sign_hash(&state.result(), &SecretKey::from(signing_f))
}

fn validate_ownership(txins: &Vec<(TXIN, UTXO)>, owner_sig: &SchnorrSig) -> Result<(), Error> {
    let mut p_cmp = Pt::inf();
    let hash = {
        let mut state = Hasher::new();
        for (txin, utxo) in txins {
            let hash = Hash::digest(utxo);
            assert_eq!(hash, *txin);
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
            Err(err)
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

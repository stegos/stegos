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

//! Randhound++ - Distributed Randomness Generation
//! -------------------------------------------------------------------------
//! Distributed BFT randommness generation. A collection of witness nodes
//! is divided up into groups. Within each group, each member computes a separate
//! random value, and shares with other group members through a share from their
//! own unique random sharing polynomial. (Shamir Secret Sharing).
//!
//! They each commit to the randomness by offering ZKP's on the share values,
//! and the shares in the commitment are encrypted so that nodes can only see
//! what their own shares are.
//!
//! After receiving a BFT threshold number of commitments from other group
//! members, each member sends his own decrypted shares, one for each polynomial,
//! to all other group members. At this point, no further commitments will be
//! accepted by the group member. Waiting like this precludes any advantage to
//! lurkers who might try to game the system by waiting until they see what
//! others offer before making their own contribution.
//!
//! So, for group size N, there are N different sharing polynomials, each of
//! which offers N shares to group members. We keep track of decrypted shares
//! by which polynomial it refers to, and from which group member the share
//! arrived.
//!
//! And after receiving a sufficient number (BFT Threshold) of decrypted shares
//! for any one polynomial, each group member decodes the hidden shared randomness
//! by using Lagrange interpolation to find what the polynomial shows for share #0.
//! That is the true randomness hidden by the shared secrets. At this point no
//! further decrypted shares will be accepted for the polynomial.
//!
//! After obtaining a BFT threshold number of decoded polynomial randomness,
//! they each send their batch to the group leader, along with the identity
//! of the polynomial from which the randomness was derived. At this point
//! the group members are finished.
//!
//! Group leaders collect randomness per polynomial, and after a BFT threshold
//! number of nodes respond for any one polynomial, those random values are
//! added together to make just one random value per polynomial. At this point
//! no further randomness will be accepted for the polynomial.
//!
//! After the group leader collects a BFT threshold number of polynomial sums
//! it sends the sum of all the individual polynomial sums to the Beacon node
//! at the head of the tree. At this point the group leaders are finished.
//!
//! At the Beacon node, it awaits arrival of a BFT threshold number of random
//! values from each of the group leaders. When the threshold is crossed, the
//! Beacon node adds up all the contributions to a final grand sum. That grand
//! sum is then converted to a Tate-pairing field value, then hashed to become
//! the new lottery ticket of randomness. At that point the entire protocol
//! is finished. The Beacon broadcasts the new lottery number to all witness
//! nodes in the system, even if they didn't participate in the Randhound run.
//!
//! Witness nodes will note that new random value, and use it to determine
//! which node becomes the Leader, which node becomes the new Beacon node in
//! charge of Randhound, and what their individual roles will be, in the next
//! epoch.
//!
//! The premise of distributed randomness generation, is that even if only a
//! single node manages to produce unmolested, honest, randomness, his result
//! will make all sums which include it, also random. Randomness is contageous.
//!
//! -------------------------------------------------------------------------
//! While the blockchain relies on secure curve FR256 PBC crypto, and participant nodes
//! are identified by secure::PublicKey's, we utilize the shorter, faster,
//! symmetric pairings offered by curve AR160 in pbc::fast, for the distributed
//! randomness generation. The shared secrets only need to be protected for a
//! few seconds, from the start of a session, until the randomness has been generated.
//!
//! To clarify... wallets, transactions, and UTXO's rely on single-curve Curve1174
//! ECC crypto. But witnesses know each other by secure PBC keying, and the blockchain
//! relies on secure PBC crypto for efficient BLS multi-signatures.
//!
//! Here, we are witness nodes communicating with other witness nodes. So all crypto
//! occurs in the secure and fast PBC crypto domain.
//!
//! All messages between witness nodes carry BLS signatures that must be validated for
//! protection against trolls. Only valid signed messages from others in the known witness
//! pool, or subgroups of those witnesses, are considered valid messages. And these signatures
//! are created in the secure PBC domain. Only the internal math utilizes fast PBC crypto.
//! -------------------------------------------------------------------------

#![allow(non_snake_case)]
#![allow(dead_code)]

use super::randhound_proto::{self, RandhoundMessage, RandhoundMessageTypes};
use super::{RandHoundEvent, Randomness};

use failure::{Error, Fail};
use futures::sync::mpsc::{self, UnboundedSender};
use futures::{Async, Poll, Stream};
use log::*;
use protobuf::Message as ProtoMessage;
use std::collections::hash_map::HashMap;
use std::collections::hash_set::HashSet;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};
use std::vec::Vec;
use stegos_crypto::hash::*;
use stegos_crypto::pbc::*;
use stegos_keychain::KeyChain;
use stegos_network::Broker;
use tokio_timer::DelayQueue;

type Zr = fast::Zr;
type G1 = fast::G1;
type G2 = fast::G2;
type GT = fast::GT;

const NETWORK_DELAY: f32 = 0.5; // typical round-trip network delay (seconds)

/// PEM tag for public key.
const PBC_PKEY_TAG: &'static str = "STEGOS-PBC PUBLIC KEY";

// -------------------------------------------------------------------------
// Math support routines

fn max_byz_fails(ngrp: usize) -> usize {
    assert!(ngrp > 0, "Number in group must be > 0");
    (ngrp - 1) >> 1
}

fn poly_eval(coffs: &[Zr], x: Zr) -> Zr {
    // evaluate a polynomial in the field Zr
    coffs
        .iter()
        .rev()
        .fold(Zr::zero(), |sum, pcoff| sum * x + *pcoff)
}

fn inv_wt(n: usize, xj: usize) -> Zr {
    // used in computing Reed-Solomon check vectors
    // = InvWt_j = Prod_(i = 1..n)[x_j - x_i]
    (1..=n)
        .rev()
        .filter(|ixp| *ixp != xj)
        .fold(Zr::one(), |prod, ix| prod * ((xj as i64) - (ix as i64)))
}

fn lagrange_wt(ns: &[usize], xj: usize) -> Zr {
    let (num, den) = ns
        .iter()
        .filter(|np| **np != xj)
        .fold((Zr::one(), Zr::one()), |(num, den), ixp| {
            (num * (*ixp as i64), den * ((*ixp as i64) - (xj as i64)))
        });
    num / den
}

fn dot_prod_g1_zr(pts: &[G1], zrs: &[Zr]) -> G1 {
    pts.iter()
        .zip(zrs.iter())
        .fold(G1::new(), |sum, (ppt, pzr)| sum + *ppt * *pzr)
}

// -------------------------------------------------------------------
// Now we need to implement a stateful system....

pub(crate) struct GlobalState {
    pkey: secure::PublicKey, // node secure PBC keying - lasts eternally
    skey: secure::SecretKey, // ... ditto ...
    witnesses: HashSet<secure::PublicKey>, // a malleable list of witnesses
    session_info: Session,   // Randhound session
    epoch_info: EpochInfo,   // epoch information
    next_epoch: EpochInfo,   // epoch to be used on next round
    broker: Broker,          // handler to send messages
    msg_queue: VecDeque<Message>, // Messages received in Idle stage
    service: mpsc::UnboundedSender<RandHoundEvent>, // Events to event loop
    // List of Randomness receivers
    consumers: Vec<UnboundedSender<Option<Randomness>>>,
    // Delay Qurue for initial FastKey collection stage
    deadline: DelayQueue<Hash>,
}

// Epoch info - one epoch might have multiple Randhound sessions(?)
#[derive(Clone, Debug)]
pub(crate) struct EpochInfo {
    pub epoch: Hash,               // epoch ID
    pub leader: secure::PublicKey, // Leader node for current epoch
    pub beacon: secure::PublicKey, // Beacon leader for current epoch
}

impl Default for EpochInfo {
    fn default() -> Self {
        EpochInfo {
            epoch: Hash::from_str(&"None"),
            leader: secure::PublicKey::from(secure::G2::new()),
            beacon: secure::PublicKey::from(secure::G2::new()),
        }
    }
}

#[derive(Clone)]
struct GrpInfo {
    fkey: Option<fast::PublicKey>,                // members fast public key
    commit: bool, // true if commitment has been recv'd for group member
    decrs: HashMap<secure::PublicKey, DecrShare>, // decryted shares for his polynomial
}

// ------------------------------------------------------
// Note: In the following, with read/write locking in place
// there are many places that store altered state back into the
// locked cell. That may or may not actually be necessary. But if
// we take the clone() calls at face value, then it represents a
// copying (how deep?) of potentially lots of data. Very wasteful
// IMHO, but so be it. Hence, if duplicated, then it must be stored
// back into the cell. And hence, all the comments "is this really needed?"

// Randhound session info
#[derive(Clone)]
struct Session {
    pub session: Hash,                               // unique session ID
    pub leader: secure::PublicKey,                   // group leader for our group
    pub fpkey: fast::PublicKey,                      // fast ephemeral PBC keying for math
    pub fskey: fast::SecretKey,                      //  ... ditto ...
    pub ngrps: usize,                                // how many groups
    pub stage: SessionStage,                         // which stage we are processing
    pub grpleaders: Vec<secure::PublicKey>,          // held only by Beacon
    pub grp: Vec<secure::PublicKey>,                 // members of my group
    pub grptbl: HashMap<secure::PublicKey, GrpInfo>, // list of secure pkey / fast pkey associations
    pub rschkv: Vec<Zr>,                             // Reed-Solomon proof check vector
    pub rands: Vec<(secure::PublicKey, G2)>, // used by witnesses to accumulate decoded randomness
    pub grands: HashMap<secure::PublicKey, HashMap<secure::PublicKey, G2>>, // used by group leaders to accumulate subgroup randomness
    pub lrands: Vec<G2>, // used by group leaders to accumulate randomness
    pub brands: HashMap<secure::PublicKey, G2>, // used by Beacon to accumulate randomness
    pub msgq: VecDeque<(secure::PublicKey, MsgType)>, // pending recycled messages
}

#[derive(Clone, PartialEq, Debug)]
enum SessionStage {
    Idle,   // No session yet started
    Init,   // key collection phase
    Stage2, // encrypted random share collecting
    Stage3, // decrypted random share collecting
    Stage4, // group leaders collect decoded randomness
    Stage5, // Beacon collects group randomness
}

impl Default for Session {
    fn default() -> Self {
        let (fskey, fpkey, _fsig) = fast::make_deterministic_keys(b"idle");
        // Populate with some dummy values
        Session {
            session: Hash::digest(&"idle".to_string()),
            stage: SessionStage::Idle,
            leader: secure::PublicKey::from(secure::G2::new()),
            fpkey,
            fskey,
            ngrps: 0,
            grpleaders: vec![],
            grp: vec![],
            grptbl: HashMap::new(),
            rschkv: vec![],
            rands: vec![],
            grands: HashMap::new(),
            lrands: vec![],
            brands: HashMap::new(),
            msgq: VecDeque::new(),
        }
    }
}

// lazy_static! {
//     static ref GSTATE: GlobalState = make_initial_global_state();
// }
// lazy_static! {
//     static ref GSTATE: state::Storage<GlobalState> = state::Storage::new();
// }

// ------------------------------------------------------------
// Pertaining to global state

pub(crate) fn init_state(
    keychain: &KeyChain,
    broker: Broker,
    service: UnboundedSender<RandHoundEvent>,
) -> GlobalState {
    debug!("Node's pkey is: {:#?}", keychain.cosi_pkey);
    GlobalState {
        pkey: keychain.cosi_pkey.clone(),
        skey: keychain.cosi_skey.clone(),
        witnesses: HashSet::new(),
        session_info: Session::default(),
        epoch_info: EpochInfo::default(),
        next_epoch: EpochInfo::default(),
        broker,
        msg_queue: VecDeque::new(),
        service,
        consumers: vec![],
        deadline: DelayQueue::new(),
    }
}

impl GlobalState {
    pub fn poll_deadline(&mut self) -> Poll<Option<Hash>, Error> {
        match self.deadline.poll() {
            Ok(Async::Ready(Some(expired))) => return Ok(Async::Ready(Some(expired.into_inner()))),
            Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn subscribe(&mut self, consumer: UnboundedSender<Option<Randomness>>) {
        self.consumers.push(consumer);
    }

    pub(crate) fn add_witness(&mut self, pkey: &secure::PublicKey) {
        self.witnesses.insert(*pkey);
    }

    fn drop_witness(&mut self, pkey: &secure::PublicKey) {
        self.witnesses.remove(&pkey);
    }

    fn is_valid_witness(&self, pkey: &secure::PublicKey) -> bool {
        self.witnesses.contains(&pkey)
    }

    fn get_witnesses(&self) -> HashSet<secure::PublicKey> {
        // TODO: make sure we have some real witnesses
        // Must include Leader node, Beacon node, and at least a
        // handful of others...
        self.witnesses.clone()
    }

    pub(crate) fn witnesses_size(&self) -> usize {
        self.witnesses.len()
    }

    // -------------------------------------------------------------------
    // Pertaining to Epoch

    pub(crate) fn get_current_leader(&self) -> secure::PublicKey {
        self.epoch_info.leader
    }

    pub(crate) fn get_current_beacon(&self) -> secure::PublicKey {
        self.epoch_info.beacon
    }

    fn get_current_epoch(&self) -> Hash {
        self.epoch_info.epoch
    }

    pub(crate) fn set_epoch(&mut self, e: EpochInfo) {
        self.epoch_info = e;
    }

    pub(crate) fn set_next_epoch(&mut self, e: EpochInfo) {
        self.next_epoch = e;
    }

    fn get_my_fast_pkey(&self) -> fast::PublicKey {
        self.session_info.fpkey.clone()
    }

    fn get_my_fast_skey(&self) -> fast::SecretKey {
        self.session_info.fskey.clone()
    }

    fn add_fast_key(&mut self, pkey: &secure::PublicKey, fpkey: &fast::PublicKey) {
        // If an entry for pkey in the grptbl is missing, then add one
        // in as initialized with the indicated fast pkey.
        self.session_info.grptbl.entry(*pkey).or_insert(GrpInfo {
            fkey: Some(*fpkey),
            commit: false,
            decrs: HashMap::new(),
        });
    }

    fn get_ngroups(&self) -> usize {
        self.session_info.ngrps
    }

    fn group_size(&self) -> usize {
        self.session_info.grp.len()
    }

    fn actual_group_size(&self) -> usize {
        self.session_info.grptbl.len()
    }

    fn position_in_group(&self, pkey: &secure::PublicKey) -> usize {
        let mut pos = 0;
        for key in self.session_info.grp.iter() {
            if *pkey == *key {
                return pos;
            }
            pos += 1;
        }
        // oops! we aren't in our own group??
        panic!("Shouldn't happen");
    }

    fn get_stage(&self) -> SessionStage {
        self.session_info.stage.clone()
    }

    fn set_stage(&mut self, stage: SessionStage) {
        info!("Progessed to stage: {:#?}", stage);
        self.session_info.stage = stage;
    }

    fn is_group_leader(&self, pkey: &secure::PublicKey) -> bool {
        for key in self.session_info.grpleaders.iter() {
            if *key == *pkey {
                return true;
            }
        }
        false
    }

    // --------------------------------------------------------------------------------
    // Global Node info

    pub(crate) fn get_pkey(&self) -> secure::PublicKey {
        self.pkey
    }

    fn get_skey(&self) -> secure::SecretKey {
        self.skey
    }

    pub(crate) fn get_current_session(&self) -> Hash {
        self.session_info.session
    }

    fn get_group_keys(&self) -> Vec<secure::PublicKey> {
        self.session_info.grp.clone()
    }

    fn is_group_member(&self, pkey: &secure::PublicKey) -> bool {
        for key in self.session_info.grp.iter() {
            if *key == *pkey {
                return true;
            }
        }
        false
    }

    fn get_group_leader(&self) -> secure::PublicKey {
        self.session_info.leader.clone()
    }

    fn make_signed_message(&self, body: &MsgType) -> Message {
        // Add a signature to the message, and identify it
        // as coming from us, for (our notion of) the current session.
        let sess = self.get_current_session();
        let h = Hash::digest_chain(&[&sess, body]);
        let sig = secure::sign_hash(&h, &self.get_skey());
        Message {
            sess: sess,
            typ: body.clone(),
            sig: sig,
            from: self.get_pkey(), // our secure::PublicKey for "who sent it?"
        }
    }
    fn validate_signed_message(&mut self, msg: &Message) -> Result<(), MsgErr> {
        // Generic message validation...
        match msg.typ {
            MsgType::Start { epoch, .. } => {
                self.epoch_info = self.next_epoch.clone();
                // New Start message valid only if arrives from Beacon
                // and for current Epoch.
                if msg.from != self.get_current_beacon() {
                    return Err(MsgErr::NotFromBeacon);
                }
                if epoch != self.get_current_epoch() {
                    return Err(MsgErr::NotCurrentEpoch);
                }
                if self.get_pkey() != msg.from {
                    // if I'm not the beacon node
                    if self.get_stage() != SessionStage::Idle {
                        // If we were left in a session, or got a second notice
                        // to Start, then clear state and try again.
                        self.clear_session_state();
                    }
                }
            }
            _ => {
                // other messages only valid if we are in a session,
                // and must be for the current session,
                if self.get_stage() == SessionStage::Idle {
                    self.msg_queue.push_back(msg.clone());
                    return Ok(());
                    // return Err(MsgErr::NotInSession);
                }
                let sess = self.get_current_session();
                if sess != msg.sess {
                    return Err(MsgErr::SessionMismatch(sess, msg.sess));
                }
                if let MsgType::GroupRandomness { .. } = msg.typ {
                    // ... and this must have arrived from a group leader
                    if !self.is_group_leader(&msg.from) {
                        return Err(MsgErr::NotFromGroupLeader);
                    }
                } else {
                    // ... and this must have arrived from node in our group
                    if !self.is_group_member(&msg.from) {
                        return Err(MsgErr::NotFromGroupMember);
                    }
                }
            }
        }
        // validate the signature on the messsage - discards most trolls
        let h = Hash::digest_chain(&[&msg.sess, &msg.typ]);
        if secure::check_hash(&h, &msg.sig, &msg.from) {
            return Ok(());
        } else {
            return Err(MsgErr::InvalidSignature);
        }
    }

    // -------------------------------------------------------------------
    // Pertaining to Randhound Session

    fn start_session(&mut self, id: &Hash, grp: &Vec<secure::PublicKey>) {
        // leader is group leader
        // Beacon/leader has already initialized session,
        // So initialize only when Stage is Idle (participants)
        if self.get_stage() == SessionStage::Idle {
            debug!("Starting new session!");
            // Beacon inits its own session_info, we might be Beacon
            let leader = grp[0];
            assert!(self.is_valid_witness(&leader), "Invalid leader");
            // generate ephemeral fast keying for new session
            let seed = Hash::digest_chain(&[id, &self.get_skey()]);
            let (fskey, fpkey, fsig) = fast::make_deterministic_keys(&seed.bits());
            assert!(fast::check_keying(&fpkey, &fsig));
            self.session_info = Session {
                session: id.clone(),
                stage: SessionStage::Init,
                leader: leader.clone(), // group leader
                fpkey: fpkey,
                fskey: fskey,
                ngrps: 0,
                grpleaders: Vec::new(),
                grp: grp.to_vec(),
                grptbl: HashMap::new(),
                rschkv: Vec::new(),
                rands: Vec::new(),
                grands: HashMap::new(),
                lrands: Vec::new(),
                brands: HashMap::new(),
                msgq: VecDeque::new(),
            };
            debug!("New session structure ready");
            let me = self.get_pkey();
            self.add_fast_key(&me, &fpkey);
            debug!("Start session done!");
        }
        info!("Randound session started ({})!", self.session_info.session);
    }

    // ------------------------------------------------------------------------
    // The entire protocol is based on asynchronous message handling.
    // During any particular phase at one node, messages corresponding to
    // more advanced phases from other nodes could be arriving.
    //
    // As a result, sometimes we reach a state during earlier phases where
    // we can actuall skip ahead to much more advanced phases, instead of
    // the next logical phase in sequence.
    //
    // If we are in a phase (most notably during Init key collection) that
    // isn't ready to handle more advanced messages, those incoming messages
    // get pushed into a FIFO queue for later processing.
    // ------------------------------------------------------------------------

    pub fn dispatch_incoming_message(&mut self, msg: &Message) -> Result<(), MsgErr> {
        // This is the function that should be called by the message receiver loop
        // If the message is valid, an Ok(()) will be returned. Otherwise, one of
        // the MsgErr values will be sent back.
        self.validate_signed_message(&msg)?;
        match msg.typ {
            MsgType::Start {
                epoch: _,
                sess,
                ref grps,
            } => {
                self.handle_start_message(&sess, &grps);
                // dispatch messages received during Idle stage
                let mut q = self.msg_queue.clone();
                for m in q.drain(..) {
                    self.dispatch_incoming_message(&m)?;
                }
                self.msg_queue = VecDeque::new();
            }
            _ => {
                // Perform the new incoming message first, then look at what
                // is in the FIFO queue.
                //
                // The already stashed messages resulted from our state evolution
                // up to this point, and there is little reason to expect any change
                // unless provoked by the new incoming message. Maybe the new message
                // will nudge the state and let it evolve forward.
                //
                self.dispatch_message(&msg.from, &msg.typ);
                self.dispatch_fifo_messages();
            }
        }
        Ok(())
    }

    fn dispatch_fifo_messages(&mut self) {
        // FIFO Messages have already been validated. So just run through
        // the queue till empty. This run through may enqueue additional
        // messages, so work on a copy of the current FIFO queue, and repeat
        // until no changes are detected in number of enqueued messages.
        // TODO: Exit from the loop if stage wasn't changed
        debug!("Dispatching queued messages");
        loop {
            let msgs;
            {
                // we are already in a running session (not always)
                let mut sess = self.session_info.clone();
                if sess.msgq.len() > 0 {
                    msgs = sess.msgq;
                    sess.msgq = VecDeque::new();
                    self.session_info = sess; // is this actually needed?
                } else {
                    debug!("Nothing to process, breaking out!");
                    break;
                }
            }

            let nel = msgs.len();
            for (from, msg) in msgs {
                self.dispatch_message(&from, &msg);
            }
            if nel == self.session_info.msgq.len() {
                // no change so get out...
                break;
            }
        }
        debug!("Finished processing FIFO messages!");
    }

    fn dispatch_message(&mut self, from: &secure::PublicKey, msg: &MsgType) {
        match msg {
            // Start message is handled directly, not here
            MsgType::FastKey { key } => self.collect_fast_key(&from, &key),
            MsgType::SubgroupCommit { ref commit } => self.stash_commitment(&from, &commit),
            MsgType::DecrShares { ref shares } => self.stash_decrypted_shares(&from, &shares),
            MsgType::SubgroupRandomness { ref rands } => {
                self.stash_subsubgroup_randomness(&from, &rands)
            }
            MsgType::GroupRandomness { ref rand } => self.stash_group_randomness(&from, &rand),
            MsgType::FinalLotteryTicket { ref ticket } => {
                info!("Final lottery ticket receiced: {}", ticket);
                // There should me more to do here...
                // (hold election, assign new roles, etc.)
                self.consumers.retain(move |tx| {
                    tx.unbounded_send(Some(Randomness {
                        value: ticket.clone(),
                    }))
                    .is_ok()
                });
                self.clear_session_state() // but certainly this much...
            }
            _ => (),
        }
    }

    fn stash_fifo(&mut self, from: &secure::PublicKey, msg: &MsgType) {
        // Stash a message onto the FIFO queue for later processing
        self.session_info.msgq.push_back((*from, msg.clone()));
    }

    // --------------------------------------------------------------------------------
    // Communication among nodes

    fn broadcast(&self, msg: &MsgType) -> Result<(), Error> {
        // TODO: Send to message to ALL witnesses,
        // even those not participating in Randhound
        debug!("Sending broadcast message");
        let smsg = self.make_signed_message(msg);
        debug!("Sent Message: {:#?}", smsg);
        // send the signed message
        let buf = msg_to_proto(&smsg).write_to_bytes()?;
        self.broker.publish(&crate::TOPIC, buf)?;
        Ok(())
    }

    fn send_message(&self, key: &secure::PublicKey, msg: &MsgType) -> Result<(), Error> {
        // TODO: Send the message to the node identified with key
        let smsg = self.make_signed_message(msg);
        debug!("Sending unicast message to: {:#?}", key);
        debug!("Sent Message: {:#?}", smsg);
        // send the signed message
        let buf = msg_to_proto(&smsg).write_to_bytes()?;
        self.broker
            .publish(&crate::node_id_from_hashable(key), buf)?;
        Ok(())
    }

    fn broadcast_grp(&self, msg: &MsgType) -> Result<(), Error> {
        debug!("Sending broadcast message to group");
        self.broadcast(msg)
        // This function shoudl send the message to all other nodes
        // in our group, but not to ourself.

        // Not working with current unicast implementation

        // let grp = self.get_group_keys();
        // let me = self.get_pkey();
        // for key in grp {
        //     if key != me {
        //         self.send_message(&key, msg)?;
        //     }
        // }
        // Ok(())
    }

    // ------------------------------------------------------------------
    // STAGE 1 - Startup
    // ------------------------------------------------------------------
    // Start up a Randhound round - called from election central when node is *BEACON*

    pub fn start_randhound_round(&mut self) {
        // Function should only be called from Beacon node after new election
        //
        // This function takes the list of witnesses and divides them into groups.
        // For N witnesses, form Sqrt(N) groups of Sqrt(N) nodes.
        //
        // First node in each group becomes group leader. Group leaders report back
        // to Beacon node as the overall leader.
        //
        // All witness nodes are potential participants, including BEACON
        // and LEADER just elected. But we limit the number of participats
        // to 1600 nodes or fewer.
        //
        // If fewer than 36 witnesses, then only one group is formed, with Beacon
        // as the group leader.
        //
        // Send the Start message with fresh session ID, and the list of groups,
        // to all participating witnesses, including Beacon node (ourself).
        // Nodes search the group lists for their public keys, to find their assigned
        // groups.
        //
        fn re_order_witnesses(
            state: &GlobalState,
            wits: &HashSet<secure::PublicKey>,
        ) -> Vec<secure::PublicKey> {
            // re-order the list of witnesses, planting Beacon node at the head of the list
            let beacon = state.get_current_beacon();
            let mut new_wits = vec![beacon];
            for wit in wits {
                if *wit != beacon {
                    new_wits.push(wit.clone());
                }
            }
            new_wits
        }

        self.epoch_info = self.next_epoch.clone();

        debug!(
            "Checking for beacon, me: {:#?}, beacon: {:#?}",
            self.get_pkey(),
            self.get_current_beacon()
        );
        let me = self.get_pkey();
        if self.get_current_beacon() == me {
            debug!("We are beacon!");
            let mut all_witnesses = re_order_witnesses(&self, &self.get_witnesses()); // return a Vec<secure::PublicKey>

            // Beacon node is front of list,
            // and will also become a group leader
            //
            // decide on group sizes
            let nwits = all_witnesses.len();
            let mut grps = Vec::new();
            let ngrps;
            let grpsiz;
            let mut nrem = 0;
            let mut nincr = 0;
            if nwits > 1600 {
                ngrps = 40;
                grpsiz = 40;
            } else if nwits < 36 {
                ngrps = 1;
                grpsiz = nwits;
            } else {
                // Sqrt(N) groups with Sqrt(N) group size
                //
                // Rust does not have isqrt() !! Are you kidding?
                grpsiz = f32::sqrt(nwits as f32) as usize;
                ngrps = grpsiz;
                nrem = nwits - grpsiz * ngrps;
                nincr = nrem / ngrps;
            }
            // Now partition the witnesses into groups
            for _ in 0..ngrps {
                let nel = if nrem > 0 {
                    if nrem >= nincr {
                        nrem -= nincr;
                    } else {
                        // we actually shouldn't ever get here...
                        nincr = nrem;
                        nrem = 0;
                    }
                    grpsiz + nincr
                } else {
                    grpsiz
                };
                let tl = all_witnesses.split_off(nel);
                grps.push(all_witnesses);
                all_witnesses = tl;
            }
            // Collect the group leaders.
            // This will be retained only by Beacon node
            let mut grp_leaders = Vec::new();
            for ix in 0..ngrps {
                grp_leaders.push(grps[ix][0].clone());
            }
            //
            // Set up the Beacon node's info. This info is special because
            // it is the only one to store all the groups, and group leaders.
            // All other nodes just dummy up those slots.
            //
            let my_group = grps.first().unwrap();
            let my_leader = my_group.first().unwrap();
            let mut hasher = Hasher::new();
            let _secs_from_bigbang = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .hash(&mut hasher);
            self.get_current_epoch().hash(&mut hasher);
            self.get_skey().hash(&mut hasher);

            let session_id = hasher.result();

            let (fskey, fpkey, fsig) = fast::make_deterministic_keys(&session_id.bits());
            assert!(fast::check_keying(&fpkey, &fsig));
            self.session_info = Session {
                session: session_id,
                stage: SessionStage::Init,
                leader: *my_leader,
                fpkey: fpkey,
                fskey: fskey,
                ngrps: ngrps,
                grpleaders: grp_leaders,
                grp: my_group.clone(),
                grptbl: HashMap::new(),
                rschkv: Vec::new(),
                rands: Vec::new(),
                grands: HashMap::new(),
                lrands: Vec::new(),
                brands: HashMap::new(),
                msgq: VecDeque::new(),
            };
            self.add_fast_key(&me, &fpkey);
            let msg = MsgType::Start {
                epoch: self.get_current_epoch(),
                sess: session_id.clone(),
                grps: grps.clone(),
            };
            // send START to every witness, including me!
            if let Err(e) = self.broadcast(&msg) {
                error!("Failed to broadcast message: {}", e);
            }
            // NOTE: if broadcast also sends to myself,
            // then comment out the following line...
            // (but no harm if left alone)
            self.handle_start_message(&session_id, &grps);
        } else {
            debug!("I'm not a beacon");
        }
    }

    fn clear_session_state(&mut self) {
        // Called at the very end as a result of seeing a FinalLoterryTicket message.
        // All witnesses receive this message. But only those participating will reach
        // this function.
        self.session_info = Session::default();
        self.msg_queue = VecDeque::new();
    }

    fn handle_start_message(&mut self, sess: &Hash, grps: &Vec<Vec<secure::PublicKey>>) {
        // This function is performed by each witness node on receipt of a valid Start
        // message from the Beacon node. Record new session ID, find own group among the
        // groups list provided by the Beacon node, and then broadcast your new ephemeral
        // fast public key to other group members.
        //
        fn find_my_group(
            me: &secure::PublicKey,
            grps: &Vec<Vec<secure::PublicKey>>,
        ) -> Option<Vec<secure::PublicKey>> {
            for grp in grps {
                for pkey in grp {
                    if me == pkey {
                        return Some(grp.to_vec());
                    }
                }
            }
            None
        }

        let me = self.get_pkey();
        match find_my_group(&me, grps) {
            None => {
                debug!("We are no in any group, ignoring message");
                // Not assigned to any group. Just sit this session out.
            }
            Some(grp) => {
                // We are participating. Set up our global state,
                // and assign new ephemeral fast keying.
                //
                // Tell everybody in our group what our new fast public key is,
                // so they can encode some random shares for us...
                //
                debug!("Calling start_session");
                self.start_session(sess, &grp);
                let fkey = self.get_my_fast_pkey();
                let msg = MsgType::FastKey { key: fkey };
                if let Err(e) = self.broadcast_grp(&msg) {
                    error!("Failed to send broadcast message to group: {}", e);
                }

                // this one is easy - very minimal compute overhead at each node
                // so just have to account for network delays
                // schedule_after(3.0 * NETWORK_DELAY, &self.maybe_transition_from_init_phase);
                self.deadline.insert(
                    self.get_current_session(),
                    Duration::from_secs(self.group_size() as u64 * 2),
                );
            }
        }
    }

    pub(crate) fn maybe_transition_from_init_phase(&mut self) {
        // Called after timeout. Check to see if we have achieved
        // at least the BFT threshold number of responses. If so,
        // start running the protocol. Otherwise, we have been fatally attacked.
        //
        if self.get_stage() == SessionStage::Init {
            let ngrp = self.group_size();
            let thresh = ngrp - max_byz_fails(ngrp);
            if self.actual_group_size() >= thresh {
                info!("BFT threshold for init phase reached! Moving on to Stage2");
                self.set_stage(SessionStage::Stage2);
                // Dispatch OOB messages
                self.dispatch_fifo_messages();
                self.generate_shared_randomness();
            } else {
                info!("BFT threshold of witnesses not reached in Init phase. Resetting state.");
                self.consumers
                    .retain(move |tx| tx.unbounded_send(None).is_ok());
                self.clear_session_state();
            }
        }
    }

    fn collect_fast_key(&mut self, from: &secure::PublicKey, key: &fast::PublicKey) {
        // This is called during Init phase to accumulate fast public keys
        // from all our group members.
        //
        // This function / phase is perhaps the most important one, since
        // slow-to-respond nodes may become left out, which could needlessly
        // increase the likelihood of BFT failure.
        //
        // So rather than simply transitioning to the next phase on reaching the
        // minimum acceptable threshold here, I would recommend delaying until, say,
        // three times the normal network round-trip duration, and then embark
        // on the threshold test only after accepting as many responses as you can.
        //
        match self.get_stage() {
            SessionStage::Init => {
                self.add_fast_key(from, key);
                if self.actual_group_size() == self.group_size() {
                    debug!("Received all possible keys, moving on to next stage!");
                    self.deadline.clear();
                    self.set_stage(SessionStage::Stage2);
                    // Dispatch OOB messages
                    self.dispatch_fifo_messages();
                    self.generate_shared_randomness();
                }
            }
            _ => {
                // latecomers... just ignore
            }
        }
    }
    // ----------------------------------------------------------------------------------
    // STAGE 2 -- Generate Shared Secret Randomness
    // ----------------------------------------------------------------------------------

    fn generate_shared_randomness(&mut self) {
        // Every node runs this startup code, after receiving a super-majority
        // of fast keying info from other group members.
        //
        // Construct Randhound state for ourselves, compute a shared secret
        // randomness along with ZKP proofs on the sharing polynomial
        // coefficients and proofs of the computed shares. Send all this
        // information to all other nodes in our group.
        //
        let me = self.get_pkey();
        let ngrp = self.group_size();
        let share_thresh = 1 + max_byz_fails(ngrp);

        // Compute the shares for distribution to group members
        let mut coffs = Vec::<Zr>::new();
        for _ in 0..share_thresh {
            coffs.push(Zr::random());
        }
        let krand = Zr::random();
        let kpt = krand * G1::generator();
        let mut shares = Vec::<Zr>::new();
        let mut proofs = Vec::<G1>::new();
        let mut enc_shares = Vec::<G2>::new();
        {
            for (ix, pkey) in (1..=ngrp).zip(self.session_info.grp.clone()) {
                //
                // If we have actual keying information for this recipient
                // then our encrypted share will validate against his fast
                // public key.
                //
                // But if we don't have that info, then we have no way of
                // getting his share across.
                //
                // If we use our own key in place of his, then the commitment
                // proof will fail against his real key, and he wouldn't be able
                // to decrypt the encrypted share either, but the proof vector
                // will pass the Reed-Solomon encoding test. What to do...
                //
                // We need some way of forming a valid Reed-Solomon proof vector,
                // while notifying others not to bother checking the proof for
                // proper formation against his key.
                //
                // So we dummy it up using our own fast public key to get past
                // Reed-Solomon, and send along a bit vector indicating which
                // shares to check for validity.
                //
                let share = poly_eval(&coffs, Zr::from(ix as i64));
                let proof = share * kpt;
                shares.push(share);
                proofs.push(proof);
                let mut eshare = G2::zero();
                if let Some(GrpInfo { fkey, .. }) = self.session_info.grptbl.get(&pkey) {
                    if let Some(actual_fpkey) = fkey {
                        eshare = share * G2::from(*actual_fpkey);
                    }
                }
                enc_shares.push(eshare);
            }
        } // end of read-lock (poor semantic syntax...)

        // Decrypted commits stored in table indexed by secure::PublicKey
        // each entry is a list of Dectypted commits for the polynomial
        // generated by the node indicated by the key index.
        let my_pos = self.position_in_group(&me); // this outside of write-lock boundary
                                                  // Precompute our own decrypted commitment
                                                  // From Lisp: this saves about 20% of processing time,
                                                  // since every node does this.
        let decr = DecrShare {
            index: my_pos + 1,
            share: shares[my_pos] * G2::generator(),
            proof: proofs[my_pos],
            kpt: kpt,
        };
        self.session_info.grptbl.entry(me).and_modify(|e| {
            e.commit = true;
            e.decrs.insert(me, decr);
        });

        // Compute and pre-cache the Reed-Solomon check vector
        // corresponding to the shares from our share polynomial
        let ncheck = ngrp - share_thresh;
        let mut coffs = Vec::<Zr>::new();
        for _ in 0..ncheck {
            coffs.push(Zr::random());
        }
        for ix in 1..=ngrp {
            let rschk = poly_eval(&coffs, Zr::from(ix as i64));
            let invwt = inv_wt(ngrp, ix);
            self.session_info.rschkv.push(rschk / invwt);
        }

        // we perform this last so we don't have to clone the proofs vector
        let commit = Commitment {
            kpt: kpt,
            eshares: enc_shares,
            proofs: proofs,
        };
        let msg = MsgType::SubgroupCommit { commit: commit };
        if let Err(e) = self.broadcast_grp(&msg) {
            error!("Failed to send broadcast message to group: {}", e);
        }

        // We might have been receiving commitments all along
        // from other nodes. Check to see if we now exceed the
        // threshold
        debug!(
            "In generate shared randomness, number of commitments received: {}",
            self.nbr_commits()
        );
        if self.nbr_commits() >= share_thresh {
            self.show_decrypted_shares();
        }
    }

    // ----------------------------------------------------------------------------
    // STAGE 3 -- Accumulate Commitments until a super-majority, then show
    // all the decrypted shares. This is key.
    //
    // Waiting until a supermajority of nodes has committed to their randomness
    // avoids the possibility that attackers might game the system by waiting
    // to see what others produce before they produce their own contributions.
    //
    // By waiting until a supermajority has committed before we disclose any
    // decryptions, there is no point trying to game the system.
    // ----------------------------------------------------------------------------

    fn nbr_commits(&self) -> usize {
        let grpinfo = &self.session_info.grptbl;
        let mut count = 0;
        for (_, entry) in grpinfo.iter() {
            if entry.commit && entry.decrs.len() > 0 {
                // consider the commitment usable only if we were able
                // to decrypt the share
                count += 1;
            }
        }
        count
    }

    fn validate_commitment(&self, commit: &Commitment) -> bool {
        if commit.proofs.len() > 1 {
            // proofs can't be all the same - that could only happen if there
            // were only one member in the group => Zero order share polynomial.
            let fst = commit.proofs.first().unwrap();
            let mut all_same = true;
            for proof in commit.proofs.iter() {
                if *proof != *fst {
                    all_same = false;
                    break;
                }
            }
            if all_same {
                return false;
            }
        }

        let sess = self.session_info.clone();

        // Reed-Solomon check for valid proofs vector
        let rschk = dot_prod_g1_zr(&commit.proofs, &sess.rschkv);
        if rschk != G1::zero() {
            return false;
        }

        // check that each proof pairs properly with the fast pkey and encr share
        for (pkey, (proof, eshare)) in sess
            .grp
            .iter()
            .zip(commit.proofs.iter().zip(commit.eshares.iter()))
        {
            //
            // Check for proper formation of encrypted share and its proof
            //
            if *eshare != G2::zero() {
                // Sender had keying info for this group member
                if let Some(GrpInfo { fkey, .. }) = sess.grptbl.get(pkey) {
                    if let Some(fpkey) = fkey {
                        // we have keying info for group member,
                        // so check proper formation
                        let p1 = fast::compute_pairing(proof, &G2::from(*fpkey));
                        let p2 = fast::compute_pairing(&commit.kpt, eshare);
                        if p1 != p2 {
                            return false; // was definitely bad
                        }
                    } else {
                        // We don't have keying info for this group member.
                        // see commentary below...
                    }
                } else {
                    // We don't have any keying info for this group member,
                    // but that may not be his fault.
                    // see commentary below...
                }
            } else {
                // Sender didn't have any keying when the share was created
                // for this particular group member. So he dummied the eshare
                // with zero to get past the Reed-Solomon check. But the proof
                // and encrypted share won't pass a check against this key, even
                // if *we* have the keying info for the group member.
                //
                // ----------------------------
                // No keying info available, can't validate this component,
                // but for BFT we probably shouldn't completely disregard
                // the commitment...
                //
                // If we disregard the entire commitment, then someone else
                // has to pick it up. And with Byzantine attacks, it is possible
                // that every node would fail this test right here, because at least
                // one key might have been prevented from making it to all other
                // group nodes. That represents a bad outcome for claimed BFT.
                //
                // If we don't disregard the entire commitment, then what could
                // sneak through? All we need is at least one honest broker.
                // Adding in more potential dishonesty doesn't change the outcome.
                //
                // So I vote to pass on this... We should only fail validation if
                // the commitment is provably bad.
            }
        }
        true
    }

    fn stash_commitment(&mut self, from: &secure::PublicKey, commit: &Commitment) {
        // Stash incoming commitments into the hashmap by polynomial.
        // Polynomials derive their identity from the sender of the commitment.
        // A HashMap here prevents duplication from trolls or network jumbles.
        //
        // Every node in a group produces a randomness commitment along with
        // a ZKP on the polynomial coefficients and the values of the secret
        // shares provided to all other group members.
        //
        // This is the code that receives the commitments from other nodes
        // and validates them, and then decrypts our own particular share of
        // the secret.
        //
        // We stash that decrypted share, and after seeing a super-majority
        // of other commitments, we send the whole stash to all other nodes
        // in the group.
        //
        match self.get_stage() {
            SessionStage::Init => {
                // somebody commited before we were ready ourselves.
                // get back to this later...
                let msg = MsgType::SubgroupCommit {
                    commit: commit.clone(),
                };
                self.stash_fifo(from, &msg);
            }
            SessionStage::Stage2 => {
                let ngrp = self.group_size();
                let thresh = ngrp - max_byz_fails(ngrp);
                let mut newrand = None;
                // let mut sess = self.session_info.clone();
                self.session_info.grptbl.entry(*from).or_insert({
                    // We haven't seen sender's fast public key.
                    // But that shouldn't stop us from accepting his commitments.
                    GrpInfo {
                        fkey: None,
                        commit: false,
                        decrs: HashMap::new(),
                    }
                });

                debug!("Trying to validate commitment {:#?}", commit);
                if !self.validate_commitment(commit) {
                    error!("Invalid commitment received! Ignoring...");
                    return;
                }

                let me = self.get_pkey();
                let my_index = self.position_in_group(&me);
                let my_fast_skey = self.get_my_fast_skey();
                if let Some(e) = self.session_info.grptbl.get_mut(from) {
                    debug!("Commitment is valid!");
                    e.commit = true; // record his commitment

                    // pre-stash our own decrypted share into his polynomial's
                    // list of decrytions
                    let eshare = commit.eshares[my_index];
                    if eshare != G2::zero() && e.decrs.len() < thresh {
                        // sender had our fast public key,
                        // so the share is good, and we are below thresh
                        e.decrs.insert(
                            me,
                            DecrShare {
                                index: 1 + my_index,
                                kpt: commit.kpt,
                                proof: commit.proofs[my_index],
                                share: eshare / Zr::from(my_fast_skey),
                            },
                        );
                        if e.decrs.len() >= thresh {
                            // if we just obtained a threshold number of decryptions,
                            // then perform Lagrange interpolation to 0 to extract the
                            // original randomness (now applied to G1).
                            newrand = Some((*from, reduce_lagrange_interpolate(&e.decrs)));
                        }
                    }
                } else {
                    debug!("Commit is invalid!");
                }

                debug!("Number of commitments received: {}", self.nbr_commits());
                if self.nbr_commits() >= thresh {
                    self.show_decrypted_shares();
                }

                // if we collected new randomness, pool it into the pending vector
                if let Some(pair) = newrand {
                    self.session_info.rands.push(pair);
                    if self.session_info.rands.len() >= thresh {
                        // If the output pending vector now has a threshold number
                        // of decoded randomness, then send the batch to our group
                        // leader.
                        let rands = self.session_info.rands.clone();
                        self.send_randomness_to_group_leader(&rands);
                    }
                }
            }
            _ => {
                // latecomers... just ignore message
            }
        }
    }

    fn show_decrypted_shares(&mut self) {
        // Send the stash to all other group members
        self.set_stage(SessionStage::Stage3); // now awaiting decodings
        self.dispatch_fifo_messages();
        let me = self.get_pkey();
        let mut decrs = Vec::new();
        for (pkey, entry) in self.session_info.grptbl.iter() {
            if let Some(pt) = entry.decrs.get(&me) {
                decrs.push((*pkey, pt.clone()));
            }
        }
        let msg = MsgType::DecrShares { shares: decrs };
        if let Err(e) = self.broadcast_grp(&msg) {
            error!("Failed to send broadcast message to group: {}", e);
        }
    }

    // ----------------------------------------------------------------------------
    // STAGE 4 -- Accumulate decrypted shares until we can perform
    // Lagrange interpolation to unwrap the hidden randomness
    // ----------------------------------------------------------------------------

    fn send_randomness_to_group_leader(&mut self, v: &Vec<(secure::PublicKey, G2)>) {
        // Send a batch of decoded randomness to the group leader
        self.set_stage(SessionStage::Stage4); // now awaiting subgroup randomness
        self.dispatch_fifo_messages();
        let me = self.get_pkey();
        let grpleader = self.get_group_leader();
        if me == grpleader {
            // I am a group leader, so just call my handler directly
            self.stash_subsubgroup_randomness(&me, v);
        } else {
            let msg = MsgType::SubgroupRandomness { rands: v.clone() };
            if let Err(e) = self.send_message(&grpleader, &msg) {
                error!("Failed to send message to leader: {}", e);
            }
        }
    }

    fn stash_decrypted_shares(
        &mut self,
        from: &secure::PublicKey,
        shares: &Vec<(secure::PublicKey, DecrShare)>,
    ) {
        // Each node gets this message from other nodes in the group.
        // Collect the decrypted shares into HashMaps per the
        // poynomial identity. Entries are pkey from which it arrived, and
        // the decrypted share for the slot's polynomial.
        //
        // After a BFT threshold number of decrypted shares for any one
        // polynomial, combine the hidden randomness at p(0) using
        // Lagrange interpolation.
        //
        // Shares arrive in batches. As we find polynomials to decode, we
        // stash their results until the end of batch processing. Then we
        // forward any decoded randomness to the group leader node,
        // identifying the polynomial from which the randomness was
        // obtained.
        //
        match self.get_stage() {
            SessionStage::Init => {
                // not ready to participate just yet...
                let msg = MsgType::DecrShares {
                    shares: shares.clone(),
                };
                self.stash_fifo(from, &msg);
            }
            SessionStage::Stage2 | SessionStage::Stage3 => {
                let ngrp = self.group_size();
                let thresh = ngrp - max_byz_fails(ngrp);
                let mut sess = self.session_info.clone();
                let mut newsess = sess.clone();
                let mut done = false;
                for (pkey, decr) in shares {
                    if validate_share(decr) {
                        // if the share isn't from a troll...
                        sess.grptbl
                            .entry(*pkey)
                            .and_modify(|e| {
                                if e.decrs.len() < thresh {
                                    // accumulate decrypted shares only if we haven't already seen
                                    // a threshold number for this polynomial.
                                    e.decrs.insert(*from, decr.clone());
                                    if e.decrs.len() >= thresh {
                                        // if we just obtained a threshold number of decryptions,
                                        // then perform Lagrange interpolation to 0 to extract the
                                        // original randomness (now applied to G1).
                                        //
                                        // Accumulate the decoded randomness, along with the polynomial identity,
                                        // into the output pending vector.
                                        newsess
                                            .rands
                                            .push((*pkey, reduce_lagrange_interpolate(&e.decrs)));
                                        if newsess.rands.len() >= thresh {
                                            // If the output pending vector now has a threshold number of decoded
                                            // randomness, then send the batch to our group leader.
                                            self.send_randomness_to_group_leader(&newsess.rands);
                                            done = true; // don't bother accepting any more decryptions.
                                        }
                                    }
                                }
                            })
                            .or_insert({
                                // We haven't seen this poly before, but don't discard the
                                // decrypted randomness. It might actually live onward...
                                let mut grpinfo = GrpInfo {
                                    fkey: None,
                                    commit: false,
                                    decrs: HashMap::new(),
                                };
                                grpinfo.decrs.insert(*from, decr.clone());
                                grpinfo
                            });
                        if done {
                            // we're outa here...
                            break;
                        }
                    }
                }
                newsess.grptbl = sess.grptbl.clone(); // is this really necessary?
                self.session_info = newsess; // is this really necessary?
            }
            _ => {
                // latecomers... just ignore the message
            }
        }
    }
    // ----------------------------------------------------------------------------
    // STAGE 5 -- Group Leader accumulates incoming randomness
    // ----------------------------------------------------------------------------

    fn send_to_beacon(&mut self, rand: G2) {
        self.set_stage(SessionStage::Stage5); // now awaiting group randomness
        self.dispatch_fifo_messages();
        let me = self.get_pkey();
        let beacon = self.get_current_beacon();
        if me == beacon {
            // I am the Beacon, so just call my handler directly
            self.stash_group_randomness(&me, &rand);
        } else {
            let msg = MsgType::GroupRandomness { rand: rand };
            if let Err(e) = self.send_message(&beacon, &msg) {
                error!("Failed to send message to beacon: {}", e);
            }
        }
    }

    fn stash_subsubgroup_randomness(
        &mut self,
        from: &secure::PublicKey,
        rands: &Vec<(secure::PublicKey, G2)>,
    ) {
        // Group leaders perform this code.
        //
        // Decoded randomness arrives in batches, identified by polynomial.
        // For each polynomial we accumulate the incoming randomness until a
        // sharing threshold of accumulations has occured.
        //
        // At that point we stop accepting new randomness for the polynomial
        // and accumulate its accumulated randomness into a group randomness
        // bucket.
        //
        // After a sharing threshold of group randomness accumulation, we
        // stop accepting any more incoming batches of randomness, and
        // forward the accumulated group randomness to the Beacon node.
        //
        if self.get_pkey() == self.get_group_leader() {
            // am I really a group leader?
            match self.get_stage() {
                SessionStage::Init
                | SessionStage::Stage2
                | SessionStage::Stage3
                | SessionStage::Stage4 => {
                    let ngrp = self.group_size();
                    let thresh = ngrp - max_byz_fails(ngrp);
                    let mut sess = self.session_info.clone();
                    let mut newsess = sess.clone();
                    let mut done = false;
                    for (pkey, pt) in rands {
                        // session_info.grands is a HashMap arranged by polynomial
                        // (polynomials are identified by the secure::PublicKey of their creator)
                        //
                        // Within each polynomial entry is another HashMap arranged by sender.
                        // The value in that secondary map is the decrypted randomness obtained
                        // from that polynomial, by that sender.
                        //
                        // By using a second level HashMap we avoid false accumulations as a
                        // result of trolling or from repeated network messages.
                        //
                        // The pkeys in the rands identify the polynomials. The pt is the decoded
                        // randomness, presented in group G2.
                        //
                        sess.grands
                            .entry(*pkey)
                            .and_modify(|map| {
                                if map.len() < thresh {
                                    // Accept new randomness for this polynomial only if we haven't
                                    // seen a threshold number of them.
                                    //
                                    // If this is a duplicate, the HashMap will update with this new value,
                                    // but it won't increase the count.
                                    //
                                    map.insert(*from, *pt);
                                    if map.len() >= thresh {
                                        // If we finally have a threshold number of randomness values,
                                        // then accumulate their sum into the pending outgoing vector.
                                        newsess.lrands.push(
                                            map.iter().fold(G2::zero(), |ans, (_, pt)| ans + *pt),
                                        );
                                        if newsess.lrands.len() >= thresh {
                                            // If the pending outgoing vector now has a threshold
                                            // number of entries, then send their sum up to the Beacon.
                                            //
                                            // We also terminate this phase of the protocol for ourselves.
                                            //
                                            // If at least one node has been honest in the group, then his
                                            // randomness will prevail, and the resulting sum will be random.
                                            //
                                            self.send_to_beacon(
                                                newsess
                                                    .lrands
                                                    .iter()
                                                    .fold(G2::zero(), |ans, pt| ans + *pt),
                                            );
                                            done = true;
                                        }
                                    }
                                }
                            })
                            .or_insert({
                                // First entry for a polynomial...
                                let mut map = HashMap::new();
                                map.insert(*from, *pt);
                                map
                            });
                        if done {
                            break;
                        }
                    }
                    newsess.grands = sess.grands.clone(); // are these really necesasry?
                    self.session_info = newsess; // ditto...
                }
                _ => {
                    // latecomers... just drop the message
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // STAGE 6 -- Beacon node accumulates group-leader randomness
    // ------------------------------------------------------------------

    fn stash_group_randomness(&mut self, from: &secure::PublicKey, rand: &G2) {
        // This message should only arrive at the Beacon node, as group leaders
        // forward their composite group randomness.
        //
        // Collect incoming group randomness into a bucket for Randhound.
        // Again, we use a HashMap to avoid trolls and duplicate network messages.
        //
        // After we accumulate a sharing threshold number of group-random
        // values from the group leaders, we stop accepting any more
        // randomness, and compute an election seed.
        //
        // Then we broadcast a HOLD-ELECTION message to all witness nodes in
        // the blockchain system, supplying that seed. We are finished at
        // that point.
        //
        if self.get_pkey() == self.get_current_beacon() {
            let ngrps = self.get_ngroups();
            let thresh = ngrps - max_byz_fails(ngrps);
            // let mut sess = self.session_info.clone();
            if self.session_info.brands.len() < thresh {
                // Only accept new randomness if we haven't yet seen a threshold
                // number of them.
                self.session_info.brands.entry(*from).or_insert(*rand);
                if self.session_info.brands.len() >= thresh {
                    // If we finally have a threshold number of randomness values,
                    // then we are finished!! Yay!
                    //
                    // Form the sum, then the hash of the sum in the pairing field, GT,
                    // paired with the generator for G1.
                    //
                    // The final new random lottery ticket is the hash of the pairing
                    // value.
                    //
                    // If randomness from at least one group was honestly random (at least one
                    // group member was honest), then the sum is honestly random, regardless of
                    // however many attackers tried to force otherwise.
                    //
                    let grand = self
                        .session_info
                        .brands
                        .iter()
                        .fold(G2::zero(), |sum, (_, pt)| sum + *pt);
                    let trand = fast::compute_pairing(&G1::generator(), &grand);
                    let ticket = Hash::digest(&trand);
                    info!("Calculated Final Lottery Ticket: {}", ticket);
                    self.consumers.retain(move |tx| {
                        tx.unbounded_send(Some(Randomness {
                            value: ticket.clone(),
                        }))
                        .is_ok()
                    });
                    let msg = MsgType::FinalLotteryTicket { ticket: ticket };
                    // tell everyone the outcome with the next lottery ticket
                    if let Err(e) = self.broadcast(&msg) {
                        error!("Failed to broadcast lottery ticket: {}", e);
                    }
                    self.session_info = Session::default(); // we're done here...
                }
            }
        }
    }
}

// --------------------------------------------------------------------------------
// Communication Messages between Nodes

#[derive(Clone, Debug)]
pub struct DecrShare {
    kpt: G1,
    share: G2,
    proof: G1,
    index: usize,
}

impl Hashable for DecrShare {
    fn hash(&self, state: &mut Hasher) {
        "DecrShare".hash(state);
        self.kpt.hash(state);
        self.share.hash(state);
        self.proof.hash(state);
        let mut v = [0u8; 4];
        let mut x = self.index;
        for ix in 0..4 {
            v[ix] = x as u8;
            x >>= 8;
        }
        v.hash(state);
    }
}

#[derive(Clone, Debug)]
pub struct Commitment {
    kpt: G1,
    eshares: Vec<G2>,
    proofs: Vec<G1>,
}

impl Hashable for Commitment {
    fn hash(&self, state: &mut Hasher) {
        self.kpt.hash(state);
        for share in self.eshares.clone() {
            share.hash(state);
        }
        for proof in self.proofs.clone() {
            proof.hash(state);
        }
    }
}

#[derive(Clone, Debug)]
pub enum MsgType {
    Start {
        epoch: Hash,
        sess: Hash,
        grps: Vec<Vec<secure::PublicKey>>,
    },
    FastKey {
        key: fast::PublicKey,
    },
    SubgroupCommit {
        commit: Commitment,
    },
    DecrShares {
        shares: Vec<(secure::PublicKey, DecrShare)>,
    },
    SubgroupRandomness {
        rands: Vec<(secure::PublicKey, G2)>,
    },
    GroupRandomness {
        rand: G2,
    },
    FinalLotteryTicket {
        ticket: Hash,
    },
}

impl Hashable for MsgType {
    fn hash(&self, state: &mut Hasher) {
        match self {
            MsgType::Start { epoch, sess, grps } => {
                "Start".hash(state);
                epoch.hash(state);
                sess.hash(state);
                for grp in grps {
                    "Grp".hash(state);
                    for key in grp {
                        key.hash(state);
                    }
                }
            }
            MsgType::FastKey { key } => {
                "FastKey".hash(state);
                key.hash(state);
            }
            MsgType::SubgroupCommit { commit } => {
                "SubgroupCommit".hash(state);
                commit.hash(state);
            }
            MsgType::DecrShares { shares } => {
                "DecrShares".hash(state);
                for (key, decr) in shares {
                    key.hash(state);
                    decr.hash(state);
                }
            }
            MsgType::SubgroupRandomness { rands } => {
                "SubgroupRandomness".hash(state);
                for (key, pt) in rands {
                    key.hash(state);
                    pt.hash(state);
                }
            }
            MsgType::GroupRandomness { rand } => {
                "GroupRandomness".hash(state);
                rand.hash(state);
            }
            MsgType::FinalLotteryTicket { ticket } => {
                "FinalTicket".hash(state);
                ticket.hash(state);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Message {
    pub sess: Hash,              // the session ID
    pub typ: MsgType,            // what kind of message in the body
    pub sig: secure::Signature,  // BLS signature on hash of the (sess, typ)
    pub from: secure::PublicKey, // PKey of sender
}

#[derive(Copy, Clone, Fail, Debug)]
pub enum MsgErr {
    #[fail(display = "Session mismatch (expected: {}, got: {}", _0, _1)]
    SessionMismatch(Hash, Hash),
    #[fail(display = "Message not from a group member")]
    NotFromGroupMember,
    #[fail(display = "Invalid Signature")]
    InvalidSignature,
    #[fail(display = "Message not from Beacon")]
    NotFromBeacon,
    #[fail(display = "Message from another Epoch")]
    NotCurrentEpoch,
    #[fail(display = "Message not from Beacon")]
    NotFromGroupLeader,
    #[fail(display = "Not in session")]
    NotInSession,
    #[fail(display = "Invalid protobuf message")]
    BadProtobuf,
}

fn validate_share(share: &DecrShare) -> bool {
    // share is valid if e(Proof, U) = e(K, DecrShare)
    let p1 = fast::compute_pairing(&share.proof, &G2::generator());
    let p2 = fast::compute_pairing(&share.kpt, &share.share);
    p1 == p2
}

fn reduce_lagrange_interpolate(v: &HashMap<secure::PublicKey, DecrShare>) -> G2 {
    // first collect the X,Y pairs: X = index into group, Y = decr share value (a pt in G2)
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for (_, entry) in v {
        let zx = entry.index;
        xs.push(zx);
        ys.push(entry.share);
    }
    // Now compute the Lagrange interpolation at X = 0 to get the hidden randomness
    xs.iter()
        .zip(ys.iter())
        .fold(G2::zero(), |ans, (x, y)| ans + *y * lagrange_wt(&xs, *x))
}

fn schedule_after(_dursec: f32, _skedfn: &dyn Fn() -> ()) {
    // TODO: somehow pull this off...
    // Wait till dursec seconds have elapsed, then call the indicated function.
    //
    // NOTE: using Timer::schedule_with_delay() is probably insufficient
    // because we need to perform potentially blocking activities, and Timer
    // schedules the task on the timer thread.
    //
    // We need Actors with non-blocking message send...
    //
    // Meanwhile, while awaiting the timeout, we should be processing
    // incoming messages.
}

/// Turns a raw Randhound message into a type-safe message.
pub(crate) fn proto_to_msg(mut message: RandhoundMessage) -> Result<Message, Error> {
    let sess = Hash::try_from_bytes(&message.take_sess().to_vec())?;
    let sig = secure::Signature::try_from_bytes(&message.take_sig().to_vec())?;
    let from = secure::PublicKey::try_from_bytes(&message.take_from().to_vec())?;
    let typ = match message.get_field_type() {
        RandhoundMessageTypes::START => {
            if !message.has_start() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let mut start_msg = message.take_start();
            let epoch = Hash::try_from_bytes(&start_msg.take_epoch().to_vec())?;
            let sess = Hash::try_from_bytes(&start_msg.take_sess().to_vec())?;

            let mut grps: Vec<Vec<secure::PublicKey>> = vec![];
            for g in start_msg.get_grps().iter() {
                let mut group = vec![];
                for k in g.get_pkeys() {
                    let pkey = secure::PublicKey::try_from_bytes(k)?;
                    group.push(pkey);
                }
                grps.push(group);
            }
            MsgType::Start { epoch, sess, grps }
        }
        RandhoundMessageTypes::FASTKEY => {
            if !message.has_fast_key() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let mut fk_msg = message.take_fast_key();
            let key = fast::PublicKey::try_from_bytes(&fk_msg.take_key().to_vec())?;
            MsgType::FastKey { key }
        }
        RandhoundMessageTypes::SUBGROUP_COMMIT => {
            if !message.has_sub_group_commit() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let mut commit_msg = message.take_sub_group_commit().take_commit();
            let kpt = fast::G1::try_from_bytes(&commit_msg.take_kpt().to_vec())?;
            let mut eshares = vec![];
            for e in commit_msg.get_eshares() {
                let eshare = fast::G2::try_from_bytes(e)?;
                eshares.push(eshare);
            }
            let mut proofs = vec![];
            for p in commit_msg.get_proofs() {
                let proof = fast::G1::try_from_bytes(p)?;
                proofs.push(proof);
            }
            MsgType::SubgroupCommit {
                commit: Commitment {
                    kpt,
                    eshares,
                    proofs,
                },
            }
        }
        RandhoundMessageTypes::DECR_SHARES => {
            if !message.has_decr_shares() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let shares_msg = message.take_decr_shares().take_shares();
            let mut shares = vec![];
            for s in shares_msg.iter() {
                let pkey = secure::PublicKey::try_from_bytes(&s.get_pkey().to_vec())?;
                let decr_share_msg = s.get_decr_share();
                let kpt = G1::try_from_bytes(&decr_share_msg.get_kpt().to_vec())?;
                let share = G2::try_from_bytes(&decr_share_msg.get_share().to_vec())?;
                let proof = G1::try_from_bytes(&decr_share_msg.get_proof().to_vec())?;
                let index = decr_share_msg.get_index() as usize;
                let decr_share = DecrShare {
                    kpt,
                    share,
                    proof,
                    index,
                };
                shares.push((pkey, decr_share));
            }
            MsgType::DecrShares { shares }
        }
        RandhoundMessageTypes::SUBGROUP_RANDOMNESS => {
            if !message.has_sub_group_randomness() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let mut rands = vec![];
            for r in message.take_sub_group_randomness().take_rands().iter() {
                let pkey = secure::PublicKey::try_from_bytes(&r.get_pkey().to_vec())?;
                let pt = G2::try_from_bytes(&r.get_pt().to_vec())?;
                rands.push((pkey, pt));
            }
            MsgType::SubgroupRandomness { rands }
        }
        RandhoundMessageTypes::GROUP_RANDOMNESS => {
            if !message.has_group_randomness() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let rand = G2::try_from_bytes(&message.take_group_randomness().take_rand().to_vec())?;
            MsgType::GroupRandomness { rand }
        }
        RandhoundMessageTypes::FINAL_LOTTERY_TICKET => {
            if !message.has_final_lottery_ticket() {
                return Err(MsgErr::BadProtobuf.into());
            }
            let ticket =
                Hash::try_from_bytes(&message.take_final_lottery_ticket().take_ticket().to_vec())?;
            MsgType::FinalLotteryTicket { ticket }
        }
    };
    let msg = Message {
        sess,
        sig,
        from,
        typ,
    };
    Ok(msg)
}

// Turns a type-safe Randhound message into the corresponding row protobuf message.
pub(crate) fn msg_to_proto(rh_msg: &Message) -> RandhoundMessage {
    let mut msg = RandhoundMessage::new();
    msg.set_sess(rh_msg.sess.into_bytes().to_vec());
    msg.set_sig(rh_msg.sig.into_bytes().to_vec());
    msg.set_from(rh_msg.from.into_bytes().to_vec());
    match rh_msg.typ {
        MsgType::Start {
            epoch,
            sess,
            ref grps,
        } => {
            let mut msg_typ = randhound_proto::Start::new();
            msg_typ.set_epoch(epoch.into_bytes().to_vec());
            msg_typ.set_sess(sess.into_bytes().to_vec());
            for g in grps {
                let mut group = randhound_proto::Start_Group::new();
                for k in g {
                    group.mut_pkeys().push(k.into_bytes().to_vec());
                }
                msg_typ.mut_grps().push(group);
            }
            msg.set_start(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::START);
        }
        MsgType::FastKey { key } => {
            let mut msg_typ = randhound_proto::FastKey::new();
            msg_typ.set_key(key.into_bytes().to_vec());
            msg.set_fast_key(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::FASTKEY);
        }
        MsgType::SubgroupCommit { ref commit } => {
            let mut msg_typ = randhound_proto::SubGroupCommit::new();
            let mut commit_msg = randhound_proto::SubGroupCommit_Commitment::new();
            commit_msg.set_kpt(commit.kpt.into_bytes().to_vec());
            for e in commit.eshares.iter() {
                commit_msg.mut_eshares().push(e.into_bytes().to_vec());
            }
            for p in commit.proofs.iter() {
                commit_msg.mut_proofs().push(p.into_bytes().to_vec());
            }
            msg_typ.set_commit(commit_msg);
            msg.set_sub_group_commit(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::SUBGROUP_COMMIT);
        }
        MsgType::DecrShares { ref shares } => {
            let mut msg_typ = randhound_proto::DecrShares::new();
            for s in shares {
                let mut decr_share_msg = randhound_proto::DecrShares_DecrShare::new();
                decr_share_msg.set_kpt(s.1.kpt.into_bytes().to_vec());
                decr_share_msg.set_share(s.1.share.into_bytes().to_vec());
                decr_share_msg.set_proof(s.1.proof.into_bytes().to_vec());
                decr_share_msg.set_index(s.1.index as u32);
                let mut share_msg = randhound_proto::DecrShares_Share::new();
                share_msg.set_pkey(s.0.into_bytes().to_vec());
                share_msg.set_decr_share(decr_share_msg);
                msg_typ.mut_shares().push(share_msg);
            }
            msg.set_decr_shares(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::DECR_SHARES)
        }
        MsgType::SubgroupRandomness { ref rands } => {
            let mut msg_typ = randhound_proto::SubGroupRandomness::new();
            for r in rands {
                let mut rand_msg = randhound_proto::SubGroupRandomness_Randomness::new();
                rand_msg.set_pkey(r.0.into_bytes().to_vec());
                rand_msg.set_pt(r.1.into_bytes().to_vec());
                msg_typ.mut_rands().push(rand_msg);
            }
            msg.set_sub_group_randomness(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::SUBGROUP_RANDOMNESS)
        }
        MsgType::GroupRandomness { rand } => {
            let mut msg_typ = randhound_proto::GroupRandomness::new();
            msg_typ.set_rand(rand.into_bytes().to_vec());
            msg.set_group_randomness(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::GROUP_RANDOMNESS)
        }
        MsgType::FinalLotteryTicket { ticket } => {
            let mut msg_typ = randhound_proto::FinalLotteryTicket::new();
            msg_typ.set_ticket(ticket.into_bytes().to_vec());
            msg.set_final_lottery_ticket(msg_typ);
            msg.set_field_type(RandhoundMessageTypes::FINAL_LOTTERY_TICKET)
        }
    };
    msg
}

#[cfg(test)]
mod tests {
    use crate::randhound::{msg_to_proto, proto_to_msg, Commitment, DecrShare, Message, MsgType};
    use protobuf::{self, Message as ProtoMessage};
    use rand;
    use stegos_crypto::hash::Hash;
    use stegos_crypto::pbc::{fast, secure};

    fn random_vec(len: usize) -> Vec<u8> {
        let key = (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        key
    }

    fn roundtrip_check(rh_msg: Message) {
        let proto_msg = msg_to_proto(&rh_msg);
        let buf = proto_msg.write_to_bytes().unwrap();
        let new_proto_msg = protobuf::parse_from_bytes(&buf).unwrap();
        let new_msg = proto_to_msg(new_proto_msg).unwrap();

        assert_eq!(rh_msg.sess, new_msg.sess);
        assert_eq!(rh_msg.sig, new_msg.sig);
        assert_eq!(rh_msg.from, new_msg.from);
        assert_eq!(Hash::digest(&rh_msg.typ), Hash::digest(&new_msg.typ),);
    }

    #[test]
    fn randhound_start() {
        let mut grps = vec![];
        for _i in 0..5 {
            let mut g = vec![];
            for _j in 0..10 {
                g.push(secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap());
            }
            grps.push(g);
        }
        let msg_typ = MsgType::Start {
            epoch: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            grps,
        };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_fastkey() {
        let msg_typ = MsgType::FastKey {
            key: fast::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_subgroup_commit() {
        let mut eshares = vec![];
        let mut proofs = vec![];
        for _i in 0..10 {
            eshares.push(fast::G2::try_from_bytes(&random_vec(65)).unwrap());
            proofs.push(fast::G1::try_from_bytes(&random_vec(65)).unwrap());
        }

        let commit = Commitment {
            kpt: fast::G1::try_from_bytes(&random_vec(65)).unwrap(),
            eshares,
            proofs,
        };

        let msg_typ = MsgType::SubgroupCommit { commit };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_decr_shares() {
        let mut shares = vec![];
        for _i in 0..10 {
            let share = DecrShare {
                kpt: fast::G1::try_from_bytes(&random_vec(65)).unwrap(),
                share: fast::G2::try_from_bytes(&random_vec(65)).unwrap(),
                proof: fast::G1::try_from_bytes(&random_vec(65)).unwrap(),
                index: rand::random::<usize>(),
            };
            let pkey = secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap();
            shares.push((pkey, share));
        }

        let msg_typ = MsgType::DecrShares { shares };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_subgroup_randomness() {
        let mut rands = vec![];
        for _i in 0..10 {
            let pkey = secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap();
            let pt = fast::G2::try_from_bytes(&random_vec(65)).unwrap();
            rands.push((pkey, pt));
        }

        let msg_typ = MsgType::SubgroupRandomness { rands };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_group_randomness() {
        let msg_typ = MsgType::GroupRandomness {
            rand: fast::G2::try_from_bytes(&random_vec(65)).unwrap(),
        };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }

    #[test]
    fn randhound_final_lottery_ticket() {
        let msg_typ = MsgType::FinalLotteryTicket {
            ticket: Hash::try_from_bytes(&random_vec(32)).unwrap(),
        };

        let msg = Message {
            sess: Hash::try_from_bytes(&random_vec(32)).unwrap(),
            typ: msg_typ,
            sig: secure::Signature::try_from_bytes(&random_vec(33)).unwrap(),
            from: secure::PublicKey::try_from_bytes(&random_vec(65)).unwrap(),
        };

        roundtrip_check(msg);
    }
}

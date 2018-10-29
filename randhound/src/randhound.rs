//! Randhound++ - Distributed Randomness Generation

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

#![allow(non_snake_case)]
#![allow(dead_code)]

use parking_lot::RwLock;
use std::collections::hash_map::HashMap;
use std::collections::hash_set::HashSet;

use stegos_crypto::hash::*;
use stegos_crypto::pbc::*;

use lazy_static::*;
use std::sync::Arc;

// -------------------------------------------------------------------------
// While the blockchain relies on secure PBC crypto, and participant nodes
// are identified by secure::PublicKey's, we utilize the shorter, faster,
// symmetric pairings offered by curve AR160 in pbc::fast, for the distributed
// randomness generation. The shared secrets only need to be protected for a
// few seconds, from the start of a session, until the randomness has been generated.
// -------------------------------------------------------------------------

type Zr = fast::Zr;
type G1 = fast::G1;
type G2 = fast::G2;
type GT = fast::GT;

// -------------------------------------------------------------------------

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

#[derive(Clone)]
struct GlobalState {
    pub pkey: secure::PublicKey,
    pub skey: secure::SecretKey,
    pub witnesses: Arc<RwLock<HashSet<secure::PublicKey>>>,
    pub session_info: Arc<RwLock<Option<Session>>>,
}

#[derive(Clone)]
struct Session {
    pub session: Hash,
    pub leader: secure::PublicKey,
    pub fpkey: fast::PublicKey,
    pub fskey: fast::SecretKey,
    pub stage: Arc<RwLock<SessionStage>>,
    pub grp: HashMap<secure::PublicKey, fast::PublicKey>,
}

#[derive(PartialEq)]
enum SessionStage {
    Init,
    Stage1,
    Stage2,
    Stage3,
    Stage4,
}

lazy_static! {
    static ref GSTATE: GlobalState = make_initial_global_state();
}

fn make_initial_global_state() -> GlobalState {
    // TODO: Read keying seed from config file
    let (skey, pkey, sig) = secure::make_deterministic_keys(b"Test");
    assert!(secure::check_keying(&pkey, &sig));
    GlobalState {
        pkey: pkey,
        skey: skey,
        witnesses: Arc::new(RwLock::new(HashSet::new())),
        session_info: Arc::new(RwLock::new(None)),
    }
}

fn start_session(id: Hash, leader: secure::PublicKey) {
    if is_valid_witness(leader) {
        let seed = Hash::digest_chain(&[&id, &GSTATE.skey]);
        let (fskey, fpkey, fsig) = fast::make_deterministic_keys(&seed.bits());
        assert!(fast::check_keying(&fpkey, &fsig));
        let mut pdata = GSTATE.session_info.write();
        *pdata = Some(Session {
            session: id,
            stage: Arc::new(RwLock::new(SessionStage::Init)),
            leader: leader,
            fpkey: fpkey,
            fskey: fskey,
            grp: HashMap::new(),
        })
    }
}

fn get_fast_key(pkey: secure::PublicKey) -> Option<fast::PublicKey> {
    let psess = GSTATE.session_info.read();
    match *psess {
        None => None,
        Some(ref sess) => Some(*sess.grp.get(&pkey)?),
    }
}

fn add_witness(pkey: secure::PublicKey) {
    let mut wits = GSTATE.witnesses.write();
    wits.insert(pkey);
}

fn drop_witness(pkey: secure::PublicKey) {
    let mut wits = GSTATE.witnesses.write();
    wits.remove(&pkey);
}

fn is_valid_witness(pkey: secure::PublicKey) -> bool {
    let wits = GSTATE.witnesses.read();
    wits.contains(&pkey)
}

fn is_in_session() -> bool {
    let info = GSTATE.session_info.read();
    match *info {
        None => false,
        Some(_) => true,
    }
}

fn is_current_session(id: Hash, stage: SessionStage) -> bool {
    let info = GSTATE.session_info.read();
    match *info {
        None => false,
        Some(ref sess) => (id == sess.session) && (stage == *sess.stage.read()),
    }
}

fn add_fast_key(session: Hash, pkey: secure::PublicKey, fpkey: fast::PublicKey) {
    // IF:
    //   the indicated pkey is in the witness pool, and
    //   the indicated session is the current session, and
    //   we are still in the Init stage
    // THEN
    //   add the (secure pkey, fast pkey) association to the session group
    let mut info = GSTATE.session_info.write(); // grab write lock first
    if is_valid_witness(pkey) && is_current_session(session, SessionStage::Init) {
        match *info {
            Some(ref mut sess) => {
                sess.grp.insert(pkey, fpkey);
            }
            None => unreachable!(),
        }
    }
}

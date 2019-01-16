//! mod.rs - DiceMix for secure and anonymous info exchange

//
// Copyright (c) 2019 Stegos
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

#![allow(unused)]

// use super::*;
use crate::curve1174;
use crate::hash::{Hash, Hashable, Hasher};
use stegos_crypto::*;
// use crate::utils;
// use crate::CryptoError;
use crate::bulletproofs::*;
use failure::Fail;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::time::{Duration, SystemTime};

extern crate rayon;
use rayon::prelude::*;

use crate::dicemix::*;

// -------------------------------------------------

type Fr = curve1174::fields::Fr;
type Pt = curve1174::cpt::Pt;
type ECp = curve1174::ecpt::ECp;

type PublicKey = curve1174::cpt::PublicKey;
type SecretKey = curve1174::cpt::SecretKey;
type SchnorrSig = curve1174::cpt::SchnorrSig;

type TXIN = Hash;

#[derive(Clone)]
pub struct UTXO {
    // Provisional code - just to get a compile
    pub id: Hash,
    pub pkey: PublicKey,
    pub bp: BulletProof,
    pub keying: (PublicKey, PublicKey),
    pub payload: [u8; 256],
}

impl Hashable for UTXO {
    // Provisional code - just to get a compile
    fn hash(&self, state: &mut Hasher) {
        "UTXO".hash(state);
        self.id.hash(state);
        self.pkey.hash(state);
        self.bp.hash(state);
        self.keying.0.hash(state);
        self.keying.1.hash(state);
        self.payload.hash(state);
    }
}

#[derive(Clone)]
pub struct Transaction {
    // Provisional code - just to get a compile
    pub txins: Vec<TXIN>,
    pub txouts: Vec<UTXO>,
    pub fee: u64,
    pub gamma_adj: Fr,
    pub sig: SchnorrSig,
}

impl Hashable for Transaction {
    // Provisional code - just to get a compile
    fn hash(&self, state: &mut Hasher) {
        "Transaction".hash(state);
        self.txins.iter().for_each(|txin| txin.hash(state));
        self.txouts.iter().for_each(|txout| txout.hash(state));
        self.fee.hash(state);
        self.gamma_adj.hash(state);
    }
}

fn serialize_utxo(_utxo: &UTXO) -> Vec<u8> {
    // Provisional code - just to get a compile
    let mut out = Vec::<u8>::new();
    // TODO
    out
}

pub fn dc_encode_matrix(
    utxos: &Vec<UTXO>,
    participants: &Vec<PublicKey>,
    my_pkey: &PublicKey,
    share_cloaks: &HashMap<PublicKey, Hash>,
) -> DcMatrix {
    let n_utxos = utxos.len();
    assert!(n_utxos <= MAX_UTXOS);
    let mut matrix = Vec::<Vec<Vec<Fr>>>::new();
    let mut sheet_id = 0;
    for utxo in utxos {
        let msg = serialize_utxo(&utxo);
        let sheet = dc_encode_sheet(
            sheet_id,
            MAX_CHUNKS,
            &msg,
            participants,
            my_pkey,
            share_cloaks,
        );
        matrix.push(sheet);
        sheet_id += 1;
    }
    let null_msg = Vec::<u8>::new();
    for _ in n_utxos..MAX_UTXOS {
        let sheet = dc_encode_sheet(
            sheet_id,
            MAX_CHUNKS,
            &null_msg,
            participants,
            &my_pkey,
            share_cloaks,
        );
        matrix.push(sheet);
        sheet_id += 1;
    }
    matrix
}

#[derive(Clone)]
pub struct TXINPacket {
    // One of these sent to all participants at start of session
    // we send a list of TXIN's, identified by their UTXO Hash,
    // and a corresponding ownership signature
    pub txins: Vec<(Hash, SchnorrSig)>,
}

#[derive(Clone)]
pub struct KeyingPacket {
    // At start of every session round, we randomly re-key for
    // cloaked sharing. The public side of this information
    // is shared with every participant.
    pub sess_pkeys: HashMap<PublicKey, PublicKey>,
}

#[derive(Clone)]
pub struct CommitmentPacket {
    // After constructing our cloaked sharing values we send
    // a commitment to them to all participants. That way they
    // can check that when we send the actual cloaked values
    // they are seen to be the same.
    pub commit: Hash,
}

#[derive(Clone)]
pub struct CloakedPacket {
    // After validating commitmemnts to this information,
    // we send the cloaked gamma_adj and matrix of UTXOs
    // to every participant. We also send a list of cloaking
    // hash values used between us and all the excluded participants.
    //
    // NOTE: unless there remain at least 3 participants (including us)
    // in any round, the disclosure of the shared cloaking hashes
    // could allow an attacker to reveal our cloaked values early,
    // thereby obviating anonymous sharing.
    pub gamma_adj: Fr,
    pub matrix: DcMatrix,
    pub k_excl: HashMap<PublicKey, Hash>,
}

pub enum UTXOType {
    PaymentUTXO,
    DataUTXO,
}
pub struct ProposedUTXO {
    pub utype: UTXOType,
    pub recip: PublicKey,
    pub amount: u64,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Fail)]
pub enum VsError {
    #[fail(display = "Can't form SuperTransaction")]
    VsFail, // if can't achieve any result in ValueShuffle session
}

pub fn vs_start(
    participants: &Vec<PublicKey>,
    my_pkey: &PublicKey,
    my_skey: &SecretKey,
    txins: &Vec<(TXIN, SchnorrSig)>,
    txouts: &Vec<ProposedUTXO>,
) -> Result<Transaction, VsError> {
    // at start of run we must share our TXINS with everyone
    // note that "participants" includes us too.
    send_txins(txins, participants);

    // get all the other TXINS and form the full collection
    let mut all_txins: HashMap<PublicKey, Vec<TXIN>> = HashMap::new();
    let my_txins = txins.iter().map(|pair| (*pair).0).collect();
    all_txins.insert(*my_pkey, my_txins);

    let mut p_excl = Vec::<PublicKey>::new();
    receive_txins(participants, &mut all_txins, &mut p_excl);

    // run rounds till we either succeed, or fail completely
    let (my_utxos, final_utxos, total_fee, gamma_adj) =
        vs_run(participants, &mut p_excl, my_pkey, &all_txins, txouts)?;

    // we succeeded, so construct the super transaction
    let parts = all_excluding(participants, &p_excl);
    let mut proposed_transaction = make_transaction(
        &parts,
        &all_txins,
        &my_utxos,
        &final_utxos,
        total_fee,
        gamma_adj,
        my_pkey,
        my_skey,
    );
    let leader = leader_pkey(&parts);
    if *my_pkey == leader {
        // if I'm leader, then collect component signatures
        // and form the final composite signature on the super transaction
        // then send the super transaction to the blockchain
        let mut all_sigs: HashMap<PublicKey, SchnorrSig> = HashMap::new();
        receive_signatures(&parts, &mut all_sigs);
        let sig = proposed_transaction.sig;
        let mut u_sum = sig.u;
        let mut k_sum = sig.K.decompress().unwrap();
        for p in parts {
            match all_sigs.get(&p) {
                None => return Err(VsError::VsFail),
                Some(other_sig) => {
                    u_sum += other_sig.u;
                    k_sum += other_sig.K.decompress().unwrap();
                }
            }
        }
        proposed_transaction.sig = SchnorrSig {
            u: u_sum,
            K: k_sum.compress(),
        };
        send_super_transaction(&proposed_transaction);
    } else {
        // I'm not leader, so send my signature to the leader
        send_signature(&leader, &proposed_transaction.sig);
    }
    Ok(proposed_transaction)
}

fn receive_signatures(participants: &Vec<PublicKey>, sigs: &mut HashMap<PublicKey, SchnorrSig>) {
    // collect signatures from all participants
    // TODO
}

fn send_signature(leader: &PublicKey, sig: &SchnorrSig) {
    // send signature to leader node
    // TODO
}

fn send_super_transaction(transaction: &Transaction) {
    // send final superTransaction to blockchain
    // TODO
}

fn leader_pkey(participants: &Vec<PublicKey>) -> PublicKey {
    // select the leader as the public key having the lowest hash
    let mut candidates: Vec<(PublicKey, Hash)> = participants
        .iter()
        .map(|&p| (p, Hash::digest(&p)))
        .collect();
    // there must be at least 3 of us in here...
    let (mut min_pkey, mut min_hash) = candidates.pop().unwrap();
    for (pkey, hash) in candidates {
        if hash < min_hash {
            min_pkey = pkey;
            min_hash = hash;
        }
    }
    min_pkey
}

fn send_txins(txins: &Vec<(TXIN, SchnorrSig)>, participants: &Vec<PublicKey>) {
    // send the list of txins to everyone except myself
    // TODO
}

fn receive_txins(
    participants: &Vec<PublicKey>,
    txin_map: &mut HashMap<PublicKey, Vec<(TXIN)>>,
    p_excl: &mut Vec<PublicKey>,
) {
    // receive TXINPackets from each participant, except myself.
    // Validate each TXIN using its accompanying ownership signature
    // If signature checks out, then add TXIN to the txin_map,
    // otherwise add respondent's public key to a list of excluded
    // participants for next round.
    // TODO
}

fn all_excluding(participants: &Vec<PublicKey>, p_excl: &Vec<PublicKey>) -> Vec<PublicKey> {
    fn member(p: PublicKey, pset: &Vec<PublicKey>) -> bool {
        for &px in pset {
            if p == px {
                return true;
            }
        }
        false
    }

    let mut rem = participants.clone();
    rem.retain(|&p| !member(p, p_excl));
    rem
}

fn make_transaction(
    participants: &Vec<PublicKey>,
    txins: &HashMap<PublicKey, Vec<TXIN>>,
    my_utxos: &Vec<(UTXO, Fr)>,
    utxos: &Vec<UTXO>,
    fee: u64,
    gamma_adj: Fr,
    my_pkey: &PublicKey,
    my_skey: &SecretKey,
) -> Transaction {
    // collect surviving TXINs
    let mut all_txins = Vec::<TXIN>::new();
    for p in participants {
        let mut other_txins = txins.get(&p).unwrap().clone();
        all_txins.append(&mut other_txins);
    }

    // compute secret key for my portion of collective signature
    let my_txins = txins.get(my_pkey).unwrap();
    let mut gamma_sum = Fr::zero();
    let mut gamma_delta_sum = Fr::zero();
    let mut txin_ct = 0;
    for txin in my_txins {
        txin_ct += 1;
        let (gamma, delta) = open_txin(txin, my_pkey, my_skey);
        gamma_sum += gamma;
        gamma_delta_sum += gamma * delta;
    }
    for (_, gamma) in my_utxos {
        gamma_sum -= *gamma;
    }
    let skfr = txin_ct * Fr::from(*my_skey) + gamma_sum + gamma_delta_sum;
    let eff_skey = SecretKey::from(skfr);

    // create a dummy sig just so we can form the transaction
    // and compute its hash
    let hash = Hash::from_str("dummy-placeholder");
    let dum_sig = curve1174::cpt::sign_hash(&hash, my_skey);

    let mut trans = Transaction {
        txins: all_txins,
        txouts: utxos.clone(),
        fee: fee,
        gamma_adj: gamma_adj,
        sig: dum_sig,
    };

    // fill in a proper signature
    let mut state = Hasher::new();
    trans.hash(&mut state);
    let t_hash = state.result();
    trans.sig = curve1174::cpt::sign_hash(&t_hash, &eff_skey);

    trans
}

fn open_txin(txin: &TXIN, my_pkey: &PublicKey, my_skey: &SecretKey) -> (Fr, Fr) {
    // locate the physical UTXO corresponding to txin
    // decrypt the encrypted payload
    // and return the enclosed (gamma, detla) cloaking factors
    // TODO
    (Fr::zero(), Fr::zero())
}

fn vs_run(
    participants: &Vec<PublicKey>,
    p_excl: &mut Vec<PublicKey>,
    my_pkey: &PublicKey,
    txins: &HashMap<PublicKey, Vec<TXIN>>,
    txouts: &Vec<ProposedUTXO>,
) -> Result<(Vec<(UTXO, Fr)>, Vec<UTXO>, u64, Fr), VsError> {
    // TODO
    // run rounds of this function in threads until it either fails completely
    // or succeeds the zero balance condition between TXINS and TXOUTS
    //
    // Each successive round uses fewer participants, growing the p_excl list
    //
    Ok((Vec::<(UTXO, Fr)>::new(), Vec::<UTXO>::new(), 0, Fr::zero()))
}

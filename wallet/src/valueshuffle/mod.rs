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
#![allow(non_snake_case)]

mod error;
pub use error::*;

mod message;
pub use message::*;

// use super::*;
use chrono::Utc;
use failure::Fail;
use std::collections::HashMap;
use stegos_blockchain::{Output, PaymentOutput, PaymentPayloadData, Transaction};
use stegos_crypto::bulletproofs::{fee_a, simple_commit};
use stegos_crypto::curve1174::cpt::{
    make_deterministic_keys, sign_hash, validate_sig, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::curve1174::ecpt::*;
use stegos_crypto::dicemix::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_serialization::traits::ProtoConvert;

// ========================================================================
// When a wallet wants to participate in a ValueShuffle session,
// it should advertise its desire by sending a message to the Facilitator
// node, along with its network ID (currently a pbc::secure::PublicKey).
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

// -------------------------------------------------

// -------------------------------------------------

type Fr = stegos_crypto::curve1174::fields::Fr;
type ECp = stegos_crypto::curve1174::ecpt::ECp;

type TXIN = Hash;
type ParticipantID = stegos_crypto::pbc::secure::PublicKey;

type UTXO = PaymentOutput;

// -------------------------------------------------

fn serialize_utxo(utxo: &UTXO) -> Vec<u8> {
    utxo.into_buffer().expect("Can't serialize UTXO")
}

fn deserialize_utxo(msg: &Vec<u8>) -> UTXO {
    UTXO::from_buffer(msg).expect("Can't deserialize UTXO")
}

// -------------------------------------------------
// Domain helpers...

fn times_G(val: Fr) -> ECp {
    // produce Pt = val*G
    simple_commit(val, Fr::zero())
}

// -------------------------------------------------

#[derive(Clone)]
pub enum ProposedUTXO {
    Payment(Payment),
    Data(Data),
}

#[derive(Clone)]
pub struct Payment {
    pub recip: PublicKey, // payee pkey (will be cloaked with Pkey+delta*gamma*G)
    pub amount: i64,
}

#[derive(Clone)]
pub struct Data {
    pub recip: PublicKey,
    pub amount: i64,
    pub data: String,
}

#[derive(Clone)]
pub struct TxinRecord {
    // Each TXIN UTXO may have been encoded toward a different
    // recipient pkey. So each must be accompanied by a proof of
    // ownership signature (checked by other participants), and
    // the corresponding SecretKey to which the UTXO was sent.
    // We need those keys in order to generate transaction signatures here.
    //
    pub txin: Hash,      // reference to UTXO on blockchain
    pub skey: SecretKey, // the corresponding secret key
}

struct ValidationData {
    // used to pass extra data to the blame discovery validator fn
    pub txins: HashMap<ParticipantID, Vec<TXIN>>,
    pub sigs: HashMap<ParticipantID, SchnorrSig>,
}

// -------------------------------------------------

pub fn vs_start(
    participants: &Vec<ParticipantID>, // all participants
    my_id: &ParticipantID,
    txins: &Vec<TxinRecord>,    // list of my TXINs
    txouts: &Vec<ProposedUTXO>, // list of my proposed UTXOs
    my_fee: i64,
    sid: &Hash, // unique obtained from Facilitator
) -> Result<Transaction, VsError> {
    // Perform initial argument checking
    // ... since we are providing our own TxinRecords
    // and ProposedUTXO, I won't bother checking them,
    // but all other participants will...
    //
    // If our data is bad, others will detect and exclude us
    // from participation in the round. We will get a timeout
    // waiting for additional data, and we should then try again.
    //
    // But since we are never notified of the reason for exclusion
    // we might endlessly try to pass off bad data without realizing it.
    //
    // So maybe we better check our data...

    // check if too many UTXOs
    if txouts.len() > MAX_UTXOS {
        return Err(VsError::VsTooManyUTXO);
    }

    // TXINs are checked, first thing, inside vs_run().

    // -----------------------------------------------------
    // Now prep arguments and launch protocol

    // run rounds till we either succeed, or fail completely
    let (tran, remaining_participants) = vs_run(participants, my_id, txins, txouts, my_fee, sid)?;

    let leader = leader_id(&remaining_participants);

    if *my_id == leader {
        // if I'm leader, then send the completed super-transaction
        // to the blockchain.
        send_super_transaction(&tran);
    }
    Ok(tran)
}

// -------------------------------------------------

fn vs_run(
    participants: &Vec<ParticipantID>,
    my_id: &ParticipantID,
    my_txins: &Vec<TxinRecord>,
    my_txouts: &Vec<ProposedUTXO>,
    my_fee: i64,
    sid: &Hash,
) -> Result<(Transaction, Vec<ParticipantID>), VsError> {
    // run rounds of this function in threads until it either fails completely
    // or succeeds the zero balance condition between TXINS and TXOUTS
    //
    // Each successive round uses fewer participants, growing the p_excl list
    // ----------------------------------------------------------------

    // validate each TXIN and get my initial signature keying info
    let mut my_txin_skey = Fr::zero();
    let mut txin_gamma_sum = Fr::zero();
    let mut shared_txins = Vec::<(TXIN, SchnorrSig)>::new();
    let mut amt_in = 0;
    for rec in my_txins {
        let utxo = get_utxo(&rec.txin)?;
        let (gamma, delta, amount) = open_utxo(&utxo, &rec.skey)?;
        let own_s = Fr::from(rec.skey) + gamma * delta;
        let own_skey = SecretKey::from(own_s);
        let hash = hash_utxo(&utxo);
        let own_sig = sign_hash(&hash, &own_skey);
        validate_ownership(&rec.txin, &own_sig)?;
        shared_txins.push((rec.txin.clone(), own_sig));
        my_txin_skey += own_s + gamma;
        txin_gamma_sum += gamma;
        amt_in += amount;
    }
    // check that we have a zero balance condition
    // might as well abort right now, if not...
    let mut amt_out = 0;
    my_txouts.iter().for_each(|rec| {
        amt_out += match rec {
            ProposedUTXO::Payment(rec) => rec.amount,
            ProposedUTXO::Data(rec) => rec.amount,
        }
    });
    if amt_in != amt_out + my_fee {
        return Err(VsError::VsBadTransaction);
    }

    // sort list of participants so all nodes will agree on
    // order dependent items
    // Ensure that we are a participant
    let mut parts = all_excluding(participants, &vec![*my_id]);
    parts.push(*my_id);
    parts.sort(); // put into consistent order
    let other_parts = all_excluding(&participants, &vec![*my_id]);

    // Generate initial session ID based on hash of client SID and participant list
    let sid_pre = {
        let mut state = Hasher::new();
        sid.hash(&mut state);
        participants.iter().for_each(|&p| p.hash(&mut state));
        state.result()
    };

    // At start of session we must share our TXINS with everyone.
    // Each TXIN is accompanied by our proof of ownership signature.
    send_txins(&other_parts, &shared_txins, &sid_pre);

    // get all the other TXINS and form the full collection
    let my_txins: Vec<TXIN> = my_txins.iter().map(|rec| rec.txin).collect();
    let mut all_txins: HashMap<ParticipantID, Vec<TXIN>> = HashMap::new();
    all_txins.insert(*my_id, my_txins);

    let mut p_excl = Vec::<ParticipantID>::new();
    receive_txins(&other_parts, &mut p_excl, &mut all_txins, &sid_pre);

    let mut round = 0;
    loop {
        // make new participant list
        let mut parts = all_excluding(&participants, &p_excl);
        if parts.len() < 3 {
            return Err(VsError::VsFail);
        }
        let mut other_parts = all_excluding(&parts, &vec![*my_id]);

        // incr round, and form new session ID
        round += 1;
        let sid = {
            let mut state = Hasher::new();
            "sid".hash(&mut state);
            sid_pre.hash(&mut state);
            (round as u32).hash(&mut state);
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

        let my_k = {
            let mut state = Hasher::new();
            "kVal".hash(&mut state);
            sid.hash(&mut state);
            my_txin_skey.hash(&mut state);
            Fr::from(state.result())
        };
        let my_sigK = times_G(my_k); // = my_k * G
        let my_sigKcmp = my_sigK.compress();

        let mut sigK_vals: HashMap<ParticipantID, ECp> = HashMap::new();
        sigK_vals.insert(*my_id, my_sigK);

        // Generate new cloaked sharing key set and share with others
        let (sess_sk, sess_pk) = make_session_key(my_txin_skey, &sid);
        send_session_key(&other_parts, &sess_pk, &my_sigKcmp, &sid);

        // Collect cloaked sharing keys from others
        let mut sess_pkeys: HashMap<ParticipantID, PublicKey> = HashMap::new();
        sess_pkeys.insert(*my_id, sess_pk);

        let mut p_excl_inner = Vec::<ParticipantID>::new();

        receive_session_keys(
            &other_parts,
            &mut p_excl_inner,
            &mut sess_pkeys,
            &mut sigK_vals,
            &sid,
        );

        if !p_excl_inner.is_empty() {
            merge_excl(&mut p_excl, &p_excl_inner);
            if parts.len() - p_excl_inner.len() < 3 {
                return Err(VsError::VsFail);
            }
            parts = all_excluding(&parts, &p_excl_inner);
            other_parts = all_excluding(&other_parts, &p_excl_inner);
            p_excl_inner.clear();
        }

        // Generate shared cloaking factors
        let k_cloaks = dc_keys(&other_parts, &sess_pkeys, my_id, &sess_sk, &sid);

        // Construct fresh UTXOS and gamma_adj
        let my_pairs = generate_fresh_utxos(my_txouts, &sess_sk);
        let mut my_utxos = Vec::<UTXO>::new();
        let mut my_gamma_adj = txin_gamma_sum;
        let mut my_signing_skey = my_txin_skey;
        my_pairs.iter().for_each(|(utxo, gamma)| {
            my_utxos.push(utxo.clone());
            my_gamma_adj -= *gamma;
            my_signing_skey -= *gamma;
        });

        let matrix = encode_matrix(&parts, &my_utxos, my_id, &k_cloaks);
        let mut matrices: HashMap<ParticipantID, DcMatrix> = HashMap::new();
        matrices.insert(*my_id, matrix.clone());

        // cloaked gamma_adj for sharing
        let mut gamma_adjs: HashMap<ParticipantID, Fr> = HashMap::new();
        let cloaked_gamma_adj = dc_encode_scalar(my_gamma_adj, &parts, my_id, &k_cloaks);
        gamma_adjs.insert(*my_id, cloaked_gamma_adj);

        // form commitments to our matrix and gamma sum
        let commit = hash_data(&matrix, cloaked_gamma_adj);

        // send sharing commitment to other participants
        send_commitment(&other_parts, &commit, &sid);

        // Collect and validate commitments from other participants
        let mut commits: HashMap<ParticipantID, Hash> = HashMap::new();
        commits.insert(*my_id, commit);

        receive_commitments(&other_parts, &mut p_excl_inner, &mut commits, &sid);

        if !p_excl_inner.is_empty() {
            merge_excl(&mut p_excl, &p_excl_inner);
            if parts.len() - p_excl_inner.len() < 3 {
                return Err(VsError::VsFail);
            }
            parts = all_excluding(&parts, &p_excl_inner);
            other_parts = all_excluding(&other_parts, &p_excl_inner);
        }

        // ---------------------------------------------------------------
        // NOTE:
        // from here to end, we keep newly excluded pkeys in a separate list
        // for use by potential blame discovery. Those newly excluded keys
        // will have had cloaking factors generated by us for them.
        //
        // If there are no further critical dropouts, then we can de-cloak the
        // remaining shared data with the keying info we are about to send everyone.
        //
        // In the event of additional critical dropouts, we have already merged
        // these additional dropouts into the exclusion list for the next round.
        // ---------------------------------------------------------------

        // collect the cloaking factors shared with non-responding participants
        // we share these with all other partipants, along with our cloaked data
        // in case anyone decides that we need a blame discovery session
        let mut all_excl_k_cloaks: HashMap<ParticipantID, HashMap<ParticipantID, Hash>> =
            HashMap::new();
        let mut my_excl_k_cloaks: HashMap<ParticipantID, Hash> = HashMap::new();
        for p in p_excl_inner.clone() {
            let cloak = k_cloaks.get(&p).expect("Can't access cloaking");
            my_excl_k_cloaks.insert(p, *cloak);
        }
        all_excl_k_cloaks.insert(*my_id, my_excl_k_cloaks.clone());

        // send committed and cloaked data to all participants
        send_cloaked_data(
            &other_parts,
            &matrix,
            &cloaked_gamma_adj,
            &my_excl_k_cloaks,
            &sid,
        );

        // At this point, if we don't hear valid responses from all
        // remaining participants, we abort and start a new session
        let mut p_excl_local_2 = Vec::<ParticipantID>::new();
        // collect cloaked contributions from others
        receive_cloaked_data(
            &other_parts,
            &mut p_excl_local_2,
            &commits,
            &mut matrices,
            &mut gamma_adjs,
            &mut all_excl_k_cloaks,
            &sid,
        );
        if !p_excl_local_2.is_empty() {
            // we can't do discovery on partial data
            // so merge local exclusions with outer list for
            // next session round
            merge_excl(&mut p_excl, &p_excl_local_2);
            continue;
        }

        // we got valid responses from all participants,
        let msgs = dc_decode(
            &parts,
            &matrices,
            my_id,
            MAX_UTXOS,
            MAX_CHUNKS,
            &p_excl_inner,
            &all_excl_k_cloaks,
        );
        let mut pkey_sum = ECp::inf(); // this produces 0*G in curve group

        let mut trn_txins = Vec::<TXIN>::new();
        parts.iter().for_each(|p| {
            let p_txins = all_txins.get(p).expect("Can't access TXINS");
            p_txins.iter().for_each(|txin| {
                trn_txins.push(txin.clone());
                let utxo = get_utxo(txin).expect("Can't access TXIN UTXO"); // TXINS should all be present by this point
                                                                            // these are already known good ECC points
                let pkey_pt = Pt::from(utxo.recipient)
                    .decompress()
                    .expect("Can't decompress TXIN recipient pkey");
                let cmt_pt = utxo
                    .proof
                    .vcmt
                    .decompress()
                    .expect("Can't decompress TXIN Bulletproof commitment");
                pkey_sum += pkey_pt + cmt_pt;
            });
        });
        // ---------------------------------------------------
        // TODO: decide on the fee structure
        let total_fee = 0i64;
        // ---------------------------------------------------
        pkey_sum -= fee_a(total_fee);

        let mut all_utxos = Vec::<UTXO>::new();
        for msg in msgs {
            let utxo = deserialize_utxo(&msg);
            all_utxos.push(utxo.clone());
            let cmt_pt = match utxo.proof.vcmt.decompress() {
                Ok(pt) => pt,
                _ => ECp::inf(), // not a good ECC point, dummy up, but may fail later
            };
            pkey_sum -= cmt_pt;
        }
        let gamma_adj = dc_scalar_open(&gamma_adjs, &p_excl_inner, &all_excl_k_cloaks);

        // Compute the capK value for collective signatures
        let mut sigK_sum = my_sigK;
        other_parts.iter().for_each(|p| {
            // these have already been decompressed and
            // checked for validity in the receive
            sigK_sum += *sigK_vals.get(p).expect("Can't access sigK");
        });
        let pkey_sum = PublicKey::from(pkey_sum);
        let sigK_sum = sigK_sum.compress();
        let mut trans = make_transaction(
            &sess_sk,
            &trn_txins,
            &all_utxos,
            total_fee,
            gamma_adj,
            &SecretKey::from(my_signing_skey),
            &pkey_sum,
            &sigK_sum,
            my_k,
        );

        // fill in multi-signature...
        let sig = trans.sig;
        send_signature(&other_parts, &sig, &sid);

        let mut all_sigs: HashMap<ParticipantID, SchnorrSig> = HashMap::new();
        all_sigs.insert(*my_id, sig);
        receive_signatures(&other_parts, &mut p_excl_local_2, &mut all_sigs, &sid_pre);

        if !p_excl_local_2.is_empty() {
            // we can't form a proper super-transaction without all signatures
            // so merge exclusions to outer list and retry
            merge_excl(&mut p_excl, &p_excl_local_2);
            continue;
        }

        let mut u_sum = sig.u;
        let mut sigK_sum = sig.K.decompress().expect("Can't decompress sigK"); // known to be good ECC point
        other_parts.iter().for_each(|p| {
            let other_sig = all_sigs.get(p).expect("Can't access sig");
            u_sum += other_sig.u;
            // known good ECC point from receive checking
            sigK_sum += other_sig.K.decompress().expect("Can't decompress sigK");
        });
        trans.sig = SchnorrSig {
            u: u_sum,
            K: sigK_sum.compress(),
        };
        if validate_transaction(&trans) {
            return Ok((trans, parts));
        }
        // ------------------------------------------------------
        // Something is wrong with super-transaction:
        // (1) something phony in the transaction
        //    (1a) phony UTXO
        //    (1b) phony gamma_adj
        // (1) not all nodes agreed on its structure
        // (2) someone sent a phony signature

        // Enter blame discovery for retry sans cheater
        // broadcast our session skey and begin a round of blame discovery
        send_session_skey(&other_parts, &sess_sk, &sid);

        let mut sess_skeys: HashMap<ParticipantID, SecretKey> = HashMap::new();
        sess_skeys.insert(*my_id, sess_sk);
        receive_session_skeys(&other_parts, &mut p_excl_local_2, &mut sess_skeys, &sid);

        if !p_excl_local_2.is_empty() {
            // can't perform discovery without all the session_skeys,
            // so absorb new exclusions for next round
            merge_excl(&mut p_excl, &p_excl_local_2);
            continue;
        }
        // everyone responded with their secret session key
        // let's do blame discovery
        // collect pkeys of cheaters and add to exclusions for next round
        let data = ValidationData {
            txins: all_txins.clone(),
            sigs: all_sigs,
        };
        let new_p_excl = dc_reconstruct(
            &parts,
            &sess_pkeys,
            my_id,
            &sess_skeys,
            &matrices,
            &gamma_adjs,
            &sid,
            &p_excl_inner,
            &all_excl_k_cloaks,
            validate_uncloaked_contrib,
            &data,
        );
        merge_excl(&mut p_excl, &new_p_excl);
        // and begin another round
    }
}

// -------------------------------------------------

fn hash_utxo(utxo: &UTXO) -> Hash {
    let mut state = Hasher::new();
    utxo.hash(&mut state);
    state.result()
}

fn validate_ownership(txin: &Hash, owner_sig: &SchnorrSig) -> Result<bool, VsError> {
    let utxo = get_utxo(txin)?;
    let hash = hash_utxo(&utxo);
    match validate_sig(&hash, owner_sig, &utxo.recipient) {
        Ok(tf) => {
            if !tf {
                return Err(VsError::VsBadTXIN);
            } else {
                return Ok(true);
            }
        }
        _ => {
            // sigK or utxo.recipient pkey must have been bad ECC points
            return Err(VsError::VsBadTXIN);
        }
    }
}

fn leader_id(participants: &Vec<ParticipantID>) -> ParticipantID {
    // select the leader as the public key having the lowest hash
    let mut candidates: Vec<(ParticipantID, Hash)> = participants
        .iter()
        .map(|&p| (p, Hash::digest(&p)))
        .collect();
    // there must be at least 3 of us in here...
    let (mut min_pkey, mut min_hash) = candidates.pop().expect("Empty candidates list");
    for (pkey, hash) in candidates {
        if hash < min_hash {
            min_pkey = pkey;
            min_hash = hash;
        }
    }
    min_pkey
}

// -----------------------------------------------------------------
// Participation helpers...

fn merge_excl(p_excl: &mut Vec<ParticipantID>, p_excl_new: &Vec<ParticipantID>) {
    p_excl_new.iter().for_each(|&p| p_excl.push(p));
}

fn all_excluding(
    participants: &Vec<ParticipantID>,
    p_excl: &Vec<ParticipantID>,
) -> Vec<ParticipantID> {
    fn member(p: ParticipantID, pset: &Vec<ParticipantID>) -> bool {
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

// -----------------------------------------------------------------

fn make_transaction(
    my_skey: &SecretKey,
    txins: &Vec<TXIN>,
    utxos: &Vec<UTXO>,
    total_fee: i64,
    gamma_adj: Fr,
    my_signing_skey: &SecretKey,
    pkey_sum: &PublicKey,
    sigK_sum: &Pt,
    my_k: Fr,
) -> Transaction {
    let mut inputs = Vec::<Output>::new();
    for txin in txins {
        let utxo = get_utxo(txin).expect("Can't access TXIN UTXO");
        inputs.push(Output::PaymentOutput(utxo));
    }
    let mut outputs = Vec::<Output>::new();
    for utxo in utxos {
        outputs.push(Output::PaymentOutput(utxo.clone()));
    }
    let mut trans =
        stegos_blockchain::Transaction::new(my_skey, &inputs, &outputs, gamma_adj, total_fee)
            .expect("Can't construct the super-transaction");

    // fill in a proper signature
    // We have to do this manually, instead of calling the crypto primitive
    // because we don't know the secret key of the super-transactoin
    let t_hash = {
        let mut state = Hasher::new();
        sigK_sum.hash(&mut state);
        pkey_sum.hash(&mut state);
        trans.hash(&mut state);
        state.result()
    };
    let u_val = my_k + Fr::from(t_hash) * Fr::from(*my_signing_skey);
    let capK_val = times_G(my_k);
    trans.sig = SchnorrSig {
        u: u_val,
        K: capK_val.compress(),
    };
    trans
}

fn validate_transaction(tx: &Transaction) -> bool {
    // Check that super-transaction signature validates
    // against transaction contents, just like a validator would do.

    let mut inputs = Vec::<Output>::new();
    for txin in tx.body.txins.clone() {
        let utxo = get_utxo(&txin).expect("Can't access TXIN UTXO");
        inputs.push(Output::PaymentOutput(utxo.clone()));
    }
    match tx.validate(&inputs) {
        Ok(_) => true,
        _ => false,
    }
    /*
    // TODO - provisional code just to get clean compile
    let hash = {
        let mut state = Hasher::new();
        tx.hash(&mut state);
        state.result()
    };
    let mut pkey = ECp::inf();
    for txin in tx.txins.clone() {
        let utxo = get_utxo(&txin);
        pkey += Pt::from(utxo.recipient)
            .decompress()
            .expect("Can't decompress TXIN recipient pkey")
            + utxo
                .proof
                .vcmt
                .decompress()
                .expect("Can't decompress TXIN Bulletproof commitment");
    }
    for utxo in tx.txouts.clone() {
        pkey -= utxo
            .proof
            .vcmt
            .decompress()
            .expect("Can't decompress UTXO recipient pkey");
    }
    pkey -= fee_a(tx.fee);
    let pkey = PublicKey::from(pkey);
    match validate_sig(&hash, &tx.sig, &pkey) {
        Ok(tf) => tf,
        _ => false,
    }
    */
}

fn validate_uncloaked_contrib(
    pid: &ParticipantID,
    msgs: &Vec<Vec<u8>>,
    gamma_adj: Fr,
    data: &ValidationData,
) -> bool {
    // accept a list of uncloaked messages that belong to pkey, along with gamma sum of his,
    // convert the messages into his UTXOS, and then verify that they satisfy the zero balance
    // condition with his TXIN.

    let all_txins = &data.txins;
    let all_sigs = &data.sigs;
    let mut txin_sum = ECp::inf();
    let mut eff_pkey = ECp::inf();
    let mut state = Hasher::new();
    for txin in all_txins.get(pid).expect("Can't access TXIN") {
        // all txins have already been checked for validity
        txin.hash(&mut state);
        let utxo = get_utxo(txin).expect("Can't access TXIN UTXO");
        let pkey_pt = Pt::from(utxo.recipient)
            .decompress()
            .expect("Can't decompress TXIN recipient pkey");
        let cmt_pt = utxo
            .proof
            .vcmt
            .decompress()
            .expect("Can't decompress TXIN Bulletproof commitment");
        txin_sum += cmt_pt;
        eff_pkey += pkey_pt + cmt_pt;
    }
    let mut txout_sum = ECp::inf();
    for msg in msgs {
        let utxo = deserialize_utxo(msg);
        utxo.hash(&mut state);
        let cmt_pt = match utxo.proof.vcmt.decompress() {
            Ok(pt) => pt,
            _ => {
                return false;
            }
        };
        txout_sum += cmt_pt;
        eff_pkey -= cmt_pt;
    }
    // TODO: Fix this to proper fee
    let fee = 0;
    // check for zero balance condition
    if txin_sum != txout_sum + simple_commit(gamma_adj, Fr::from(fee)) {
        return false;
    }
    // check signature on this portion of transaction
    (fee as u64).hash(&mut state);
    gamma_adj.hash(&mut state);
    let t_hash = state.result();
    eff_pkey -= fee_a(fee);
    let eff_pkey = PublicKey::from(eff_pkey.compress());
    let sig = all_sigs.get(pid).expect("Can't access signature");
    match validate_sig(&t_hash, &sig, &eff_pkey) {
        Ok(tf) => tf,
        _ => false,
    }
}

fn encode_matrix(
    participants: &Vec<ParticipantID>,
    my_utxos: &Vec<UTXO>,
    my_id: &ParticipantID,
    k_cloaks: &HashMap<ParticipantID, Hash>,
) -> DcMatrix {
    // Encode UTXOs to matrix for cloaked sharing
    let mut matrix = Vec::<DcSheet>::new();
    let mut sheet_id = 0;
    for utxo in my_utxos.clone() {
        sheet_id += 1;
        let msg = serialize_utxo(&utxo);
        let sheet = dc_encode_sheet(sheet_id, MAX_CHUNKS, &msg, participants, my_id, &k_cloaks);
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
            MAX_CHUNKS,
            &null_msg,
            participants,
            my_id,
            &k_cloaks,
        );
        matrix.push(sheet);
    }

    matrix
}

fn get_utxo(_txin: &TXIN) -> Result<UTXO, VsError> {
    // TODO - provisional code just to get clean compile

    // construct a dummy UTXO
    let (skey, pkey, _) = make_deterministic_keys(b"Dummy");
    let (utxo, _gamma) = stegos_blockchain::PaymentOutput::new(0, &skey, &pkey, 0)
        .expect("Can't produce dummy UTXO");
    Ok(utxo)
}

fn open_utxo(utxo: &UTXO, skey: &SecretKey) -> Result<(Fr, Fr, i64), VsError> {
    // decrypt the encrypted payload of the UTXO and
    // return the (gamma, delta, amount)
    let data = match utxo.decrypt_payload(skey) {
        Ok(data) => data,
        _ => {
            return Err(VsError::VsBadTXIN);
        }
    };
    Ok((data.gamma, data.delta, data.amount))
}

fn generate_fresh_utxos(txouts: &Vec<ProposedUTXO>, my_skey: &SecretKey) -> Vec<(UTXO, Fr)> {
    // generate a fresh set of UTXOs based on the list of proposed UTXOs
    // Return new UTXOs with fresh randomness, and the sum of all gamma factors

    let tstamp = Utc::now().timestamp() as u64;
    let mut outs = Vec::<(UTXO, Fr)>::new();
    for txout in txouts.clone() {
        let pair = match txout {
            ProposedUTXO::Payment(pmt) => {
                PaymentOutput::new(tstamp, my_skey, &pmt.recip, pmt.amount)
                    .expect("Can't produce Payment UTXO")
            }
            ProposedUTXO::Data(dat) => {
                let data = PaymentPayloadData::Comment(dat.data);
                PaymentOutput::with_payload(tstamp, my_skey, &dat.recip, dat.amount, data)
                    .expect("Can't produce Data UTXO")
            }
        };
        outs.push(pair);
    }
    outs
}

fn make_session_key(skey: Fr, sid: &Hash) -> (SecretKey, PublicKey) {
    let seed = {
        let mut state = Hasher::new();
        sid.hash(&mut state);
        skey.hash(&mut state);
        state.result()
    };
    let (skey, pkey, _) = make_deterministic_keys(&seed.into_bytes());
    (skey, pkey)
}

fn hash_data(matrix: &DcMatrix, cloaked_gamma_adj: Fr) -> Hash {
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
    state.result()
}

// -------------------------------------------------

fn send_session_key(
    participants: &Vec<ParticipantID>,
    sess_pkey: &PublicKey,
    sess_KSig: &Pt,
    sid: &Hash,
) {
    // send our session_pkey to all participants

    // TODO - provisional code just to get clean compile
}

fn receive_session_keys(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    sess_pkeys: &HashMap<ParticipantID, PublicKey>,
    sess_Ksigs: &HashMap<ParticipantID, ECp>,
    sid: &Hash,
) {
    // collect session pkeys from all participants.
    // If any participant does not answer, add him to the exclusion list, p_excl

    // TODO - provisional code just to get clean compile
}

fn receive_session_skeys(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    sess_skeys: &mut HashMap<ParticipantID, SecretKey>,
    sid: &Hash,
) {
    // receive session skeys from all participants
    // non-respondents are added to p_excl

    // TODO - provisional code just to get clean compile
}

fn send_session_skey(participants: &Vec<ParticipantID>, skey: &SecretKey, sid: &Hash) {
    // send the session secret key to all participants

    // TODO - provisional code just to get clean compile
}

fn receive_cloaked_data(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    commits: &HashMap<ParticipantID, Hash>,
    matrices: &mut HashMap<ParticipantID, DcMatrix>,
    sum_gammas: &mut HashMap<ParticipantID, Fr>,
    excl_k_cloaks: &mut HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,
    sid: &Hash,
) {
    // receive cloaked data from each participant.
    // If participants don't respond, or respond
    // with invalid data, as per previous commitment,
    // then add them to exclusion list.

    // TODO - provisional code just to get clean compile
}

fn send_cloaked_data(
    participants: &Vec<ParticipantID>,
    matrix: &DcMatrix,
    sum: &Fr,
    excl_k_cloaks: &HashMap<ParticipantID, Hash>,
    sid: &Hash,
) {
    // send matrix, sum, and excl_k_cloaks to all participants

    // TODO - provisional code just to get clean compile
}

fn send_commitment(participants: &Vec<ParticipantID>, commit: &Hash, sid: &Hash) {
    // send our commitment to cloaked data to all other participants

    // TODO - provisional code just to get clean compile
}

fn receive_commitments(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    commits: &mut HashMap<ParticipantID, Hash>,
    sid: &Hash,
) {
    // receive commitments from all other participants
    // if any fail to send commitments, add them to exclusion list p_excl

    // TODO - provisional code just to get clean compile
}

fn receive_signatures(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    sigs: &mut HashMap<ParticipantID, SchnorrSig>,
    sid: &Hash,
) {
    // collect signatures from all participants
    // should not count as collected unless signature is partially valid.
    //
    // Partial valid = K component is valid ECC point

    // TODO
}

fn send_signature(participants: &Vec<ParticipantID>, sig: &SchnorrSig, sid: &Hash) {
    // send signature to leader node
    // TODO
}

fn send_super_transaction(transaction: &Transaction) {
    // send final superTransaction to blockchain
    // TODO
}

fn send_txins(participants: &Vec<ParticipantID>, txins: &Vec<(TXIN, SchnorrSig)>, sid: &Hash) {
    // send the list of txins to everyone except myself
    // TODO
}

fn receive_txins(
    participants: &Vec<ParticipantID>,
    p_excl: &mut Vec<ParticipantID>,
    txin_map: &mut HashMap<ParticipantID, Vec<(TXIN)>>,
    sid: &Hash,
) {
    // receive TXINPackets from each participant.
    // Validate each TXIN using its accompanying ownership signature
    // If signature checks out, then add TXIN to the txin_map,
    // otherwise add respondent's public key to a list of excluded
    // participants for next round.
    // TODO
}

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

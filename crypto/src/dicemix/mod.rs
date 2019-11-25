//! mod.rs - DiceMix for secure and anonymous info exchange

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

#![allow(unused)]

pub mod ffi;

use crate::bulletproofs::*;
use crate::hash::{Hash, Hashable, Hasher};
use crate::pbc;
use crate::scc;
use crate::utils::u8v_to_hexstr;
use crate::CryptoError;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int};
use std::result;
use std::time::{Duration, SystemTime};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

// ------------------------------------------------
/*
The DiceMix matrix... a multi-dimensional matrix of message
fragments.

For each user, a submatrix is indexed by (message, fragment, pkey),
where "message" indexes which of N messages are being sent,
      "fragment" indexes the fragments of each message
         (in our case, fragment is converted into Fr element), and
      "pkey" indexes one per public key of all other participants.
         (this index carries the modular powers of the fragment)

The complete DiceMix matrix is composed of a pile of these individual matrices,
one for each participant in the session, and indexed by "pkey".

Messages are split into fixed-length chunks, and each chunk is converted
to a field element in Fr. To avoid problems of distinguishability,
all messages should be the same length and contain the same number of chunks.

For each chunk, modular powers of the chunk are cloaked and distributed
across the "pkey" dimension of the submatrix. Bringing together all the
submatrices from other participants, and forming a sum of these powers in
each chunk cell, permits the cloaking factors to cancel out of the sums,
and the set of chunk powers can be solved to derive the original chunk
values from each participant.

Every message contains at least one chunk. If there are more, additional
chunks are prefixed with a (hopefully!) unique hash tag, based on the hash
of the first chunk, so that associated chunks can be located in sequence,
to reconstruct the original messages.

The first chunk contain MAX_BYTES bytes before conversion to Fr value. The
following chunks contain NCHUNK = MAX_BYTES - NPREF bytes of data, along
with the hash tag prefix.

Since conversion to Fr domain expects 32 bytes in little-endian format,
the hash tag will comprise the least significant bytes of the value.
Every chunk has Fr value < |Fr|. Since |Fr| approx = 2^249, we must insist
that every chunk have value with 248 bits = 31 bytes. The last byte of
every chunk value will be zero.

The beauty of this algorithm is that, while full messages are
obtained from each participant, nobody can identify which participant
sent any particular message. Anonymity is preserved when at least 3
participants engage.
*/

// -------------------------------------------------

use scc::Fr;
use scc::Pt;

use scc::PublicKey;
use scc::SchnorrSig;
use scc::SecretKey;
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ParticipantID {
    pub pkey: pbc::PublicKey,
    pub seed: [u8; 32],
}

impl ParticipantID {
    pub fn new(pkey: pbc::PublicKey, seed: [u8; 32]) -> Self {
        ParticipantID { pkey, seed }
    }

    pub fn from_pk(pkey: pbc::PublicKey) -> Self {
        let seed = [0u8; 32];
        ParticipantID { pkey, seed }
    }
}

impl Hashable for ParticipantID {
    fn hash(&self, state: &mut Hasher) {
        self.pkey.hash(state);
        self.seed.hash(state);
    }
}

impl fmt::Display for ParticipantID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pkey, u8v_to_hexstr(&self.seed[0..3]))
    }
}

pub type DcRow = Vec<Fr>; // one cell per chunk
pub type DcSheet = Vec<DcRow>;
pub type DcMatrix = Vec<DcSheet>;

// -------------------------------------------------

const SLOT_BYTES: usize = 32; // must correspond to Fr bytes
const MAX_BYTES: usize = 31; // for Fr we need < 254 bits
const NPREF: usize = 3; // bytes - will 24 bits be long enough?
pub const NCHUNK: usize = MAX_BYTES - NPREF; // nbr bytes of message in prefixed chunks

// -------------------------------------------------

fn prep_pref(v: &mut [u8; 32]) {
    // Hash the vector v and stuff NPREF bytes
    // of the hash over the first bytes of v.
    let h = Hash::from_vector(v);

    let p = h.bits();
    for i in 0..NPREF {
        v[i] = p[i];
    }
}

pub fn split_message(msg: &[u8], max_cols: Option<usize>) -> DcRow {
    // split a long message into elements < |Fr|
    //
    // First element is used to compute an id hash
    // that becomes prefixed on to all following
    // segments. For now, we use a 4-byte prefix.
    //
    // In the encoding process, recall that
    // conversions from bytes to Fr require
    // little-endian format in the bytes.
    //
    // With optional parameter max_chunks, if it is provided as None,
    // then the message is split into as many chunks as it requires.
    // And the vector of chunks is returned. Its length can be queried by
    // the calling function.
    //
    // When max_chunks is provided as Some(size), then the message is
    // split into chunks and padded at the end with zero values up to
    // that maximum length. It is an error to have message require more
    // chunks than the specified size.

    fn umin(a: usize, b: usize) -> usize {
        if a <= b {
            a
        } else {
            b
        }
    }

    fn rem_len(nvec: usize, start: usize) -> usize {
        if nvec > start {
            nvec - start
        } else {
            0
        }
    }

    fn stuff_slot(dst: &mut [u8], src: &[u8], start1: usize, start2: usize, nel: usize) {
        let ndst = rem_len(dst.len(), start1);
        let nsrc = rem_len(src.len(), start2);
        let n = umin(nel, umin(ndst, nsrc));
        for i in 0..n {
            dst[start1 + i] = src[start2 + i];
        }
        for i in n..umin(ndst, nel) {
            dst[start1 + i] = 0; // stuff MSB's
        }
    }

    let mut out = Vec::<Fr>::new();

    // form first segment
    let mut seg: [u8; SLOT_BYTES] = [0u8; SLOT_BYTES];
    stuff_slot(&mut seg, &msg, 0, 0, MAX_BYTES);
    out.push(Fr::try_from_bytes(&seg).expect("ok"));
    let mut offs = MAX_BYTES;
    let nb = msg.len();
    let mut ncols = 1;
    if offs < nb {
        // form segment prefix
        prep_pref(&mut seg);

        // accum remaining segmemnts with prefix
        while offs < nb {
            ncols += 1;
            match max_cols {
                None => {}
                Some(ncmax) => assert!(ncols <= ncmax, "Message requires too many cols"),
            }
            stuff_slot(&mut seg, &msg, NPREF, offs, NCHUNK);
            // Fr::try_from_bytes() checks for valid input range 0 <= val < modulus
            out.push(Fr::try_from_bytes(&seg).expect("ok"));
            offs += NCHUNK;
        }
    }
    match max_cols {
        None => {}
        Some(ncmax) => {
            for _ in ncols..ncmax {
                out.push(Fr::zero());
            }
        }
    }
    out
}

fn gen_cell_seed(sheet: usize, chunk: usize, expon: usize) -> Vec<u8> {
    format!("sheet: {} chunk: {} expon: {}", sheet, chunk, expon).into_bytes()
}

fn index_vec(dim: usize) -> Vec<usize> {
    let mut ans = vec![0; dim];
    for ix in 1..dim {
        ans[ix] = ix;
    }
    ans
}

fn exp_vec(base: &Fr, n: u64) -> Vec<Fr> {
    let mut vans = Vec::<Fr>::new();
    let base = Scalar::from(*base);
    let mut tmp = base.clone();
    vans.push(Fr::from(base.clone()));
    for i in 1..n {
        tmp *= base;
        vans.push(Fr::from(tmp.clone()));
    }
    vans
}

pub fn dc_encode_sheet(
    sheet: usize,
    max_chunks: usize,
    msg: &[u8],
    participants: &Vec<ParticipantID>,
    my_id: &ParticipantID,
    share_cloaks: &HashMap<ParticipantID, Hash>,
) -> DcSheet {
    // Accept a byte string message and split into chunks.
    // Form a row for each chunk, and plant modular power of chunk^(col+1),
    // add row-column cloaking factor, and place into
    // successive rows.
    //
    // Rows label cardinal index of participant, and columns label exponent index.
    //
    // Return a 2-D vector of result.

    // remove ourself from the participants list, if present
    let parts: Vec<ParticipantID> = participants
        .iter()
        .filter(|&&p| p != *my_id)
        .map(|p| p.clone())
        .collect();
    let nparts = parts.len() + 1; // one row for each of us, including me
    let chunks = split_message(&msg, Some(max_chunks));
    let nchunks = chunks.len();
    index_vec(nchunks)
        .par_iter()
        .map(|&r_ix| {
            let mut row = exp_vec(&chunks[r_ix], nparts as u64);
            for c_ix in 0..nparts {
                let seed_str = gen_cell_seed(sheet, r_ix, c_ix);
                row[c_ix] += dc_slot_pad(&parts, &my_id, share_cloaks, &seed_str);
            }
            row
        })
        .collect()
}

fn dc_slot_pad(
    participants: &Vec<ParticipantID>,
    my_id: &ParticipantID,
    share_cloaks: &HashMap<ParticipantID, Hash>,
    seed: &Vec<u8>,
) -> Fr {
    // construct a self-cancelling cloaking factor based on the seed.
    participants
        .iter()
        .filter(|&p| *p != *my_id)
        .fold(Fr::zero(), |sum, p| {
            // excluding ourself, which would have no effect anyway,
            // but would probably not have a share_cloaks entry for ourself.
            let share_cloak = share_cloaks.get(p).unwrap();
            let mut state = Hasher::new();
            share_cloak.hash(&mut state);
            (*seed).hash(&mut state);
            let h = state.result();
            let val = Fr::from(h);
            if *my_id < *p {
                sum - val
            } else {
                sum + val
            }
        })
}

// -----------------------------------------------------------------------

fn stuff_msg(out: &mut Vec<u8>, seg: &[u8; 32], start: usize, nel: usize) {
    // stuff some bytes of a chunk into a collecting byte string
    for i in start..(start + nel) {
        out.push(seg[i]);
    }
}

pub fn dc_decode(
    participants: &Vec<ParticipantID>,
    mats: &HashMap<ParticipantID, DcMatrix>,
    my_id: &ParticipantID,
    nsheets: usize,
    nchunks: usize,
    p_excl: &Vec<ParticipantID>,
    k_excl: &HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    // Accept a 4-D array (vector of 3-D vectors) containing
    // modular powers of cloaked chunks. Split along first dimension,
    // which represents the DiceMix matrix from each participant.
    // Add corresponding cells from each matrix to produce a result
    // 3-D matrix of unencrypted chunk power sums.
    //
    // For each sheet of the 3-D result matrix, we have one message from
    // each participant. Each row represents the power sum of message chunks,
    // with the modular exponent labeled by the row number, starting at 1.
    // The columns of a sheet are labeled by chunk index.
    //
    // Call on power sum polynomial root finder to recover all chunks
    // in each column, one chunk per user in some unknown order.
    //
    // Reassemble byte string messgaes from each user, by concatenating
    // cells from each column with the same hash-id prefix.
    //
    // Return the vector of messages. Each message represents a serialization
    // of a UTXO or a TXIN reference, obtained from someone, we just don't
    // know who.
    //
    fn has_hash_prefix(seg: &[u8], pref: &[u8]) -> bool {
        for i in 0..NPREF {
            if seg[i] != pref[i] {
                return false;
            }
        }
        true
    }

    // From a vector of responses from participants,
    // form the exclusion list for missing matrices,
    // and check to be sure that all matrices have the same
    // dimensions.
    let dim_p = participants.len() + p_excl.len(); // includes me, and MIA's
    let dim_r = nchunks;
    let dim_c = dim_p;
    let dim_s = nsheets;
    for p in participants {
        let m = mats.get(p).unwrap();
        assert!(dim_s == m.len(), "Mismatch nbr sheets in matrix");
        for sheet in m {
            assert!(dim_r == sheet.len(), "Mismatch nbr rows in matrix");
            for row in sheet {
                assert!(dim_c == row.len(), "Mismatch nbr cols in matrix");
            }
        }
    }

    let msgs_rs: Vec<Result<Vec<Vec<u8>>, CryptoError>> = index_vec(dim_s)
        .par_iter()
        .map(|&s_ix| {
            // operate on one sheet at a time
            // (one message from each participant)
            let mut sheet_of_results: Vec<Result<DcRow, CryptoError>> = index_vec(dim_r)
                .par_iter()
                .map(|&r_ix| {
                    // each row contains the cloaked powers of a chunk
                    let mut row = Vec::<Fr>::new();
                    for c_ix in 0..dim_c {
                        // dc_open forms a sum of powers and automatically
                        // uncloaks the power sum
                        row.push(dc_open(
                            participants,
                            &mats,
                            s_ix,
                            r_ix,
                            c_ix,
                            p_excl,
                            k_excl,
                        ));
                    }
                    // find the roots (original chunks) for the polynomial
                    // corresponding to this sequence of power sums.
                    dc_solve(&row)
                })
                .collect(); // we now have a sheet of uncloaked chunks

            match sheet_of_results.iter().find(|&x| x.is_err()) {
                Some(Ok(_)) => unreachable!(),
                Some(Err(_)) => Err(CryptoError::DiceMixNoSolution),
                None => {
                    let mut sheet: Vec<DcRow> = sheet_of_results
                        .iter()
                        .map(|x| x.as_ref().unwrap().clone())
                        .collect();

                    // The hash tag of the first chunk from any participant will be
                    // a prefix on corresponding chunks in successive columns.
                    // Here we reassemble the byte-string messages from each participant.

                    let mut msgs = Vec::<Vec<u8>>::new();
                    for m_ix in 0..dim_c {
                        // scan all rows for msgs
                        let frval = &sheet[0][m_ix];
                        if *frval != Fr::zero() {
                            // if leading chunk is zero, then no msg in this row
                            let mut msg = Vec::<u8>::new();
                            let mut chunk1 = frval.to_bytes();
                            stuff_msg(&mut msg, &chunk1, 0, MAX_BYTES);
                            prep_pref(&mut chunk1);
                            for r in 1..dim_r {
                                // try to collect one chunk from each row
                                let mut found = false;
                                for c in 0..dim_c {
                                    // scanning all cols for a chunk in that column
                                    let frval = &sheet[r][c];
                                    if *frval != Fr::zero() {
                                        // ignore zero chunk values
                                        let chunk = frval.to_bytes();
                                        if has_hash_prefix(&chunk, &chunk1) {
                                            stuff_msg(&mut msg, &chunk, NPREF, NCHUNK);
                                            sheet[r][c] = Fr::zero(); // shorten next peek
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                                if !found {
                                    // no chunk found, we must be finished with this msg
                                    break;
                                }
                            }
                            msgs.push(msg);
                        }
                    }
                    Ok(msgs)
                }
            }
        })
        .collect(); // we now have collection of messages per sheet
                    // concatenate message groups into a list of messages
                    // each sheet produces a group of messages, one per participant
    match msgs_rs.iter().find(|&m| m.is_err()) {
        Some(&Ok(_)) => unreachable!(),
        Some(&Err(_)) => Err(CryptoError::DiceMixNoSolution),
        None => {
            let msgs: Vec<Vec<Vec<u8>>> = msgs_rs
                .iter()
                .map(|m| m.as_ref().unwrap().clone())
                .collect();
            let mut out = Vec::<Vec<u8>>::new();
            for clump in msgs {
                for msg in clump {
                    out.push(msg);
                }
            }
            Ok(out) // we just need a simple collection of messages
        }
    }
}

fn dc_open(
    participants: &Vec<ParticipantID>,
    mats: &HashMap<ParticipantID, DcMatrix>,
    sheet: usize,
    row: usize,
    col: usize,
    p_excl: &Vec<ParticipantID>,
    k_excl: &HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,
) -> Fr {
    let mut pwrsum = mats
        .iter()
        .fold(Fr::zero(), |sum, (_, mat)| sum + mat[sheet][row][col]);
    if !p_excl.is_empty() {
        let seed_str = gen_cell_seed(sheet, row, col);
        participants.iter().for_each(|p| {
            let ktbl = k_excl.get(p).expect("can't get k_excl");
            pwrsum -= dc_slot_pad(p_excl, p, ktbl, &seed_str);
        });
    }
    pwrsum
}

// ----------------------------------------------------------------------
// FLINT Solver interface...
// (shamelessly adapted from Dedis DiceMix Master)

const RET_OK: c_int = 0;
const RET_INVALID: c_int = 1;
const RET_NON_MONIC_ROOT: c_int = 2;
const RET_NOT_ENOUGH_ROOTS: c_int = 3;

fn dc_solve(col: &Vec<Fr>) -> Result<Vec<Fr>, CryptoError> {
    fn c_str(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    // For Curve25519 the modulus is 2^255-19 (embedding field)
    // Both the Ristretto group and the Ed25519 basepoint have prime order
    // |Fr| = 2^{252} + 27742317777372353535851937790883648493 .
    let s_fr_mod = c_str("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");

    let n = col.len();

    let s_col: Vec<_> = col.iter().map(|sum| c_str(&sum.to_hex())).collect();
    let s_col_ptrs: Vec<_> = s_col.iter().map(|s| s.as_ptr()).collect();

    let mut out_messages_hex = vec![vec![0u8; 65]; n];
    let out_messages_hex_ptrs: Vec<_> = out_messages_hex
        .iter_mut()
        .map(|s| s.as_mut_ptr())
        .collect();

    let ret;
    unsafe {
        ret = ffi::solve(
            out_messages_hex_ptrs.as_ptr() as *const *mut c_char,
            s_fr_mod.as_ptr(),
            s_col_ptrs.as_ptr(),
            n,
        );
    }
    match ret {
        RET_OK => {
            /*
                        let msgs: Vec<&str> = out_messages_hex
                            .iter()
                            .map(|m_hex| {
                                let leading_non_zero = m_hex.iter().take_while(|c| **c != 0).count();
                                ::std::str::from_utf8(&m_hex[0..leading_non_zero]).unwrap()
                            })
                            .collect();
                        dbg!(&msgs);
            */
            Ok(out_messages_hex
                .iter()
                .map(|m_hex| {
                    let leading_non_zero = m_hex.iter().take_while(|c| **c != 0).count();
                    let rust_string = ::std::str::from_utf8(&m_hex[0..leading_non_zero]).unwrap();
                    Fr::try_from_hex(rust_string).unwrap()
                })
                .collect())
        }
        RET_INVALID => Err(CryptoError::DiceMixNoSolution),
        RET_NON_MONIC_ROOT => Err(CryptoError::DiceMixNonMonicRoot),
        RET_NOT_ENOUGH_ROOTS => Err(CryptoError::DiceMixNotEnoughRoots),
        x => Err(CryptoError::DiceMixInternalError(x)),
    }
}

// ---------------------------------------------------------------------------

pub fn dc_keys(
    participants: &Vec<ParticipantID>,
    sess_pkeys: &HashMap<ParticipantID, PublicKey>,
    my_id: &ParticipantID,
    my_sess_skey: &SecretKey, // our session secret key value
    sess: &Hash,
) -> HashMap<ParticipantID, Hash> {
    // Return a hashmap of participant key to shared cloaking hash value
    //
    // my_id is the node public key used for all rounds
    // my_sess_pkey is the public key invented for each specific session round
    // my_sess_skey is the secret key invented for each specific session round
    //
    // Satisfies commutativity:
    //  shared_key(id1, id2, s1, pk2) == shared_key(id2, id1, s2, pk1)
    // so we can both agree on the cloaking key
    let alpha = Fr::from(*my_sess_skey);
    let mut out: HashMap<ParticipantID, Hash> = HashMap::new();
    participants.iter().filter(|&&p| p != *my_id).for_each(|p| {
        let sess_pkey = sess_pkeys.get(p).expect("can't get session pkey");
        let comm_pt = alpha * Pt::from(*sess_pkey);

        let mut state = Hasher::new();
        comm_pt.hash(&mut state);
        if *my_id < *p {
            my_id.hash(&mut state);
            p.hash(&mut state);
        } else {
            p.hash(&mut state);
            my_id.hash(&mut state);
        }
        sess.hash(&mut state);
        let comm = state.result();

        out.insert(*p, comm);
    });
    out
}

pub type ValidatorFn<T> = fn(&ParticipantID, &Vec<Vec<u8>>, Fr, Fr, &T) -> bool;

pub fn dc_reconstruct<T>(
    participants: &Vec<ParticipantID>,
    sess_pkeys: &HashMap<ParticipantID, PublicKey>,
    my_id: &ParticipantID,
    sess_skeys: &HashMap<ParticipantID, SecretKey>,
    dc: &HashMap<ParticipantID, DcMatrix>,
    sum_dc1: &HashMap<ParticipantID, Fr>, // table of cloaked gamma_adj
    sum_dc2: &HashMap<ParticipantID, Fr>, // table of cloaked fees
    sess: &Hash,
    p_excl: &Vec<ParticipantID>,
    k_excl: &HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,
    vfn: ValidatorFn<T>,
    data: &T,
) -> Vec<ParticipantID>
where
    T: Sync,
{
    // Take a collection of matrices from each participant
    // and uncloak them to reconstruct the original messages.
    //
    // Then reconstruct each sheet to see if/where there is disagreement
    //
    let opts: Vec<Option<ParticipantID>> = participants
        .par_iter()
        .map(|pkey| {
            // p_all is every participant including me,
            // including those previously flagged as non-participating,
            // but in any event, exclude pkey from the group
            let mut p_all = participants.clone();
            let mut p_ex = p_excl.clone();
            p_all.append(&mut p_ex);
            p_all.retain(|p| *p != *my_id);
            p_all.push(my_id.clone());
            p_all.retain(|p| *p != *pkey);

            let sk = sess_skeys.get(pkey).unwrap();
            let cloaks = dc_keys(&p_all, sess_pkeys, pkey, sk, sess);

            let mat = dc.get(pkey).unwrap();
            let nsheets = mat.len();
            let mut pkey_fail = false;
            let mut msgs = Vec::<Vec<u8>>::new();
            for s in 0..nsheets {
                // reconstruct the messaage for each sheet,
                // collect into payload list of messages,
                // and verify that this message would have produced the
                // sheet as shared with all participants
                let sheet = &mat[s];
                let mut msg = Vec::<u8>::new();
                let seed_str = gen_cell_seed(s, 0, 0);
                let mut chunk1 = (sheet[0][0].clone()
                    - dc_slot_pad(participants, pkey, &cloaks, &seed_str))
                .to_bytes();
                stuff_msg(&mut msg, &chunk1, 0, MAX_BYTES);

                let dim_r = sheet.len(); // nbr of chunks
                let dim_c = sheet[0].len(); // s.b. nbr of participants
                for r in 1..dim_r {
                    let seed_str = gen_cell_seed(s, r, 0);
                    let chunk = (sheet[r][0].clone()
                        - dc_slot_pad(participants, pkey, &cloaks, &seed_str))
                    .to_bytes();
                    stuff_msg(&mut msg, &chunk, NPREF, NCHUNK);
                }

                let new_sheet = dc_encode_sheet(s, dim_r, &msg, &p_all, &pkey, &cloaks);
                msgs.push(msg);
                for r in 0..dim_r {
                    for c in 0..dim_c {
                        if new_sheet[r][c] != sheet[r][c] {
                            pkey_fail = true;
                            break;
                        }
                    }
                    if pkey_fail {
                        break;
                    }
                }
                if pkey_fail {
                    break;
                }
            }

            if !pkey_fail {
                // recover component of shared sum and validate the payload
                let seed_str = scalar_open_seed();
                let r_adj = sum_dc1.get(pkey).expect("Can't access sum_dc1").clone()
                    - dc_slot_pad(participants, pkey, &cloaks, &seed_str);
                let fee = sum_dc2.get(pkey).expect("Can't access sum_dc2").clone()
                    - dc_slot_pad(participants, pkey, &cloaks, &seed_str);
                pkey_fail = !vfn(&pkey, &msgs, r_adj, fee, data);
            }

            if !pkey_fail {
                // check that pkey has published correct symmetric keys
                let my_cloaks = k_excl.get(pkey).unwrap();
                for p_ex in p_excl {
                    if cloaks.get(p_ex).unwrap() != my_cloaks.get(p_ex).unwrap() {
                        pkey_fail = true;
                        break;
                    }
                }
            }

            if pkey_fail {
                Some(pkey.clone())
            } else {
                None
            }
        })
        .collect();
    let mut out = Vec::<ParticipantID>::new();
    for opt in opts {
        match opt {
            None => (),
            Some(pkey) => {
                out.push(pkey);
            }
        }
    }
    out
}

// -----------------------------------------------------------
// Shared scalar sums

fn scalar_open_seed() -> Vec<u8> {
    format!("sum").into_bytes()
}

pub fn dc_encode_scalar(
    x: Fr,
    participants: &Vec<ParticipantID>,
    my_id: &ParticipantID,
    share_cloaks: &HashMap<ParticipantID, Hash>,
) -> Fr {
    // cloak a scalar, x, a member of field Fr, so that
    // it can be anonymously shared into a running sum
    // along with similar contributions from other participants
    //
    // For now we assume there is only one such item, and use the
    // constant cloaking seed "sum". This is also assumed in the
    // dc_reconstruct() code used for blame discovery.
    let seed_str = scalar_open_seed();
    x + dc_slot_pad(participants, my_id, &share_cloaks, &seed_str)
}

pub fn dc_scalar_open(
    participants: &Vec<ParticipantID>,
    elts: &HashMap<ParticipantID, Fr>,
    p_excl: &Vec<ParticipantID>,
    k_excl: &HashMap<ParticipantID, HashMap<ParticipantID, Hash>>,
) -> Fr {
    // add contribs from all users to remove cloaking
    // and form sum of shared scalar values
    let mut sum = elts.iter().fold(Fr::zero(), |sum, (_, &elt)| sum + elt);
    if !p_excl.is_empty() {
        let seed_str = scalar_open_seed();
        participants.iter().for_each(|p| {
            let ktbl = k_excl.get(p).expect("can't get k_excl");
            sum -= dc_slot_pad(p_excl, p, ktbl, &seed_str);
        });
    }
    sum
}

// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::dbg;

    #[test]
    fn tst_split_message() {
        let msg = b"This is a message This is a message This is a message This is a message This is a message";
        let v = split_message(&msg[..], None);
        dbg!(&v);

        /* -- not possible for Scalar to be out of range
        // check that each Fr is < |Fr|
        let limit = Fr::modulus();
        println!("{} = |Fr|", limit.to_hex());
        for val in v.clone() {
            assert!(val.bits() < limit);
        }
        */

        // show component chunks
        println!("v len = {}", v.len());
        for val in v.clone() {
            println!("{}", val.to_hex());
        }

        // check that hash of first chunk is prefix of remaining chunks
        let v0 = v[0].to_bytes();
        let h = Hash::from_vector(&v0).bits();
        for i in 1..v.len() {
            let bits = v[i].to_bytes();
            for j in 0..NPREF {
                assert!(bits[j] == h[j]);
            }
        }

        // reconstruct message from chunks
        let mut rmsg: Vec<char> = v0.iter().take(MAX_BYTES).map(|c| *c as char).collect();
        for i in 1..v.len() {
            let mut bits = v[i].to_bytes();
            for b in bits.iter().take(MAX_BYTES).skip(NPREF) {
                rmsg.push(*b as char);
            }
        }
        println!("rmsg {:?}", rmsg);

        // compare reconstructed with original message
        let mut mmsg: Vec<char> = msg.into_iter().map(|c| *c as char).collect();
        println!("mmsg {:?}", mmsg);
        for i in 0..mmsg.len() {
            assert!(rmsg[i] == mmsg[i]);
        }
    }

    fn show_sheet(sheet: &Vec<Vec<Fr>>) {
        fn show_row(row: &Vec<Fr>) {
            let ncols = row.len();
            println!("  ncols = {} [", ncols);
            for cell in row {
                println!("    Fr({})", cell.to_hex());
            }
            println!("  ]");
        }
        let nrows = sheet.len();
        println!("Sheet [");
        println!("  nrows = {}", nrows);
        for row in sheet {
            show_row(row);
        }
        println!("]");
    }

    #[test]
    fn tst_sheet_gen() {
        let (sk1, pk1) = pbc::make_deterministic_keys(b"User1");
        let (sk2, pk2) = pbc::make_deterministic_keys(b"User2");
        let (sk3, pk3) = pbc::make_deterministic_keys(b"User3");
        let all_participants = vec![
            ParticipantID::from_pk(pk1.clone()),
            ParticipantID::from_pk(pk2.clone()),
            ParticipantID::from_pk(pk3.clone()),
        ];
        dbg!(&all_participants);

        let participants_1 = vec![
            ParticipantID::from_pk(pk2.clone()),
            ParticipantID::from_pk(pk3.clone()),
        ];
        let participants_2 = vec![
            ParticipantID::from_pk(pk1.clone()),
            ParticipantID::from_pk(pk3.clone()),
        ];
        let participants_3 = vec![
            ParticipantID::from_pk(pk1.clone()),
            ParticipantID::from_pk(pk2.clone()),
        ];

        let sess = Hash::from_str("session1");
        let (sess_sk1, sess_pk1) = scc::make_deterministic_keys(b"User1-session1");
        let (sess_sk2, sess_pk2) = scc::make_deterministic_keys(b"User2-session1");
        let (sess_sk3, sess_pk3) = scc::make_deterministic_keys(b"User3-session1");

        let mut npk1 = HashMap::new();
        npk1.insert(ParticipantID::from_pk(pk2.clone()), sess_pk2);
        npk1.insert(ParticipantID::from_pk(pk3.clone()), sess_pk3);

        let mut npk2 = HashMap::new();
        npk2.insert(ParticipantID::from_pk(pk1.clone()), sess_pk1);
        npk2.insert(ParticipantID::from_pk(pk3.clone()), sess_pk3);

        let mut npk3 = HashMap::new();
        npk3.insert(ParticipantID::from_pk(pk1.clone()), sess_pk1);
        npk3.insert(ParticipantID::from_pk(pk2.clone()), sess_pk2);

        let shared_cloaking_1 = dc_keys(
            &all_participants,
            &npk1,
            &ParticipantID::from_pk(pk1.clone()),
            &sess_sk1,
            &sess,
        );
        let shared_cloaking_2 = dc_keys(
            &participants_2,
            &npk2,
            &ParticipantID::from_pk(pk2.clone()),
            &sess_sk2,
            &sess,
        );
        let shared_cloaking_3 = dc_keys(
            &participants_3,
            &npk3,
            &ParticipantID::from_pk(pk3.clone()),
            &sess_sk3,
            &sess,
        );
        dbg!(&shared_cloaking_1);
        dbg!(&shared_cloaking_2);
        dbg!(&shared_cloaking_3);

        let seed = gen_cell_seed(1, 1, 2);
        dbg!(&seed);

        let pad_1 = dc_slot_pad(
            &all_participants,
            &ParticipantID::from_pk(pk1.clone()),
            &shared_cloaking_1,
            &seed,
        )
        .clone();
        let pad_2 = dc_slot_pad(
            &participants_2,
            &ParticipantID::from_pk(pk2.clone()),
            &shared_cloaking_2,
            &seed,
        )
        .clone();
        let pad_3 = dc_slot_pad(
            &participants_3,
            &ParticipantID::from_pk(pk3.clone()),
            &shared_cloaking_3,
            &seed,
        )
        .clone();
        dbg!(&pad_1);
        dbg!(&pad_2);
        dbg!(&pad_3);
        dbg!(pad_1 + pad_2 + pad_3);

        // show that adding together the padding from all of us, produces a zero Fr value
        assert!(pad_1 + pad_2 + pad_3 == Fr::zero());

        // Form a matrix sheet from each participant
        let msg_1 = b"From 1 - This is a message This is a message This is a message This is a message This is a message";
        let cells_1 = split_message(&msg_1[..], None);
        let max_cells = cells_1.len();

        let sheet_1 = dc_encode_sheet(
            1,
            max_cells,
            &msg_1[..],
            &all_participants,
            &ParticipantID::from_pk(pk1.clone()),
            &shared_cloaking_1,
        );

        println!("Sheet_1");
        show_sheet(&sheet_1);
        assert!(sheet_1[0].len() == all_participants.len());

        let msg_2 = b"From 2 - This is a message This is a message This is a message This is a message This is a message";
        let cells_2 = split_message(&msg_2[..], Some(max_cells));

        let sheet_2 = dc_encode_sheet(
            1,
            max_cells,
            &msg_2[..],
            &all_participants,
            &ParticipantID::from_pk(pk2.clone()),
            &shared_cloaking_2,
        );
        println!("Sheet_2");
        show_sheet(&sheet_2);

        let msg_3 = b"From 3 - This is a message This is a message This is a message This is a message This is a message";
        let cells_3 = split_message(&msg_3[..], Some(max_cells));

        let sheet_3 = dc_encode_sheet(
            1,
            max_cells,
            &msg_3[..],
            &all_participants,
            &ParticipantID::from_pk(pk3.clone()),
            &shared_cloaking_3,
        );
        println!("Sheet_3");
        show_sheet(&sheet_3);

        // construct the uncloaked power sum sheet
        let matrix = vec![&sheet_1, &sheet_2, &sheet_3];
        let mut sum_sheet = Vec::<Vec<Fr>>::new();
        let n_rows = sheet_1.len();
        assert!(n_rows == max_cells);
        assert!(3 == sheet_1[0].len());
        for r in 0..n_rows {
            let mut row = Vec::<Fr>::new();
            for c in 0..3 {
                let mut sum = Fr::zero();
                for sheet in matrix.clone() {
                    sum += sheet[r][c];
                }
                row.push(sum);
            }
            sum_sheet.push(row);
        }
        println!("Sum Sheet");
        show_sheet(&sum_sheet);

        fn expi(base: &Fr, expon: u64) -> Fr {
            let mut tmp = Fr::one();
            let mut x = base.clone();
            let mut ebits = expon;
            while ebits > 0 {
                if (ebits & 1) != 0 {
                    tmp *= x;
                }
                ebits >>= 1;
                x *= x.clone();
            }
            tmp
        }

        // check that every cell has its cloaking cancelled out
        // and equals what we would expect in the row power sums
        let rows = vec![&cells_1, &cells_2, &cells_3];
        for r in 0..max_cells {
            for c in 0..3 {
                let mut sum = Fr::zero();
                for rc in 0..3 {
                    sum += expi(&rows[rc][r], (c + 1) as u64);
                }
                assert!(sum == sum_sheet[r][c]);
            }
        }

        // -------------------------------------------------
        // Try a real decode on the shared messages
        let mut mats = HashMap::new();
        mats.insert(ParticipantID::from_pk(pk1.clone()), vec![sheet_1.clone()]);
        mats.insert(ParticipantID::from_pk(pk2.clone()), vec![sheet_2.clone()]);
        mats.insert(ParticipantID::from_pk(pk3.clone()), vec![sheet_3.clone()]);

        let p_excl = Vec::<ParticipantID>::new();
        let k_excl: HashMap<ParticipantID, HashMap<ParticipantID, Hash>> = HashMap::new();
        let my_id = all_participants[0];

        // interim test - try opening every cell of the sum sheet
        // result should be same as our direct sum sheet created above.
        let mut dec_sheet = Vec::<Vec<Fr>>::new();
        for r in 0..n_rows {
            let mut row = Vec::<Fr>::new();
            for c in 0..3 {
                let val = dc_open(&all_participants, &mats, 0, r, c, &p_excl, &k_excl);
                assert!(val == sum_sheet[r][c]);
                row.push(val);
            }
            dec_sheet.push(row);
        }
        println!("dec_sheet");
        show_sheet(&dec_sheet);

        // Full-up test of solver... yea!
        let msgs = dc_decode(
            &all_participants,
            &mats,
            &my_id,
            1,
            max_cells,
            &p_excl,
            &k_excl,
        )
        .expect("ok");
        let nmsgs = msgs.len();
        assert!(3 == nmsgs);
        let mut cmsgs = Vec::<String>::new();
        for m_in in msgs {
            let mut msg = String::new();
            for c in m_in {
                if c == 0 {
                    break;
                }
                msg.push(c as char);
            }
            cmsgs.push(msg);
        }
        dbg!(&cmsgs);
    }

    #[test]
    fn tst_short_hash_collisions() {
        // generate a bunch of fake UTXOs and look to see if
        // any of them end up with the same hash prefix on their chunks
        let ntry = 255;

        // --------------------------------------------------
        // copied from split_message() above
        fn umin(a: usize, b: usize) -> usize {
            if a <= b {
                a
            } else {
                b
            }
        }

        fn rem_len(nvec: usize, start: usize) -> usize {
            if nvec > start {
                nvec - start
            } else {
                0
            }
        }

        fn stuff_slot(dst: &mut [u8], src: &[u8], start1: usize, start2: usize, nel: usize) {
            let ndst = rem_len(dst.len(), start1);
            let nsrc = rem_len(src.len(), start2);
            let n = umin(nel, umin(ndst, nsrc));
            for i in 0..n {
                dst[start1 + i] = src[start2 + i];
            }
            for i in n..umin(ndst, nel) {
                dst[start1 + i] = 0; // stuff MSB's
            }
        }

        // --------------------------------------------------

        let mut seen = HashSet::new();
        for ix in 0..ntry {
            let utxo = vec![(ix + 1) as u8; 64];
            let mut seg: [u8; SLOT_BYTES] = [0u8; SLOT_BYTES];
            stuff_slot(&mut seg, &utxo, 0, 0, MAX_BYTES);
            prep_pref(&mut seg);
            let mut hash = [0u8; NPREF];
            for i in 0..NPREF {
                hash[i] = seg[i];
            }
            if None != seen.get(&hash) {
                panic!("Duplicate hash prefix encountered");
            }
            seen.insert(hash);
        }
        println!("Ok - guess we didn't see any hash collisions");
    }

    fn tst_end_to_end(nparts: usize, nutxo: usize, utxo_len: usize) {
        assert!(3 <= nparts && nparts <= 50);
        assert!(1 <= nutxo && nutxo <= 5);

        // first generate participants - simulated wallets
        let mut participants = Vec::<ParticipantID>::new();
        for ix in 0..nparts {
            let seed = format!("User_{}", ix).into_bytes();
            let (sk, pk) = pbc::make_deterministic_keys(&seed);
            // skeys.push(sk);
            participants.push(ParticipantID::from_pk(pk));
        }
        let my_id = participants[0].clone();

        // ------------------------------------------------------------
        // simulated start of VS session at one node
        // generate new session keying
        // this would normally be received by messages from other nodes,
        // where each node would generate their own session key pair and
        // send their public keys to everyone else.
        let start = SystemTime::now();
        let mut sess_pkeys = HashMap::new();
        let mut sess_skeys = HashMap::new();
        for ix in 0..nparts {
            let seed = format!("User_{}_Session_Key", ix).into_bytes();
            let (sk, pk) = scc::make_deterministic_keys(&seed);
            let p = participants[ix].clone();
            sess_pkeys.insert(p.clone(), pk.clone());
            sess_skeys.insert(p.clone(), sk);
        }
        let my_sess_pkey = sess_pkeys.get(&my_id).unwrap();
        let my_sess_skey = sess_skeys.get(&my_id).unwrap();
        let timing = start.elapsed();
        println!("Keying time = {:?}", timing);

        // -------------------------------------------------------------
        // generate shared secret cloaking - each node would do this
        let start = SystemTime::now();
        let sess = Hash::from_str("Session 1");
        let shared_cloaking = dc_keys(&participants, &sess_pkeys, &my_id, &my_sess_skey, &sess);
        let timinig = start.elapsed().unwrap();
        println!("Shared Cloaking Gen = {:?}", timing);

        // --------------------------------------------------------------
        // generate 5 simulated UTXOS and matrix sheets, one sheet per UTXO
        println!("Generate a Matrix with {} UTXO", nutxo);
        let start = SystemTime::now();
        let mut max_cells: Option<usize> = None;
        let mut matrix = Vec::<DcSheet>::new();
        for ix in 0..nutxo {
            let utxo_id = ix + 1;
            assert!(0 < utxo_id && utxo_id < 256);
            let utxo = vec![utxo_id as u8; utxo_len]; // a realistic size
            if None == max_cells {
                let vecfrs = split_message(&utxo[..], None);
                max_cells = Some(vecfrs.len());
            }
            let sheet = dc_encode_sheet(
                ix,
                max_cells.unwrap(),
                &utxo[..],
                &participants,
                &my_id,
                &shared_cloaking,
            );
            matrix.push(sheet);
        }
        let timing = start.elapsed();
        println!("matrix enc = {:?}", timing);

        // cache for later use
        let max_cells = max_cells.unwrap();
        let nsheets = matrix.len();
        let nrows = matrix[0].len();
        let ncols = matrix[0][0].len();
        println!("matrix dims = {},{},{}", nsheets, nrows, ncols);
        assert!(nrows == max_cells);
        assert!(nsheets == nutxo);
        assert!(ncols == nparts);

        // ------------------------------------------------------------
        // now construct the matrices from all other participants...
        // this will take a while, and should not be counted in the timings
        // since all nodes are doing this in parallel.
        println!("Generate matrices from other nodes");
        let start = SystemTime::now();
        let mut matrices: HashMap<ParticipantID, DcMatrix> = HashMap::new();
        fn gen_matrix(
            ix_p: usize,
            nutxo: usize,
            utxo_len: usize,
            max_cells: usize,
            participants: &Vec<ParticipantID>,
            sess_skeys: &HashMap<ParticipantID, SecretKey>,
            sess_pkeys: &HashMap<ParticipantID, PublicKey>,
            sess: &Hash,
        ) -> (ParticipantID, DcMatrix) {
            let mut matrix = Vec::<DcSheet>::new();
            let p = participants[ix_p].clone();
            let s = sess_skeys.get(&p).unwrap();
            let shared_cloaking = dc_keys(&participants, &sess_pkeys, &p, &s, &sess);
            for ix_u in 0..nutxo {
                // every UTXO should be unique
                let utxo_id = (ix_u + 1) + 5 * ix_p;
                assert!(0 < utxo_id && utxo_id < 256);
                let utxo = vec![utxo_id as u8; utxo_len];
                let sheet = dc_encode_sheet(
                    ix_u,
                    max_cells,
                    &utxo[..],
                    &participants,
                    &p,
                    &shared_cloaking,
                );
                matrix.push(sheet);
            }
            (p, matrix)
        }
        /* */

        let mut indices = vec![0; nparts - 1];
        for ix in 0..nparts - 1 {
            indices[ix] = ix + 1;
        }
        let mut mats: Vec<(ParticipantID, DcMatrix)> = indices
            .par_iter()
            .map(|ix_p| {
                gen_matrix(
                    *ix_p,
                    nutxo,
                    utxo_len,
                    max_cells,
                    &participants,
                    &sess_skeys,
                    &sess_pkeys,
                    &sess,
                )
            })
            .collect();

        matrices.insert(my_id.clone(), matrix);
        for (p, m) in mats {
            matrices.insert(p, m);
        }

        let timing = start.elapsed();
        println!("full construction of input = {:?}", timing);

        // -------------------------------------------------
        // Now solve for all the anonymously shared UTXO's
        println!("Start solving for UTXOs");
        let start = SystemTime::now();
        let p_excl = Vec::<ParticipantID>::new();
        let mut k_excl: HashMap<ParticipantID, HashMap<ParticipantID, Hash>> = HashMap::new();
        for ix in 0..nparts {
            let p = participants[ix].clone();
            k_excl.insert(p, HashMap::new());
        }
        let my_id = participants[0];
        let k_exs = k_excl.get(&my_id).unwrap();
        let msgs = dc_decode(
            &participants,
            &matrices,
            &my_id,
            nsheets,
            max_cells,
            &p_excl,
            &k_excl,
        )
        .expect("Ok");
        let timing = start.elapsed();
        println!("{}x{} Solve {} Time = {:?}", nsheets, nrows, ncols, timing);

        // -------------------------------------------------------
        // check that we got the expected number of UTXO messages = 5 * nparts
        dbg!(msgs.len());
        let mut maxlen = 0;
        for ix in 0..msgs.len() {
            let mlen = msgs[ix].len();
            if mlen > maxlen {
                maxlen = mlen;
            }
        }
        dbg!(maxlen);

        assert!(msgs.len() == nparts * nsheets);
        //
        // check that each message is the same length
        // and that no message has been seen in duplicate
        // and that every element of message is the same value
        // (this is expected, by way of the manner in which we
        //    constructed the original messages)
        //
        let mut idstr = String::new();
        for ix in 0..256 {
            idstr.push('_');
        }
        // dbg!(&idstr);
        let mut ids = HashSet::new();
        let mut master_ct = None;
        for m in msgs {
            let mut ct = 0;
            let chk = m[0];
            // be sure we haven't seen this one already
            if (ids.get(&chk) != None) {
                dbg!(&idstr);
                dbg!(&chk);
                panic!("duplicate message");
            }
            ids.insert(chk);
            idstr.remove(chk as usize);
            idstr.insert(chk as usize, '*');
            for b in m {
                if b != 0 {
                    // be sure every byte is the same,
                    // except for tail zero padding
                    assert!(b == chk);
                    ct += 1;
                } else {
                    // ignore zero padding at end
                    break;
                }
            }
            match master_ct {
                None => master_ct = Some(ct),
                Some(val) => assert!(val == ct),
            }
        }
        dbg!(&idstr);

        // --------------------------------------------------------------
        // get the blame discovery timing estimate
        let mut gamma_adjs = HashMap::new();
        for ix in 0..nparts {
            let p = participants[ix].clone();
            gamma_adjs.insert(p, Fr::zero());
        }

        fn dum_validate_payload(
            pkey: &ParticipantID,
            msgs: &Vec<Vec<u8>>,
            r_adj: Fr,
            fee: Fr,
            dum_data: &Vec<usize>,
        ) -> bool {
            // deserialize msgs and check the validity of the components.
            // E.g., if each msg is a UTXO, validate the Bulletproofs
            // then check that sum of TXIN matches sum of TXOUT with
            // fee and gamma_adj
            true
        }

        println!("Start blame discovery");
        let start = SystemTime::now();
        let dum_data = Vec::new();
        let pexcl = dc_reconstruct(
            &participants,
            &sess_pkeys,
            &my_id,
            &sess_skeys,
            &matrices,
            &gamma_adjs,
            &gamma_adjs,
            &sess,
            &p_excl,
            &k_excl,
            dum_validate_payload,
            &dum_data,
        );
        let timing = start.elapsed();
        println!(
            "{}x{}x{} Discovery Time = {:?}",
            nsheets, nrows, ncols, timing
        );
        dbg!(pexcl.len());
        dbg!(&pexcl);
    }

    #[test]
    #[ignore]
    fn tst_50_50() {
        // ------------------------------------------------------------
        // Get the timings for 50 participants, each sharing 5 UTXOs
        // with each UTXO taking 50 chunks.
        //
        // DiceMix matrices have 5 sheets of 50 rows of 50 cols = 12,500 chunks
        // ------------------------------------------------------------

        let nparts = 50; // nbr of participants 3..50
        let nutxo = 5; // nbr of UTXO per participant 1..5
        let utxo_len = 1350; // long enough to produce 50 chunks
        tst_end_to_end(nparts, nutxo, utxo_len);
    }

    #[test]
    fn tst_10_5() {
        tst_end_to_end(10, 5, 1350);
    }

    #[test]
    fn test_solver() {
        fn add_col(col: &mut Vec<Fr>, x: &Vec<Fr>) {
            for ix in 0..col.len() {
                col[ix] += x[ix];
            }
        }

        for _ in 0..1000 {
            let f1 = Fr::random();
            let f2 = Fr::random();
            let f3 = Fr::random();
            let f4 = Fr::random();
            let mut col = exp_vec(&f1, 4);
            add_col(&mut col, &exp_vec(&f2, 4));
            add_col(&mut col, &exp_vec(&f3, 4));
            add_col(&mut col, &exp_vec(&f4, 4));
            /* */
            let ans = dc_solve(&col).expect("ok");
            if !(ans.contains(&f1) && ans.contains(&f2) && ans.contains(&f3) && ans.contains(&f4)) {
                println!("col = {:?}", col);
                println!("[f1,f2,f3,f4] = [{:?}, {:?}, {:?}, {:?}]", f1, f2, f3, f4);
                println!("ans = {:?}", ans);
                panic!("invalid recovery");
            };
            /* */
        }
    }
}

//! BLS MultiSignature.

//
// Copyright (c) 2018 Stegos AG
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

use crate::VALIDATORS_MAX;
use bitvector::BitVector;
use std::collections::BTreeMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;

///
/// Return true if supermajority of votes has been collected.
///
pub fn check_supermajority(got_votes: usize, total_votes: usize) -> bool {
    assert!(got_votes <= total_votes);
    let need_votes = (total_votes * 2 + 3) / 3;
    (got_votes >= need_votes)
}

///
/// Create a new multi-signature from individual signatures
///
pub fn create_multi_signature(
    validators: &Vec<(secure::PublicKey, i64)>,
    signatures: &BTreeMap<secure::PublicKey, secure::Signature>,
) -> (secure::Signature, BitVector) {
    let mut multisig = secure::G1::zero();
    let mut multisigmap = BitVector::new(VALIDATORS_MAX);
    let mut count: usize = 0;
    for (bit, (pkey, _stake)) in validators.iter().enumerate() {
        let sig = match signatures.get(pkey) {
            Some(sig) => *sig,
            None => continue,
        };
        let sig: secure::G1 = sig.into();
        multisig += sig;
        let ok = multisigmap.insert(bit);
        assert!(ok);
        count += 1;
    }
    assert_eq!(count, signatures.len());

    let multisig: secure::Signature = multisig.into();
    (multisig, multisigmap)
}

///
/// Create a new self-signed multisignature.
///
pub fn create_proposal_signature(
    hash: &Hash,
    skey: &secure::SecretKey,
    pkey: &secure::PublicKey,
    validators: &Vec<(secure::PublicKey, i64)>,
) -> (secure::Signature, BitVector) {
    let mut signatures: BTreeMap<secure::PublicKey, secure::Signature> = BTreeMap::new();
    let sig = secure::sign_hash(hash, skey);
    signatures.insert(pkey.clone(), sig);
    create_multi_signature(validators, &signatures)
}

///
/// Check multi-signature
///
pub fn check_multi_signature(
    hash: &Hash,
    multisig: &secure::Signature,
    multisigmap: &BitVector,
    validators: &Vec<(secure::PublicKey, i64)>,
    leader: &secure::PublicKey,
    is_proposal: bool,
) -> bool {
    // Check for trailing bits in the bitmap.
    if multisigmap.len() > validators.len() {
        return false;
    }

    let mut has_leader = false;
    let mut multisigpkey = secure::G2::zero();

    let mut count: usize = 0;
    for (bit, pkey) in validators.iter().map(|(k, _)| k).enumerate() {
        if !multisigmap.contains(bit) {
            continue;
        }
        has_leader = has_leader || (pkey == leader);
        let pkey: secure::G2 = pkey.clone().into();
        multisigpkey += pkey;
        count += 1;
    }

    // Multi-signature must contain leader's key.
    if !has_leader {
        return false;
    }

    // Proposal must only be signed by the leader.
    if is_proposal && count != 1 {
        return false;
    }

    // Multi-signature must be signed by the supermajority of validators.
    if !is_proposal && !check_supermajority(count, validators.len()) {
        return false;
    }

    // The hash must match the signature.
    let multipkey: secure::PublicKey = multisigpkey.into();
    debug_assert!(!is_proposal || &multipkey == leader);
    secure::check_hash(&hash, &multisig, &multipkey)
}

///
/// Merge two multisignatures.
///
pub fn merge_multi_signature(
    dst_multisig: &mut secure::Signature,
    dst_multisigmap: &mut BitVector,
    src_multisig: &secure::Signature,
    src_multisigmap: &BitVector,
) {
    let orig_dst_len = dst_multisigmap.len();
    dst_multisigmap.union_inplace(src_multisigmap);
    let new_dst_len = dst_multisigmap.len();
    if new_dst_len == orig_dst_len {
        // src is a subset of dst - nothing to merge.
        return;
    } else if new_dst_len == orig_dst_len + src_multisigmap.len() {
        // Non-intersecting sets.
        *dst_multisig += src_multisig.clone();
        return;
    } else {
        // Intersecting sets.
        panic!("Can't merge n intersected multi-signatures")
    }
}

//! pBFT Consensus - BLS Multisignature.

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

use bitvector::BitVector;
use std::collections::BTreeMap;
use stegos_blockchain::WITNESSES_MAX;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::check_hash as secure_check_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;
use stegos_crypto::pbc::secure::G1;
use stegos_crypto::pbc::secure::G2;

///
/// Return true if supermajority of votes has been collected.
///
pub(crate) fn check_supermajority(got_votes: usize, total_votes: usize) -> bool {
    assert!(got_votes <= total_votes);
    let need_votes = (total_votes * 2 + 3) / 3;
    (got_votes >= need_votes)
}

///
/// Create a new multi-signature from individual signatures
///
pub fn create_multi_signature(
    witnesses: &BTreeMap<SecurePublicKey, i64>,
    signatures: &BTreeMap<SecurePublicKey, SecureSignature>,
) -> (SecureSignature, BitVector) {
    assert!(check_supermajority(signatures.len(), witnesses.len()));

    let mut multisig = G1::zero();
    let mut multisigmap = BitVector::new(WITNESSES_MAX);
    let mut count: usize = 0;
    for (bit, (pkey, _stake)) in witnesses.iter().enumerate() {
        let sig = match signatures.get(pkey) {
            Some(sig) => *sig,
            None => continue,
        };
        let sig: G1 = sig.into();
        multisig += sig;
        let ok = multisigmap.insert(bit);
        assert!(ok);
        count += 1;
    }
    assert_eq!(count, signatures.len());

    let multisig: SecureSignature = multisig.into();
    (multisig, multisigmap)
}

///
/// Check multi-signature
///
pub fn check_multi_signature(
    hash: &Hash,
    multisig: &SecureSignature,
    multisigmap: &BitVector,
    witnesses: &BTreeMap<SecurePublicKey, i64>,
    leader: &SecurePublicKey,
) -> bool {
    let mut has_leader = false;
    let mut multisigpkey = G2::zero();

    let mut count: usize = 0;
    for (bit, pkey) in witnesses.keys().enumerate() {
        if !multisigmap.contains(bit) {
            continue;
        }
        has_leader = has_leader || (pkey == leader);
        let pkey: G2 = pkey.clone().into();
        multisigpkey += pkey;
        count += 1;
    }

    // Multi-signature must contain leader's key.
    if !has_leader {
        return false;
    }

    // Multi-signature must be signed by the supermajority of witnesses.
    if !check_supermajority(count, witnesses.len()) {
        return false;
    }

    // The hash must match the signature.
    let multipkey: SecurePublicKey = multisigpkey.into();
    secure_check_hash(&hash, &multisig, &multipkey)
}

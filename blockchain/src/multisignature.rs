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

use crate::error::MultisignatureError;
use crate::VALIDATORS_MAX;
use bitvector::BitVector;
use std::collections::BTreeMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;

///
/// Return true if supermajority of votes has been collected.
///
pub fn check_supermajority(got_votes: i64, total_votes: i64) -> bool {
    assert!(got_votes <= total_votes);
    assert!(got_votes >= 0);
    assert!(total_votes > 0);
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
    create_multi_signature_index(
        // convert Map<Pk, Signature> -> Iterator<(id, Signature)>
        validators
            .iter()
            .enumerate() // add id
            .map(|(id, other)| (id as u32, other)) //convert id to u32
            .filter_map(|(id, (pk, _stake))| {
                // map pk -> Option<signature>
                signatures.get(pk).map(|pk| (id, pk))
            }),
    )
}

///
/// Create a new multi-signature from individual signatures
/// version which work for array of validators id's
///
pub fn create_multi_signature_index<'a, I>(signatures: I) -> (secure::Signature, BitVector)
where
    I: Iterator<Item = (u32, &'a secure::Signature)>,
{
    let mut multisig = secure::G1::zero();
    let mut multisigmap = BitVector::new(VALIDATORS_MAX);
    let mut vec: Vec<_> = signatures.collect();
    vec.sort_by_key(|i| i.0);

    for (bit, sig) in vec {
        assert!(bit < VALIDATORS_MAX as u32);
        let sig: secure::G1 = sig.clone().into();
        multisig += sig;
        let ok = multisigmap.insert(bit as usize);
        assert!(ok);
    }

    let multisig: secure::Signature = multisig.into();

    (multisig, multisigmap)
}

///
/// Check multi-signature of group, each signature is weighted by stake.
///
pub fn check_multi_signature(
    hash: &Hash,
    multisig: &secure::Signature,
    multisigmap: &BitVector,
    validators: &Vec<(secure::PublicKey, i64)>,
    total_slots: i64,
) -> Result<(), MultisignatureError> {
    // Check for trailing bits in the bitmap.
    if multisigmap.len() > validators.len() {
        return Err(MultisignatureError::TooBigBitmap(
            multisigmap.len(),
            validators.len(),
        ));
    };

    let mut multisigpkey = secure::G2::zero();
    // total count of group slots
    let mut group_total_slots = 0;

    for bit in multisigmap.iter() {
        let validator = &validators[bit];
        let pkey: secure::G2 = validator.0.into();
        let slots = validator.1;
        assert!(slots > 0);

        multisigpkey += pkey;
        group_total_slots += slots;
    }

    // Multi-signature must be signed by the supermajority of validators.
    if !check_supermajority(group_total_slots, total_slots) {
        return Err(MultisignatureError::NotEnoughtVotes(
            group_total_slots,
            total_slots,
        ));
    }

    // The hash must match the signature.
    let multipkey: secure::PublicKey = multisigpkey.into();
    if let Err(_e) = secure::check_hash(&hash, &multisig, &multipkey) {
        return Err(MultisignatureError::InvalidSignature(*hash));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_multisig() {
        let _ = simple_logger::init();
        let mut skeys = Vec::new();

        let mut validators = Vec::new();
        const NUM_VALIDATORS: usize = 1;
        for _i in 0..NUM_VALIDATORS {
            let (s, p) = secure::make_random_keys();
            validators.push((p, 1));
            skeys.push(s);
        }

        let ref hash = Hash::digest("test");
        let mut signatures = Vec::new();

        for i in 0..NUM_VALIDATORS {
            let sign = secure::sign_hash(hash, &skeys[i]);
            signatures.push((sign, i as u32));
            secure::check_hash(hash, &signatures[i].0, &validators[i].0).unwrap();
        }

        let multisig = create_multi_signature_index(signatures.iter().map(|p| (p.1, &p.0)));
        assert!(check_multi_signature(hash, &multisig.0, &multisig.1, &validators, 1).is_ok())
    }
}

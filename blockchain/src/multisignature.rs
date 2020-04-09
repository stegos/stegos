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
use crate::ValidatorId;
use bit_vec::BitVec;
use log::warn;
use std::collections::BTreeMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

///
/// Return true if supermajority of votes has been collected.
///
pub fn check_supermajority(got_votes: i64, total_votes: i64) -> bool {
    assert!(got_votes <= total_votes);
    assert!(got_votes >= 0);
    assert!(total_votes > 0);
    let need_votes = (total_votes * 2 + 3) / 3;
    got_votes >= need_votes
}

///
/// Create a new multi-signature from individual signatures
///
pub fn create_multi_signature(
    validators: &Vec<(pbc::PublicKey, i64)>,
    signatures: &BTreeMap<pbc::PublicKey, pbc::Signature>,
) -> (pbc::Signature, BitVec) {
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
        validators.len(),
    )
}

///
/// Create a new multi-signature from individual signatures
/// version which work for array of validators id's
///
pub fn create_multi_signature_index<'a, I>(
    signatures: I,
    validators_len: usize,
) -> (pbc::Signature, BitVec)
where
    I: Iterator<Item = (ValidatorId, &'a pbc::Signature)>,
{
    let mut multisig = pbc::G1::zero();
    let mut multisigmap = BitVec::from_elem(validators_len, false);
    for (validator_id, sig) in signatures {
        assert!((validator_id as usize) < validators_len);
        assert!(!multisigmap[validator_id as usize]);
        multisigmap.set(validator_id as usize, true);
        let sig: pbc::G1 = sig.clone().into();
        multisig += sig;
    }
    let multisig: pbc::Signature = multisig.into();
    (multisig, multisigmap)
}

///
/// Check multi-signature of group, each signature is weighted by stake.
///
pub fn check_multi_signature(
    hash: &Hash,
    multisig: &pbc::Signature,
    multisigmap: &BitVec,
    validators: &Vec<(pbc::PublicKey, i64)>,
    total_slots: i64,
) -> Result<(), MultisignatureError> {
    // Check for trailing bits in the bitmap.
    if multisigmap.len() > validators.len() {
        warn!("multisigmap = {:?}", multisigmap);
        return Err(MultisignatureError::TooBigBitmap(
            multisigmap.len(),
            validators.len(),
        ));
    };

    let mut multisigpkey = pbc::G2::zero();
    // total count of group slots
    let mut group_total_slots = 0;

    for ((validator_pkey, slots), val) in validators.iter().zip(multisigmap.iter()) {
        if !val {
            continue;
        }
        assert!(*slots > 0);
        multisigpkey += validator_pkey.clone().into();
        group_total_slots += *slots;
    }

    // Multi-signature must be signed by the supermajority of validators.
    if !check_supermajority(group_total_slots, total_slots) {
        return Err(MultisignatureError::NotEnoughtVotes(
            group_total_slots,
            total_slots,
        ));
    }

    // The hash must match the signature.
    let multipkey: pbc::PublicKey = multisigpkey.into();
    if let Err(_e) = pbc::check_hash(&hash, &multisig, &multipkey) {
        return Err(MultisignatureError::InvalidSignature(*hash));
    }
    Ok(())
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
            let (s, p) = pbc::make_random_keys();
            validators.push((p, 1));
            skeys.push(s);
        }

        let ref hash = Hash::digest("test");
        let mut signatures = Vec::new();

        for i in 0..NUM_VALIDATORS {
            let sign = pbc::sign_hash(hash, &skeys[i]);
            signatures.push((sign, i as u32));
            pbc::check_hash(hash, &signatures[i].0, &validators[i].0).unwrap();
        }

        let multisig =
            create_multi_signature_index(signatures.iter().map(|p| (p.1, &p.0)), NUM_VALIDATORS);
        assert!(check_multi_signature(hash, &multisig.0, &multisig.1, &validators, 1).is_ok())
    }
}

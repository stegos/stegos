//! mod.rs - Ristretto Group Bulletproofs

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
//

#![allow(non_snake_case)]

use crate::curve1174::{Fr, Pt, BPGENS, PCGENS};
use crate::hash::*;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use ristretto_bulletproofs::RangeProof;
use std::fmt;
use std::fmt::Debug;

// -------------------------------------------------------------

#[derive(Clone)]
pub struct BulletProof {
    pub vcmt: Pt,
    pub proof: RangeProof,
}

impl BulletProof {
    pub fn construct(val: i64) -> (BulletProof, Fr) {
        make_range_proof(val)
    }

    pub fn validate(&self) -> bool {
        validate_range_proof(self)
    }
}

impl Hashable for BulletProof {
    fn hash(&self, state: &mut Hasher) {
        "BulletProof".hash(state);
        self.vcmt.hash(state);
        self.proof.to_bytes().hash(state);
    }
}

impl Debug for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BP(vcmt: {:?}, ...)", self.vcmt.compress().to_bytes())
    }
}

impl Eq for BulletProof {}

impl PartialEq for BulletProof {
    fn eq(&self, other: &Self) -> bool {
        self.vcmt == other.vcmt && self.proof.to_bytes() == other.proof.to_bytes()
    }
}

// -------------------------------------------------------------

pub fn simple_commit(blind: &Fr, val: &Fr) -> Pt {
    // blinding on G, value on H
    Pt::from(Scalar::from(*blind) * PCGENS.B_blinding + Scalar::from(*val) * PCGENS.B)
}

pub fn fee_a(val: i64) -> Pt {
    assert!(val >= 0);
    Pt::from(Scalar::from(val as u64) * PCGENS.B)
}

pub fn make_range_proof(secret_value: i64) -> (BulletProof, Fr) {
    let mut prover_transcript = Transcript::new(b"BulletProof");
    let blinding = Scalar::random(&mut thread_rng());
    // if this blows up - it is because you passed a negative value
    assert!(secret_value >= 0);
    let (proof, committed_value) = RangeProof::prove_single(
        &*BPGENS,
        &*PCGENS,
        &mut prover_transcript,
        secret_value as u64,
        &blinding,
        64,
    )
    .expect("valid");
    let vcmt = Pt::from(committed_value.decompress().unwrap());
    let gamma = Fr::from(blinding);
    let bp = BulletProof { vcmt, proof };
    (bp, gamma)
}

pub fn validate_range_proof(bp: &BulletProof) -> bool {
    let mut verifier_transcript = Transcript::new(b"BulletProof");
    bp.proof
        .verify_single(
            &*BPGENS,
            &*PCGENS,
            &mut verifier_transcript,
            &bp.vcmt.compress(),
            64,
        )
        .is_ok()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::curve1174::{make_random_keys, sign_hash, validate_sig, PublicKey};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use std::time::SystemTime;

    #[test]
    fn test_new_bp() {
        // run this code using:
        //   cargo run -p stegos_crypto --example bulletproofs --release

        assert!(RistrettoPoint::from(Pt::one()) == PCGENS.B_blinding);

        // A secret value we want to prove lies in the range [0, 2^32)
        let secret_value = 1037578891i64;

        // let (bp, gamma) = BulletProof::construct(secret_value);
        // assert!(bp.validate());
        let (bp, _gamma) = make_range_proof(secret_value);
        assert!(validate_range_proof(&bp));
        let start = SystemTime::now();
        for _ in 0..1000 {
            // Verification requires a transcript with identical initial state:
            validate_range_proof(&bp);
        }
        let timing = start.elapsed().expect("ok");
        println!("BP Validation: {:?}", timing / 1000);

        // Test Schnorr sigs in Ristretto Group
        let (skey, pkey) = make_random_keys();
        let message = b"Test message";
        let h = Hash::from_vector(message);
        let sig = sign_hash(&h, &skey);

        let start = SystemTime::now();
        for _ in 0..1000 {
            let h = Hash::from_vector(message);
            validate_sig(&h, &sig, &pkey).expect("validate sig");
        }
        let timing = start.elapsed().expect("ok");
        println!("Sig Validation: {:?}", timing / 1000);

        // Check Ristretto Group compression
        let x = RistrettoPoint::random(&mut thread_rng());
        let start = SystemTime::now();
        for _ in 0..1000 {
            assert!(32 == x.compress().to_bytes().len());
        }
        let timing = start.elapsed().expect("ok");
        println!("Ristretto Cmpr Time: {:?}", timing / 1000);

        // Check Ristretto Group decompression
        let x = RistrettoPoint::random(&mut thread_rng());
        let bytes = x.compress().to_bytes();
        let start = SystemTime::now();
        for _ in 0..1000 {
            CompressedRistretto::from_slice(&bytes)
                .decompress()
                .unwrap();
        }
        let timing = start.elapsed().expect("ok");
        println!("Ristretto DeCmpr Time: {:?}", timing / 1000);

        let s = pkey.to_bytes();
        let pkey2 = PublicKey::try_from_bytes(&s).expect("ok");
        assert!(pkey == pkey2);
        let s = pkey.to_hex();
        let pkey2 = PublicKey::try_from_hex(&s).expect("ok");
        assert!(pkey == pkey2);

        println!("one = {}", Fr::one().to_hex());
        // println!("pkey = {}", pkey);
        // println!("pkey = {:}", pkey);
        println!("pkey = {:?}", pkey);

        fn prt8(v: Scalar) {
            use crate::utils::u8v_to_hexstr;
            let mut bytes = v.to_bytes();
            bytes.reverse(); // because we are little endian byte vector
            let hex = u8v_to_hexstr(&bytes);
            println!("{}", hex);
        }
        let x = Scalar::zero() - Scalar::one();
        prt8(x);
        let two = Scalar::one() + Scalar::one();
        let xx = x + two;
        prt8(xx);

        let (bp1, gamma1) = make_range_proof(15);
        let (bp2, gamma2) = make_range_proof(12);
        let (bp3, gamma3) = make_range_proof(3);
        assert!(validate_range_proof(&bp1));
        assert!(validate_range_proof(&bp2));
        assert!(validate_range_proof(&bp3));
        assert!(bp1.vcmt == simple_commit(&gamma1, &Fr::from(15i64)));
        assert!(bp1.vcmt == gamma1 * Pt::one() + fee_a(15i64));
        let gamma_adj = gamma1 - gamma2 - gamma3;
        let pedsum = bp1.vcmt - bp2.vcmt - bp3.vcmt;
        assert!(pedsum == gamma_adj * Pt::one());
    }
}

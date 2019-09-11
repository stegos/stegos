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

use crate::hash::*;
use crate::scc::{Fr, Pt, BPGENS, PCGENS};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use ristretto_bulletproofs::RangeProof;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;

// -------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct BulletProof {
    pub vcmt: Pt,
    #[serde(deserialize_with = "crate::utils::deserialize_range_proof")]
    #[serde(serialize_with = "crate::utils::serialize_range_proof")]
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
        write!(f, "BP(vcmt: {:?}, ...)", self.vcmt.to_bytes())
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
            &bp.vcmt.internal_use_compress(),
            64,
        )
        .is_ok()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::scc::{make_random_keys, sign_hash, validate_sig, PublicKey};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use hex;
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

    #[test]
    fn check_hashable() {
        //let (bp, _gamma) = make_range_proof(12345);
        //let vcmt = hex::encode(bp.vcmt.to_bytes());
        //let proof = hex::encode(bp.proof.to_bytes());
        //println!("vcmt: {}", vcmt);
        //println!("proof: {}", proof);
        let vcmt = "4094e93f1aa89163bee6e1f5c013923fa7cc0b34793244751128ce0def09700b";
        let vcmt = hex::decode(vcmt).unwrap();
        let vcmt = Pt::try_from_bytes(&vcmt).unwrap();
        let proof = "183ad8f0c37b55c7fe17bf0cf2e4968ad76dc53f2f57c1e90b3135d2c8f86f422a0a502eef0b114e3c4aef6ff58bbd1a12a148dad1dd7eb0747d2dccabb67f6d60fc5c6998f07ef05abe41fee9f23922bb46724eadb29221c7f3af0497601a39a651731679a8a7ffccb3185342e1a0faa49510c6c5e187d31e203dbd7ad86e53a156649e26b6b143cc45ffbd29b247776db7a00910c4c01f3933e1dd7120760a90ee0c2c0d3e6ee7f45adec9e65a7275162010326c341629cca78fdf099d7e0ce585f5b143bf37a0cfe84e22220c902086e10a0fe6271590c5027dc62a6141045cdaf8bf2463a90893aa32e8ef43e03228eaf046292bfa435f95cca90a81be68e267de39afda7d4780d30ab00fe318230a7daa2937a3392757634368a1d5fd052ab5abee1800670c2d39e04a4e426a2842ab596f7ac7a614b6c254dcc3e88b0412b76806eb00f62a6644e64bb0a088cbbad8bb8e29ecd5a1d680a96487d8c40ede4e84854ce5b0b219cbd92497b2a837e5fd4e378bb8f9913c203712ac11865f48429ecabdfb22a5312cd774b0229690ad9380a857df4976d41d71d71acfe755be001ca8151fecb5cef0408ec5f01a7e34320d7ac6600b2994841e0e978edf05121d15190467579103648f200c07ddcd3b36f365765711eb03a35487072957524a1915c374b27f7772ec7005e06e5534249e34051f83df0f3c131a7784f6ba04c0c1d686cb2c5f2b61e9d905077ad04695d528200c542a3f069e15be33f99b5f12b71ed72062c341f5f42829f64557dfd358710cddefb5241cdf2d31b69ed51cc8e265edddf9244a7624160c273e4372f3ee74e91832cac904adc2cd147cc859b6275249bc71bddcac23ddae32515f526c2f7e373a32a027af28694fc7700f09fde6d37578339675e03b0c8317f66b63147878e0546cce737e7ad61971a82000";
        let proof = hex::decode(proof).unwrap();
        let proof = RangeProof::from_bytes(&proof).unwrap();
        let bp = BulletProof { vcmt, proof };
        assert_eq!(
            Hash::digest(&bp).to_hex(),
            "ca0f704c358938845c5028bcb492e45f71fafda2c48a39a15a8e0a4def60df6c"
        );
    }
}

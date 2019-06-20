//! mod.rs - Single-Curve Crypto
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

// use crate::CryptoError;

// use base58check::{FromBase58Check, ToBase58Check};
// use clear_on_drop::clear::Clear;
// use crypto::aes;
// use crypto::aes::KeySize::KeySize128;
// use crypto::aesni;
// use crypto::aessafe;
// use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
// use serde::de::{Deserialize, Deserializer};
// use serde::ser::{Serialize, Serializer};
// use std::cmp::Ordering;
// use std::hash as stdhash;

// use std::str::FromStr;
// use std::string::ToString;

extern crate curve25519_dalek;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate new_bulletproofs;
use new_bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

extern crate rand;
use rand::thread_rng;

use crate::hash::*;

extern crate sha3;
use sha3::Digest;

#[cfg(test)]
pub mod tests {
    use super::*;
    // use serde_json;
    use crate::curve1174::{make_random_keys, sign_hash, validate_sig, ECp};
    use std::time::SystemTime;

    #[test]
    fn test_new_bp() {
        /// run this code using:
        ///   cargo run -p stegos_crypto --example bulletproofs --release
        // Generators for Pedersen commitments.  These can be selected
        // independently of the Bulletproofs generators.
        let pc_gens = PedersenGens::default();

        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to 1.
        let bp_gens = BulletproofGens::new(64, 1);

        // A secret value we want to prove lies in the range [0, 2^32)
        let secret_value = 1037578891u64;

        // The API takes a blinding factor for the commitment.
        let blinding = Scalar::random(&mut thread_rng());

        // The proof can be chained to an existing transcript.
        // Here we create a transcript with a doctest domain separator.
        let mut prover_transcript = Transcript::new(b"doctest example");

        // Create a 64-bit rangeproof.
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret_value,
            &blinding,
            64,
        )
        .expect("A real program could handle errors");

        let start = SystemTime::now();
        for _ in 0..1000 {
            // Verification requires a transcript with identical initial state:
            let mut verifier_transcript = Transcript::new(b"doctest example");
            assert!(proof
                .verify_single(
                    &bp_gens,
                    &pc_gens,
                    &mut verifier_transcript,
                    &committed_value,
                    64
                )
                .is_ok());
        }
        let timing = start.elapsed().expect("ok");
        println!("BP Validation: {:?}", timing / 1000);

        // Test Schnorr sigs in Ristretto Group
        let gen = RistrettoPoint::random(&mut thread_rng());
        let skey = Scalar::random(&mut thread_rng());
        let pkey = skey * gen;
        let message = b"Test message";
        let secret_k = Scalar::random(&mut thread_rng());
        let big_k = secret_k * gen;
        let mut state = Hasher::new();
        big_k.compress().to_bytes().hash(&mut state);
        pkey.compress().to_bytes().hash(&mut state);
        message.hash(&mut state);
        let h = state.result();
        let map_val = Scalar::from_bits(h.bits());
        let u_val = secret_k + map_val * skey;

        let start = SystemTime::now();
        for _ in 0..1000 {
            let mut state = Hasher::new();
            big_k.compress().to_bytes().hash(&mut state);
            pkey.compress().to_bytes().hash(&mut state);
            message.hash(&mut state);
            let h = state.result();
            let map_val = Scalar::from_bits(h.bits());
            assert!(u_val * gen == big_k + map_val * pkey);
        }
        let timing = start.elapsed().expect("ok");
        println!("Sig Validation: {:?}", timing / 1000);

        // Compare with Curve1174 Schnorr Sigs
        let (skey, pkey) = make_random_keys();
        let h = Hash::from_vector(message);
        let sig = sign_hash(&h, &skey);
        let start = SystemTime::now();
        for _ in 0..1000 {
            let h = Hash::from_vector(message);
            validate_sig(&h, &sig, &pkey).expect("ok");
        }
        let timing = start.elapsed().expect("ok");
        println!("Schnorr Sig Validation: {:?}", timing / 1000);

        // Check Curve1174 Point Compression
        let x = ECp::random();
        let start = SystemTime::now();
        for _ in 0..1000 {
            x.compress();
        }
        let timing = start.elapsed().expect("ok");
        println!("Curve1174 Cmpr Time: {:?}", timing / 1000);

        // Check Ristretto Group compression
        let x = RistrettoPoint::random(&mut thread_rng());
        let start = SystemTime::now();
        for _ in 0..1000 {
            assert!(32 == x.compress().to_bytes().len());
        }
        let timing = start.elapsed().expect("ok");
        println!("Ristretto Cmpr Time: {:?}", timing / 1000);

        // Check Curve1174 Point decompression
        let x = ECp::random();
        let bytes = x.compress().to_bytes();
        let start = SystemTime::now();
        for _ in 0..1000 {
            ECp::try_from_bytes(bytes).expect("ok");
        }
        let timing = start.elapsed().expect("ok");
        println!("Curve1174 DeCmpr Time: {:?}", timing / 1000);

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
    }
}

//! Transaction output.

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

use failure::Error;
use std::fmt;
use stegos_crypto::bulletproofs::{make_range_proof, BulletProof};
use stegos_crypto::curve1174::cpt::{aes_encrypt, EncryptedPayload, PublicKey, SecretKey};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

// Re-export symbols needed for public API
pub use stegos_crypto::curve1174::CurveError;

/// Transaction output.
/// (ID, P_{M, δ}, Bp, E_M(x, γ, δ))
#[derive(Debug, Clone)]
pub struct Output {
    /// Clocked public key of recipient.
    /// P_M + δG
    pub recipient: PublicKey,

    /// Bulletproof on range on amount x.
    /// Contains Pedersen commitment.
    /// Size is approx. 3-5 KB (very structured data type).
    pub proof: BulletProof,

    /// Encrypted payload.
    ///
    /// E_M(x, γ, δ)
    /// Represents an encrypted packet contain the information about x, γ, δ
    /// that only receiver can red
    /// Size is approx 137 Bytes =
    ///     (R-val 65B, crypto-text 72B = (amount 8B, gamma 32B, delta 32B))
    pub payload: EncryptedPayload,
}

impl Output {
    /// Constructor for Output.
    pub fn new(
        timestamp: u64,
        sender_skey: SecretKey,
        recipient_pkey: PublicKey,
        amount: i64,
    ) -> Result<(Self, Fr), CurveError> {
        // Clock recipient public key
        let (cloaked_pkey, delta) = Self::cloak_key(sender_skey, recipient_pkey, timestamp);

        let (proof, gamma) = make_range_proof(amount);
        let payload = Self::encrypt_payload(delta, gamma, amount, cloaked_pkey)?;

        let output = Output {
            recipient: cloaked_pkey,
            proof,
            payload,
        };

        Ok((output, delta))
    }

    /// Cloak recipient's public key.
    fn cloak_key(
        sender_skey: SecretKey,
        recipient_pkey: PublicKey,
        timestamp: u64,
    ) -> (PublicKey, Fr) {
        // h is the digest of the recipients actual public key mixed with a timestamp.
        let mut hasher = Hasher::new();
        recipient_pkey.hash(&mut hasher);
        timestamp.hash(&mut hasher);
        let h = hasher.result();

        // Use deterministic randomness here too, to protect against PRNG attacks.
        let delta: Fr = Fr::synthetic_random(&"PKey", &sender_skey, &h);

        // Resulting publickey will be a random-like value in a safe range of the field,
        // not too small, and not too large. This helps avoid brute force attacks, looking
        // for the discrete log corresponding to delta.
        (recipient_pkey.cloak(delta), delta)
    }

    /// Create a new monetary transaction.
    fn encrypt_payload(
        delta: Fr,
        gamma: Fr,
        amount: i64,
        pkey: PublicKey,
    ) -> Result<EncryptedPayload, CurveError> {
        // Convert amount to BE vector.
        use std::mem::transmute;
        let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_be()) };

        let gamma_bytes: [u8; 32] = gamma.bits().to_lev_u8();
        let delta_bytes: [u8; 32] = delta.bits().to_lev_u8();

        let payload: Vec<u8> = [&amount_bytes[..], &delta_bytes[..], &gamma_bytes[..]].concat();

        // Ensure that the total length of package is 72 bytes.
        assert_eq!(payload.len(), 72);

        // String together a gamma, delta, and Amount (i64) all in one long vector and encrypt it.
        aes_encrypt(&payload, &pkey)
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Output({})", Hash::digest(self))
    }
}

impl Hashable for Output {
    /// Unique identifier of the output.
    /// Formed by hashing all fields of this structure.
    /// H_r(P_{M, δ},B_p, E_M(x, γ, δ)).
    fn hash(&self, state: &mut Hasher) {
        self.recipient.hash(state);
        self.proof.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for Box<Output> {
    fn hash(&self, state: &mut Hasher) {
        let output = self.as_ref();
        output.hash(state)
    }
}

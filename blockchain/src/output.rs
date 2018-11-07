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

use payload::EncryptedPayload;
use std::fmt;
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

/// Transaction output.
/// (ID, P_{M, δ}, Bp, E_M(x, γ, δ))
#[derive(Debug, Clone)]
pub struct Output {
    /// Unique identifier of the output.
    /// Formed by hashing the rest of this structure.
    /// H_r(P_{M, δ},B_p, E_M(x, γ, δ)).
    pub hash: Hash,

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
    pub fn new(recipient: PublicKey, proof: BulletProof, payload: EncryptedPayload) -> Output {
        let mut hasher = Hasher::new();
        recipient.hash(&mut hasher);
        // TODO: UTXO hash is non-deterministic
        // https://github.com/stegos/stegos/issues/125
        // proof.hash(&mut hasher);
        payload.hash(&mut hasher);
        let hash = hasher.result();

        Output {
            hash: hash,
            recipient: recipient,
            proof: proof,
            payload: payload,
        }
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Output({})", self.hash)
    }
}

impl Hashable for Output {
    fn hash(&self, state: &mut Hasher) {
        // Don't include self.hash because it is redundant in this case
        self.recipient.hash(state);
        // TODO: UTXO hash is non-deterministic
        // https://github.com/stegos/stegos/issues/125
        // proof.hash(&mut hasher);
        self.payload.hash(state);
    }
}

impl Hashable for Box<Output> {
    fn hash(&self, state: &mut Hasher) {
        let output = self.as_ref();
        output.hash(state)
    }
}

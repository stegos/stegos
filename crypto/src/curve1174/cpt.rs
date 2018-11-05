//! cpt.rs - Compressed Points & main API

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
//

use super::*;

extern crate crypto;

use crypto::aes;
use crypto::aes::KeySize::KeySize128;
use crypto::aesni;
use crypto::aessafe;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

// ------------------------------------------------------------------------------------------
// Client API - compressed points and simple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Pt([u8; 32]);

impl Pt {
    pub fn bits(self) -> [u8; 32] {
        self.0
    }

    pub fn nbr_str(&self) -> String {
        let v = Lev32(self.0);
        basic_nbr_str(&v.to_lev_u64())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let mut v = [0u8; 32];
        hexstr_to_lev_u8(&s, &mut v)?;
        Ok(Pt(v))
    }

    pub fn decompress(pt: Self) -> Result<ECp, CurveError> {
        ECp::try_from(pt)
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pt({})", self.nbr_str())
    }
}

impl Hashable for Pt {
    fn hash(&self, state: &mut Hasher) {
        "Pt".hash(state);
        (*self).bits().hash(state);
    }
}

impl From<ECp> for Pt {
    fn from(pt: ECp) -> Pt {
        let mut afpt = pt;
        norm(&mut afpt);
        let ptx = Fq::from(afpt.x);
        let mut x = U256::from(ptx).to_lev_u8();
        if afpt.y.is_odd() {
            x[31] |= 0x80;
        }
        Pt(x)
    }
}

// --------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SecretKey(Fr);

impl SecretKey {
    fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        Ok(SecretKey(Fr::from_str(s)?))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SKey({})", (*self).0.nbr_str())
    }
}

impl Hashable for SecretKey {
    fn hash(&self, state: &mut Hasher) {
        "SKey".hash(state);
        (*self).0.hash(state);
    }
}

impl From<Fr> for SecretKey {
    fn from(zr: Fr) -> Self {
        SecretKey(zr.unscaled())
    }
}

impl From<SecretKey> for Fr {
    fn from(skey: SecretKey) -> Self {
        skey.0
    }
}

// -----------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PublicKey(Pt);

impl PublicKey {
    fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        Ok(PublicKey(Pt::from_str(s)?))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PKey({})", (*self).0.nbr_str())
    }
}

impl Hashable for PublicKey {
    fn hash(&self, state: &mut Hasher) {
        "PKey".hash(state);
        (*self).0.hash(state);
    }
}

impl From<PublicKey> for Pt {
    fn from(pkey: PublicKey) -> Self {
        pkey.0
    }
}

impl From<ECp> for PublicKey {
    fn from(pt: ECp) -> Self {
        PublicKey(ECp::compress(pt))
    }
}

impl From<SecretKey> for PublicKey {
    fn from(skey: SecretKey) -> Self {
        let pt = Fr::from(skey) * *G;
        Self::from(pt)
    }
}

// -----------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey, SchnorrSig) {
    let h = Hash::from_vector(&seed);
    let zr = Fr::synthetic_random("skey", &*G, &h);
    let pt = zr * *G;
    let skey = SecretKey::from(zr);
    let pkey = PublicKey::from(pt);
    let hkey = Hash::digest(&pkey);
    let sig = sign_hash(&hkey, &skey);
    (skey, pkey, sig)
}

pub fn check_keying(pkey: &PublicKey, sig: &SchnorrSig) -> Result<bool, CurveError> {
    let hkey = Hash::digest(pkey);
    validate_sig(&hkey, &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey, SchnorrSig) {
    make_deterministic_keys(&Lev32::random().bits())
}

// -----------------------------------------------------------------------
// Schnorr Signatures (u, K)
//
// u*G = K + Fr(H(K, P, msg))*P
// generate K = k*G for k = random Fr
// generate u = k + Fr(H(K, P, msg)) * s

#[derive(Copy, Clone)]
pub struct SchnorrSig {
    pub u: Fr,
    pub K: Pt,
}

pub fn sign_hash(hmsg: &Hash, skey: &SecretKey) -> SchnorrSig {
    // Note: While we want k random, it should be deterministically random.
    // If, for the same keying, any two distinct messages produce a Schnorr signature
    // derived from the same k value, then it becomes possible to solve for the secret key,
    // using simple algebra in the Fr field, by observing the u component of the signature.
    //
    // We want k to appear to be random with respect to the message hash. So here we derive k from
    // the hash of the secret key and message hash. If the PRNG were attacked, we would be protected.
    //
    // At the same time, we don't want k to be too small, making a brute force search on K feasible,
    // since that could also be used to find the secret key. So we rehash the k value, if necessary,
    // until its value lies within an acceptable range.
    let k = Fr::synthetic_random("sig-k", skey, hmsg);
    let K = k * *G;
    let pkey = PublicKey::from(*skey);
    let h = Hash::digest_chain(&[&K, &pkey, hmsg]);
    let u = k + Fr::from(h) * Fr::from(*skey);
    SchnorrSig {
        u: u.unscaled(),
        K: Pt::from(K),
    }
}

pub fn validate_sig(hmsg: &Hash, sig: &SchnorrSig, pkey: &PublicKey) -> Result<bool, CurveError> {
    let h = Hash::digest_chain(&[&sig.K, pkey, hmsg]);
    let Ppt = Pt::decompress(pkey.0)?;
    let Kpt = Pt::decompress(sig.K)?;
    Ok(sig.u * *G == Kpt + Fr::from(h) * Ppt)
}

// ----------------------------------------------------------------
// Encrypted payloads with unilateral keying
//
// Transmit key info as pair (alpha*P + k*G, a*G) so user can compute
// keying seed k*G by subtracting s*(alpha*G) = alpha*P, from first tuple element.
// Actual AES keying comes from Hash(k*G).
// k and alpha are random Fr values.

use std::iter::repeat;

pub struct EncryptedPayload {
    pub apkg: Pt,
    pub ag: Pt,
    pub ctxt: Vec<u8>,
}

fn aes_encrypt_with_key(msg: &[u8], key: &[u8; 32]) -> Vec<u8> {
    // on input, key is 32B. AES128 only needs 16B for keying.
    // So take first 16B of key as keying,
    // and last 16B of key as CTR mode nonce
    let mut ctr = [0u8; 16];
    ctr.copy_from_slice(&key[16..]);
    let mut aes_enc = aes::ctr(aes::KeySize::KeySize128, key, &ctr[..]);
    let mut ctxt: Vec<u8> = repeat(0).take(msg.len()).collect();
    aes_enc.process(msg, &mut ctxt);
    ctxt
}

pub fn aes_encrypt(msg: &[u8], pkey: &PublicKey) -> Result<EncryptedPayload, CurveError> {
    let h = Hash::from_vector(msg);
    let alpha = Fr::synthetic_random("encr-alpha", pkey, &h);
    let k = Fr::synthetic_random("encr-k", pkey, &h);
    let ppt = ECp::decompress(Pt::from(*pkey))?; // could give CurveError if invalid PublicKey
    let apkg = alpha * ppt + k * *G; // generate key transfer cloaking pair, apkg and ag
    let ag = alpha * *G;
    let kg = k * *G; // the actual key seed
    let key = Hash::digest(&kg);
    let ctxt = aes_encrypt_with_key(msg, &key.bits());
    Ok(EncryptedPayload {
        apkg: Pt::from(apkg),
        ag: Pt::from(ag),
        ctxt: ctxt,
    })
}

pub fn aes_decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Vec<u8>, CurveError> {
    let zr = Fr::from(*skey);
    let apkg = ECp::decompress(payload.apkg)?; // could give CurveError if corrupted payload
    let ag = ECp::decompress(payload.ag)?; // ... ditto ...
    let kg = apkg - zr * ag; // compute the actual key seed = k*G
    let key = Hash::digest(&kg);
    Ok(aes_encrypt_with_key(&payload.ctxt, &key.bits()))
}

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
use crate::CryptoError;

use crypto::aes;
use crypto::aes::KeySize::KeySize128;
use crypto::aesni;
use crypto::aessafe;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use std::cmp::Ordering;
use std::hash as stdhash;

// ------------------------------------------------------------------------------------------
// Client API - compressed points and simple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Pt([u8; 32]);

impl Pt {
    /// Return random point on a curve.
    pub fn random() -> Self {
        ECp::random().compress()
    }

    /// Convert into raw bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        return self.0;
    }

    /// Try to convert from raw bytes.
    pub fn try_from_bytes(bytes_slice: &[u8]) -> Result<Self, CryptoError> {
        if bytes_slice.len() != 32 {
            return Err(CryptoError::InvalidBinaryLength(32, bytes_slice.len()));
        }
        let mut bytes: [u8; 32] = [0u8; 32];
        bytes.copy_from_slice(bytes_slice);
        ECp::try_from_bytes(bytes)?; // validate point
        let pt = Pt(bytes);
        Ok(pt)
    }

    /// Create from an uncompressed point.
    #[inline]
    pub fn compress(ept: ECp) -> Pt {
        let bytes = ECp::into_bytes(ept);
        Pt(bytes)
    }

    /// Decompress point.
    #[inline]
    pub fn decompress(self) -> Result<ECp, CryptoError> {
        ECp::decompress(self)
    }

    /// Convert into hex string.
    pub fn into_hex(self) -> String {
        let v = Lev32(self.0);
        basic_nbr_str(&v.to_lev_u64())
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut v = [0u8; 32];
        hexstr_to_lev_u8(&s, &mut v)?;
        ECp::try_from_bytes(v)?; // validate point
        Ok(Pt(v))
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pt({})", self.into_hex())
    }
}

impl fmt::Debug for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pt({})", self.into_hex())
    }
}

impl Hashable for Pt {
    fn hash(&self, state: &mut Hasher) {
        "Pt".hash(state);
        (*self).0.hash(state);
    }
}

impl From<ECp> for Pt {
    fn from(pt: ECp) -> Pt {
        pt.compress()
    }
}

impl Ord for Pt {
    fn cmp(&self, other: &Pt) -> Ordering {
        Lev32(self.into_bytes()).cmp(&Lev32(other.into_bytes()))
    }
}

impl PartialOrd for Pt {
    fn partial_cmp(&self, other: &Pt) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

// --------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SecretKey(Fr);

impl SecretKey {
    /// Convert into hex string.
    #[inline]
    pub fn into_hex(self) -> String {
        self.0.into_hex()
    }

    /// Try to convert from hex string.
    #[inline]
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(SecretKey(Fr::try_from_hex(s)?))
    }

    /// Convert into raw bytes.
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(SecretKey(Fr::try_from_bytes(bytes)?))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SKey({})", self.into_hex())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SKey({})", self.into_hex())
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
    /// Convert into raw bytes.
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(PublicKey(Pt::try_from_bytes(bytes)?))
    }

    /// Convert into hex string.
    #[inline]
    pub fn into_hex(self) -> String {
        self.0.into_hex()
    }

    /// Try to convert from hex string.
    #[inline]
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(PublicKey(Pt::try_from_hex(s)?))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKey({})", self.into_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKey({})", self.into_hex())
    }
}

impl Hashable for PublicKey {
    fn hash(&self, state: &mut Hasher) {
        "PKey".hash(state);
        (*self).0.hash(state);
    }
}

impl stdhash::Hash for PublicKey {
    fn hash<H: stdhash::Hasher>(&self, state: &mut H) {
        stdhash::Hash::hash(&"PKey", state);
        let bytes: [u8; 32] = self.into_bytes();
        stdhash::Hash::hash(&bytes, state);
    }
}

impl From<PublicKey> for Pt {
    fn from(pkey: PublicKey) -> Self {
        pkey.0
    }
}

impl From<Pt> for PublicKey {
    fn from(pt: Pt) -> Self {
        PublicKey(pt)
    }
}

impl From<ECp> for PublicKey {
    fn from(pt: ECp) -> Self {
        PublicKey(Pt::from(pt))
    }
}

impl From<SecretKey> for PublicKey {
    fn from(skey: SecretKey) -> Self {
        let pt = Fr::from(skey) * *G;
        Self::from(pt)
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        Pt::from(*self).cmp(&Pt::from(*other))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
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

pub fn check_keying(pkey: &PublicKey, sig: &SchnorrSig) -> Result<bool, CryptoError> {
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

#[derive(Copy, Clone, Debug)]
pub struct SchnorrSig {
    pub u: Fr,
    pub K: Pt,
}

impl Hashable for SchnorrSig {
    fn hash(&self, state: &mut Hasher) {
        "SchnorrSig".hash(state);
        self.u.hash(state);
        self.K.hash(state);
    }
}

impl Add<SchnorrSig> for SchnorrSig {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        // user should have ensured that sig.K are valid
        // before calling this operator
        let errmsg = "Invalid SchnorrSig.K point";
        let K_sum = self.K.decompress().expect(errmsg) + other.K.decompress().expect(errmsg);
        SchnorrSig {
            u: self.u + other.u,
            K: K_sum.compress(),
        }
    }
}

impl AddAssign<SchnorrSig> for SchnorrSig {
    fn add_assign(&mut self, other: Self) {
        let sum_sig = *self + other;
        self.u = sum_sig.u;
        self.K = sum_sig.K;
    }
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
    //
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

pub fn sign_hash_with_kval(
    hmsg: &Hash,
    skey: &SecretKey,
    k_val: Fr,
    sumK: &ECp,
    sumPKey: &ECp,
) -> SchnorrSig {
    // special signing primitive for use in generating multi-signatures
    // k_val was previously selected, then shared as K_val = k_val*G.
    //
    // The sumK argument here should represent the sum all participating K_vals.
    // The sumPKey argument should be the sum of all participating PublicKeys.
    //
    // We now form the u_val of the signature and return the completed
    // Schorr signature. The grand sumK_val and sumPKey are used in computing
    // the hash, but the returned K value in the signature represents only
    // our portion.
    //
    // When all signatures are added together, the resulting sig.K value should
    // be the same as the grand sum K_val used here.
    //
    // NOTE: Be Very Careful here... improper use of k_val can lead to Sony PS Attack.
    // No two different messages should ever be signed using the same k_val. In general,
    // it is safest to make k_val be deterministically random based on the message hash.
    //
    // Sony PS Attack: two different messages, same Pkey, same skey, and same k_val:
    // Using simple algebra in the field Fr, we can discover user's skey (SecretKey) by
    // subtracting the two sig.u_vals and dividing the difference by the difference in hash
    // values of the two messages. The common k_val cancels out in the sig.u_val sibtraction.
    // This is disastrous!
    //
    let my_K = k_val * *G;
    let pkey = PublicKey::from(Pt::from(*sumPKey));
    let h = Hash::digest_chain(&[sumK, &pkey, hmsg]);
    let u = k_val + Fr::from(h) * Fr::from(*skey);
    SchnorrSig {
        u: u.unscaled(),
        K: Pt::from(my_K),
    }
}

pub fn validate_sig(hmsg: &Hash, sig: &SchnorrSig, pkey: &PublicKey) -> Result<bool, CryptoError> {
    let h = Hash::digest_chain(&[&sig.K, pkey, hmsg]);
    let Ppt = Pt::decompress(pkey.0)?;
    let Kpt = Pt::decompress(sig.K)?;
    Ok(sig.u * *G == Kpt + Fr::from(h) * Ppt)
}

// ----------------------------------------------------------------
// Encrypted payloads with unilateral keying
//
// Transmit key hint as alpha*G, so recipient can compute
// keying seed alpha*P = s*(alpha*G)
// Actual AES keying comes from Hash(s*alpha*G).
// alpha is a random Fr value.

use std::iter::repeat;

#[derive(Clone)]
pub struct EncryptedPayload {
    pub ag: Pt,        // key hint = alpha*G
    pub ctxt: Vec<u8>, // ciphertext
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ag={} cmsg={}", self.ag, u8v_to_hexstr(&self.ctxt))
    }
}

impl fmt::Display for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Hashable for EncryptedPayload {
    fn hash(&self, state: &mut Hasher) {
        "Encr".hash(state);
        self.ag.hash(state);
        self.ctxt[..].hash(state);
    }
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

pub fn aes_encrypt(msg: &[u8], pkey: &PublicKey) -> Result<EncryptedPayload, CryptoError> {
    let h = Hash::from_vector(msg);
    let alpha = Fr::synthetic_random("encr-alpha", pkey, &h);
    let ppt = ECp::decompress(Pt::from(*pkey))?; // could give CryptoError if invalid PublicKey
    let ap = alpha * ppt; // generate key (alpha*s*G = alpha*P), and hint ag = alpha*G
    let ag = alpha * *G;
    let key = Hash::digest(&ap);
    let ctxt = aes_encrypt_with_key(msg, &key.bits());
    Ok(EncryptedPayload {
        ag: Pt::from(ag),
        ctxt: ctxt,
    })
}

pub fn aes_decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    let zr = Fr::from(*skey);
    let ag = ECp::decompress(payload.ag)?; // could give CryptoError if corrupted payload
    let asg = zr * ag; // compute the actual key seed = s*alpha*G
    let key = Hash::digest(&asg);
    Ok(aes_encrypt_with_key(&payload.ctxt, &key.bits()))
}

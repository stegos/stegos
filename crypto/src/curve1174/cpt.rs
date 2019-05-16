//! cpt.rs - Compressed Points & main API

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

use super::*;
use crate::CryptoError;

use clear_on_drop::clear::Clear;
use crypto::aes;
use crypto::aes::KeySize::KeySize128;
use crypto::aesni;
use crypto::aessafe;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::cmp::Ordering;
use std::hash as stdhash;

// ------------------------------------------------------------------------------------------
// Client API - compressed points and simple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Pt([u8; 32]);

impl Pt {
    // return a totally invalid point of all zeros
    pub fn zero() -> Self {
        Pt([0u8; 32])
    }

    pub fn flip_sign(cmt: &mut Pt) {
        // flip sign bit in compressed Pt
        // used for test purposes in BulletProofs
        cmt.0[31] ^= 0x80;
    }

    /// Return random point on a curve.
    pub fn random() -> Self {
        ECp::random().compress()
    }

    /// Convert into raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
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
    pub(crate) fn compress(ept: ECp) -> Pt {
        let pt_4 = ecpt::prescale_for_compression(ept);
        let bytes = ECp::to_bytes(&pt_4);
        Pt(bytes)
    }

    /// Decompress point.
    #[inline]
    pub fn decompress(&self) -> Result<ECp, CryptoError> {
        ECp::try_from_bytes(self.0)
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
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

impl fmt::Debug for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pt({})", self.to_hex())
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
    // ValueShuffle needs a pseudo ordering of Pt values...
    fn cmp(&self, other: &Pt) -> Ordering {
        let me = self.decompress().unwrap().compress();
        let pt = other.decompress().unwrap().compress();
        Lev32(me.to_bytes()).cmp(&Lev32(pt.to_bytes()))
    }
}

impl PartialOrd for Pt {
    fn partial_cmp(&self, other: &Pt) -> Option<Ordering> {
        Some(Self::cmp(self, other))
    }
}

// --------------------------------------------------------------------

#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey(Fr);

impl SecretKey {
    /// Convert into hex string.
    #[inline]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from hex string.
    #[inline]
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(SecretKey(Fr::try_from_hex(s)?))
    }

    /// Convert into raw bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(SecretKey(Fr::try_from_bytes(bytes)?))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SKey(*HIDDEN DATA*)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zap();
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
        Self::from(&zr)
    }
}

impl<'a> From<&'a Fr> for SecretKey {
    fn from(zr: &'a Fr) -> Self {
        SecretKey(zr.unscaled())
    }
}

impl From<SecretKey> for Fr {
    fn from(skey: SecretKey) -> Self {
        Fr::from(&skey)
    }
}

impl<'a> From<&'a SecretKey> for Fr {
    fn from(skey: &'a SecretKey) -> Self {
        skey.0
    }
}

// -----------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PublicKey(Pt);

impl PublicKey {
    // zero key - totally invalid point, but useful for
    // universal encryption
    pub fn zero() -> Self {
        PublicKey(Pt::zero())
    }

    /// Decompress into a point.
    #[inline]
    pub fn decompress(self) -> Result<ECp, CryptoError> {
        self.0.decompress()
    }

    /// Convert into raw bytes.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(PublicKey(Pt::try_from_bytes(bytes)?))
    }

    /// Convert into hex string.
    #[inline]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from hex string.
    #[inline]
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(PublicKey(Pt::try_from_hex(s)?))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        write!(f, "{}", &self.to_hex()[0..12])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKey({})", self.to_hex())
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
        let bytes: [u8; 32] = self.to_bytes();
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

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PublicKey::try_from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// -----------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey) {
    let h = Hash::from_vector(&seed);
    let zr = Fr::synthetic_random("skey", &*G, &h);
    let pt = zr * *G;
    let skey = SecretKey::from(zr);
    let pkey = PublicKey::from(pt);
    (skey, pkey)
}

pub fn check_keying(skey: &SecretKey, pkey: &PublicKey) -> Result<(), CryptoError> {
    let hkey = Hash::digest(&pkey);
    let sig = sign_hash(&hkey, &skey);
    validate_sig(&hkey, &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey) {
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

impl SchnorrSig {
    pub fn new() -> Self {
        // construct a dummy signature
        SchnorrSig {
            u: Fr::zero(),
            K: (*G).compress(),
        }
    }
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
    let pkey = PublicKey::from(skey.clone());
    let h = Hash::digest_chain(&[&K, &pkey, hmsg]);
    let u = k + Fr::from(h) * Fr::from(skey.clone());
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
    let u = k_val + Fr::from(h) * Fr::from(skey.clone());
    SchnorrSig {
        u: u.unscaled(),
        K: Pt::from(my_K),
    }
}

pub fn validate_sig(hmsg: &Hash, sig: &SchnorrSig, pkey: &PublicKey) -> Result<(), CryptoError> {
    let h = Hash::digest_chain(&[&sig.K, pkey, hmsg]);
    let Ppt = pkey.0.decompress()?;
    let Kpt = sig.K.decompress()?;
    if sig.u * *G == Kpt + Fr::from(h) * Ppt {
        return Ok(());
    } else {
        return Err(CryptoError::BadKeyingSignature);
    }
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
        write!(f, "ag={:?} cmsg={}", self.ag, u8v_to_hexstr(&self.ctxt))
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
    let mut aes_enc = aes::ctr(aes::KeySize::KeySize128, &key[..16], &key[16..]);
    let mut ctxt: Vec<u8> = repeat(0).take(msg.len()).collect();
    aes_enc.process(msg, &mut ctxt);
    ctxt
}

pub fn aes_encrypt(msg: &[u8], pkey: &PublicKey) -> Result<EncryptedPayload, CryptoError> {
    if *pkey == PublicKey::zero() {
        // construct an unencrypted payload that anyone can read.
        Ok(EncryptedPayload {
            ag: Pt::zero(),
            ctxt: msg.to_vec(),
        })
    } else {
        // normal encrytion with keying hint
        let h = Hash::from_vector(msg);
        let alpha = Fr::synthetic_random("encr-alpha", pkey, &h);
        let ppt = pkey.decompress()?; // could give CryptoError if invalid PublicKey
        let ap = alpha * ppt; // generate key (alpha*s*G = alpha*P), and hint ag = alpha*G
        let ag = alpha * *G;
        let key = Hash::digest(&ap);
        let ctxt = aes_encrypt_with_key(msg, &key.bits());
        Ok(EncryptedPayload {
            ag: Pt::from(ag),
            ctxt,
        })
    }
}

pub fn aes_decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    if payload.ag == Pt::zero() {
        // universal unencrypted payload
        Ok(payload.ctxt.clone())
    } else {
        // normal encryption, key = skey * AG
        let zr = Fr::from(skey.clone());
        let ag = payload.ag.decompress()?; // could give CryptoError if corrupted payload
        let asg = zr * ag; // compute the actual key seed = s*alpha*G
        let key = Hash::digest(&asg);
        Ok(aes_encrypt_with_key(&payload.ctxt, &key.bits()))
    }
}

// -----------------------------------------------------------

fn make_securing_keys(seed: &str) -> (SecretKey, PublicKey) {
    // Do we need a salt? We won't be storing these seed keys
    // anywhere, so there is nothing to guard against rainbow table
    // attacks. And so I don't think we need salting.
    let mut seed = Hash::from_str(seed);
    for _ in 1..1024 {
        seed = Hash::from_vector(&seed.bits());
    }
    make_deterministic_keys(&seed.bits())
}

#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub payload: EncryptedPayload,
    pub sig: SchnorrSig,
}

impl Hashable for EncryptedKey {
    fn hash(&self, state: &mut Hasher) {
        self.payload.hash(state);
        self.sig.hash(state);
    }
}

pub fn encrypt_key(seed: &str, key_to_encrypt: &[u8]) -> EncryptedKey {
    // For secure storage of keying material
    // Returns an AES encrypted key, along with a SchnorrSig on
    // the encrytped key.
    let (skey, pkey) = make_securing_keys(seed);
    let payload = aes_encrypt(key_to_encrypt, &pkey).expect("Valid Pubkey");
    let mut state = Hasher::new();
    payload.hash(&mut state);
    let h = state.result();
    let sig = sign_hash(&h, &skey);
    EncryptedKey { payload, sig }
}

pub fn decrypt_key(seed: &str, encr_key: &EncryptedKey) -> Result<Vec<u8>, CryptoError> {
    // For secure retrieval of keying material
    // check that the signature matches the encrypted key,
    // then decrypt the key
    //
    // Return CryptoError::BadKeyingSignature if the Schnorr
    // signature fails to validate the hash of the encrypted payload.
    let (skey, pkey) = make_securing_keys(seed);
    let mut state = Hasher::new();
    encr_key.payload.hash(&mut state);
    let h = state.result();
    validate_sig(&h, &encr_key.sig, &pkey)?;
    aes_decrypt(&encr_key.payload, &skey)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn encr_keying() {
        let (skey, _) = make_deterministic_keys(b"testing");
        let my_cloaking_seed = "diddly";
        let encr_key = encrypt_key(my_cloaking_seed, &skey.to_bytes());
        assert!(encr_key.payload.ctxt != skey.to_bytes());
        let recovered_skey =
            decrypt_key(my_cloaking_seed, &encr_key).expect("Key couldn't be decrypted");
        assert!(recovered_skey == skey.to_bytes());
    }
}

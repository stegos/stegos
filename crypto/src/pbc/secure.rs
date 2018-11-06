//! Secure Pairings using BN Curve FR256 (type F, r approx 256 bits)

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

//! --------------------------------------------------------------------------
//! Field and group elements can be constructed from byte-vectors
//! with UTF8 hex chars, as in b"FF3C...". Never use str format "FF3C..."
//!
//! This pairing system is intended for blockchain BLS mulit-signatures, and
//! encrypted payloads in UTXO's. No math is performed on the individual groups,
//! and so we do not provide convenient infix access to such operations.
//! --------------------------------------------------------------------------

use super::*;
use hash::*;
use rand::thread_rng;
use utils::*;

use std::cmp::Ordering;
use std::hash as stdhash;
use std::ops::Neg;

use rand::{Rng, ThreadRng};

// --------------------------------------------------------------------------------

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Zr([u8; ZR_SIZE_FR256]);

impl Zr {
    pub fn new() -> Zr {
        Zr(Zr::wv())
    }

    fn wv() -> [u8; ZR_SIZE_FR256] {
        [0u8; ZR_SIZE_FR256]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn acceptable_minval() -> Self {
        // approx sqrt modulus
        let mut x = [0u8; ZR_SIZE_FR256];
        {
            let mid = ZR_SIZE_FR256 >> 1;
            let (_, bot) = x.split_at_mut(mid);
            let botlen = ZR_SIZE_FR256 - mid;
            bot.copy_from_slice(&(*ORD_FR256)[0..botlen]);
        }
        Zr(x)
    }

    pub fn acceptable_maxval() -> Self {
        // approx = modulus - sqrt(modulus)
        -*MIN_FR256
    }

    pub fn acceptable_random_rehash(k: Self) -> Self {
        let min = *MIN_FR256;
        let max = *MAX_FR256;
        let mut mk = k;
        while mk < min || mk > max {
            mk = Self::from(Hash::digest(&mk));
        }
        mk
    }

    pub fn random() -> Self {
        let mut rng: ThreadRng = thread_rng();
        let mut zx = Zr(rng.gen::<[u8; ZR_SIZE_FR256]>());
        let min = *MIN_FR256;
        let max = *MAX_FR256;
        while zx < min || zx > max {
            zx = Zr(rng.gen::<[u8; ZR_SIZE_FR256]>());
        }
        zx
    }

    pub fn synthetic_random(pref: &str, uniq: &Hashable, h: &Hash) -> Self {
        // Construct a pseudo random field value without using the PRNG
        // This generates so-called "deterministic randomness" and assures
        // random-appearing values that will always be the same for the same
        // input keying. The result will be in the "safe" range for the field.
        let x = Self::from(Hash::digest_chain(&[&Hash::from_str(pref), uniq, h]));
        Self::acceptable_random_rehash(x)
    }

    pub fn from_str(s: &str) -> Result<Zr, hex::FromHexError> {
        // result might be larger than prime order, r,
        // but will be interpreted by PBC lib as (Zr mod r).
        let mut v = Zr::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(Zr(v))
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Zr", &self.base_vector())
    }
}

impl From<Hash> for Zr {
    fn from(h: Hash) -> Self {
        let v = Zr::new();
        unsafe {
            rust_libpbc::get_Zr_from_hash(
                *CONTEXT_FR256,
                v.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        v
    }
}

impl Eq for Zr {}
impl PartialEq for Zr {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl Ord for Zr {
    fn cmp(&self, other: &Self) -> Ordering {
        ucmp_be(&self.0, &other.0)
    }
}

impl PartialOrd for Zr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Zr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for Zr {
    fn hash(&self, state: &mut Hasher) {
        "Zr".hash(state);
        self.base_vector().hash(state);
    }
}

impl Neg for Zr {
    type Output = Self;
    fn neg(self) -> Self {
        let ans = self.clone();
        unsafe {
            rust_libpbc::neg_Zr_val(*CONTEXT_FR256, ans.base_vector().as_ptr() as *mut _);
        }
        ans
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
#[repr(C)]
pub struct G1([u8; G1_SIZE_FR256]);

impl G1 {
    pub fn new() -> G1 {
        G1(G1::wv())
    }

    fn wv() -> [u8; G1_SIZE_FR256] {
        [0u8; G1_SIZE_FR256]
    }
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G1", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<G1, hex::FromHexError> {
        let mut v = G1::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(G1(v))
    }

    pub fn generator() -> Self {
        let v = Self::new();
        unsafe {
            rust_libpbc::get_g1(
                *CONTEXT_FR256,
                v.base_vector().as_ptr() as *mut _,
                G1_SIZE_FR256 as u64,
            );
        }
        v
    }
}

impl fmt::Display for G1 {
    // for display of signatures
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for G1 {
    fn hash(&self, state: &mut Hasher) {
        "G1".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for G1 {}
impl PartialEq for G1 {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
#[repr(C)]
pub struct G2([u8; G2_SIZE_FR256]);

impl G2 {
    pub fn new() -> Self {
        G2(G2::wv())
    }

    fn wv() -> [u8; G2_SIZE_FR256] {
        [0u8; G2_SIZE_FR256]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G2", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let mut v = Self::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(G2(v))
    }

    pub fn generator() -> Self {
        let v = Self::new();
        unsafe {
            rust_libpbc::get_g2(
                *CONTEXT_FR256,
                v.base_vector().as_ptr() as *mut _,
                G2_SIZE_FR256 as u64,
            );
        }
        v
    }
}

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for G2 {
    fn hash(&self, state: &mut Hasher) {
        "G2".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for G2 {}
impl PartialEq for G2 {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl stdhash::Hash for G2 {
    fn hash<H: stdhash::Hasher>(&self, state: &mut H) {
        stdhash::Hash::hash("G2", state);
        stdhash::Hash::hash(&self.0[..], state);
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GT([u8; GT_SIZE_FR256]);

impl GT {
    pub fn new() -> GT {
        GT(GT::wv())
    }

    fn wv() -> [u8; GT_SIZE_FR256] {
        [0u8; GT_SIZE_FR256]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("GT", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let mut v = GT::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(GT(v))
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for GT {
    fn hash(&self, state: &mut Hasher) {
        "GT".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for GT {}
impl PartialEq for GT {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct SecretKey(Zr);

impl SecretKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("SKey", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let z = Zr::from_str(s)?;
        Ok(SecretKey(z))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for SecretKey {
    fn hash(&self, state: &mut Hasher) {
        "SKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// -----------------------------------------

#[derive(Copy, Clone)]
pub struct PublicKey(G2);

impl PublicKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("PKey", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let g = G2::from_str(s)?;
        Ok(PublicKey(g))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for PublicKey {
    fn hash(&self, state: &mut Hasher) {
        "PKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for PublicKey {}
impl PartialEq for PublicKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

impl stdhash::Hash for PublicKey {
    // we often want to look things up by public key
    // std::HashMap needs this
    fn hash<H: stdhash::Hasher>(&self, state: &mut H) {
        stdhash::Hash::hash("PKey", state);
        stdhash::Hash::hash(&self.0, state);
    }
}

// -----------------------------------------

#[derive(Copy, Clone)]
pub struct SecretSubKey(G1);

impl SecretSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("SSubKey", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let g = G1::from_str(s)?;
        Ok(SecretSubKey(g))
    }
}

impl fmt::Display for SecretSubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for SecretSubKey {
    fn hash(&self, state: &mut Hasher) {
        "SSubKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for SecretSubKey {}
impl PartialEq for SecretSubKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct PublicSubKey(G2);

impl PublicSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("PSubKey", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let g = G2::from_str(s)?;
        Ok(PublicSubKey(g))
    }
}

impl fmt::Display for PublicSubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for PublicSubKey {
    fn hash(&self, state: &mut Hasher) {
        "PSubKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for PublicSubKey {}
impl PartialEq for PublicSubKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// -----------------------------------------

#[derive(Copy, Clone)]
pub struct Signature(G1);

impl Signature {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Sig", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let g = G1::from_str(s)?;
        Ok(Signature(g))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for Signature {
    fn hash(&self, state: &mut Hasher) {
        "Sig".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// -----------------------------------------

#[derive(Copy, Clone)]
pub struct BlsSignature {
    sig: Signature,
    pkey: PublicKey,
}

// ------------------------------------------------------------------------
// BLS Signature Generation & Checking

pub fn sign_hash(h: &Hash, skey: &SecretKey) -> Signature {
    // return a raw signature on a hash
    let v = G1::new();
    unsafe {
        rust_libpbc::sign_hash(
            *CONTEXT_FR256,
            v.base_vector().as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    Signature(v)
}

pub fn check_hash(h: &Hash, sig: &Signature, pkey: &PublicKey) -> bool {
    // check a hash with a raw signature, return t/f
    unsafe {
        0 == rust_libpbc::check_signature(
            *CONTEXT_FR256,
            sig.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
            pkey.base_vector().as_ptr() as *mut _,
        )
    }
}

pub fn sign_message(msg: &[u8], skey: &SecretKey, pkey: &PublicKey) -> BlsSignature {
    // hash the message and form a BLS signature
    BlsSignature {
        sig: sign_hash(&Hash::from_vector(&msg), skey),
        pkey: pkey.clone(),
    }
}

pub fn check_message(msg: &[u8], sig: &BlsSignature) -> bool {
    // check the message against the BLS signature, return t/f
    check_hash(&Hash::from_vector(&msg), &sig.sig, &sig.pkey)
}

// ------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey, Signature) {
    let h = Hash::from_vector(&seed);
    let zr = Zr::synthetic_random("skey", &G1::generator(), &h);
    let pt = G2::generator().clone(); // public keys in G2
    unsafe {
        rust_libpbc::exp_G2z(
            *CONTEXT_FR256,
            pt.base_vector().as_ptr() as *mut _,
            zr.base_vector().as_ptr() as *mut _,
        )
    }
    let skey = SecretKey(zr);
    let pkey = PublicKey(pt);
    let hpk = Hash::digest(&pkey);
    let sig = sign_hash(&hpk, &skey);
    (skey, pkey, sig)
}

pub fn check_keying(pkey: &PublicKey, sig: &Signature) -> bool {
    check_hash(&Hash::digest(pkey), &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey, Signature) {
    let mut rng: ThreadRng = thread_rng();
    make_deterministic_keys(&rng.gen::<[u8; 32]>())
}

// ------------------------------------------------------------------------
// Subkey generation and Sakai-Kasahara Encryption

pub fn make_secret_subkey(skey: &SecretKey, seed: &[u8]) -> SecretSubKey {
    let h = Hash::from_vector(&seed);
    let sk = G1::new();
    unsafe {
        rust_libpbc::make_secret_subkey(
            *CONTEXT_FR256,
            sk.base_vector().as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    SecretSubKey(sk)
}

pub fn make_public_subkey(pkey: &PublicKey, seed: &[u8]) -> PublicSubKey {
    let h = Hash::from_vector(&seed);
    let pk = G2::new();
    unsafe {
        rust_libpbc::make_public_subkey(
            *CONTEXT_FR256,
            pk.base_vector().as_ptr() as *mut _,
            pkey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    PublicSubKey(pk)
}

// -----------------------------------------------------
// Sakai-Hasakara Encryption

#[derive(Copy, Clone)]
pub struct RVal(G2);

impl RVal {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("RVal", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let g = G2::from_str(s)?;
        Ok(RVal(g))
    }
}

impl fmt::Display for RVal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Hashable for RVal {
    fn hash(&self, state: &mut Hasher) {
        "RVal".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for RVal {}
impl PartialEq for RVal {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// structure of a SAKKI encryption.
// ---------------------------------
// For use in UTXO's you will only want to store the
// ciphertext, cmsg, and the rval. Proper recipients
// already know their own public keys, and the IBE ID
// that was used to encrypt their payload.
// ----------------------------------
pub struct EncryptedPacket {
    pkey: PublicKey, // public key of recipient
    id: Vec<u8>,     // IBE ID
    rval: RVal,      // R_val used for SAKE encryption
    cmsg: Vec<u8>,   // encrypted payload
}

impl EncryptedPacket {
    pub fn rval(&self) -> &RVal {
        &self.rval
    }

    pub fn cmsg(&self) -> &Vec<u8> {
        &self.cmsg
    }
}

pub fn ibe_encrypt(msg: &[u8], pkey: &PublicKey, id: &[u8]) -> EncryptedPacket {
    let nmsg = msg.len();

    // compute IBE public key
    let pkid = make_public_subkey(&pkey, &id);

    // compute hash of concatenated id:msg
    let mut concv = Vec::from(id);
    for b in msg.to_vec() {
        concv.push(b);
    }
    let rhash = Hash::from_vector(&concv);

    let rval = G2::new();
    let pval = GT::new();
    unsafe {
        rust_libpbc::sakai_kasahara_encrypt(
            *CONTEXT_FR256,
            rval.base_vector().as_ptr() as *mut _,
            pval.base_vector().as_ptr() as *mut _,
            pkid.base_vector().as_ptr() as *mut _,
            rhash.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    // encrypt with (msg XOR H(pairing-val))
    let mut cmsg = hash_nbytes(nmsg, &pval.base_vector());
    for ix in 0..nmsg {
        cmsg[ix] ^= msg[ix];
    }
    EncryptedPacket {
        pkey: *pkey,
        id: id.to_vec(),
        rval: RVal(rval),
        cmsg: cmsg,
    }
}

pub fn ibe_decrypt(pack: &EncryptedPacket, skey: &SecretKey) -> Option<Vec<u8>> {
    let skid = make_secret_subkey(&skey, &pack.id);
    let pkid = make_public_subkey(&pack.pkey, &pack.id);
    let nmsg = pack.cmsg.len();
    let pval = GT::new();
    unsafe {
        rust_libpbc::sakai_kasahara_decrypt(
            *CONTEXT_FR256,
            pval.base_vector().as_ptr() as *mut _,
            pack.rval.base_vector().as_ptr() as *mut _,
            skid.base_vector().as_ptr() as *mut _,
        );
    }
    // decrypt using (ctxt XOR H(pairing_val))
    let mut msg = hash_nbytes(nmsg, &pval.base_vector());
    for ix in 0..nmsg {
        msg[ix] ^= pack.cmsg[ix];
    }
    // Now check that message was correctly decrypted
    // compute hash of concatenated id:msg
    let mut concv = pack.id.clone();
    for b in msg.clone() {
        concv.push(b);
    }
    let rhash = Hash::from_vector(&concv);
    unsafe {
        let ans = rust_libpbc::sakai_kasahara_check(
            *CONTEXT_FR256,
            pack.rval.base_vector().as_ptr() as *mut _,
            pkid.base_vector().as_ptr() as *mut _,
            rhash.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
        if ans == 0 {
            Some(msg)
        } else {
            None
        }
    }
}

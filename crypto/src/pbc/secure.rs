//! Secure Pairings using BN Curve FR256 (type F, r approx 256 bits)

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

//! --------------------------------------------------------------------------
//! Field and group elements can be constructed from byte-vectors
//! with UTF8 hex chars, as in b"FF3C...". Never use str format "FF3C..."
//!
//! This pairing system is intended for blockchain BLS mulit-signatures, and
//! encrypted payloads in UTXO's. No math is performed on the individual groups,
//! and so we do not provide convenient infix access to such operations.
//! --------------------------------------------------------------------------

use super::*;
use crate::CryptoError;

use clear_on_drop::clear::Clear;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use rand::Rng;
use serde::ser::{Serialize, Serializer};
use std::cmp::Ordering;
use std::hash as stdhash;
use std::ops::{Add, AddAssign, Neg};

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

    pub fn zap(&mut self) {
        self.0.clear();
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

    pub fn synthetic_random(pref: &str, uniq: &dyn Hashable, h: &Hash) -> Self {
        // Construct a pseudo random field value without using the PRNG
        // This generates so-called "deterministic randomness" and assures
        // random-appearing values that will always be the same for the same
        // input keying. The result will be in the "safe" range for the field.
        let x = Self::from(Hash::digest_chain(&[&Hash::from_str(pref), uniq, h]));
        Self::acceptable_random_rehash(x)
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        u8v_to_hexstr(&self.0)
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Zr, CryptoError> {
        // result might be larger than prime order, r,
        // but will be interpreted by PBC lib as (Zr mod r).
        let mut v = Zr::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(Zr(v))
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> [u8; ZR_SIZE_FR256] {
        self.0
    }

    /// Try to convert from raw bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ZR_SIZE_FR256 {
            return Err(CryptoError::InvalidBinaryLength(ZR_SIZE_FR256, bytes.len()).into());
        }
        let mut bits: [u8; ZR_SIZE_FR256] = [0u8; ZR_SIZE_FR256];
        bits.copy_from_slice(bytes);
        Ok(Zr(bits))
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

impl Hashable for Zr {
    fn hash(&self, state: &mut Hasher) {
        "SecureZr".hash(state);
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
    /// Create a new point which binary representation consists of all zeros.
    pub fn zero() -> G1 {
        G1(G1::wv())
    }

    /// Check that binary representation consists of all zeros.
    pub fn is_zero(&self) -> bool {
        self.0[..] == G1::wv()[..]
    }

    pub fn zap(&mut self) {
        self.0.clear();
    }

    fn wv() -> [u8; G1_SIZE_FR256] {
        [0u8; G1_SIZE_FR256]
    }
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        u8v_to_hexstr(&self.0)
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<G1, CryptoError> {
        let mut v = G1::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(G1(v))
    }

    pub fn to_bytes(&self) -> [u8; G1_SIZE_FR256] {
        self.0
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != G1_SIZE_FR256 {
            return Err(CryptoError::InvalidBinaryLength(G1_SIZE_FR256, bytes.len()).into());
        }
        let mut bits: [u8; G1_SIZE_FR256] = [0u8; G1_SIZE_FR256];
        bits.copy_from_slice(bytes);
        Ok(G1(bits))
    }

    pub fn generator() -> Self {
        let v = Self::zero();
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

impl fmt::Debug for G1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureG1({})", self.to_hex())
    }
}

impl Hashable for G1 {
    fn hash(&self, state: &mut Hasher) {
        "SecureG1".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for G1 {}
impl PartialEq for G1 {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl Add<G1> for G1 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        add_G1_G1(&self, &other)
    }
}

impl AddAssign<G1> for G1 {
    fn add_assign(&mut self, other: Self) {
        *self = add_G1_G1(self, &other);
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
#[repr(C)]
pub struct G2([u8; G2_SIZE_FR256]);

impl G2 {
    /// Create a new point which binary representation consists of all zeros.
    pub fn zero() -> G2 {
        G2(G2::wv())
    }

    /// Check that binary representation consists of all zeros.
    pub fn is_zero(&self) -> bool {
        self.0[..] == G2::wv()[..]
    }

    fn wv() -> [u8; G2_SIZE_FR256] {
        [0u8; G2_SIZE_FR256]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        u8v_to_hexstr(&self.0)
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut v = Self::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(G2(v))
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> [u8; G2_SIZE_FR256] {
        self.0
    }

    /// Try to convert from raw bytes.
    pub fn try_from_bytes(bytes_slices: &[u8]) -> Result<Self, CryptoError> {
        if bytes_slices.len() != G2_SIZE_FR256 {
            return Err(CryptoError::InvalidBinaryLength(G2_SIZE_FR256, bytes_slices.len()).into());
        }
        let mut bytes: [u8; G2_SIZE_FR256] = [0u8; G2_SIZE_FR256];
        bytes.copy_from_slice(bytes_slices);
        Ok(G2(bytes))
    }

    pub fn generator() -> Self {
        let v = Self::zero();
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

impl fmt::Debug for G2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureG2({})", self.to_hex())
    }
}

impl Hashable for G2 {
    fn hash(&self, state: &mut Hasher) {
        "SecureG2".hash(state);
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

impl Add<G2> for G2 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        add_G2_G2(&self, &other)
    }
}

impl AddAssign<G2> for G2 {
    fn add_assign(&mut self, other: Self) {
        *self = add_G2_G2(self, &other);
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

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        u8v_to_hexstr(&self.0)
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut v = GT::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(GT(v))
    }
}

impl Hashable for GT {
    fn hash(&self, state: &mut Hasher) {
        "SecureGT".hash(state);
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
#[derive(Clone)]
pub struct SecretKey(Zr);

impl SecretKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let z = Zr::try_from_hex(s)?;
        Ok(SecretKey(z))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureSKey(*HIDDEN DATA*)")
    }
}

impl Hashable for SecretKey {
    fn hash(&self, state: &mut Hasher) {
        "SecureSKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zap();
    }
}

// -----------------------------------------

#[derive(Copy, Clone)]
pub struct PublicKey(G2);

impl PublicKey {
    /// A some dummy key for initialization.
    pub fn dum() -> Self {
        G2::zero().into()
    }

    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    /// Convert into hex string.
    #[inline]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G2::try_from_hex(s)?;
        Ok(PublicKey(g))
    }

    /// Convert into hex string.
    #[inline]
    pub fn to_bytes(&self) -> [u8; G2_SIZE_FR256] {
        self.0.to_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(PublicKey(G2::try_from_bytes(bytes)?))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurePKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        write!(f, "{}", &self.to_hex()[0..12])
    }
}

impl From<PublicKey> for G2 {
    fn from(pkey: PublicKey) -> Self {
        pkey.0
    }
}

impl From<G2> for PublicKey {
    fn from(g: G2) -> Self {
        PublicKey(g)
    }
}

impl Hashable for PublicKey {
    fn hash(&self, state: &mut Hasher) {
        "SecurePKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for PublicKey {}
impl PartialEq for PublicKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// Needed to sort the list of validators
impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        self.0.base_vector().cmp(&other.0.base_vector())
    }
}
impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
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

impl Add<PublicKey> for PublicKey {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        PublicKey(self.0 + other.0)
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

// -----------------------------------------

#[derive(Clone)]
pub struct SecretSubKey(G1);

impl SecretSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert form hex string
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G1::try_from_hex(s)?;
        Ok(SecretSubKey(g))
    }
}

impl fmt::Debug for SecretSubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        write!(f, "SecretSubKey(*HIDDEN DATA*)")
    }
}

impl Hashable for SecretSubKey {
    fn hash(&self, state: &mut Hasher) {
        "SecureSSubKey".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for SecretSubKey {}
impl PartialEq for SecretSubKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

impl Drop for SecretSubKey {
    fn drop(&mut self) {
        self.0.zap();
    }
}

// -----------------------------------------
#[derive(Clone)]
pub struct PublicSubKey(G2);

impl PublicSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert form hex string
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G2::try_from_hex(s)?;
        Ok(PublicSubKey(g))
    }
}

impl fmt::Display for PublicSubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        write!(f, "{}", &self.to_hex()[0..12])
    }
}

impl Hashable for PublicSubKey {
    fn hash(&self, state: &mut Hasher) {
        "SecurePSubKey".hash(state);
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
    /// Create a new point which binary representation consists of all zeros.
    pub fn zero() -> Signature {
        Signature(G1::zero())
    }

    /// Check that binary representation consists of all zeros.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G1::try_from_hex(s)?;
        Ok(Signature(g))
    }

    pub fn to_bytes(&self) -> [u8; G1_SIZE_FR256] {
        self.0.to_bytes()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Signature(G1::try_from_bytes(bytes)?))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureSig({})", self.to_hex())
    }
}

impl Hashable for Signature {
    fn hash(&self, state: &mut Hasher) {
        "SecureSig".hash(state);
        self.base_vector().hash(state);
    }
}

impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

impl Add<Signature> for Signature {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Signature(self.0 + other.0)
    }
}

impl AddAssign<Signature> for Signature {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl From<Signature> for G1 {
    fn from(sig: Signature) -> Self {
        sig.0
    }
}

impl From<G1> for Signature {
    fn from(g: G1) -> Self {
        Signature(g)
    }
}

// ------------------------------------------------------------------------
// BLS Signature Generation & Checking

pub fn sign_hash(h: &Hash, skey: &SecretKey) -> Signature {
    // return a raw signature on a hash
    let v = G1::zero();
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

pub fn check_hash(h: &Hash, sig: &Signature, pkey: &PublicKey) -> Result<(), CryptoError> {
    if sig.is_zero() {
        // if signature is empty libpbc will panic, so return false.
        return Err(CryptoError::BadKeyingSignature);
    }
    // check a hash with a raw signature, return t/f
    let rc = unsafe {
        rust_libpbc::check_signature(
            *CONTEXT_FR256,
            sig.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
            pkey.base_vector().as_ptr() as *mut _,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(CryptoError::BadKeyingSignature),
    }
}

// ------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey) {
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
    (skey, pkey)
}

pub fn check_keying(skey: &SecretKey, pkey: &PublicKey) -> Result<(), CryptoError> {
    let hpk = Hash::digest(&pkey);
    let sig = sign_hash(&hpk, &skey);
    check_hash(&hpk, &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey) {
    let mut rng: ThreadRng = thread_rng();
    make_deterministic_keys(&rng.gen::<[u8; 32]>())
}

// ------------------------------------------------------------------------
// Subkey generation and Sakai-Kasahara Encryption

pub fn make_secret_subkey(skey: &SecretKey, seed: &[u8]) -> SecretSubKey {
    let h = Hash::from_vector(&seed);
    let sk = G1::zero();
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
    let pk = G2::zero();
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

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Try to convert from hex string
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G2::try_from_hex(s)?;
        Ok(RVal(g))
    }

    /// Convert into bytes slice
    #[inline]
    pub fn to_bytes(&self) -> [u8; G2_SIZE_FR256] {
        self.0.to_bytes()
    }

    /// Try to convert from raw bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(RVal(G2::try_from_bytes(bytes)?))
    }
}

impl Hashable for RVal {
    fn hash(&self, state: &mut Hasher) {
        "SecureRVal".hash(state);
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
    pub fn new(pkey: &PublicKey, id: &[u8], rval: &RVal, cmsg: &[u8]) -> Self {
        EncryptedPacket {
            pkey: pkey.clone(),
            id: id.to_vec(),
            rval: rval.clone(),
            cmsg: cmsg.to_vec(),
        }
    }

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

    let rval = G2::zero();
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
        cmsg,
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

// -------------------------------------------------------
// VRF's provable, unforgeable, deterministic randomness
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct VRF {
    pub rand: Hash, // hash digest of generated randomness in pairing field
    pub proof: G1,  // proof on randomness
}

impl Hashable for VRF {
    fn hash(&self, state: &mut Hasher) {
        self.rand.hash(state);
        self.proof.hash(state);
    }
}

impl fmt::Display for VRF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VRF({})", self.rand.to_hex())
    }
}

pub fn make_VRF(skey: &SecretKey, seed: &Hash) -> VRF {
    // whatever the source of the seed, it should all be
    // pre-hashed before calling this function
    let proof = G1::zero();
    unsafe {
        rust_libpbc::make_secret_subkey(
            *CONTEXT_FR256,
            proof.base_vector().as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            seed.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    let rand = compute_pairing(&proof, &G2::generator());
    VRF {
        rand: Hash::digest(&rand),
        proof,
    }
}

pub fn validate_VRF_randomness(vrf: &VRF) -> bool {
    // Public validation - anyone can validate the randomness
    // knowing only its value and the accompanying proof.
    let rand = compute_pairing(&vrf.proof, &G2::generator());
    vrf.rand == Hash::digest(&rand)
}

pub fn validate_VRF_source(vrf: &VRF, pkey: &PublicKey, seed: &Hash) -> bool {
    // whatever the source of the seed, it should all be
    // pre-hashed before calling this function.
    //
    // Anyone knowing the pkey of the originator, and the seed that
    // was used, can verify that the randomness originated from the
    // holder of the corresponding secret key and that seed.
    //
    let pk = G2::zero();
    unsafe {
        rust_libpbc::make_public_subkey(
            *CONTEXT_FR256,
            pk.base_vector().as_ptr() as *mut _,
            pkey.base_vector().as_ptr() as *mut _,
            seed.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
        );
    }
    let p1 = compute_pairing(&vrf.proof, &pk);
    let p2 = compute_pairing(&G1::generator(), &G2::generator());
    p1 == p2
}

// -------------------------------------------------------
// primitives

pub fn add_G1_G1(a: &G1, b: &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G1_pts(
            *CONTEXT_FR256,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn add_G2_G2(a: &G2, b: &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G2_pts(
            *CONTEXT_FR256,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn compute_pairing(a: &G1, b: &G2) -> GT {
    let ans = GT::new();
    unsafe {
        rust_libpbc::compute_pairing(
            *CONTEXT_FR256,
            ans.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

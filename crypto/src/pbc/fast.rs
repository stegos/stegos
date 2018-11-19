//! Faster, but less secure, pairings with curves AR160 (type A, r approx 160 bits)
//! (intended for eRandHound ephemeral secrets)

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

//!
//! --------------------------------------------------------------------------
//! Field and group elements can be constructed from byte-vectors
//! with UTF8 hex chars, as in b"FF3C...". Never use str format "FF3C..."
//!
//! This weaker pairing system is intended for eRandHound, distributed randomness
//! generation, where secrets must be kept for durations measured in mere seconds,
//! and not for longer term exposure in the blockchain.
//!
//! Since eRandHound performs a lot of math on the curves, for shared polynomials,
//! Lagrange interpolation, and point addition accumulators, we provide infix math
//! operations on the curve field and groups.
//!
//! We do not provide features like sub-keys, signatures, encryption. For those
//! purposes you should be using the "secure" module of PBC.
//! --------------------------------------------------------------------------

use super::*;
use crate::hash::*;
use crate::utils::*;
use rand::thread_rng;

use std::cmp::Ordering;
use std::hash as stdhash;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use rand::rngs::ThreadRng;
use rand::Rng;

// ---------------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct Zr([u8; ZR_SIZE_AR160]);

impl Zr {
    pub fn new() -> Self {
        Zr(Self::wv())
    }

    fn wv() -> [u8; ZR_SIZE_AR160] {
        // wv = Working Vector
        [0u8; ZR_SIZE_AR160]
    }

    pub fn zero() -> Self {
        Self::new()
    }

    pub fn one() -> Self {
        let mut v = Self::wv();
        v[ZR_SIZE_AR160 - 1] = 1;
        Zr(v)
    }

    pub fn acceptable_minval() -> Self {
        // approx sqrt modulus
        let mut x = [0u8; ZR_SIZE_AR160];
        {
            let mid = ZR_SIZE_AR160 >> 1;
            let (_, bot) = x.split_at_mut(mid);
            let botlen = ZR_SIZE_AR160 - mid;
            bot.copy_from_slice(&(*ORD_AR160)[0..botlen]);
        }
        Zr(x)
    }

    pub fn acceptable_maxval() -> Self {
        // approx = modulus - sqrt(modulus)
        -*MIN_AR160
    }

    pub fn acceptable_random_rehash(k: Self) -> Self {
        let min = *MIN_AR160;
        let max = *MAX_AR160;
        let mut mk = k;
        while mk < min || mk > max {
            mk = Self::from(Hash::digest(&mk));
        }
        mk
    }

    pub fn random() -> Self {
        let mut rng: ThreadRng = thread_rng();
        let mut zx = Zr(rng.gen::<[u8; ZR_SIZE_AR160]>());
        let min = *MIN_AR160;
        let max = *MAX_AR160;
        while zx < min || zx > max {
            zx = Zr(rng.gen::<[u8; ZR_SIZE_AR160]>());
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

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let mut v = Self::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(Zr(v))
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Zr", &self.base_vector())
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

impl From<i64> for Zr {
    fn from(x: i64) -> Self {
        let mut v = Self::wv(); // big-endian encoding as byte vector
        let mut vx = if x < 0 { -(x as i128) } else { x as i128 };
        for ix in 0..8 {
            v[ZR_SIZE_AR160 - ix - 1] = (vx & 0x0ff) as u8;
            vx >>= 8;
        }
        if x < 0 {
            -Zr(v)
        } else {
            Zr(v)
        }
    }
}

impl fmt::Debug for Zr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
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

impl From<Hash> for Zr {
    fn from(h: Hash) -> Self {
        let v = Zr::new();
        unsafe {
            rust_libpbc::get_Zr_from_hash(
                *CONTEXT_AR160,
                v.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        v
    }
}

// -------------------------------------
// Zr op i64

impl Add<i64> for Zr {
    type Output = Self;
    fn add(self, other: i64) -> Self {
        self + Self::from(other)
    }
}

impl Sub<i64> for Zr {
    type Output = Self;
    fn sub(self, other: i64) -> Self {
        self - Self::from(other)
    }
}

impl Mul<i64> for Zr {
    type Output = Self;
    fn mul(self, other: i64) -> Self {
        self * Self::from(other)
    }
}

impl Div<i64> for Zr {
    type Output = Self;
    fn div(self, other: i64) -> Self {
        self / Self::from(other)
    }
}

// -------------------------------------
// i64 op Zr

impl Add<Zr> for i64 {
    type Output = Zr;
    fn add(self, other: Zr) -> Zr {
        Zr::from(self) + other
    }
}

impl Sub<Zr> for i64 {
    type Output = Zr;
    fn sub(self, other: Zr) -> Zr {
        Zr::from(self) - other
    }
}

impl Mul<Zr> for i64 {
    type Output = Zr;
    fn mul(self, other: Zr) -> Zr {
        Zr::from(self) * other
    }
}

impl Div<Zr> for i64 {
    type Output = Zr;
    fn div(self, other: Zr) -> Zr {
        Zr::from(self) / other
    }
}

// -------------------------------------
// Zr op Zr

impl Neg for Zr {
    type Output = Self;
    fn neg(self) -> Self {
        neg_Zr(&self)
    }
}

impl Add<Zr> for Zr {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        add_Zr_Zr(&self, &other)
    }
}

impl Sub<Zr> for Zr {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        sub_Zr_Zr(&self, &other)
    }
}

impl Mul<Zr> for Zr {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        mul_Zr_Zr(&self, &other)
    }
}

impl Div<Zr> for Zr {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        div_Zr_Zr(&self, &other)
    }
}

impl AddAssign<i64> for Zr {
    fn add_assign(&mut self, other: i64) {
        *self += Self::from(other);
    }
}

impl SubAssign<i64> for Zr {
    fn sub_assign(&mut self, other: i64) {
        *self -= Self::from(other);
    }
}

impl MulAssign<i64> for Zr {
    fn mul_assign(&mut self, other: i64) {
        *self *= Self::from(other);
    }
}

impl DivAssign<i64> for Zr {
    fn div_assign(&mut self, other: i64) {
        *self /= Self::from(other);
    }
}

impl AddAssign<Zr> for Zr {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign<Zr> for Zr {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for Zr {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl DivAssign<Zr> for Zr {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G1([u8; G1_SIZE_AR160]);

impl G1 {
    pub fn zero() -> Self {
        Self::new()
    }

    pub fn new() -> Self {
        G1(Self::wv())
    }

    fn wv() -> [u8; G1_SIZE_AR160] {
        [0u8; G1_SIZE_AR160]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G1", &self.base_vector())
    }

    pub fn from_str(s: &str) -> Result<Self, hex::FromHexError> {
        let mut v = Self::wv();
        hexstr_to_bev_u8(&s, &mut v)?;
        Ok(G1(v))
    }

    pub fn generator() -> G1 {
        let u = G1::new();
        unsafe {
            rust_libpbc::get_g1(
                *CONTEXT_AR160,
                u.base_vector().as_ptr() as *mut _,
                G1_SIZE_AR160 as u64,
            );
        }
        u
    }

    pub fn random() -> G1 {
        let mut rng: ThreadRng = thread_rng();
        let h = rng.gen::<[u8; HASH_SIZE]>();
        let u = G1::new();
        unsafe {
            rust_libpbc::get_G1_from_hash(
                *CONTEXT_AR160,
                u.base_vector().as_ptr() as *mut _,
                h.as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        u
    }
}

impl Eq for G1 {}
impl PartialEq for G1 {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl fmt::Debug for G1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl fmt::Display for G1 {
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

impl From<Hash> for G1 {
    fn from(h: Hash) -> Self {
        let v = G1::new();
        unsafe {
            rust_libpbc::get_G1_from_hash(
                *CONTEXT_AR160,
                v.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        v
    }
}

impl Neg for G1 {
    type Output = Self;
    fn neg(self) -> Self {
        neg_G1(&self)
    }
}

impl Add<G1> for G1 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        add_G1_G1(&self, &other)
    }
}

impl Sub<G1> for G1 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        sub_G1_G1(&self, &other)
    }
}

impl Mul<Zr> for G1 {
    type Output = Self;
    fn mul(self, other: Zr) -> Self {
        mul_G1_Zr(&self, &other)
    }
}

impl Div<Zr> for G1 {
    type Output = Self;
    fn div(self, other: Zr) -> Self {
        div_G1_Zr(&self, &other)
    }
}

impl Mul<G1> for Zr {
    type Output = G1;
    fn mul(self, other: G1) -> G1 {
        mul_G1_Zr(&other, &self)
    }
}

impl Mul<G1> for i64 {
    type Output = G1;
    fn mul(self, other: G1) -> G1 {
        Zr::from(self) * other
    }
}

impl Div<i64> for G1 {
    type Output = Self;
    fn div(self, other: i64) -> Self {
        self / Zr::from(other)
    }
}

impl Mul<i64> for G1 {
    type Output = Self;
    fn mul(self, other: i64) -> Self {
        self * Zr::from(other)
    }
}

impl AddAssign<G1> for G1 {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign<G1> for G1 {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for G1 {
    fn mul_assign(&mut self, other: Zr) {
        *self = *self * other;
    }
}

impl DivAssign<Zr> for G1 {
    fn div_assign(&mut self, other: Zr) {
        *self = *self / other;
    }
}

impl MulAssign<i64> for G1 {
    fn mul_assign(&mut self, other: i64) {
        *self *= Zr::from(other);
    }
}

impl DivAssign<i64> for G1 {
    fn div_assign(&mut self, other: i64) {
        *self /= Zr::from(other);
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G2([u8; G2_SIZE_AR160]);

impl G2 {
    pub fn zero() -> Self {
        Self::new()
    }

    pub fn new() -> Self {
        G2(Self::wv())
    }

    fn wv() -> [u8; G2_SIZE_AR160] {
        [0u8; G2_SIZE_AR160]
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

    pub fn generator() -> G2 {
        let v = G2::new();
        unsafe {
            rust_libpbc::get_g2(
                *CONTEXT_AR160,
                v.base_vector().as_ptr() as *mut _,
                G2_SIZE_AR160 as u64,
            );
        }
        v
    }

    pub fn random() -> G2 {
        let mut rng: ThreadRng = thread_rng();
        let h = rng.gen::<[u8; HASH_SIZE]>();
        let v = G2::new();
        unsafe {
            rust_libpbc::get_G2_from_hash(
                *CONTEXT_AR160,
                v.base_vector().as_ptr() as *mut _,
                h.as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        v
    }
}

impl Eq for G2 {}
impl PartialEq for G2 {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
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

impl From<Hash> for G2 {
    fn from(h: Hash) -> Self {
        let v = G2::new();
        unsafe {
            rust_libpbc::get_G2_from_hash(
                *CONTEXT_AR160,
                v.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
            );
        }
        v
    }
}

impl Neg for G2 {
    type Output = Self;
    fn neg(self) -> Self {
        neg_G2(&self)
    }
}

impl Add<G2> for G2 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        add_G2_G2(&self, &other)
    }
}

impl Sub<G2> for G2 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        sub_G2_G2(&self, &other)
    }
}

impl Mul<Zr> for G2 {
    type Output = Self;
    fn mul(self, other: Zr) -> Self {
        mul_G2_Zr(&self, &other)
    }
}

impl Mul<i64> for G2 {
    type Output = Self;
    fn mul(self, other: i64) -> Self {
        self * Zr::from(other)
    }
}

impl Div<Zr> for G2 {
    type Output = Self;
    fn div(self, other: Zr) -> Self {
        div_G2_Zr(&self, &other)
    }
}

impl Div<i64> for G2 {
    type Output = Self;
    fn div(self, other: i64) -> Self {
        self / Zr::from(other)
    }
}

impl Mul<G2> for Zr {
    type Output = G2;
    fn mul(self, other: G2) -> G2 {
        mul_G2_Zr(&other, &self)
    }
}

impl Mul<G2> for i64 {
    type Output = G2;
    fn mul(self, other: G2) -> G2 {
        other * Zr::from(self)
    }
}

impl AddAssign<G2> for G2 {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign<G2> for G2 {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for G2 {
    fn mul_assign(&mut self, other: Zr) {
        *self = *self * other;
    }
}

impl DivAssign<Zr> for G2 {
    fn div_assign(&mut self, other: Zr) {
        *self = *self / other;
    }
}

impl MulAssign<i64> for G2 {
    fn mul_assign(&mut self, other: i64) {
        *self *= Zr::from(other);
    }
}

impl DivAssign<i64> for G2 {
    fn div_assign(&mut self, other: i64) {
        *self /= Zr::from(other);
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
pub struct GT([u8; GT_SIZE_AR160]);

impl GT {
    pub fn new() -> Self {
        GT(Self::wv())
    }

    fn wv() -> [u8; GT_SIZE_AR160] {
        [0u8; GT_SIZE_AR160]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("GT", &self.base_vector())
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Eq for GT {}
impl PartialEq for GT {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl Hashable for GT {
    fn hash(&self, state: &mut Hasher) {
        "GT".hash(state);
        self.base_vector().hash(state);
    }
}

impl Mul<GT> for GT {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        mul_GT_GT(&self, &other)
    }
}

impl Div<GT> for GT {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        div_GT_GT(&self, &other)
    }
}

impl MulAssign<GT> for GT {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl DivAssign<GT> for GT {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
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
}

impl fmt::Display for SecretKey {
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

impl From<SecretKey> for Zr {
    fn from(skey: SecretKey) -> Zr {
        skey.0
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
}

impl Eq for PublicKey {}
impl PartialEq for PublicKey {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
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

impl stdhash::Hash for PublicKey {
    // we often want to look things up by public key
    // std::HashMap needs this
    fn hash<H: stdhash::Hasher>(&self, state: &mut H) {
        stdhash::Hash::hash("PKey", state);
        stdhash::Hash::hash(&self.0, state);
    }
}

impl From<PublicKey> for G2 {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

// ------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct Signature(G1);

impl Signature {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Sig", &self.base_vector())
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

impl PartialEq for Signature {
    fn eq(&self, b: &Self) -> bool {
        self.0 == b.0
    }
}

// ------------------------------------------------------------------
// Key Generation & Checking

pub fn sign_hash(h: &Hash, skey: &SecretKey) -> Signature {
    // return a raw signature on a hash
    let v = G1::new();
    unsafe {
        rust_libpbc::sign_hash(
            *CONTEXT_AR160,
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
            *CONTEXT_AR160,
            sig.0.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64,
            pkey.base_vector().as_ptr() as *mut _,
        )
    }
}

// ----------------------------------------------------------------

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey, Signature) {
    let h = Hash::from_vector(&seed);
    let zr = Zr::synthetic_random("skey", &G1::generator(), &h);
    let pt = G2::generator().clone(); // public keys in G2
    unsafe {
        rust_libpbc::exp_G2z(
            *CONTEXT_AR160,
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

// ----------------------------------------------------------------
// Curve Arithmetic...

pub fn add_Zr_Zr(a: &Zr, b: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_Zr_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn sub_Zr_Zr(a: &Zr, b: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_Zr_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn mul_Zr_Zr(a: &Zr, b: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::mul_Zr_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn div_Zr_Zr(a: &Zr, b: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::div_Zr_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn exp_Zr_Zr(a: &Zr, b: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_Zr_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn neg_Zr(a: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_Zr_val(*CONTEXT_AR160, ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn inv_Zr(a: &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::inv_Zr_val(*CONTEXT_AR160, ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// ---------------------------------

pub fn mul_G1_Zr(a: &G1, b: &Zr) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_G1z(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn div_G1_Zr(a: &G1, b: &Zr) -> G1 {
    let invb = inv_Zr(&b);
    mul_G1_Zr(&a, &invb)
}

pub fn add_G1_G1(a: &G1, b: &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G1_pts(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn sub_G1_G1(a: &G1, b: &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_G1_pts(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn neg_G1(a: &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_G1_pt(*CONTEXT_AR160, ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// ------------------------------------------------------

pub fn mul_G2_Zr(a: &G2, b: &Zr) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_G2z(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn div_G2_Zr(a: &G2, b: &Zr) -> G2 {
    let invb = inv_Zr(&b);
    mul_G2_Zr(&a, &invb)
}

pub fn add_G2_G2(a: &G2, b: &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G2_pts(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn sub_G2_G2(a: &G2, b: &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_G2_pts(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn neg_G2(a: &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_G2_pt(*CONTEXT_AR160, ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// -------------------------------------------------

pub fn compute_pairing(a: &G1, b: &G2) -> GT {
    let ans = GT::new();
    unsafe {
        rust_libpbc::compute_pairing(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn mul_GT_GT(a: &GT, b: &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::mul_GT_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn div_GT_GT(a: &GT, b: &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::div_GT_vals(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn exp_GT_Zr(a: &GT, b: &Zr) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_GTz(
            *CONTEXT_AR160,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    }
    ans
}

pub fn inv_GT(a: &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::inv_GT_val(*CONTEXT_AR160, ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// -------------------------------------------

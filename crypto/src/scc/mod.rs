//! scc - Single-Curve Сrypto based on Ristretto Group

//
// Copyright (c) 2019 Stegos AG
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

#![allow(non_snake_case)]

use crate::hash::*;
use crate::utils::*;
use crate::CryptoError;
use base58check::{FromBase58Check, ToBase58Check};
use crypto::aes;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use lazy_static::lazy_static;
use rand::prelude::*;
use rand::thread_rng;
use ristretto_bulletproofs::{BulletproofGens, PedersenGens};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::str::FromStr;

// -----------------------------------------------------------------

lazy_static! {
    pub static ref INIT: bool = {
        check_prng();
        true
    };
    pub static ref UNIQ: [u8; 32] = {
        assert!(*INIT, "can't happen");
        thread_rng().gen::<[u8; 32]>()
    };
    pub static ref PCGENS: PedersenGens = {
        assert!(*INIT, "can't happen");
        PedersenGens::default()
    };
    pub static ref BPGENS: BulletproofGens = {
        assert!(*INIT, "can't happen");
        BulletproofGens::new(64, 1)
    };
}

fn check_prng() {
    use std::f32;
    let mut rng: ThreadRng = thread_rng();
    let n = 1_000_000;
    let (sum, sumsq) = (0..n).fold((0.0f32, 0.0f32), |(s, s2), _| {
        let x = rng.gen::<f32>() - 0.5;
        (s + x, s2 + x * x)
    });
    let mn = sum / (n as f32);
    let stdev = f32::sqrt(sumsq / (n as f32));
    let invrt12 = 1.0 / f32::sqrt(12.0);
    let delta = 5.0 * invrt12 / f32::sqrt(n as f32);
    // approx 5-sigma bounds
    // could still fail on legitimate system, but only 1 in 3.5 million plausible
    let msg = "plausible PRNG failure";
    assert!(f32::abs(mn) < delta, msg);
    assert!(f32::abs(stdev - invrt12) < delta, msg);
}

// ------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Fr(Scalar);

#[derive(Copy, Clone)]
pub enum Pt {
    PtRaw(RistrettoPoint),
    PtCmpr([u8; 32]),
    PtNone,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(Fr);

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PublicKey(Pt);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SchnorrSig {
    pub u: Fr,
    pub K: Pt,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedPayload {
    pub ag: Pt,        // key hint = alpha*G
    pub ctxt: Vec<u8>, // ciphertext
}

#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub payload: EncryptedPayload,
    pub sig: SchnorrSig,
}

// -----------------------------------------------------------------------

impl Hashable for Scalar {
    fn hash(&self, state: &mut Hasher) {
        "Scalar".hash(state);
        self.to_bytes().hash(state);
    }
}

impl Hashable for RistrettoPoint {
    fn hash(&self, state: &mut Hasher) {
        "Point".hash(state);
        self.compress().to_bytes().hash(state);
    }
}

// -----------------------------------------------------------------------
// serialization support for Ristretto objects

impl Fr {
    pub fn zero() -> Self {
        Fr::from(Scalar::zero())
    }

    pub fn one() -> Self {
        Fr::from(Scalar::one())
    }

    pub fn random() -> Self {
        Fr::from(Scalar::random(&mut thread_rng()))
    }

    pub fn synthetic_random(pref: &str, uniq: &dyn Hashable, h: &Hash) -> Self {
        // Construct a pseudo random field value without using the PRNG
        // This generates so-called "deterministic randomness" and assures
        // random-appearing values that will always be the same for the same
        // input keying. The result will be in the "safe" range for the field.
        let mut state = Hasher::new();
        pref.hash(&mut state);
        uniq.hash(&mut state);
        h.hash(&mut state);
        UNIQ.hash(&mut state);
        Fr::from(state.result())
    }

    pub fn to_i64(self) -> Result<i64, CryptoError> {
        let bytes = self.to_bytes();
        for ix in 8..32 {
            if bytes[ix] != 0 {
                return Err(CryptoError::TooLarge);
            }
        }
        if bytes[7] & 0x80 != 0 {
            return Err(CryptoError::TooLarge);
        }
        let mut val = 0u64;
        for ix in 0..8 {
            val <<= 8;
            val |= bytes[7 - ix] as u64;
        }
        Ok(val as i64)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        Scalar::from(*self).to_bytes()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::TooLarge);
        }
        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        match Scalar::from_canonical_bytes(bits) {
            None => Err(CryptoError::TooLarge),
            Some(v) => Ok(Fr(v)),
        }
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse(); // because we are little endian byte vector
        u8v_to_hexstr(&bytes)
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        hexstr_to_lev_u8(s, &mut bytes)?;
        Ok(Fr::try_from_bytes(&bytes)?)
    }
}

impl fmt::Debug for Fr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fr({})", self.to_hex())
    }
}

impl Hashable for Fr {
    fn hash(&self, state: &mut Hasher) {
        "Fr".hash(state);
        self.0.hash(state);
    }
}

impl From<Fr> for Scalar {
    fn from(val: Fr) -> Scalar {
        val.0
    }
}

impl From<Scalar> for Fr {
    fn from(val: Scalar) -> Fr {
        Fr(val.reduce())
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr::from(-Scalar::from(self))
    }
}

impl Add<Fr> for Fr {
    type Output = Fr;
    fn add(self, other: Fr) -> Fr {
        Fr::from(Scalar::from(self) + Scalar::from(other))
    }
}

impl Sub<Fr> for Fr {
    type Output = Fr;
    fn sub(self, other: Fr) -> Fr {
        Fr::from(Scalar::from(self) - Scalar::from(other))
    }
}

impl Mul<Fr> for Fr {
    type Output = Fr;
    fn mul(self, other: Fr) -> Fr {
        Fr::from(Scalar::from(self) * Scalar::from(other))
    }
}

impl Div<Fr> for Fr {
    type Output = Fr;
    fn div(self, other: Fr) -> Fr {
        assert!(Scalar::from(other) != Scalar::zero());
        Fr::from(Scalar::from(self) * Scalar::from(other).invert())
    }
}

impl AddAssign<Fr> for Fr {
    fn add_assign(&mut self, other: Fr) {
        let tmp = self.0 + Scalar::from(other);
        self.0 = tmp.reduce();
    }
}

impl SubAssign<Fr> for Fr {
    fn sub_assign(&mut self, other: Fr) {
        let tmp = self.0 - Scalar::from(other);
        self.0 = tmp.reduce();
    }
}

impl MulAssign<Fr> for Fr {
    fn mul_assign(&mut self, other: Fr) {
        let tmp = self.0 * Scalar::from(other);
        self.0 = tmp.reduce();
    }
}

impl From<Hash> for Fr {
    fn from(h: Hash) -> Fr {
        Fr::from(Scalar::from_bits(h.bits()))
    }
}

impl From<u64> for Fr {
    fn from(val: u64) -> Fr {
        Fr::from(Scalar::from(val))
    }
}

impl From<i64> for Fr {
    fn from(val: i64) -> Fr {
        assert!(val >= 0);
        Fr::from(Scalar::from(val as u64))
    }
}

// -----------------------------------------------------------------------

impl Pt {
    pub fn inf() -> Self {
        Pt::from(RistrettoPoint::identity())
    }

    pub fn identity() -> Self {
        Pt::inf()
    }

    pub fn one() -> Self {
        Pt::from(PCGENS.B_blinding)
    }

    pub fn is_identity(&self) -> bool {
        match self {
            Pt::PtRaw(ipt) => ipt.is_identity(),
            Pt::PtCmpr(ipt) => {
                let cpt = CompressedRistretto::from_slice(ipt);
                let dpt = cpt.decompress();
                match dpt {
                    None => false,
                    Some(pt) => pt.is_identity(),
                }
            }
            Pt::PtNone => false,
        }
    }

    pub fn decompress(&self) -> Result<Pt, CryptoError> {
        match self {
            Pt::PtRaw(_) => Ok(*self),
            Pt::PtCmpr(ipt) => {
                let cpt = CompressedRistretto::from_slice(ipt);
                let dpt = cpt.decompress();
                match dpt {
                    None => Err(CryptoError::InvalidPoint),
                    Some(pt) => Ok(Pt::from(pt)),
                }
            }
            Pt::PtNone => Err(CryptoError::InvalidPoint),
        }
    }

    pub fn check_valid(&self) -> Result<(), CryptoError> {
        match self.decompress() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn random() -> Self {
        Pt::from(RistrettoPoint::random(&mut thread_rng()))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Pt::PtRaw(ipt) => ipt.compress().to_bytes(),
            Pt::PtCmpr(ipt) => *ipt,
            Pt::PtNone => panic!("should never happen"),
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidBinaryLength(32, bytes.len()));
        }
        let mut mybytes = [0u8; 32];
        mybytes.copy_from_slice(bytes);
        Ok(Pt::PtCmpr(mybytes))
    }

    pub fn internal_use_compress(&self) -> CompressedRistretto {
        // Note: You should not call this.
        // It is needed only for BulletProof wrapper code
        match self {
            Pt::PtRaw(ipt) => ipt.compress(),
            Pt::PtCmpr(ipt) => CompressedRistretto::from_slice(ipt),
            Pt::PtNone => RistrettoPoint::identity().compress(), // not really, but hopefully causes arith to fail
        }
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse(); // little endian repr
        u8v_to_hexstr(&bytes)
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        hexstr_to_lev_u8(s, &mut bytes)?;
        Ok(Self::try_from_bytes(&bytes)?)
    }
}

impl Hashable for Pt {
    fn hash(&self, state: &mut Hasher) {
        "PtPoint".hash(state); // "Point" is for compatibility with Hashable(RistrettoPoint)
        self.to_bytes().hash(state);
    }
}

impl fmt::Debug for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pt({})", self.to_hex())
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_hex();
        write!(f, "Pt({})", &s[0..7])
    }
}

impl From<Pt> for RistrettoPoint {
    fn from(pt: Pt) -> RistrettoPoint {
        match pt {
            Pt::PtRaw(ipt) => ipt,
            Pt::PtCmpr(ipt) => {
                let cpt = CompressedRistretto::from_slice(&ipt);
                let dpt = cpt.decompress();
                match dpt {
                    Some(pt) => pt,
                    None => RistrettoPoint::identity(), // not really...
                }
            }
            Pt::PtNone => RistrettoPoint::identity(), // not really...
        }
    }
}

impl From<CompressedRistretto> for Pt {
    fn from(cpt: CompressedRistretto) -> Pt {
        Pt::PtCmpr(cpt.to_bytes())
    }
}

impl From<RistrettoPoint> for Pt {
    fn from(pt: RistrettoPoint) -> Pt {
        Pt::PtRaw(pt)
    }
}

impl Mul<Scalar> for Pt {
    type Output = Pt;
    fn mul(self, other: Scalar) -> Pt {
        match self {
            Pt::PtRaw(ipt) => Pt::from(ipt * other),
            Pt::PtCmpr(ipt) => {
                let cpt = CompressedRistretto::from_slice(&ipt);
                let dpt = cpt.decompress();
                match dpt {
                    None => Pt::PtNone,
                    Some(pt) => Pt::from(pt * other),
                }
            }
            Pt::PtNone => Pt::PtNone,
        }
    }
}

impl Mul<Fr> for Pt {
    type Output = Pt;
    fn mul(self, other: Fr) -> Pt {
        self * Scalar::from(other)
    }
}

impl Mul<Pt> for Fr {
    type Output = Pt;
    fn mul(self, other: Pt) -> Pt {
        other * self
    }
}

impl Div<Scalar> for Pt {
    type Output = Pt;
    fn div(self, other: Scalar) -> Pt {
        assert!(other != Scalar::zero());
        self * other.invert()
    }
}

impl Div<Fr> for Pt {
    type Output = Pt;
    fn div(self, other: Fr) -> Pt {
        self / Scalar::from(other)
    }
}

impl Neg for Pt {
    type Output = Pt;
    fn neg(self) -> Pt {
        match self {
            Pt::PtRaw(pt) => Pt::from(-pt),
            Pt::PtCmpr(pt) => {
                let cpt = CompressedRistretto::from_slice(&pt);
                let dpt = cpt.decompress();
                match dpt {
                    None => Pt::PtNone,
                    Some(pt) => Pt::from(-pt),
                }
            }
            Pt::PtNone => Pt::PtNone,
        }
    }
}

impl AddAssign<Pt> for Pt {
    fn add_assign(&mut self, other: Pt) {
        *self = *self + other;
    }
}

impl SubAssign<Pt> for Pt {
    fn sub_assign(&mut self, other: Pt) {
        *self = *self - other;
    }
}

impl MulAssign<Fr> for Pt {
    fn mul_assign(&mut self, other: Fr) {
        *self = *self * other;
    }
}

impl DivAssign<Fr> for Pt {
    fn div_assign(&mut self, other: Fr) {
        *self = *self / other;
    }
}

impl Add<Pt> for Pt {
    type Output = Pt;
    fn add(self, other: Pt) -> Pt {
        match self {
            Pt::PtRaw(ipt) => match other {
                Pt::PtRaw(opt) => Pt::from(ipt + opt),
                Pt::PtCmpr(opt) => {
                    let cpt = CompressedRistretto::from_slice(&opt);
                    let dpt = cpt.decompress();
                    match dpt {
                        None => Pt::PtNone,
                        Some(pt) => Pt::from(ipt + pt),
                    }
                }
                Pt::PtNone => Pt::PtNone,
            },
            Pt::PtCmpr(ipt) => {
                let cpt = CompressedRistretto::from_slice(&ipt);
                let dpt = cpt.decompress();
                match dpt {
                    None => Pt::PtNone,
                    Some(pt) => match other {
                        Pt::PtRaw(opt) => Pt::from(pt + opt),
                        Pt::PtCmpr(opt) => {
                            let cpt = CompressedRistretto::from_slice(&opt);
                            let dpt = cpt.decompress();
                            match dpt {
                                None => Pt::PtNone,
                                Some(pt2) => Pt::from(pt + pt2),
                            }
                        }
                        Pt::PtNone => Pt::PtNone,
                    },
                }
            }
            Pt::PtNone => Pt::PtNone,
        }
    }
}

impl Sub<Pt> for Pt {
    type Output = Pt;
    fn sub(self, other: Pt) -> Pt {
        self + (-other)
    }
}

impl Eq for Pt {}
impl PartialEq<Pt> for Pt {
    fn eq(&self, other: &Pt) -> bool {
        match self {
            Pt::PtRaw(apt) => match other {
                Pt::PtRaw(bpt) => apt.eq(&bpt),
                Pt::PtCmpr(bpt) => {
                    let cpt = CompressedRistretto::from_slice(bpt);
                    let dpt = cpt.decompress();
                    match dpt {
                        None => false,
                        Some(pt) => apt.eq(&pt),
                    }
                }
                Pt::PtNone => false,
            },
            Pt::PtCmpr(apt) => {
                let cpt = CompressedRistretto::from_slice(apt);
                let dpt = cpt.decompress();
                match dpt {
                    None => false,
                    Some(pt) => match other {
                        Pt::PtRaw(bpt) => pt.eq(&bpt),
                        Pt::PtCmpr(bpt) => {
                            let cpt = CompressedRistretto::from_slice(bpt);
                            let dpt = cpt.decompress();
                            match dpt {
                                None => false,
                                Some(pt2) => pt.eq(&pt2),
                            }
                        }
                        Pt::PtNone => false,
                    },
                }
            }
            Pt::PtNone => false,
        }
    }
}

// -----------------------------------------------------------------------

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(SecretKey::from(Fr::try_from_bytes(bytes)?))
    }
}

impl Hashable for SecretKey {
    fn hash(&self, state: &mut Hasher) {
        "SecretKey".hash(state);
        self.0.hash(state);
    }
}

impl From<SecretKey> for Fr {
    fn from(skey: SecretKey) -> Fr {
        skey.0
    }
}

impl From<Fr> for SecretKey {
    fn from(fr: Fr) -> SecretKey {
        SecretKey(fr)
    }
}

impl From<SecretKey> for Scalar {
    fn from(s: SecretKey) -> Scalar {
        Scalar::from(Fr::from(s))
    }
}

impl From<Scalar> for SecretKey {
    fn from(fr: Scalar) -> SecretKey {
        SecretKey(Fr::from(fr))
    }
}

impl From<SecretKey> for PublicKey {
    fn from(s: SecretKey) -> PublicKey {
        PublicKey::from(Pt::from(Scalar::from(s) * RistrettoPoint::from(Pt::one())))
    }
}

// -----------------------------------------------------------------------

impl PublicKey {
    pub fn zero() -> Self {
        PublicKey::from(Pt::inf())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        Pt::from(*self).to_bytes()
    }

    pub fn decompress(&self) -> Result<Self, CryptoError> {
        Ok(PublicKey::from(Pt::from(*self).decompress()?))
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(PublicKey::from(Pt::try_from_bytes(bytes)?))
    }

    pub fn to_hex(&self) -> String {
        Pt::from(*self).to_hex()
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(PublicKey::from(Pt::try_from_hex(s)?))
    }
}

impl Hashable for PublicKey {
    fn hash(&self, state: &mut Hasher) {
        "PublicKey".hash(state);
        self.0.hash(state);
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_hex();
        write!(f, "PublicKey({}...{})", &s[0..7], &s[57..64])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_hex();
        write!(f, "PublicKey({}...{})", &s[0..7], &s[57..64])
    }
}

impl From<PublicKey> for RistrettoPoint {
    fn from(pkey: PublicKey) -> RistrettoPoint {
        RistrettoPoint::from(Pt::from(pkey))
    }
}

impl From<RistrettoPoint> for PublicKey {
    fn from(pt: RistrettoPoint) -> PublicKey {
        PublicKey(Pt::from(pt))
    }
}

impl From<Pt> for PublicKey {
    fn from(pt: Pt) -> PublicKey {
        PublicKey(pt)
    }
}

impl From<PublicKey> for Pt {
    fn from(pkey: PublicKey) -> Pt {
        pkey.0
    }
}

impl<'a> From<&'a PublicKey> for String {
    fn from(pkey: &'a PublicKey) -> String {
        let bytes = pkey.to_bytes();
        bytes.to_base58check(crate::BASE58_VERSIONID)
    }
}

impl FromStr for PublicKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (version, raw_bytes) = s.from_base58check()?;
        if version != crate::BASE58_VERSIONID {
            return Err(CryptoError::WrongBase58VerisonId(version));
        }
        let pt = match CompressedRistretto::from_slice(&raw_bytes).decompress() {
            None => {
                return Err(CryptoError::InvalidPoint);
            }
            Some(pt) => Pt::from(pt),
        };
        Ok(PublicKey::from(pt))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// -----------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey) {
    let h = Hash::from_vector(&seed);
    let skey = SecretKey::from(Scalar::from_bits(h.bits()));
    let pkey = PublicKey::from(skey);
    (skey, pkey)
}

pub fn check_keying(skey: &SecretKey, pkey: &PublicKey) -> Result<(), CryptoError> {
    let hkey = Hash::digest(&pkey);
    let sig = sign_hash(&hkey, &skey);
    validate_sig(&hkey, &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey) {
    let seed = thread_rng().gen::<[u8; 32]>();
    make_deterministic_keys(&seed)
}

// -----------------------------------------------------------------------
// Schnorr Signatures (u, K)
//
// u*G = K + Fr(H(K, P, msg))*P
// generate K = k*G for k = random Fr
// generate u = k + Fr(H(K, P, msg)) * s

impl SchnorrSig {
    pub fn new() -> Self {
        // construct a dummy signature
        SchnorrSig {
            u: Fr::zero(),
            K: Pt::identity(),
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

impl<'a, 'b> Add<&'a SchnorrSig> for &'b SchnorrSig {
    type Output = SchnorrSig;
    fn add(self, other: &'a SchnorrSig) -> SchnorrSig {
        // user should have ensured that sig.K are valid
        // before calling this operator
        let sum_u = Scalar::from(self.u) + Scalar::from(other.u);
        let sum_k = RistrettoPoint::from(self.K) + RistrettoPoint::from(other.K);
        SchnorrSig {
            u: Fr::from(sum_u),
            K: Pt::from(sum_k),
        }
    }
}

impl<'a> Add<&'a SchnorrSig> for SchnorrSig {
    type Output = SchnorrSig;
    fn add(self, other: &'a SchnorrSig) -> SchnorrSig {
        &self + other
    }
}

impl<'b> Add<SchnorrSig> for &'b SchnorrSig {
    type Output = SchnorrSig;
    fn add(self, other: SchnorrSig) -> SchnorrSig {
        self + &other
    }
}

impl Add<SchnorrSig> for SchnorrSig {
    type Output = SchnorrSig;
    fn add(self, other: SchnorrSig) -> SchnorrSig {
        &self + &other
    }
}

impl<'a> AddAssign<&'a SchnorrSig> for SchnorrSig {
    fn add_assign(&mut self, other: &SchnorrSig) {
        let sum_sig = &*self + other;
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
    let h = Hash::digest_chain(&[hmsg, skey]);
    let k = Scalar::from_bits(h.bits());
    let big_k = Pt::from(k * RistrettoPoint::from(Pt::one()));
    let pkey = PublicKey::from(*skey);
    let h = Hash::digest_chain(&[&big_k, &pkey, hmsg]);
    let u = k + Scalar::from_bits(h.bits()) * Scalar::from(*skey);
    SchnorrSig {
        u: Fr::from(u),
        K: Pt::from(big_k),
    }
}

pub fn sign_hash_with_kval(
    hmsg: &Hash,
    skey: &SecretKey,
    k_val: &Fr,
    sumK: &Pt,
    sumPKey: &Pt,
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
    let kval = Scalar::from(*k_val);
    let my_big_k = kval * RistrettoPoint::from(Pt::one());
    let pkey = PublicKey::from(Pt::from(*sumPKey));
    let h = Hash::digest_chain(&[sumK, &pkey, hmsg]);
    let u = kval + Scalar::from_bits(h.bits()) * Scalar::from(*skey);
    SchnorrSig {
        u: Fr::from(u),
        K: Pt::from(my_big_k),
    }
}

pub fn validate_sig(hmsg: &Hash, sig: &SchnorrSig, pkey: &PublicKey) -> Result<(), CryptoError> {
    let h = Hash::digest_chain(&[&sig.K, pkey, hmsg]);
    let Ppt = RistrettoPoint::from(*pkey);
    let Kpt = RistrettoPoint::from(sig.K);
    let uval = Scalar::from(sig.u);
    if uval * RistrettoPoint::from(Pt::one()) == Kpt + Scalar::from_bits(h.bits()) * Ppt {
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

pub fn aes_encrypt(msg: &[u8], pkey: &PublicKey) -> Result<(EncryptedPayload, Fr), CryptoError> {
    if *pkey == PublicKey::zero() {
        // construct an unencrypted payload that anyone can read.
        Ok((
            EncryptedPayload {
                ag: Pt::from(RistrettoPoint::identity()),
                ctxt: msg.to_vec(),
            },
            Fr::zero(),
        ))
    } else {
        // normal encrytion with keying hint
        let h = Hash::from_vector(msg);
        let mut state = Hasher::new();
        "encr_alpha".hash(&mut state);
        pkey.hash(&mut state);
        h.hash(&mut state);
        let hh = state.result();
        let alpha = Scalar::from_bits(hh.bits());
        let ppt = RistrettoPoint::from(*pkey);
        let ap = alpha * ppt; // generate key (alpha*s*G = alpha*P), and hint ag = alpha*G
        let ag = alpha * RistrettoPoint::from(Pt::one());
        let key = Hash::digest(&ap).bits();
        let ctxt = aes_encrypt_with_key(msg, &key);
        Ok((
            EncryptedPayload {
                ag: Pt::from(ag),
                ctxt,
            },
            Fr::from(alpha),
        ))
    }
}

pub fn aes_decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    if payload.ag.is_identity() {
        // universal unencrypted payload
        Ok(payload.ctxt.clone())
    } else {
        // normal encryption, key = skey * AG
        let zr = Scalar::from(*skey);
        let ag = RistrettoPoint::from(payload.ag);
        let asg = zr * ag; // compute the actual key seed = s*alpha*G
        let key = Hash::digest(&asg).bits();
        let ans = aes_encrypt_with_key(&payload.ctxt, &key);
        Ok(ans)
    }
}

pub fn aes_decrypt_with_rvalue(
    payload: &EncryptedPayload,
    rvalue: &Fr,
    pkey: &PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    if payload.ag.is_identity() {
        // universal unencrypted payload
        Ok(payload.ctxt.clone())
    } else {
        // normal encryption, key = r * P
        let asg = Scalar::from(*rvalue) * RistrettoPoint::from(*pkey);
        let key = Hash::digest(&asg).bits();
        let ans = aes_encrypt_with_key(&payload.ctxt, &key);
        Ok(ans)
    }
}

// -----------------------------------------------------------

fn make_securing_keys(seed: &str) -> (SecretKey, PublicKey) {
    // Do we need a salt? We won't be storing these seed keys
    // anywhere, so there is nothing to guard against rainbow table
    // attacks. And so I don't think we need salting.
    let mut seed = Hash::from_str(seed).bits();
    for _ in 1..1024 {
        seed = Hash::from_vector(&seed).bits();
    }
    let ans = make_deterministic_keys(&seed);
    ans
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
    let (payload, _r_value) = aes_encrypt(key_to_encrypt, &pkey).expect("Valid Pubkey");
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
    use serde_json;

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

    #[test]
    fn check_base58check() {
        let pkey = make_random_keys().1;
        let encoded = String::from(&pkey);
        let decoded = PublicKey::from_str(&encoded).unwrap();
        assert_eq!(pkey, decoded);
    }

    #[test]
    fn check_hashable() {
        let fr =
            Fr::try_from_hex("0bc1914cd062c8a63b51171f8f8800d7043d0924eb8a521fbc1431018390d6ab")
                .unwrap();
        assert_eq!(
            Hash::digest(&fr).to_hex(),
            "cbea11b62f076ae22113247a0806272a6f56245751d42ba207f1fede15c90322"
        );
        let pt =
            Pt::try_from_hex("4c1caaa3bac41c0bf6199cad16a30d8fb111c168780b6c9c5cee16ce974f8c3a")
                .unwrap();
        assert_eq!(
            Hash::digest(&pt).to_hex(),
            "cbef7083c5e397105417dca11bd15361ff000ec47746629bc94924f0368a02a5"
        );

        let (skey, pkey) = make_deterministic_keys(b"test");
        assert_eq!(
            Hash::digest(&skey).to_hex(),
            "21f13221bb9792ecf7e767535f8cf7b23e7afb291e19f76782640aea43c688fa"
        );
        assert_eq!(
            Hash::digest(&pkey).to_hex(),
            "2e87868abe1889b7904a09f5e8464411674773842ab23b7dd132a9d4f47d3600"
        );

        let sig = sign_hash(&Hash::digest("test"), &skey);
        assert_eq!(
            Hash::digest(&sig).to_hex(),
            "3500d6fd11c6e5ad6bddcb387ddd0a6178ee2ea526005301b2207e3cf1c597f2"
        );

        let (payload, _rvalue) = aes_encrypt(b"test", &pkey).unwrap();
        assert_eq!(
            Hash::digest(&payload).to_hex(),
            "bbb2e0e61f055eda70466e4b57488d08f87d51a6baa486faa04d26e4d35e2ac7"
        );

        let encrypted_key = encrypt_key("seed", b"key");
        assert_eq!(
            Hash::digest(&encrypted_key).to_hex(),
            "16a72db9253a1112553e723152c7210374719fc43c4c09267d7dde6fee319aee"
        );
    }

    #[test]
    fn check_serde() {
        let pkey = make_random_keys().1;
        let serialized = serde_json::to_string(&pkey).unwrap();
        let deserialized: PublicKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(pkey, deserialized);
    }
}

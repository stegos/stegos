//! pbc -- BLS12-381 PBC for faster BLS Signatures

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
#![allow(dead_code)]

mod internal;

use crate::hash::*;
use crate::pbc::internal::*;
use crate::utils::*;
use crate::CryptoError;
use ff::*;
use paired::bls12_381::{Bls12, Fq12, Fq2, Fq6, Fr, G1Compressed, G2Compressed};
use paired::*;
use rand::prelude::*;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash as stdhash;
use std::mem;
use std::ops::{Add, AddAssign};

// ------------------------------------------------

#[derive(Copy, Clone)]
pub enum G1 {
    G1Raw(IG1<Bls12>),
    G1Cmpr(G1Compressed),
    G1None,
}

#[derive(Copy, Clone)]
pub enum G2 {
    G2Raw(IG2<Bls12>),
    G2Cmpr(G2Compressed),
    G2None,
}

#[derive(Clone)]
pub struct SecretKey(ISecretKey<Bls12>);

#[derive(Copy, Clone)]
pub struct PublicKey(G2);

#[derive(Copy, Clone)]
pub struct Signature(G1);

#[derive(Copy, Clone)]
pub struct SecretSubKey(G1);

#[derive(Copy, Clone)]
pub struct PublicSubKey(G2);

// -------------------------------------------------------------------------------

impl Drop for SecretKey {
    fn drop(&mut self) {
        let mut rep = self.0.x.into_repr();
        rep.0[0] = 0;
        rep.0[1] = 0;
        rep.0[2] = 0;
        rep.0[3] = 0;

        //TODO: Move out dum_wau outside of flint
        #[cfg(feature = "flint")]
        unsafe {
            crate::dicemix::ffi::dum_wau(rep.0.as_ptr() as *mut _, 32);
        }
    }
}

// -------------------------------------------------------------------------------

impl G1 {
    pub fn zero() -> Self {
        G1::G1Raw(IG1::<Bls12>::zero())
    }

    pub fn generator() -> Self {
        G1::G1Raw(IG1::<Bls12>::generator())
    }

    pub fn is_zero(&self) -> bool {
        match self {
            G1::G1Raw(g1) => g1.pt.is_zero(),
            G1::G1Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(pt) => pt.is_zero(),
                _ => panic!("should never happen"),
            },
            G1::G1None => panic!("should never happen"),
        }
    }

    pub fn dcmpr(&self) -> Result<IG1<Bls12>, CryptoError> {
        match self {
            G1::G1Raw(g1) => Ok(*g1),
            G1::G1Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(g1) => Ok(IG1::<Bls12> { pt: g1 }),
                _ => Err(CryptoError::InvalidPoint),
            },
            G1::G1None => Err(CryptoError::InvalidPoint),
        }
    }

    pub fn is_decompressed(&self) -> bool {
        match self {
            G1::G1Raw(_) => true,
            _ => false,
        }
    }

    pub fn decompress(&self) -> Result<G1, CryptoError> {
        if self.is_decompressed() {
            Ok(*self)
        } else {
            Ok(G1::G1Raw(self.dcmpr()?))
        }
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        match self {
            G1::G1Raw(g1) => {
                let mut tmp = [0u8; 48];
                let cpt = g1.pt.into_compressed();
                let me_ref = cpt.as_ref();
                tmp.copy_from_slice(&me_ref[0..48]);
                tmp
            }
            G1::G1Cmpr(cmpr) => {
                let mut bytes = [0u8; 48];
                bytes.copy_from_slice(cmpr.as_ref());
                bytes
            }
            G1::G1None => panic!("should never happen"),
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 48 {
            return Err(CryptoError::InvalidBinaryLength(48, bytes.len()).into());
        }
        let mut cpt = G1Compressed::empty();
        cpt.as_mut().copy_from_slice(bytes);
        Ok(G1::G1Cmpr(cpt))
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        u8v_to_hexstr(&bytes)
    }

    pub fn try_from_hex(s: &str) -> Result<G1, CryptoError> {
        let mut tmp = [0u8; 48];
        hexstr_to_lev_u8(&s, &mut tmp)?;
        G1::try_from_bytes(&tmp)
    }
}

impl fmt::Debug for G1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp = self.to_hex();
        write!(f, "SecureG1({})", tmp)
    }
}

impl Eq for G1 {}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        for (a, b) in self.to_bytes().iter().zip(other.to_bytes().iter()) {
            if a != b {
                return false;
            }
        }
        true
    }
}

impl Add<G1> for G1 {
    type Output = G1;
    fn add(self, other: G1) -> G1 {
        match self {
            G1::G1Raw(my_g1) => match other {
                G1::G1Raw(other_g1) => {
                    let mut sum = my_g1;
                    sum.add_assign(other_g1);
                    G1::G1Raw(sum)
                }
                G1::G1Cmpr(cmpr) => match cmpr.into_affine() {
                    Ok(other_g1) => {
                        let mut sum = my_g1;
                        sum.add_assign(IG1::<Bls12> { pt: other_g1 });
                        G1::G1Raw(sum)
                    }
                    _ => G1::G1None,
                },
                G1::G1None => G1::G1None,
            },
            G1::G1Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(my_g1) => match other {
                    G1::G1Raw(other_g1) => {
                        let mut sum = IG1::<Bls12> { pt: my_g1 };
                        sum.add_assign(other_g1);
                        G1::G1Raw(sum)
                    }
                    G1::G1Cmpr(cmpr) => {
                        let pt = cmpr.into_affine();
                        match pt {
                            Ok(other_g1) => {
                                let mut sum = IG1::<Bls12> { pt: my_g1 };
                                sum.add_assign(IG1::<Bls12> { pt: other_g1 });
                                G1::G1Raw(sum)
                            }
                            _ => G1::G1None,
                        }
                    }
                    _ => G1::G1None,
                },
                _ => G1::G1None,
            },
            G1::G1None => G1::G1None,
        }
    }
}

impl AddAssign<G1> for G1 {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other
    }
}

// -------------------------------------------------------------------------------

impl G2 {
    pub fn zero() -> Self {
        G2::G2Raw(IG2::<Bls12>::zero())
    }

    pub fn generator() -> Self {
        G2::G2Raw(IG2::<Bls12>::generator())
    }

    pub fn is_zero(&self) -> bool {
        match self {
            G2::G2Raw(g2) => g2.pt.is_zero(),
            G2::G2Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(pt) => pt.is_zero(),
                _ => panic!("should never happen"),
            },
            G2::G2None => panic!("should never happen"),
        }
    }

    pub fn dcmpr(&self) -> Result<IG2<Bls12>, CryptoError> {
        match self {
            G2::G2Raw(g2) => Ok(*g2),
            G2::G2Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(g2) => Ok(IG2::<Bls12> { pt: g2 }),
                _ => Err(CryptoError::InvalidPoint),
            },
            G2::G2None => Err(CryptoError::InvalidPoint),
        }
    }

    pub fn is_decompressed(&self) -> bool {
        match self {
            G2::G2Raw(_) => true,
            _ => false,
        }
    }

    pub fn decompress(&self) -> Result<G2, CryptoError> {
        if self.is_decompressed() {
            Ok(*self)
        } else {
            Ok(G2::G2Raw(self.dcmpr()?))
        }
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        match self {
            G2::G2Raw(g2) => {
                let mut tmp = [0u8; 96];
                let cpt = g2.pt.into_compressed();
                let me_ref = cpt.as_ref();
                tmp.copy_from_slice(&me_ref[0..96]);
                tmp
            }
            G2::G2Cmpr(cmpr) => {
                let mut bytes = [0u8; 96];
                bytes.copy_from_slice(cmpr.as_ref());
                bytes
            }
            G2::G2None => panic!("should never happen"),
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidBinaryLength(96, bytes.len()).into());
        }
        let mut cpt = G2Compressed::empty();
        cpt.as_mut().copy_from_slice(bytes);
        Ok(G2::G2Cmpr(cpt))
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        u8v_to_hexstr(&bytes)
    }

    pub fn try_from_hex(s: &str) -> Result<G2, CryptoError> {
        let mut tmp = [0u8; 96];
        hexstr_to_lev_u8(&s, &mut tmp)?;
        G2::try_from_bytes(&tmp)
    }
}

impl fmt::Debug for G2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp = self.to_hex();
        write!(f, "SecureG2({})", tmp)
    }
}

impl Eq for G2 {}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        for (a, b) in self.to_bytes().iter().zip(other.to_bytes().iter()) {
            if a != b {
                return false;
            }
        }
        true
    }
}

impl Add<G2> for G2 {
    type Output = G2;
    fn add(self, other: G2) -> G2 {
        match self {
            G2::G2Raw(my_g2) => match other {
                G2::G2Raw(other_g2) => {
                    let mut sum = my_g2;
                    sum.add_assign(other_g2);
                    G2::G2Raw(sum)
                }
                G2::G2Cmpr(cmpr) => match cmpr.into_affine() {
                    Ok(other_g2) => {
                        let mut sum = my_g2;
                        sum.add_assign(IG2::<Bls12> { pt: other_g2 });
                        G2::G2Raw(sum)
                    }
                    _ => G2::G2None,
                },
                G2::G2None => G2::G2None,
            },
            G2::G2Cmpr(cmpr) => match cmpr.into_affine() {
                Ok(my_g2) => match other {
                    G2::G2Raw(other_g2) => {
                        let mut sum = IG2::<Bls12> { pt: my_g2 };
                        sum.add_assign(other_g2);
                        G2::G2Raw(sum)
                    }
                    G2::G2Cmpr(cmpr) => {
                        let pt = cmpr.into_affine();
                        match pt {
                            Ok(other_g2) => {
                                let mut sum = IG2::<Bls12> { pt: my_g2 };
                                sum.add_assign(IG2::<Bls12> { pt: other_g2 });
                                G2::G2Raw(sum)
                            }
                            _ => G2::G2None,
                        }
                    }
                    _ => G2::G2None,
                },
                _ => G2::G2None,
            },
            G2::G2None => G2::G2None,
        }
    }
}

impl AddAssign<G2> for G2 {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

// -------------------------------------------------------------------------------

impl Hashable for Signature {
    // Signature is G1 compressed = 48 bytes
    fn hash(&self, state: &mut Hasher) {
        "Signature".hash(state);
        let bytes = self.to_bytes();
        bytes[0..48].hash(state);
    }
}

impl Hashable for SecretKey {
    // SecretKey is [u64; 4]
    fn hash(&self, state: &mut Hasher) {
        "SecretKey".hash(state);
        let bytes = self.to_bytes();
        bytes[0..32].hash(state);
    }
}

impl Hashable for PublicKey {
    // Pubkey is compressed G2 = 96 bytes
    fn hash(&self, state: &mut Hasher) {
        "PublicKey".hash(state);
        let bytes = self.to_bytes();
        bytes[0..96].hash(state);
    }
}

impl Hashable for G1 {
    // G1 in compressed form is 48 bytes
    fn hash(&self, state: &mut Hasher) {
        "G1".hash(state);
        let bytes = self.to_bytes();
        bytes[0..48].hash(state);
    }
}

impl Hashable for G2 {
    // G2 in compressed form is 96 bytes
    fn hash(&self, state: &mut Hasher) {
        "G2".hash(state);
        let bytes = self.to_bytes();
        bytes[0..96].hash(state);
    }
}

impl Hashable for Fq2 {
    // no stated representation available for Fq,
    // but it is [u64;6] in compressed form
    fn hash(&self, state: &mut Hasher) {
        "Fq2".hash(state);
        let tmp = self.c0.into_repr(); // Fq
        for ix in 0..6 {
            tmp.0[ix].hash(state);
        }
        let tmp = self.c1.into_repr(); // Fq
        for ix in 0..6 {
            tmp.0[ix].hash(state);
        }
    }
}

impl Hashable for Fq6 {
    fn hash(&self, state: &mut Hasher) {
        "Fq6".hash(state);
        self.c0.hash(state); // Fq2
        self.c1.hash(state); // Fq2
        self.c2.hash(state); // Fq2
    }
}

impl Hashable for Fq12 {
    fn hash(&self, state: &mut Hasher) {
        "Fq12".hash(state);
        self.c0.hash(state); // Fq6
        self.c1.hash(state); // Fq6
    }
}

// -------------------------------------------------------------------------------

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        let tmp = self.0.x.into_repr();
        let h8 = &unsafe { mem::transmute::<_, [u8; 32]>(tmp.0) };
        let mut ans = [0u8; 32];
        ans.copy_from_slice(h8);
        ans
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidBinaryLength(32, bytes.len()));
        }
        let mut tbytes = [0u8; 32];
        tbytes.copy_from_slice(bytes);
        let h64 = &unsafe { mem::transmute::<[u8; 32], [u64; 4]>(tbytes) };
        let mut tmp = Fr::zero().into_repr();
        tmp.0.copy_from_slice(h64);
        match Fr::from_repr(tmp) {
            Err(_) => Err(CryptoError::NotInPrincipalSubgroup),
            Ok(fr) => Ok(SecretKey(ISecretKey { x: fr })),
        }
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        u8v_to_hexstr(&bytes)
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut tmp = [0u8; 32];
        hexstr_to_lev_u8(s, &mut tmp)?;
        Self::try_from_bytes(&tmp)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "SecretKey({})", hex)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        let hex = self.to_hex();
        write!(f, "SecretKey({})", &hex[0..12])
    }
}

impl Eq for SecretKey {}

impl PartialEq for SecretKey {
    fn eq(&self, b: &Self) -> bool {
        self.0.x == b.0.x
    }
}

// -------------------------------------------------------------------

impl PublicKey {
    pub fn dum() -> Self {
        G2::zero().into()
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        G2::from(self.clone()).to_bytes()
    }

    pub fn decompress(&self) -> Result<Self, CryptoError> {
        if G2::from(*self).is_decompressed() {
            Ok(*self)
        } else {
            Ok(PublicKey::from(G2::from(*self).decompress()?))
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(PublicKey::from(G2::try_from_bytes(bytes)?))
    }

    pub fn to_hex(&self) -> String {
        G2::from(self.clone()).to_hex()
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        Ok(PublicKey::from(G2::try_from_hex(s)?))
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

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::try_from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for G1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for G1 {
    fn deserialize<D>(deserializer: D) -> Result<G1, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        G1::try_from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // self.0.p_pub == other.0.p_pub
        self.0 == other.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "PublicKey({})", hex)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        let hex = self.to_hex();
        write!(f, "{}", &hex[0..12])
    }
}

// Needed to sort the list of validators
impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        let self_bytes = self.to_bytes();
        let other_bytes = other.to_bytes();
        self_bytes[0..96].cmp(&other_bytes[0..96])
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
        let bytes = G2::from(*self).to_bytes();
        stdhash::Hash::hash(&bytes[0..96], state);
    }
}

impl From<PublicKey> for G2 {
    fn from(pkey: PublicKey) -> Self {
        pkey.0
        // G2(IG2 {
        //     pt: pkey.0.p_pub.into_affine(),
        // })
    }
}

impl From<G2> for PublicKey {
    fn from(g: G2) -> Self {
        PublicKey(g)
    }
}

// -------------------------------------------------------------------

impl Signature {
    /// Create a new point which binary representation consists of all zeros.
    pub fn new() -> Signature {
        Signature::from(G1::zero())
    }

    /// Create a new point which binary representation consists of all zeros.
    pub fn zero() -> Signature {
        Signature::from(G1::zero())
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        let pt = G1::from(self.clone());
        pt.to_bytes()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pt = G1::try_from_bytes(bytes)?;
        Ok(Signature::from(pt))
    }

    pub fn to_hex(&self) -> String {
        let pt = G1::from(self.clone());
        pt.to_hex()
    }

    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let pt = G1::try_from_hex(s)?;
        Ok(Signature::from(pt))
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

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "SecureSig({})", hex)
    }
}

impl Eq for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl AddAssign<Signature> for Signature {
    fn add_assign(&mut self, other: Self) {
        *self = Signature(self.0 + other.0)
    }
}

// -------------------------------------------------------------------

pub fn sign_hash(h: &Hash, skey: &SecretKey) -> Signature {
    let pt = skey.0.sign(h.base_vector());
    Signature(G1::G1Raw(IG1::<Bls12> {
        pt: pt.s.into_affine(),
    }))
}

pub fn check_hash(h: &Hash, sig: &Signature, pkey: &PublicKey) -> Result<(), CryptoError> {
    let ipkey = IPublicKey::<Bls12> {
        p_pub: G2::from(*pkey).dcmpr()?.pt.into_projective(),
    };
    let isig = ISignature::<Bls12> {
        s: G1::from(*sig).dcmpr()?.pt.into_projective(),
    };
    if ipkey.verify(h.base_vector(), &isig) {
        Ok(())
    } else {
        Err(CryptoError::BadKeyingSignature)
    }
}

// -------------------------------------------------------------------------------

impl From<Hash> for Fr {
    fn from(h: Hash) -> Self {
        let mut rep = Fr::zero().into_repr();
        let mut hm = h.clone();
        loop {
            let h8 = &unsafe { mem::transmute::<_, [u64; 4]>(hm.bits()) };
            rep.0[0] = h8[0];
            rep.0[1] = h8[1];
            rep.0[2] = h8[2];
            rep.0[3] = h8[3];
            if rep.is_zero() {
                hm = Hash::from_vector(hm.base_vector());
            } else {
                break;
            }
        }
        while rep >= Fr::char() {
            rep.div2();
        }
        Fr::from_repr(rep).expect("ok")
    }
}

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey) {
    let iskey = ISecretKey {
        x: Fr::from(Hash::from_vector(seed)),
    };
    let ipkey = IPublicKey::<Bls12>::from_secret(&iskey);
    let skey = SecretKey(iskey);
    let pkey = PublicKey(G2::G2Raw(IG2::<Bls12> {
        pt: ipkey.p_pub.into_affine(),
    }));
    (skey, pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    make_deterministic_keys(&rng.gen::<[u8; 32]>())
}

pub fn check_keying(skey: &SecretKey, pkey: &PublicKey) -> Result<(), CryptoError> {
    let hpk = Hash::digest(&pkey);
    let sig = sign_hash(&hpk, &skey);
    check_hash(&hpk, &sig, &pkey)
}

// ------------------------------------------------------------------------
// Subkey generation and Sakai-Kasahara Encryption

pub fn make_secret_subkey(skey: &SecretKey, seed: &[u8]) -> SecretSubKey {
    let id = Fr::from(Hash::from_vector(seed));
    let iskey: ISecretSubKey<Bls12> = skey.0.into_subkey(id);
    SecretSubKey(G1::G1Raw(IG1::<Bls12> {
        pt: iskey.pt.into_affine(),
    }))
}

pub fn make_public_subkey(pkey: &PublicKey, seed: &[u8]) -> Result<PublicSubKey, CryptoError> {
    let id = Fr::from(Hash::from_vector(seed));
    let ipkey = IPublicKey::<Bls12> {
        p_pub: G2::from(*pkey).dcmpr()?.pt.into_projective(),
    };
    let ispkey: IPublicSubKey<Bls12> = ipkey.into_subkey(id);
    Ok(PublicSubKey(G2::G2Raw(IG2::<Bls12> {
        pt: ispkey.pt.into_affine(),
    })))
}

pub fn validate_subkeying(skey: &SecretSubKey, pkey: &PublicSubKey) -> Result<(), CryptoError> {
    let isskey = ISecretSubKey::<Bls12> {
        pt: skey.0.dcmpr()?.pt.into_projective(),
    };
    let ispkey = IPublicSubKey::<Bls12> {
        pt: pkey.0.dcmpr()?.pt.into_projective(),
    };
    if isskey.check_vrf(&ispkey) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSubKeying)
    }
}

// -----------------------------------------------------
// Sakai-Hasakara Encryption

#[derive(Copy, Clone)]
pub struct RVal(G2);

impl RVal {
    pub fn to_hex(&self) -> String {
        G2::from(self.clone()).to_hex()
    }

    /// Try to convert from hex string
    pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
        let g = G2::try_from_hex(s)?;
        Ok(RVal::from(g))
    }

    /// Convert into bytes slice
    pub fn to_bytes(&self) -> [u8; 96] {
        G2::from(self.clone()).to_bytes()
    }

    /// Try to convert from raw bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(RVal::from(G2::try_from_bytes(bytes)?))
    }
}

impl Hashable for RVal {
    fn hash(&self, state: &mut Hasher) {
        "SecureRVal".hash(state);
        self.to_bytes().hash(state)
    }
}

impl Eq for RVal {}

impl PartialEq for RVal {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<G2> for RVal {
    fn from(pt: G2) -> Self {
        RVal(pt)
    }
}

impl From<RVal> for G2 {
    fn from(rv: RVal) -> Self {
        rv.0
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
    pkey: PublicKey,
    // public key of recipient
    id: Vec<u8>,
    // IBE ID
    rval: RVal,
    // R_val used for SAKE encryption
    cmsg: Vec<u8>, // encrypted payload
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

pub fn ibe_encrypt(
    msg: &[u8],
    pkey: &PublicKey,
    id: &[u8],
) -> Result<EncryptedPacket, CryptoError> {
    let nmsg = msg.len();

    // compute IBE public key
    let pkid = make_public_subkey(&pkey, &id)?;

    // compute hash of concatenated id:msg
    let mut concv = Vec::from(id);
    for b in msg.to_vec() {
        concv.push(b);
    }
    let rhash = Hash::from_vector(&concv);
    let fr = Fr::from(rhash);
    let ipt = pkid.0.dcmpr()?.pt;
    let irval = ipt.mul(fr);
    let rval = RVal(G2::G2Raw(IG2::<Bls12> {
        pt: irval.into_affine(),
    }));
    let pval: Fq12 = IG1::<Bls12>::sakke_fqk(fr);
    let pvbytes = Hash::digest(&pval);
    let mut cmsg = hash_nbytes(nmsg, pvbytes.base_vector());
    // encrypt with (msg XOR H(pairing-val))
    for ix in 0..nmsg {
        cmsg[ix] ^= msg[ix];
    }
    Ok(EncryptedPacket {
        pkey: pkey.clone(),
        id: id.to_vec(),
        rval,
        cmsg,
    })
}

pub fn ibe_decrypt(pack: &EncryptedPacket, skey: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    let skid = make_secret_subkey(&skey, &pack.id);
    let pkid = make_public_subkey(&pack.pkey, &pack.id)?;
    let nmsg = pack.cmsg.len();

    let irval = pack.rval.0.dcmpr()?.pt;
    let isval = IG1::<Bls12> {
        pt: skid.0.dcmpr()?.pt,
    };
    let pval: Fq12 = IG1::pair_with(&isval, irval);
    let pvbytes = Hash::digest(&pval);

    // decrypt using (ctxt XOR H(pairing_val))
    let mut msg = hash_nbytes(nmsg, &pvbytes.base_vector());
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
    let fr = Fr::from(rhash);
    let ipt = pkid.0.dcmpr()?.pt;
    if ipt.mul(fr).into_affine() == irval {
        Ok(msg)
    } else {
        Err(CryptoError::InvalidDecryption)
    }
}

// -------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct VRF {
    pub rand: Hash,
    // hash digest of generated randomness in pairing field
    pub proof: G1, // proof on randomness
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
    let id = Fr::from(*seed);
    let (key, fq12) = skey.0.into_vrf(id);
    let proof = G1::G1Raw(IG1::<Bls12> {
        pt: key.pt.into_affine(),
    });
    let rand = Hash::digest(&fq12);
    VRF { rand, proof }
}

pub fn validate_VRF_randomness(vrf: &VRF) -> Result<(), CryptoError> {
    // Public validation - anyone can validate the randomness
    // knowing only its value and the accompanying proof.
    let key = ISecretSubKey::<Bls12> {
        pt: vrf.proof.dcmpr()?.pt.into_projective(),
    };
    let rand = key.into_fq12();
    if vrf.rand == Hash::digest(&rand) {
        Ok(())
    } else {
        Err(CryptoError::InvalidVRFRandomness)
    }
}

pub fn validate_VRF_source(vrf: &VRF, pkey: &PublicKey, seed: &Hash) -> Result<(), CryptoError> {
    // whatever the source of the seed, it should all be
    // pre-hashed before calling this function.
    //
    // Anyone knowing the pkey of the originator, and the seed that
    // was used, can verify that the randomness originated from the
    // holder of the corresponding secret key and that seed.
    //
    let id = Fr::from(*seed);
    let ipsubkey = IPublicKey::<Bls12> {
        p_pub: pkey.0.dcmpr()?.pt.into_projective(),
    }
    .into_subkey(id);
    let skey = ISecretSubKey {
        pt: vrf.proof.dcmpr()?.pt.into_projective(),
    };
    if skey.check_vrf(&ipsubkey) {
        Ok(())
    } else {
        Err(CryptoError::InvalidVRFSource)
    }
}

// -----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use paired::bls12_381::Bls12;

    #[test]
    fn sign_verify() {
        use crate::pbc::internal::*;
        use old_rand::*;
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..500 {
            let keypair = IKeypair::<Bls12>::generate(&mut rng);
            let message = format!("Message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
        }
    }

    #[test]
    fn aggregate_signatures() {
        use crate::pbc::internal::*;
        use old_rand::*;
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut inputs = Vec::with_capacity(1000);
        let mut signatures = Vec::with_capacity(1000);
        for i in 0..500 {
            let keypair = IKeypair::<Bls12>::generate(&mut rng);
            let message = format!("Message {}", i);
            let signature = keypair.sign(&message.as_bytes());
            inputs.push((keypair.public, message));
            signatures.push(signature);

            // Only test near the beginning and the end, to reduce test runtime
            if i < 10 || i > 495 {
                let asig = IAggregateSignature::from_signatures(&signatures);
                assert_eq!(
                    asig.verify(
                        &inputs
                            .iter()
                            .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                            .collect()
                    ),
                    true
                );
            }
        }
    }

    #[test]
    fn aggregate_signatures_duplicated_messages() {
        use crate::pbc::internal::*;
        use old_rand::*;
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut inputs = Vec::new();
        let mut asig = IAggregateSignature::new();

        // Create the first signature
        let keypair = IKeypair::<Bls12>::generate(&mut rng);
        let message = "First message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The first "aggregate" signature should pass
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            true
        );

        // Create the second signature
        let keypair = IKeypair::<Bls12>::generate(&mut rng);
        let message = "Second message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The second (now-)aggregate signature should pass
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            true
        );

        // Create the third signature, reusing the second message
        let keypair = IKeypair::<Bls12>::generate(&mut rng);
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The third aggregate signature should fail
        assert_eq!(
            asig.verify(
                &inputs
                    .iter()
                    .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                    .collect()
            ),
            false
        );
    }

    #[test]
    fn chk_bls() {
        use crate::pbc::internal::*;
        use old_rand::*;
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let keypair = IKeypair::<Bls12>::generate(&mut rng);
        let message = "Some message";
        let sig = keypair.sign(&message.as_bytes());
        if true {
            let csig = sig.s.into_affine().into_compressed();
            let cpkey = keypair.public.p_pub.into_affine().into_compressed();
            use std::time::SystemTime;
            let start = SystemTime::now();
            let niter = 1000;
            for _ in 0..niter {
                let mut sig = sig.clone();
                sig.s = csig.into_affine().expect("ok").into_projective();
                let mut kp = keypair.clone();
                kp.public.p_pub = cpkey.into_affine().expect("ok").into_projective();
                kp.verify(&message.as_bytes(), &sig);
            }
            let timing = start.elapsed().expect("ok");
            println!("BLS Verify = {:?}", timing / niter);
        }
        assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
    }

    #[test]
    fn chk_bls2() {
        use crate::pbc::*;

        // check key generation
        let (skey, pkey) = make_deterministic_keys(b"Test Keys");
        check_keying(&skey, &pkey).expect("ok");

        // check key serialization
        let bytes = skey.to_bytes();
        let skey2 = SecretKey::try_from_bytes(&bytes).expect("ok");
        assert!(skey == skey2);
        let hex = skey.to_hex();
        let skey2 = SecretKey::try_from_hex(&hex).expect("ok");
        assert!(skey == skey2);

        let bytes = pkey.to_bytes();
        let pkey2 = PublicKey::try_from_bytes(&bytes).expect("ok");
        assert!(pkey == pkey2);
        let hex = pkey.to_hex();
        let pkey2 = PublicKey::try_from_hex(&hex).expect("ok");
        assert!(pkey == pkey2);

        // Check BLS Signature
        let message = "Some message";
        let sig = sign_hash(&Hash::digest(message), &skey);
        check_hash(&Hash::digest(message), &sig, &pkey).expect("ok");
        // BLS Signature serialization
        let bytes = sig.to_bytes();
        let sig2 = Signature::try_from_bytes(&bytes).expect("ok");
        assert!(sig == sig2);
        let hex = sig.to_hex();
        let sig2 = Signature::try_from_hex(&hex).expect("ok");
        assert!(sig == sig2);

        // check subkeying generation
        let id = b"Testing";
        let sskey = make_secret_subkey(&skey, id);
        let pskey = make_public_subkey(&pkey, id).expect("ok");
        assert!(validate_subkeying(&sskey, &pskey).is_ok());

        // check VRF
        let h = Hash::from_str("Testing");
        let vrf = make_VRF(&skey, &h);
        assert!(validate_VRF_randomness(&vrf).is_ok());
        assert!(validate_VRF_source(&vrf, &pkey, &h).is_ok());

        // check IBE Encryption
        let payload = b"This is a test payload";
        let enc = ibe_encrypt(payload, &pkey, b"testing-identity").expect("ok");
        let dec = ibe_decrypt(&enc, &skey).expect("ok");
        assert!(dec == payload);

        // get BLS Signature validation timing
        if true {
            use std::time::SystemTime;
            let start = SystemTime::now();
            let niter = 1000;
            for _ in 0..niter {
                check_hash(&Hash::digest(message), &sig, &pkey).expect("ok");
            }
            let timing = start.elapsed().expect("ok");
            println!("BLS Verify = {:?}", timing / niter);
        }
    }

    #[test]
    fn check_hashable() {
        let g1 = G1::try_from_hex("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap();
        assert_eq!(
            Hash::digest(&g1).to_hex(),
            "cec61d62607e1e3d7d06d32751c8eb6f6063822d4c11cfc32e48cbda2828d471"
        );
        let g2 = G2::try_from_hex("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8").unwrap();
        assert_eq!(
            Hash::digest(&g2).to_hex(),
            "2fe6ac58d0a52d3679db09388c10d078a2e268f2db5018faad073ffaff587109"
        );
        let (skey, pkey) = make_deterministic_keys(b"test");
        assert_eq!(
            Hash::digest(&skey).to_hex(),
            "eef43f315ee3de18f636e59dc55cc62c7a4f1e90bcd8609f07dff16f00e6dfa9"
        );
        assert_eq!(
            Hash::digest(&pkey).to_hex(),
            "8338feb8dafed3fd58163ab69726050bc183ecd74cfe11397dd81e69048a4ca7"
        );
        let sig = sign_hash(&Hash::digest("test"), &skey);
        assert_eq!(
            Hash::digest(&sig).to_hex(),
            "904d6dcb433e4193d2af2eb4ae93312d43e70d2ca46e0eb8c8b6160cf6d299d8"
        );
    }

    #[test]
    fn check_constant_time() {
        use std::time::SystemTime;
        let skey = SecretKey::try_from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("ok");
        println!("SecretKey = {:?}", skey);
        let h = Hash::from_str("Testing");
        let niter = 10_000;
        let start = SystemTime::now();
        for _ in 0..niter {
            sign_hash(&h, &skey);
        }
        let timing = start.elapsed().unwrap();
        println!("Time (1) = {:?}", timing / niter);

        let (skey, _pkey) = make_random_keys();
        println!("SecretKey = {:?}", skey);
        let start = SystemTime::now();
        for _ in 0..niter {
            sign_hash(&h, &skey);
        }
        let timing = start.elapsed().unwrap();
        println!("Time (1111...) = {:?}", timing / niter);
    }
}

// ---------------------------------------------------------

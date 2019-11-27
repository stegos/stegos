//! Hashing with SHA3

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

use crate::utils::*;
use crate::CryptoError;

use rand::thread_rng;
use rand::Rng;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::hash as stdhash;
use std::mem;
use std::slice;
use std::time::SystemTime;

// -----------------------------------------------------
// Hashing with SHA3

pub const HASH_SIZE: usize = 32;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Return a hash with all zeros.
    pub fn zero() -> Self {
        Hash([0u8; HASH_SIZE])
    }

    /// Return an random hash.
    pub fn random() -> Self {
        Hash(thread_rng().gen::<[u8; HASH_SIZE]>())
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn bits(self) -> [u8; 32] {
        self.0
    }

    /// Convert into hex string.
    pub fn to_hex(&self) -> String {
        u8v_to_hexstr(&self.0)
    }

    /// Try to convert from hex string.
    pub fn try_from_hex(hexstr: &str) -> Result<Self, CryptoError> {
        // use this function to import a Hash digest facsimile from a string constant
        let mut v = [0u8; HASH_SIZE];
        hexstr_to_bev_u8(hexstr, &mut v)?;
        Ok(Hash(v))
    }

    pub fn from_vector(msg: &[u8]) -> Hash {
        // produce a Hash from a single &[u8] vector
        let mut hasher = Hasher::new();
        (*msg).hash(&mut hasher);
        hasher.result()
    }

    pub fn from_str(s: &str) -> Hash {
        let mut hasher = Hasher::new();
        (*s).hash(&mut hasher);
        hasher.result()
    }

    pub fn digest<T: Hashable + ?Sized>(msg: &T) -> Hash {
        // produce a Hash from a single Hashable
        let mut hasher = Hasher::new();
        msg.hash(&mut hasher);
        hasher.result()
    }

    pub fn digest_chain(msgs: &[&dyn Hashable]) -> Hash {
        // produce a Hash from a list of Hashable items
        let mut state = Hasher::new();
        for x in msgs.iter() {
            x.hash(&mut state);
        }
        state.result()
    }

    pub fn to_bytes(&self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HASH_SIZE {
            return Err(CryptoError::InvalidBinaryLength(HASH_SIZE, bytes.len()).into());
        }
        let mut bits: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
        bits.copy_from_slice(bytes);
        Ok(Hash(bits))
    }

    /// Return minimal and maximal value of hash.
    /// Used for BTreeSet iteration.
    pub fn bounds() -> (Hash, Hash) {
        (Hash([0u8; HASH_SIZE]), Hash([255u8; HASH_SIZE]))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // display only first 6 bytes.
        write!(f, "{}", &self.to_hex()[0..12])
    }
}

impl stdhash::Hash for Hash {
    fn hash<H: stdhash::Hasher>(&self, state: &mut H) {
        stdhash::Hash::hash(&self.0[..], state);
    }
}

impl Hashable for Hash {
    fn hash(&self, state: &mut Hasher) {
        self.0.hash(state);
    }
}

impl<'a, T: Hashable + ?Sized> Hashable for &'a T {
    fn hash(&self, state: &mut Hasher) {
        T::hash(self, state)
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hash::try_from_hex(&s).map_err(serde::de::Error::custom)
    }
}

pub fn hash_nbytes(nb: usize, msg: &[u8]) -> Vec<u8> {
    let nmsg = msg.len();
    let mut ct = nb;
    let mut ans = vec![0u8; nb];
    let mut jx = 0;
    let mut kx = 0u8;
    while ct > 0 {
        let mut inp = vec![kx];
        for ix in 0..nmsg {
            inp.push(msg[ix]);
        }
        let mut hasher = Hasher::new();
        inp.hash(&mut hasher);
        let out = hasher.result();
        let end = if ct > HASH_SIZE { HASH_SIZE } else { ct };
        for ix in 0..end {
            ans[jx + ix] = out.0[ix];
        }
        jx += end;
        ct -= end;
        kx += 1;
    }
    ans
}

/// Implementation of default crypto-hashing algorithm for this project.
pub struct Hasher(Sha3_256);

impl Hasher {
    /// Create the new hasher.
    pub fn new() -> Self {
        Hasher(Sha3_256::new())
    }

    /// Retrieve result.
    pub fn result(&self) -> Hash {
        // FIXME: .clone() is used because .result() doesn't use &self
        let ga = self.0.clone().result();
        let mut h = [0u8; HASH_SIZE];
        h.copy_from_slice(ga.as_slice());
        Hash(h)
    }

    /// Digest input.
    #[inline]
    pub fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.input(data);
    }

    /// Digest input in a chained manner.
    #[inline]
    pub fn chain<B: AsRef<[u8]>>(self, data: B) -> Self {
        Hasher(self.0.chain(data))
    }

    // Reset hasher instance to its initial state.
    #[inline]
    pub fn reset(&mut self) {
        self.0.reset();
    }

    /// A shortcut to calculate hash and return result
    pub fn digest<T: Hashable>(data: &T) -> Hash {
        let mut hasher = Hasher::new();
        data.hash(&mut hasher);
        hasher.result()
    }
}

/// A hashable type.
///
/// Types implementing Hashable are able to be hashed.
///
pub trait Hashable {
    /// Feeds this value into Hasher.
    fn hash(&self, state: &mut Hasher);
}

impl Hashable for bool {
    fn hash(&self, state: &mut Hasher) {
        let data = if *self { 1 } else { 0 };
        state.input(&[data])
    }
}

impl Hashable for u8 {
    fn hash(&self, state: &mut Hasher) {
        state.input(&[*self])
    }
}

impl Hashable for u16 {
    fn hash(&self, state: &mut Hasher) {
        state.input(&unsafe { mem::transmute::<_, [u8; 2]>(*self) })
    }
}

impl Hashable for u32 {
    fn hash(&self, state: &mut Hasher) {
        state.input(&unsafe { mem::transmute::<_, [u8; 4]>(*self) })
    }
}

impl Hashable for u64 {
    fn hash(&self, state: &mut Hasher) {
        state.input(&unsafe { mem::transmute::<_, [u8; 8]>(*self) })
    }
}

impl Hashable for i64 {
    fn hash(&self, state: &mut Hasher) {
        state.input(&unsafe { mem::transmute::<_, [u8; 8]>(*self) })
    }
}

impl Hashable for char {
    fn hash(&self, state: &mut Hasher) {
        let x: [u8; 4] = unsafe { mem::transmute::<_, [u8; 4]>(*self as u32) };
        println!("HashChar {} {} {} {}", x[0], x[1], x[2], x[3]);

        state.input(&unsafe { mem::transmute::<_, [u8; 4]>(*self as u32) })
    }
}

impl Hashable for str {
    fn hash(&self, state: &mut Hasher) {
        state.input(self.as_bytes());
    }
}

impl Hashable for String {
    fn hash(&self, state: &mut Hasher) {
        state.input(self.as_bytes());
    }
}

impl Hashable for SystemTime {
    fn hash(&self, state: &mut Hasher) {
        let since_the_epoch = self
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time is valid");
        let timestamp = since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_millis() as u64;
        timestamp.hash(state);
    }
}

impl Hashable for [u8] {
    fn hash(&self, state: &mut Hasher) {
        let newlen = self.len() * mem::size_of::<u8>();
        let ptr = self.as_ptr() as *const u8;
        state.input(unsafe { slice::from_raw_parts(ptr, newlen) })
    }
}

impl Hashable for Vec<u8> {
    fn hash(&self, state: &mut Hasher) {
        state.input(self);
    }
}

impl<T: Hashable> Hashable for Option<T> {
    fn hash(&self, state: &mut Hasher) {
        if let Some(val) = self {
            val.hash(state);
        }
    }
}

impl<T1: Hashable, T2: Hashable> Hashable for (T1, T2) {
    fn hash(&self, state: &mut Hasher) {
        self.0.hash(state);
        self.1.hash(state);
    }
}

impl Hashable for () {
    fn hash(&self, state: &mut Hasher) {
        "none".hash(state);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Define some structure
    struct Data {
        a: String,
        b: u8,
        c: [u8; 5],
    }

    /// Define custom hash function
    impl Hashable for Data {
        fn hash(&self, state: &mut Hasher) {
            self.a.hash(state);
            self.b.hash(state);
            self.c[..].hash(state);
        }
    }

    #[test]
    fn hasher() {
        let d = Data {
            a: "Hello".to_string(),
            b: 32,                       // space
            c: [87, 111, 114, 108, 100], // World
        };

        let garr = Sha3_256::digest(b"Hello World");
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(garr.as_slice());
        let h1 = Hash(arr);
        let h2 = Hash::digest(&d);

        // Test that manually hashed result matches Hashable for Data implementation.
        assert!(h1 == h2);
    }

    #[test]
    fn check_empty_hash() {
        // assure that we get correct Sha3-256 hash of empty vector
        let h = Hash::from_vector(b"");
        let chk = hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
            .unwrap();
        for (a, b) in h.bits().iter().zip(chk.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn check_equivalence() {
        // ensure that hash of byte vector hexstring is same as hash of hexstring
        let hv = Hash::from_vector(b"1FE9AB");
        let hs = Hash::from_str("1FE9AB");
        assert_eq!(hv, hs);
    }
}

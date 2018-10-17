// mod.rs -- hashing with SHA3
//
// DM/Emotiq 10/18
// MIT License
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

use sha3::{Digest, Sha3_256};
use std::fmt;
use std::mem;
use std::slice;
use utils::*;

// -----------------------------------------------------
// Hashing with SHA3

pub const HASH_SIZE: usize = 32;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn bits(self) -> [u8; 32] {
        self.0
    }

    pub fn from_vector(msg: &[u8]) -> Hash {
        hash(msg)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str());
        Ok(())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn hash(msg: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    let out = hasher.result();
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&out[..HASH_SIZE]);
    Hash(h)
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
        let mut hasher = Sha3_256::new();
        hasher.input(inp);
        let out = hasher.result();
        let end = if ct > HASH_SIZE { HASH_SIZE } else { ct };
        for ix in 0..end {
            ans[jx + ix] = out[ix];
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
}

/// A hashable type.
///
/// Types implementing Hashable are able to be hashed.
///
pub trait Hashable {
    /// Feeds this value into Hasher.
    fn hash(&self, state: &mut Hasher);
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

impl Hashable for [u8] {
    fn hash(&self, state: &mut Hasher) {
        let newlen = self.len() * mem::size_of::<u8>();
        let ptr = self.as_ptr() as *const u8;
        state.input(unsafe { slice::from_raw_parts(ptr, newlen) })
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

        let mut hasher = Hasher::new();
        d.hash(&mut hasher);
        let h2: Hash = hasher.result();

        // Test that manually hashed result matches Hashable for Data implementation.
        assert!(h1 == h2);
    }
}

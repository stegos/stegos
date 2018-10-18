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

extern crate generic_array;
extern crate gmp;
extern crate hex;
extern crate rand;
extern crate rust_libpbc;
extern crate sha3;

pub mod curve1174;
pub mod hash;
pub mod pbc;
pub mod utils;
use hash::{Hashable, Hasher};
use std::fmt;
use utils::u8v_to_hexstr;

/// Stub for Bullet Proof
// TODO: define
#[derive(Clone)]
pub struct BulletProof([u8; 4096]);

impl fmt::Debug for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u8v_to_hexstr(&self.0))
    }
}

impl fmt::Display for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Hashable for BulletProof {
    fn hash(&self, state: &mut Hasher) {
        self.0[..].hash(state)
    }
}

impl BulletProof {
    /// Returns some garbage.
    /// Use only for tests.
    pub fn garbage() -> BulletProof {
        BulletProof([0 as u8; 4096])
    }
}
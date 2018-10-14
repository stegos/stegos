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
use utils::*;

// -----------------------------------------------------
// Hashing with SHA3

pub const HASH_SIZE : usize = 32;

#[derive(Copy, Clone)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn bits(self) -> [u8;32] {
        self.0
    }

    pub fn from_vector(msg : &[u8]) -> Hash {
        hash(msg)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

pub fn hash(msg : &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    let out = hasher.result();
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&out[.. HASH_SIZE]);
    Hash(h)
}

pub fn hash_nbytes(nb : usize, msg : &[u8]) -> Vec<u8> {
    let nmsg = msg.len();
    let mut ct = nb;
    let mut ans = vec![0u8; nb];
    let mut jx = 0;
    let mut kx = 0u8;
    while ct > 0 {
        let mut inp = vec![kx];
        for ix in 0 .. nmsg {
            inp.push(msg[ix]);
        }
        let mut hasher = Sha3_256::new();
        hasher.input(inp);
        let out = hasher.result();
        let end = if ct > HASH_SIZE {
                    HASH_SIZE
                } else {
                    ct
                };
        for ix in 0 .. end {
            ans[jx + ix] = out[ix];
        }
        jx += end;
        ct -= end;
        kx += 1;
    }
    ans
}




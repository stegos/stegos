//! VDF Helpers.

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

#![allow(unused_imports)]

use crate::hash::Hash;

use vdf_field::{Field, Fv, FvRepr, PrimeField, PrimeFieldRepr};

// -----------------------------------------------

fn bytes_to_fvrep(bytes: &[u8]) -> FvRepr {
    let mut fvr = [0u64; 4];
    let mut len = bytes.len();
    if len > 32 {
        len = 32;
    }
    for ix in 0..len {
        let wrdpos = ix >> 3;
        let bytpos = (ix & 7) << 3;
        fvr[wrdpos] |= (bytes[ix] as u64) << bytpos;
    }
    FvRepr(fvr)
}

fn checked_bytes_to_fv(bytes: &[u8]) -> Fv {
    // checked - takes arbitrary challenge bytes
    // and ensures within field domain
    let mut rep = bytes_to_fvrep(bytes);
    let modrep = Fv::char();
    while rep >= modrep {
        rep.shr(1);
    }
    Fv::from_repr(rep).unwrap()
}

fn unchecked_bytes_to_fv(bytes: &[u8]) -> Fv {
    // unchecked - expects a valid field value in little-endian byte form
    // should only be called on items produced by fv_to_bytes()
    let rep = bytes_to_fvrep(bytes);
    Fv::from_repr(rep).unwrap()
}

fn fv_to_bytes(fv: Fv) -> [u8; 32] {
    let fvr = fv.into_repr();
    let mut bytes = [0u8; 32];
    let mut ix = 0;
    for wrd in 0..4 {
        let x = fvr.0[wrd];
        for byt in 0..8 {
            bytes[ix] = (x >> (byt << 3)) as u8;
            ix += 1;
        }
    }
    bytes
}

// --------------------------------------------------------------

/// Conventional wrapper around Sqrt VDF which supports difficulty = 0.
#[derive(Debug, Copy, Clone)]
pub struct VDF {
    qp1d4: FvRepr,
    one: Fv,
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidVDFProof();

#[derive(Debug, Copy, Clone)]
pub struct InvalidIterations(); // just here for backward compatibility - never happens

impl VDF {
    pub fn new() -> VDF {
        let rep1 = FvRepr([1, 0, 0, 0]);
        // compute (q + 1)/4 for pseudo-sqrt power
        let mut modrep = Fv::char();
        assert!(3 == (modrep.0[0] & 3)); // need q = 3 mod 4
        modrep.add_nocarry(&rep1);
        modrep.shr(2);
        VDF {
            qp1d4: modrep,
            one: Fv::from_repr(rep1).unwrap(),
        }
    }

    // --- internal routines ----

    fn xor1(&self, fv: &mut Fv) {
        // Field val XOR 1
        let rep = fv.into_repr();
        if rep.is_odd() {
            fv.sub_assign(&self.one);
        } else {
            fv.add_assign(&self.one);
        }
    }

    fn g(&self, x: Fv) -> Fv {
        // the slow prover function
        // iterated square roots with XOR fenceposts
        let mut ans = x.pow(self.qp1d4);
        self.xor1(&mut ans);
        ans
    }

    fn h(&self, x: &mut Fv) {
        // the fast validator function
        // iterated squaring with XOR fenceposts
        self.xor1(x);
        x.square();
    }

    // --- API ---

    pub fn solve(&self, challenge: &[u8], difficulty: u64) -> Result<Vec<u8>, InvalidIterations> {
        // note for future client rewrite - this never returns any errors
        if difficulty != 0 {
            let mut x = checked_bytes_to_fv(challenge);
            for _ in 0..difficulty {
                x = self.g(x);
            }
            let bytes = fv_to_bytes(x);
            return Ok(bytes.to_vec());
        }
        // Use mocked version for difficulty == 0.
        Ok(Hash::digest(&challenge).to_bytes()[..].to_vec())
    }

    pub fn check_difficulty(&self, _difficulty: u64) -> Result<(), InvalidIterations> {
        // note for future client rewrite - this never returns any errors
        Ok(())
    }

    pub fn verify(
        &self,
        challenge: &[u8],
        difficulty: u64,
        alleged_solution: &[u8],
    ) -> Result<(), InvalidVDFProof> {
        if difficulty != 0 {
            let mut x = unchecked_bytes_to_fv(alleged_solution);
            for _ in 0..difficulty {
                self.h(&mut x);
            }
            x.square();
            let mut ans = checked_bytes_to_fv(challenge);
            ans.square();
            if ans == x {
                return Ok(());
            } else {
                return Err(InvalidVDFProof());
            }
        }
        // Use mocked version for difficulty == 0.
        let solution = Hash::digest(&challenge).to_bytes()[..].to_vec();
        if &alleged_solution[..] == &solution[..] {
            return Ok(());
        }
        return Err(InvalidVDFProof());
    }
}

// --------------------------------------------------------------

#[test]
fn test_fv() {
    use std::time::{Duration, SystemTime};
    let vdf = VDF::new();
    let mult = 50000;
    for ix in 0..11 {
        let challenge = Hash::random().to_bytes();
        let difficulty = ix * mult;
        let start = SystemTime::now();
        let ans = vdf.solve(&challenge, difficulty).unwrap();
        let timing = start.elapsed().unwrap();
        println!("Solve {} = {:?}", difficulty, timing);

        let start = SystemTime::now();
        assert!(vdf.verify(&challenge, difficulty, &ans).is_ok());
        let timing = start.elapsed().unwrap();
        println!("Verify {} = {:?}", difficulty, timing);
    }
}

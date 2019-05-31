//! Hashcash.

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

/// --------------------------------------------------------------------------
/// Provide iterated hash puzzle to provide for median-predictable delays, sans parallelism.
///
/// Puzzle is, given some seed string, and an incrementing counter, perform the hash
/// of the seend and counter until some specified number of bits in the resulting hash
/// value are zero, in some specific location inside the hash value.
///
/// Since the location can be arbitrary, we settle for the leading bits in the
/// hash byte stream.
///
/// Implied delay has a median proportional to 2^N for N-bits of zeros
/// --------------------------------------------------------------------------
use crate::hash::*;

#[derive(Clone, Debug, PartialEq)]
pub struct HashCashProof {
    pub nbits: usize,
    pub seed: Vec<u8>,
    pub count: i64,
}

fn trial(seed: &Vec<u8>, ctr: i64) -> Hash {
    let mut state = Hasher::new();
    seed.hash(&mut state);
    ctr.hash(&mut state);
    state.result()
}

pub fn chkbits(h: &[u8], nbits: usize) -> bool {
    for i in 0..nbits {
        let byte = i / 8;
        let bit = i % 8;
        if 0 != (h[byte] & (1 << bit)) {
            return false;
        }
    }
    true
}

pub fn delay(nbits: usize, seed: &Vec<u8>) -> HashCashProof {
    // user should check:
    //   1. does proof indicate intended number of bits?
    //   2. does H(seed | ctr) have the requisite number of zero bits?
    let mut ctr = 0;
    loop {
        let h = trial(seed, ctr);
        if chkbits(h.base_vector(), nbits) {
            return HashCashProof {
                nbits,
                seed: seed.clone(),
                count: ctr,
            };
        }
        ctr += 1;
    }
}

pub fn check_proof(proof: &HashCashProof, nbits: usize) -> bool {
    // Proof is provided by challenged node
    // nbits is our expected puzzle size
    // verify that proof is for nbits, and that
    // H(seed | ctr) has nbits of leading zero bits
    if nbits != proof.nbits {
        return false;
    }
    let h = trial(&proof.seed, proof.count);
    chkbits(&h.base_vector(), proof.nbits)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;
    use std::time::{Duration, SystemTime};

    #[test]
    #[ignore]
    fn test_delay() {
        let nbmax = 20;
        let mut tbl = Vec::<(usize, Duration)>::new();
        for nb in 1..=nbmax {
            let mut ans = Vec::<Duration>::new();
            let mut rng: ThreadRng = thread_rng();
            for _ in 0..3 {
                let seed = rng.gen::<[u8; 32]>();
                let start = SystemTime::now();
                delay(nb, &seed.to_vec());
                let timing = start.elapsed().expect("timing");
                ans.push(timing);
            }
            ans.sort();
            tbl.push((nb, ans[1]));
            println!("Delay for {} bits: {:?}", nb, ans[1]);
        }
        dbg!(&tbl);
    }

    #[test]
    fn test_delay_check() {
        let mut rng: ThreadRng = thread_rng();
        let nb = 10;
        for _ in 0..100 {
            let seed = rng.gen::<[u8; 32]>();
            let proof = delay(nb, &seed.to_vec());
            assert!(false == check_proof(&proof, nb + 1));
            assert!(true == check_proof(&proof, nb));
        }
    }
}

// bruteforce.rs - timing tests on brute force ECDLP
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

//! ----------------------------------------------------------------------------
//! A proposal to use ElGamal encryption of amounts in UTXOs would require
//! recipients to perform brute force recovery of amounts. Let's examine
//! how quickly we could achieve this in our Rust implementation of ECC.
//! -----------------------------------------------------------------------------

#![allow(non_snake_case)]
#![allow(unused)]

use rand::rngs::ThreadRng;
use rand::thread_rng;
use rand::Rng;
use std::time::{Duration, SystemTime};
use stegos_crypto::bulletproofs::*;
use stegos_crypto::hash::*;
use stegos_crypto::keying::*;
use stegos_crypto::scc::*;

// -------------------------------------------------------------------------------
fn main() {
    let x = 0x1_0000_000u64;
    let cmt = simple_commit(&Fr::zero(), &Fr::from(x));
    println!("incr = {:?}", cmt);
    let minv = -0x8000_0000_0000_0000i128;
    let maxv = 0x7fff_ffff_ffff_ffffi128;
    let mut sum = simple_commit(&Fr::zero(), &Fr::zero());
    let incr = simple_commit(&Fr::zero(), &Fr::one());
    println!("incr = {:?}", incr);
    let mut ct = 0u32;
    let start = SystemTime::now();
    for _ in 0..maxv + 1 {
        if sum == cmt {
            break;
        }
        sum += incr;
        ct += 1;
    }
    let timing = start.elapsed().unwrap();
    println!("Duration = {:?}", timing);
    println!("Iterations = {}", ct);
    println!("Per Iter = {:?}", timing / ct);
}

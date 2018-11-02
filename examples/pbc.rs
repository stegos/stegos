//! Test PBC Crypto for Rust, atop Ben Lynn's PBCliib

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

extern crate rust_libpbc;
extern crate stegos_crypto;

use stegos_crypto::pbc::*;

extern crate hex;

// ------------------------------------------------------------------------

fn main() {
    let pt = fast::G1::generator() * fast::Zr::zero();
    println!("pt = {}", pt);
    // ------------------------------------------------------------
    // on Secure pairings
    // test PRNG
    println!("rand Zr = {}", secure::Zr::random());

    // test keying...
    let (skey, pkey, sig) = secure::make_deterministic_keys(b"Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(secure::check_keying(&pkey, &sig));
    println!("");

    // -------------------------------------
    // on Fast pairings
    // test PRNG
    println!("rand Zr = {}", fast::Zr::random());

    // test keying...
    let (skey, pkey, sig) = fast::make_deterministic_keys(b"Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(fast::check_keying(&pkey, &sig));

    // -------------------------------------
    // check some arithmetic on the Fast curves
    let a = 0x123456789i64;
    println!("chk Zr: 0x{:x} -> {}", a, fast::Zr::from(a));
    println!("chk Zr: -1 -> {}", fast::Zr::from(-1));
    println!("chk Zr: -1 + 1 -> {}", fast::Zr::from(-1) + 1);
}

// Test PBC Crypto for Rust, atop Ben Lynn's PBCliib
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

// -------------------------------------------------------------------
extern crate stegos_crypto;
extern crate rust_libpbc;

use stegos_crypto::pbc::*;

use std::sync::Mutex;

fn main() {

    // ------------------------------------------------------------------------
    // check connection to PBC library
    println!("Hello, world!");
    let input = "hello!".as_bytes();
    let output = vec![0u8; input.len()];
    unsafe {
        let echo_out = rust_libpbc::echo(
            input.len() as u64,
            input.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        );
        assert_eq!(echo_out, input.len() as u64);
        assert_eq!(input.to_vec(), output);
    }
    let out_str: String = std::str::from_utf8(&output).unwrap().to_string();
    println!("Echo Output: {}", out_str);
    println!("");

    // ------------------------------------------------------------
    // init PBC library -- must only be performed once
    let init = Mutex::new(false);
    {
        let mut done = init.lock().unwrap();
        if ! *done {
            *done = true;
            init_pairings();
        }
    }

    // test hashing
    let h = Hash::from_vector(b"");
    println!("hash(\"\") = {}", h.to_str());
    assert_eq!(h.to_str(), "H(a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a)");
    println!("");

    // -------------------------------------
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
    println!("chk Zr: 0x{:x} -> {}", a, fast::Zr::from_int(a));
    println!("chk Zr: -1 -> {}", fast::Zr::from_int(-1));
    println!("chk Zr: -1 + 1 -> {}", fast::Zr::from(-1) + 1);

    // -------------------------------------------
    let h = hash_nbytes(10, b"Testing");
    println!("h = {}", u8v_to_hexstr(&h));
    let h = hash_nbytes(64, b"Testing");
    println!("h = {}", u8v_to_hexstr(&h));
}

//! Test PBC Crypto for Rust, atop Ben Lynn's PBCliib

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

use stegos_crypto::hash::*;
use stegos_crypto::pbc;

// ------------------------------------------------------------------------

fn main() {
    // ------------------------------------------------------------
    // on Secure pairings
    // test PRNG
    // println!("rand Zr = {}", pbc::Zr::random().to_hex());

    // test keying...
    let (skey, pkey) = pbc::make_deterministic_keys(b"Testing");
    pbc::check_keying(&skey, &pkey).unwrap();
    println!();

    // -----------------------------------------
    let (skey, pkey) = pbc::make_deterministic_keys(b"Testing");
    pbc::check_keying(&skey, &pkey).unwrap();
    let hseed = Hash::from_str("VRF_Seed");
    let vrf = pbc::make_VRF(&skey, &hseed);
    println!("VRF Rand: {:?}", vrf.rand);
    println!("VRF Proof: {:?}", vrf.proof);
    assert!(pbc::validate_VRF_randomness(&vrf).is_ok());
    assert!(pbc::validate_VRF_source(&vrf, &pkey, &hseed).is_ok());
}

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

#![cfg_attr(test, feature(test))]
use stegos_blockchain::election;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;
extern crate test;
use test::Bencher;

#[bench]
fn hash_prng_1000(b: &mut Bencher) {
    let random = Hash::digest("bla");
    b.iter(|| {
        for i in 0..1000u32 {
            let mut hasher = Hasher::new();
            random.hash(&mut hasher);
            i.hash(&mut hasher);
            test::black_box(hasher.result());
        }
    });
}

#[bench]
fn select_1000_slots_out_of_16(b: &mut Bencher) {
    const SLOTS_COUNT: i64 = 1000;
    const GROUP_SIZE: usize = 16;
    const STAKE: i64 = 100_000;

    let random = Hash::digest("bla");
    let (skey, _pkey) = pbc::make_random_keys();

    let random = pbc::make_VRF(&skey, &random);

    let mut stakers = Vec::new();
    for _ in 0..GROUP_SIZE {
        let (_, pkey) = pbc::make_random_keys();
        stakers.push((pkey, STAKE));
    }

    b.iter(|| {
        test::black_box(election::select_validators_slots(
            test::black_box(stakers.clone()),
            random,
            SLOTS_COUNT,
        ));
    });
}

#[bench]
fn create_vrf(b: &mut Bencher) {
    let random = Hash::digest("bla");
    let (skey, _pkey) = pbc::make_random_keys();

    b.iter(|| {
        test::black_box(pbc::make_VRF(&skey, &random));
    });
}

#[bench]
fn verify_vrf(b: &mut Bencher) {
    let random = Hash::digest("bla");
    let (skey, pkey) = pbc::make_random_keys();
    let vrf = pbc::make_VRF(&skey, &random);

    b.iter(|| {
        test::black_box(pbc::validate_VRF_source(&vrf, &pkey, &random).unwrap());
    });
}

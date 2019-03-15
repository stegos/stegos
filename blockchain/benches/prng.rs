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
use rand::{Rng, SeedableRng};
use rand_isaac::IsaacRng;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
extern crate test;
use test::Bencher;

#[bench]
fn isaac_prng(b: &mut Bencher) {
    let random = Hash::digest("bla");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(random.base_vector());
    let mut rng = IsaacRng::from_seed(seed);
    b.iter(|| {
        for _ in 0..100 {
            test::black_box(rng.gen::<i64>());
        }
    });
}

#[bench]
fn hash_prng(b: &mut Bencher) {
    let random = Hash::digest("bla");
    b.iter(|| {
        for i in 0..100u32 {
            let mut hasher = Hasher::new();
            random.hash(&mut hasher);
            i.hash(&mut hasher);
            test::black_box(hasher.result());
        }
    });
}

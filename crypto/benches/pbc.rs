//! PBC Benchmark.

//
// MIT License
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

#![feature(test)]

use criterion::{black_box as bb, criterion_group, criterion_main, Bencher, Criterion};
use simple_logger;
use std::time::Duration;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

fn create_signature(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, _pkey) = pbc::make_random_keys();
            let hash = Hash::digest("test");
            (hash, skey)
        },
        |(hash, skey)| {
            pbc::sign_hash(bb(&hash), bb(&skey));
        },
    );
}

fn validate_signature(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, pkey) = pbc::make_random_keys();
            let hash = Hash::digest("test");
            let signature = pbc::sign_hash(&hash, &skey);
            (hash, signature, pkey)
        },
        |(hash, signature, pkey)| {
            pbc::check_hash(bb(&hash), bb(&signature), bb(&pkey)).unwrap();
        },
    );
}

fn signature_benchmark(c: &mut Criterion) {
    c.bench_function("pbc::create_bls_signature", create_signature);
    c.bench_function("pbc::validate_bls_signature", validate_signature);
}

fn create_vrf(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, _pkey) = pbc::make_random_keys();
            let seed = Hash::digest("test");
            (seed, skey)
        },
        |(seed, skey)| {
            pbc::make_VRF(bb(&skey), bb(&seed));
        },
    );
}

fn validate_vrf(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

    b.iter_with_setup(
        || {
            let (skey, pkey) = pbc::make_random_keys();
            let seed = Hash::digest("test");
            let random = pbc::make_VRF(&skey, &seed);
            (seed, random, pkey)
        },
        |(seed, vrf, pkey)| pbc::validate_VRF_source(bb(&vrf), bb(&pkey), bb(&seed)),
    );
}

fn vrf_benchmark(c: &mut Criterion) {
    c.bench_function("pbc::create_vrf", create_vrf);
    c.bench_function("pbc::validate_vrf", validate_vrf);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(3)).sample_size(100);
     targets = signature_benchmark, vrf_benchmark
}

criterion_main!(benches);

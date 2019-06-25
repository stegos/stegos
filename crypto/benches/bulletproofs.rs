//! Bulletproofs Benchmark.

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
use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use rand::Rng;
use simple_logger;
use std::time::Duration;
use stegos_crypto::bulletproofs;

fn create_bulletproof(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let mut rng = rand::thread_rng();

    b.iter_with_setup(
        || {
            let amount = rng.gen::<i64>();
            let amount = if amount >= 0 { amount } else { -amount };
            amount
        },
        |amount| {
            bulletproofs::make_range_proof(amount);
        },
    );
}

fn validate_bulletproof(b: &mut Bencher) {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let mut rng = rand::thread_rng();

    b.iter_with_setup(
        || {
            let amount = rng.gen::<i64>();
            let amount = if amount >= 0 { amount } else { -amount };
            let (bp, _gamma) = bulletproofs::make_range_proof(amount);
            bp
        },
        |bp| bulletproofs::validate_range_proof(&bp),
    );
}

fn bulletproof_benchmark(c: &mut Criterion) {
    c.bench_function("bulletproofs::create", create_bulletproof);
    c.bench_function("bulletproofs::validate", validate_bulletproof);
}

criterion_group! {
     name = benches;
     config = Criterion::default().measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(3)).sample_size(10);
     targets = bulletproof_benchmark
}

criterion_main!(benches);

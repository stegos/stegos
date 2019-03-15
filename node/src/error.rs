//! Node - Errors.

//
// MIT License
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

use failure::Fail;
use stegos_crypto::hash::Hash;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum NodeError {
    #[fail(display = "Fee is to low: min={}, got={}", _0, _1)]
    TooLowFee(i64, i64),
    #[fail(
        display = "Invalid block reward: hash={}, expected={}, got={}",
        _0, _1, _2
    )]
    InvalidBlockReward(Hash, i64, i64),
    #[fail(display = "Transaction already exists in mempool: {}.", _0)]
    TransactionAlreadyExists(Hash),
    #[fail(display = "Expected a key block, got monetary block: height={}.", _0)]
    ExpectedKeyBlock(u64),
    //#[fail(display = "Expected a monetary block, got key block: height={}.", _0)]
    //ExpectedMonetaryBlock(u64),
    #[fail(
        display = "Found a block proposal with timestamp: {} that differ with our timestamp: {}.",
        _0, _1
    )]
    UnsynchronizedBlock(u64, u64),
}

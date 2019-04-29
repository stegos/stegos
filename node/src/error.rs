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
use std::time::SystemTime;
use stegos_crypto::hash::Hash;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum TransactionError {
    #[fail(display = "Invalid signature: tx={}", _0)]
    InvalidSignature(Hash),
    #[fail(display = "Invalid monetary balance: tx={}", _0)]
    InvalidMonetaryBalance(Hash),
    #[fail(display = "Negative fee: tx={}", _0)]
    NegativeFee(Hash),
    #[fail(display = "No inputs: tx={}", _0)]
    NoInputs(Hash),
    #[fail(display = "Duplicate input: tx={}, utxo={}", _0, _1)]
    DuplicateInput(Hash, Hash),
    #[fail(display = "Duplicate output: tx={}, utxo={}", _0, _1)]
    DuplicateOutput(Hash, Hash),
    #[fail(
        display = "Transaction fee is too low: tx={}, min={}, got={}",
        _0, _1, _2
    )]
    TooLowFee(Hash, i64, i64),
    #[fail(display = "Transaction already exists in mempool: tx={}", _0)]
    AlreadyExists(Hash),
    #[fail(display = "Missing transaction input: tx={}, utxo={}", _0, _1)]
    MissingInput(Hash, Hash),
    #[fail(display = "Output hash collision: tx={}, utxo={}", _0, _1)]
    OutputHashCollision(Hash, Hash),
    #[fail(
        display = "Transaction is too large: tx={}, got_inout={}, max_inout={}",
        _0, _1, _2
    )]
    TooLarge(Hash, usize, usize),
    #[fail(display = "Can't process transaction - mempool is full: tx={}", _0)]
    MempoolIsFull(Hash),
}

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum NodeBlockError {
    #[fail(
        display = "Unexpected monetary adjustment: height={}, block={}, got={}, expected={}",
        _0, _1, _2, _3
    )]
    InvalidMonetaryAdjustment(u64, Hash, i64, i64),
    #[fail(
        display = "Expected a key block, got micro block: height={}, block={}",
        _0, _1
    )]
    ExpectedKeyBlock(u64, Hash),
    #[fail(
        display = "Expected a micro block, got key block: height={}, block={}",
        _0, _1
    )]
    ExpectedMicroBlock(u64, Hash),
    #[fail(
        display = "Timestamp is out of sync: height={}, block={}, block_timestamp={:?}, our_timestamp={:?}",
        _0, _1, _2, _3
    )]
    OutOfSyncTimestamp(u64, Hash, SystemTime, SystemTime),
    #[fail(
        display = "Proposed view_change different from ours: height={}, block={}, block_viewchange={}, our_viewchange={}",
        _0, _1, _2, _3
    )]
    OutOfSyncViewChange(u64, Hash, u32, u32),
    #[fail(
        display = "Found a outdated block proposal: block_time={:?} last_block_time={:?}.",
        _0, _1
    )]
    OutdatedBlock(SystemTime, SystemTime),
}

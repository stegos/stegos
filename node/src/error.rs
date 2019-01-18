//! Node - Errors.

//
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

use failure::Fail;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum NodeError {
    #[fail(display = "Fee is to low: min={}, got={}", _0, _1)]
    TooLowFee(i64, i64),
    #[fail(
        display = "Invalid block version: block={}, expected={}, got={}",
        _0, _1, _2
    )]
    InvalidBlockVersion(Hash, u64, u64),
    #[fail(
        display = "Invalid or out-of-order previous block: block={}, expected={}, got={}",
        _0, _1, _2
    )]
    OutOfOrderBlockHash(Hash, Hash, Hash),
    #[fail(
        display = "Invalid or out-of-order epoch: block={}, expected={}, got={}",
        _0, _1, _2
    )]
    OutOfOrderBlockEpoch(Hash, u64, u64),
    #[fail(display = "Block is already registered: hash={}", _0)]
    BlockAlreadyRegistered(Hash),
    #[fail(display = "Failed to validate block: expected={}, got={}", _0, _1)]
    InvalidBlockHash(Hash, Hash),
    #[fail(
        display = "Sealed Block from non-leader: block={}, expected={}, got={}",
        _0, _1, _2
    )]
    SealedBlockFromNonLeader(Hash, SecurePublicKey, SecurePublicKey),
    #[fail(display = "Invalid fee UTXO: hash={}", _0)]
    InvalidFeeUTXO(Hash),
    #[fail(display = "Invalid block BLS multisignature: block={}", _0)]
    InvalidBlockSignature(Hash),
    #[fail(display = "Transaction missing in mempool: {}.", _0)]
    TransactionMissingInMempool(Hash),
    #[fail(display = "Transaction already exists in mempool: {}.", _0)]
    TransactionAlreadyExists(Hash),
    #[fail(
        display = "Found a block proposal with timestamp: {} that differ with our timestamp: {}.",
        _0, _1
    )]
    UnsynchronizedBlock(u64, u64),
}

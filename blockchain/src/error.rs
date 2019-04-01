//! Blockchain Errors.

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
#[derive(Debug, Fail)]
pub enum MultisignatureError {
    #[fail(
        display = "Signature bitmap too big: len={}, validators_len={} ",
        _0, _1
    )]
    TooBigBitmap(usize, usize),
    #[fail(
        display = "Not enough votes in signature: votes={}, needed_votes={} ",
        _0, _1
    )]
    NotEnoughtVotes(i64, i64),
    #[fail(display = "Signature is not valid: hash={} ", _0)]
    InvalidSignature(Hash),
}
#[derive(Debug, Fail)]
pub enum BlockchainError {
    #[fail(
        display = "Previous hash mismatch: height={}, hash={}, expected_previous={}, got_previous={}.",
        _0, _1, _2, _3
    )]
    InvalidPreviousHash(u64, Hash, Hash, Hash),
    #[fail(display = "Block hash collision: height={}, hash={}.", _0, _1)]
    BlockHashCollision(u64, Hash),
    #[fail(display = "UXTO hash collision: {}.", _0)]
    OutputHashCollision(Hash),
    #[fail(
        display = "Out of order block: block={}, expected_height={}, got_height={}",
        _0, _1, _2
    )]
    OutOfOrderBlock(Hash, u64, u64),
    #[fail(display = "Missing UXTO {}.", _0)]
    MissingUTXO(Hash),
    #[fail(display = "Invalid block monetary balance.")]
    InvalidBlockBalance,
    #[fail(display = "Invalid block inputs: expected={}, got={}.", _0, _1)]
    InvalidBlockInputsHash(Hash, Hash),
    #[fail(display = "Invalid block outputs: expected={}, got={}.", _0, _1)]
    InvalidBlockOutputsHash(Hash, Hash),
    #[fail(display = "Duplicate block input: {}.", _0)]
    DuplicateBlockInput(Hash),
    #[fail(display = "Duplicate block output: {}.", _0)]
    DuplicateBlockOutput(Hash),
    #[fail(display = "The leader must be validator.")]
    LeaderIsNotValidator,
    #[fail(display = "No leader signature was found in BLS signature.")]
    NoLeaderSignatureFound,
    #[fail(
        display = "Found propose with more than one signature: height={}, hash={}.",
        _0, _1
    )]
    MoreThanOneSignatureAtPropose(u64, Hash),
    #[fail(
        display = "Invalid leader signature found: height={}, hash={}.",
        _0, _1
    )]
    InvalidLeaderSignature(u64, Hash),
    #[fail(
        display = "Invalid block BLS multisignature: height={}, hash={}, error={}",
        _1, _2, _0
    )]
    InvalidBlockSignature(MultisignatureError, u64, Hash),
    #[fail(
        display = "Invalid block version: height={}, hash={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidBlockVersion(u64, Hash, u64, u64),
    #[fail(
        display = "Received block with invalid random: height={}, hash={}",
        _0, _1
    )]
    IncorrectRandom(u64, Hash),
    #[fail(
        display = "Received block with wrong view_change: height={}, hash={}, our_view_change={}, block_view_change={}",
        _0, _1, _2, _3
    )]
    InvalidViewChange(u64, Hash, u32, u32),
}

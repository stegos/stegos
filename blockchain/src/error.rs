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
pub enum BlockchainError {
    #[fail(display = "Previous hash mismatch: expected={}, got={}.", _0, _1)]
    PreviousHashMismatch(Hash, Hash),
    #[fail(display = "Block hash collision: {}.", _0)]
    BlockHashCollision(Hash),
    #[fail(display = "UXTO hash collision: {}.", _0)]
    OutputHashCollision(Hash),
    #[fail(
        display = "Invalid or out-of-order epoch: block={}, expected={}, got={}",
        _0, _1, _2
    )]
    OutOfOrderBlockEpoch(Hash, u64, u64),
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
    #[fail(display = "Block must contain at least one validator.")]
    MissingValidators,
    #[fail(display = "The leader must be validator.")]
    LeaderIsNotValidator,
    #[fail(display = "KeyBlocks validators not equal to our stakers view.")]
    ValidatorsNotEqualToOurStakers,
    #[fail(display = "Invalid block BLS multisignature: block={}", _0)]
    InvalidBlockSignature(Hash),
}

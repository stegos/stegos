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
use stegos_blockchain::{BlockError, BlockchainError, StorageError};
use stegos_crypto::hash::Hash;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum NodeTransactionError {
    #[fail(display = "Invalid transaction type: tx={}", _0)]
    InvalidType(Hash),
    #[fail(
        display = "Transaction fee is too low: tx={}, min={}, got={}",
        _0, _1, _2
    )]
    TooLowFee(Hash, i64, i64),
    #[fail(display = "Transaction already exists in mempool: tx={}", _0)]
    AlreadyExists(Hash),
    #[fail(
        display = "Transaction is too large: tx={}, got_inputs={}, max_inputs={}",
        _0, _1, _2
    )]
    TooManyInputs(Hash, usize, usize),
    #[fail(
        display = "Transaction is too large: tx={}, got_outputs={}, max_outputs={}",
        _0, _1, _2
    )]
    TooManyOutputs(Hash, usize, usize),
    #[fail(display = "Can't process transaction - mempool is full: tx={}", _0)]
    MempoolIsFull(Hash),
    #[fail(
        display = "Can't process transaction - node is not synchronized: tx={}",
        _0
    )]
    NotSynchronized(Hash),
}

#[derive(Debug, Fail)]
pub enum ForkError {
    #[fail(display = "Our branch is more significant, drop this block.")]
    Canceled,
    #[fail(display = "We have found a error processing fork: error={}.", _0)]
    Error(failure::Error),
}

impl From<failure::Error> for ForkError {
    fn from(err: failure::Error) -> ForkError {
        ForkError::Error(err)
    }
}

impl From<BlockError> for ForkError {
    fn from(err: BlockError) -> ForkError {
        ForkError::Error(err.into())
    }
}

impl From<BlockchainError> for ForkError {
    fn from(err: BlockchainError) -> ForkError {
        ForkError::Error(err.into())
    }
}

impl From<StorageError> for ForkError {
    fn from(err: StorageError) -> ForkError {
        ForkError::Error(err.into())
    }
}

pub type ForkResult = Result<(), ForkError>;

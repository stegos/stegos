//! Wallet - Errors.

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
use stegos_crypto::scc;
#[allow(dead_code)]
#[derive(Debug, Fail, PartialEq, Eq)]
pub enum WalletError {
    #[fail(display = "Duplicate account: public key={}!", _0)]
    DuplicateAccount(scc::PublicKey),
    #[fail(display = "Not enough tokens!")]
    NotEnoughTokens,
    #[fail(display = "Too many inputs! Try sending a smaller amount.")]
    TooManyInputs,
    #[fail(display = "Negative amount {}!", _0)]
    NegativeAmount(i64),
    #[fail(
        display = "Amount {} should be greater than transaction fee {}!",
        _0, _1
    )]
    AmountTooSmall(i64, i64),
    /// Enough stake should be unlocked.
    #[fail(
        display = "{} tokens available out of {}. Not enough to stake!",
        _1, _0
    )]
    NoEnoughToStake(i64, i64),
    #[fail(display = "{} tokens available out of {}. Not enough to pay!", _1, _0)]
    NoEnoughToPay(i64, i64),
    #[fail(display = "{} tokens is not enough for a public payment!", _0)]
    NoEnoughToPayPublicly(i64),
    #[fail(display = "Incorrect TXIN type")]
    IncorrectTXINType,
    #[fail(display = "Snowball is busy")]
    SnowballBusy,
}

//! error.rs - ValueShuffle Errors.

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
//

use failure::Fail;

// Possible Error return codes

#[derive(Debug, Fail)]
pub enum VsError {
    #[fail(display = "Can't form SuperTransaction")]
    VsFail, // if can't achieve any result in ValueShuffle session
    #[fail(display = "Too many UTXOs proposed")]
    VsTooManyUTXO,
    #[fail(display = "Bad UTXO Encrypted Payload Keying")]
    VsBadUTXO, // UTXO has bad encryption keying on payload
    #[fail(display = "Bad TXIN Reference")]
    VsBadTXIN, // TXIN not accessible with provided ownership sig
    #[fail(display = "Bad Transaction Attempted")]
    VsBadTransaction, // user output plus fee not equal TXIN input
    #[fail(display = "We aren't a participant")]
    VsNotInParticipantList,
    #[fail(display = "ValueShuffle already started")]
    VsBusy,
    #[fail(display = "ValueShuffle not in session")]
    VsNotInSession,
    #[fail(display = "Invalid message")]
    VsInvalidMessage,
    #[fail(display = "Not enough participants: {}", _0)]
    VsTooFewParticipants(usize),
}

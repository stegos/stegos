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
pub enum QsError {
    #[fail(display = "Can't form SuperQuery")]
    QsFail, // if can't achieve any result in QueryShuffle session
    #[fail(display = "Too many Queries proposed")]
    QsTooManyUTXO,
    #[fail(display = "Bad Query")]
    QsBadQuery, // UTXO ID does not properly deserialize
    #[fail(display = "We aren't a participant")]
    QsNotInParticipantList,
    #[fail(display = "QueryShuffle already started")]
    QsBusy,
    #[fail(display = "QueryShuffle not in session")]
    QsNotInSession,
    #[fail(display = "Invalid message")]
    QsInvalidMessage,
    #[fail(display = "Not enough participants: {}", _0)]
    QsTooFewParticipants(usize),
}

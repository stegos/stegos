//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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
use std::io;
use stegos_crypto::pbc::secure;

mod behavior;
mod handler;
mod proto;
mod protocol;

pub use self::behavior::UnicastSend;

#[derive(Debug)]
pub enum UnicastOutEvent {
    Data(UnicastDataMessage),
    Success(secure::PublicKey),
    Error(Option<secure::PublicKey>, UnicastSendError),
}

#[derive(Debug)]
pub enum UnicastSendMessage {
    Data(UnicastDataMessage),
    Success(secure::PublicKey),
    Error(UnicastSendError),
}

/// Message passed to the protocol handler for delivery
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastDataMessage {
    /// Recepient public key
    pub to: secure::PublicKey,
    /// Sender's public key
    pub from: secure::PublicKey,
    /// Protocol Identifier
    pub protocol_id: String,
    /// Raw data to be delivered
    pub data: Vec<u8>,
}

#[derive(Debug, Fail)]
pub enum UnicastSendError {
    #[fail(display = "Unknown error sending data to node {}", _0)]
    UnknownError(secure::PublicKey),
    #[fail(display = "Handshake error. Bad challenge reveived.")]
    BadChallenge,
    #[fail(display = "Handshake error. No challenge received.")]
    NoChallenge,
    #[fail(display = "Protocol error. No data received.")]
    NoData,
    #[fail(display = "Bad signature received.")]
    BadSignature,
    #[fail(display = "Protocol error. Incorrect reply to challenge request")]
    BadChallengeReply,
    #[fail(display = "Substream IO error.")]
    SubstreamError(#[fail(cause)] io::Error),
    #[fail(display = "Dialout timeout")]
    DialoutTimeout,
}

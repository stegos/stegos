//! pBFT Consensus - Errors.

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
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

#[derive(Debug, Fail)]
pub enum ConsensusError {
    #[fail(display = "Unknown peer: pkey={}", _0)]
    UnknownMessagePeer(SecurePublicKey),
    #[fail(display = "Invalid message signature.")]
    InvalidMessageSignature,
    #[fail(
        display = "Invalid request hash: expected={}, got={}, pkey={}.",
        _0, _1, _2
    )]
    InvalidRequestHash(Hash, Hash, SecurePublicKey),
    #[fail(display = "Invalid message: state={} msg={}.", _0, _1)]
    InvalidMessage(&'static str, &'static str),
    #[fail(
        display = "Proposal from non-leader: request_hash={}, expected={}, got={}",
        _0, _1, _2
    )]
    ProposalFromNonLeader(Hash, SecurePublicKey, SecurePublicKey),
    #[fail(display = "Invalid BLS multisignature for request: request={}", _0)]
    InvalidRequestSignature(Hash),
}

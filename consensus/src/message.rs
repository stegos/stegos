//! pBFT Consensus - Network Messages.

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

use crate::error::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::check_hash as secure_check_hash;
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::SecretKey as SecureSecretKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

/// Consensus Message Payload.
#[derive(Clone, Debug)]
pub enum ConsensusMessageBody<Request, Proof> {
    /// Propose Message (preprepare).
    Proposal { request: Request, proof: Proof },
    /// Pre-vote Message (prepare).
    Prevote {},
    /// Pre-commit Message (commit).
    Precommit { request_hash_sig: SecureSignature },
}

impl<Request: Hashable, Proof: Hashable> Hashable for ConsensusMessageBody<Request, Proof> {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ConsensusMessageBody::Proposal { request, proof } => {
                "Propose".hash(state);
                request.hash(state);
                proof.hash(state);
            }
            ConsensusMessageBody::Prevote {} => {
                "Prevote".hash(state);
            }
            ConsensusMessageBody::Precommit { request_hash_sig } => {
                "Precommit".hash(state);
                request_hash_sig.hash(state);
            }
        }
    }
}

/// Consensus Message.
#[derive(Clone, Debug)]
pub struct ConsensusMessage<Request, Proof> {
    /// Current height.
    pub height: u64,
    /// Current epoch.
    pub epoch: u64,
    /// Hash of proposed request.
    pub request_hash: Hash,
    /// Message Body.
    pub body: ConsensusMessageBody<Request, Proof>,
    /// Sender of this message.
    pub pkey: SecurePublicKey,
    /// Signature of this message.
    pub sig: SecureSignature,
}

impl<Request, Proof> ConsensusMessage<Request, Proof> {
    pub fn name(&self) -> &'static str {
        match self.body {
            ConsensusMessageBody::Proposal { .. } => "Proposal",
            ConsensusMessageBody::Prevote { .. } => "Prevote",
            ConsensusMessageBody::Precommit { .. } => "Precommit",
        }
    }
}

impl<Request: Hashable, Proof: Hashable> ConsensusMessage<Request, Proof> {
    ///
    /// Create and sign a new consensus message.
    ///
    pub fn new(
        height: u64,
        epoch: u64,
        request_hash: Hash,
        skey: &SecureSecretKey,
        pkey: &SecurePublicKey,
        body: ConsensusMessageBody<Request, Proof>,
    ) -> ConsensusMessage<Request, Proof> {
        let mut hasher = Hasher::new();
        height.hash(&mut hasher);
        epoch.hash(&mut hasher);
        request_hash.hash(&mut hasher);
        body.hash(&mut hasher);
        let hash = hasher.result();
        let sig = secure_sign_hash(&hash, skey);
        ConsensusMessage {
            height,
            epoch,
            request_hash,
            body,
            pkey: pkey.clone(),
            sig,
        }
    }

    ///
    /// Validate signature of the message.
    ///
    pub fn validate(&self) -> Result<(), ConsensusError> {
        let mut hasher = Hasher::new();
        self.height.hash(&mut hasher);
        self.epoch.hash(&mut hasher);
        self.request_hash.hash(&mut hasher);
        self.body.hash(&mut hasher);
        let hash = hasher.result();
        if !secure_check_hash(&hash, &self.sig, &self.pkey) {
            return Err(ConsensusError::InvalidMessageSignature);
        }
        Ok(())
    }
}

/// Used by protobuf tests.
impl<Request: Hashable, Proof: Hashable> Hashable for ConsensusMessage<Request, Proof> {
    fn hash(&self, state: &mut Hasher) {
        self.height.hash(state);
        self.epoch.hash(state);
        self.request_hash.hash(state);
        self.body.hash(state);
        self.pkey.hash(state);
        self.sig.hash(state);
    }
}

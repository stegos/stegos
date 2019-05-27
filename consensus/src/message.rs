//! pBFT Consensus - Network Messages.

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

use crate::error::*;
use stegos_blockchain::{MacroBlockHeader, Transaction};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

#[derive(Clone, Debug)]
pub struct MacroBlockProposal {
    pub header: MacroBlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Hashable for MacroBlockProposal {
    fn hash(&self, state: &mut Hasher) {
        self.header.hash(state);
        let tx_count: u64 = self.transactions.len() as u64;
        tx_count.hash(state);
        for tx in &self.transactions {
            tx.fullhash(state);
        }
    }
}

/// Consensus Message Payload.
#[derive(Clone, Debug)]
pub enum ConsensusMessageBody {
    /// Propose Message (preprepare).
    Proposal(MacroBlockProposal),
    /// Pre-vote Message (prepare).
    Prevote,
    /// Pre-commit Message (commit).
    Precommit(pbc::Signature),
}

impl Hashable for ConsensusMessageBody {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ConsensusMessageBody::Proposal(proposal) => {
                "Propose".hash(state);
                proposal.hash(state);
            }
            ConsensusMessageBody::Prevote => {
                "Prevote".hash(state);
            }
            ConsensusMessageBody::Precommit(block_sig) => {
                "Precommit".hash(state);
                block_sig.hash(state);
            }
        }
    }
}

/// Consensus Message.
#[derive(Clone, Debug)]
pub struct ConsensusMessage {
    /// Current round.
    pub round: u32,
    /// Current height.
    pub height: u64,
    /// Hash of proposed request.
    pub block_hash: Hash,
    /// Message Body.
    pub body: ConsensusMessageBody,
    /// Sender of this message.
    pub pkey: pbc::PublicKey,
    /// Signature of this message.
    pub sig: pbc::Signature,
}

impl ConsensusMessage {
    pub fn name(&self) -> &'static str {
        match self.body {
            ConsensusMessageBody::Proposal { .. } => "Proposal",
            ConsensusMessageBody::Prevote { .. } => "Prevote",
            ConsensusMessageBody::Precommit { .. } => "Precommit",
        }
    }
}

impl ConsensusMessage {
    ///
    /// Create and sign a new consensus message.
    ///
    pub fn new(
        height: u64,
        round: u32,
        block_hash: Hash,
        skey: &pbc::SecretKey,
        pkey: &pbc::PublicKey,
        body: ConsensusMessageBody,
    ) -> ConsensusMessage {
        let mut hasher = Hasher::new();
        height.hash(&mut hasher);
        round.hash(&mut hasher);
        block_hash.hash(&mut hasher);
        body.hash(&mut hasher);
        let hash = hasher.result();
        let sig = pbc::sign_hash(&hash, skey);
        ConsensusMessage {
            height,
            round,
            block_hash,
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
        self.round.hash(&mut hasher);
        self.block_hash.hash(&mut hasher);
        self.body.hash(&mut hasher);
        let hash = hasher.result();
        if let Err(_e) = pbc::check_hash(&hash, &self.sig, &self.pkey) {
            return Err(ConsensusError::InvalidMessageSignature);
        }
        Ok(())
    }
}

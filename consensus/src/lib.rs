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

#![deny(warnings)]

mod error;

pub use crate::error::*;

use stegos_blockchain::*;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::check_hash as secure_check_hash;
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::SecretKey as SecureSecretKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

#[derive(Clone, Debug)]
pub struct MonetaryBlockProposal {
    pub txs: Vec<Transaction>,
    pub fee_output: Option<Output>,
    pub block_hash: Hash,
    pub block_header: MonetaryBlockHeader,
}

#[derive(Clone, Debug)]
pub enum ConsensusMessageBody {
    MonetaryBlockProposal(MonetaryBlockProposal),
}

#[derive(Clone, Debug)]
pub struct ConsensusMessage {
    /// Message Body.
    pub body: ConsensusMessageBody,
    /// Secure Public Key used to sign this message.
    pub pkey: SecurePublicKey,
    /// Secure Signature.
    pub sig: SecureSignature,
}

impl Hashable for MonetaryBlockProposal {
    fn hash(&self, state: &mut Hasher) {
        // Sign transactions.
        let txs_count: u64 = self.txs.len() as u64;
        txs_count.hash(state);
        for tx in &self.txs {
            tx.hash(state);
        }

        self.fee_output.hash(state);
        self.block_hash.hash(state);
        self.block_header.hash(state);
    }
}

impl Hashable for ConsensusMessageBody {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ConsensusMessageBody::MonetaryBlockProposal(message) => message.hash(state),
        }
    }
}

impl ConsensusMessage {
    pub fn new_block_proposal(
        skey: &SecureSecretKey,
        pkey: &SecurePublicKey,
        txs: Vec<Transaction>,
        fee_output: Option<Output>,
        block_hash: Hash,
        block_header: MonetaryBlockHeader,
    ) -> ConsensusMessage {
        let body = MonetaryBlockProposal {
            txs,
            fee_output,
            block_hash,
            block_header,
        };
        let hash = Hash::digest(&body);
        let sig = secure_sign_hash(&hash, skey);
        ConsensusMessage {
            body: ConsensusMessageBody::MonetaryBlockProposal(body),
            pkey: pkey.clone(),
            sig,
        }
    }

    ///
    /// Validate signature.
    ///
    pub fn validate(&self) -> Result<(), ConsensusError> {
        let hash = Hash::digest(&self.body);
        if !secure_check_hash(&hash, &self.sig, &self.pkey) {
            return Err(ConsensusError::InvalidMessageSignature);
        }
        Ok(())
    }
}

impl Hashable for ConsensusMessage {
    fn hash(&self, state: &mut Hasher) {
        self.body.hash(state);
        self.sig.hash(state);
    }
}

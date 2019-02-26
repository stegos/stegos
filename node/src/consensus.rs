//! Consensus Integration.

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

use stegos_blockchain::*;

use stegos_consensus::ConsensusError;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;

/// Sealed Block with multi-signature.
#[derive(Clone, Debug)]
pub struct SealedBlockMessage {
    /// Block.
    pub block: Block,
    /// Secure Public Key used to sign this message.
    pub pkey: secure::PublicKey,
    /// Secure Signature.
    pub sig: secure::Signature,
}

impl SealedBlockMessage {
    ///
    /// Create and sign a new SealedBlock message.
    ///
    pub fn new(skey: &secure::SecretKey, pkey: &secure::PublicKey, block: Block) -> Self {
        let hash = Hasher::digest(&block);
        let sig = secure::sign_hash(&hash, skey);
        Self {
            block,
            pkey: pkey.clone(),
            sig,
        }
    }

    ///
    /// Validate signature.
    ///
    pub fn validate(&self) -> Result<(), ConsensusError> {
        let hash = Hash::digest(&self.block);
        if !secure::check_hash(&hash, &self.sig, &self.pkey) {
            return Err(ConsensusError::InvalidMessageSignature);
        }
        Ok(())
    }
}

/// Used by protobuf tests.
impl Hashable for SealedBlockMessage {
    fn hash(&self, state: &mut Hasher) {
        self.block.hash(state);
        self.pkey.hash(state);
        self.sig.hash(state);
    }
}

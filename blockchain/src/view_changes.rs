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

use crate::blockchain::{Blockchain, ChainInfo};
use crate::error::MultisignatureError;
use crate::multisignature::{check_multi_signature, create_multi_signature_index};
use bitvector::BitVector;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc;

#[derive(Clone, Debug, PartialEq)]
pub struct ViewChangeProof {
    pub multimap: BitVector,
    pub multisig: pbc::Signature,
}

impl ViewChangeProof {
    pub fn new<'a, I>(signatures: I) -> Self
    where
        I: Iterator<Item = (u32, &'a pbc::Signature)>,
    {
        let (multisig, multimap) = create_multi_signature_index(signatures);
        ViewChangeProof { multisig, multimap }
    }
    pub fn validate(
        &self,
        chain_info: &ChainInfo,
        blockchain: &Blockchain,
    ) -> Result<(), MultisignatureError> {
        let hash = Hash::digest(chain_info);

        check_multi_signature(
            &hash,
            &self.multisig,
            &self.multimap,
            blockchain.validators(),
            blockchain.total_slots(),
        )?;
        Ok(())
    }
}

impl Hashable for ViewChangeProof {
    fn hash(&self, state: &mut Hasher) {
        // bitmap is only used to determine whom are signers,
        // so we can skip it in hash, and use only multisig part
        self.multisig.hash(state);
    }
}

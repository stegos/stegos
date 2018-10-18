//! Transaction Input.

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

use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::Signature;

/// Transaction Input.
#[derive(Debug, Clone)]
pub struct Input {
    /// Identifier of an unspent transaction output.
    pub source_id: Hash,
    /// Signature used to sign transactions.
    pub signature: Signature,
}

impl Input {
    /// Constructor for Input.
    pub fn new(source_id: Hash, signature: Signature) -> Input {
        Input {
            source_id: source_id,
            signature: signature,
        }
    }
}

impl Hashable for Input {
    fn hash(&self, state: &mut Hasher) {
        self.source_id.hash(state);
        self.signature.hash(state);
    }
}

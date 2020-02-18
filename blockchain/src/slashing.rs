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

use crate::MicroBlock;
use serde_derive::{Deserialize, Serialize};
use stegos_crypto::hash::{Hashable, Hasher};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingProof {
    pub block1: MicroBlock,
    pub block2: MicroBlock,
}

impl SlashingProof {
    pub fn new_unchecked(block1: MicroBlock, block2: MicroBlock) -> SlashingProof {
        let proof = SlashingProof { block1, block2 };
        proof
    }
}

impl Hashable for SlashingProof {
    fn hash(&self, state: &mut Hasher) {
        self.block1.hash(state);
        self.block2.hash(state);
    }
}

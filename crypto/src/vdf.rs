//! VDF Helpers.

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

use crate::hash::Hash;
pub use vdf::{InvalidIterations, InvalidProof};
use vdf::{VDFParams, WesolowskiVDF, WesolowskiVDFParams, VDF as VDFTrait};

/// Conventional wrapper around WesolowskiVDF which supports difficulty = 0.
#[derive(Debug, Clone)]
pub struct VDF(WesolowskiVDF);

impl VDF {
    pub fn new() -> VDF {
        VDF(WesolowskiVDFParams(2048).new())
    }

    pub fn solve(&self, challenge: &[u8], difficulty: u64) -> Result<Vec<u8>, InvalidIterations> {
        if difficulty != 0 {
            return self.0.solve(challenge, difficulty);
        }
        // Use mocked version for difficulty == 0.
        Ok(Hash::digest(&challenge).to_bytes()[..].to_vec())
    }

    pub fn check_difficulty(&self, difficulty: u64) -> Result<(), InvalidIterations> {
        if difficulty != 0 {
            self.0.check_difficulty(difficulty)
        } else {
            Ok(())
        }
    }

    pub fn verify(
        &self,
        challenge: &[u8],
        difficulty: u64,
        alleged_solution: &[u8],
    ) -> Result<(), InvalidProof> {
        if difficulty != 0 {
            return self.0.verify(challenge, difficulty, alleged_solution);
        }
        // Use mocked version for difficulty == 0.
        let solution = Hash::digest(&challenge).to_bytes()[..].to_vec();
        if &alleged_solution[..] == &solution[..] {
            return Ok(());
        }
        return Err(InvalidProof);
    }
}

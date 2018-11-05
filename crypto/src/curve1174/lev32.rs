//! lev32.rs - 32-byte little-endian vectors

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

use super::*;

// -----------------------------------------------------------------
// type Lev32 represents a 256-bit bignum as a little-endian 32-byte vector

#[derive(Copy, Clone)]
pub struct Lev32(pub [u8; 32]);

impl Lev32 {
    pub fn to_lev_u64(self) -> [u64; 4] {
        let mut ans = [0u64; 4];
        ans[0] = (self.0[0] as u64)
            | (self.0[1] as u64) << 8
            | (self.0[2] as u64) << 16
            | (self.0[3] as u64) << 24
            | (self.0[4] as u64) << 32
            | (self.0[5] as u64) << 40
            | (self.0[6] as u64) << 48
            | (self.0[7] as u64) << 56;
        ans[1] = (self.0[8] as u64)
            | (self.0[9] as u64) << 8
            | (self.0[10] as u64) << 16
            | (self.0[11] as u64) << 24
            | (self.0[12] as u64) << 32
            | (self.0[13] as u64) << 40
            | (self.0[14] as u64) << 48
            | (self.0[15] as u64) << 56;
        ans[2] = (self.0[16] as u64)
            | (self.0[17] as u64) << 8
            | (self.0[18] as u64) << 16
            | (self.0[19] as u64) << 24
            | (self.0[20] as u64) << 32
            | (self.0[21] as u64) << 40
            | (self.0[22] as u64) << 48
            | (self.0[23] as u64) << 56;
        ans[3] = (self.0[24] as u64)
            | (self.0[25] as u64) << 8
            | (self.0[26] as u64) << 16
            | (self.0[27] as u64) << 24
            | (self.0[28] as u64) << 32
            | (self.0[29] as u64) << 40
            | (self.0[30] as u64) << 48
            | (self.0[31] as u64) << 56;

        ans
    }

    fn nbr_str(&self) -> String {
        basic_nbr_str(&(*self).to_lev_u64())
    }

    pub fn bits(&self) -> &[u8] {
        &(*self).0
    }

    pub fn random() -> Self {
        let mut rng: ThreadRng = thread_rng();
        Lev32(rng.gen::<[u8; 32]>())
    }
}

impl fmt::Display for Lev32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Lev32({})", self.nbr_str())
    }
}

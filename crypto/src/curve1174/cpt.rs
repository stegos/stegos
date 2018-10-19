//! cpt.rs - Compressed Points & main API

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
//

use super::*;

// ------------------------------------------------------------------------------------------
// Client API - compressed points and simple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Pt([u8; 32]);

impl Pt {
    pub fn bits(self) -> [u8; 32] {
        self.0
    }

    fn nbr_str(&self) -> String {
        let v = Lev32(self.0);
        basic_nbr_str(&v.to_lev_u64())
    }

    pub fn from_str(s: &str) -> Pt {
        let mut v = [0u8; 32];
        hexstr_to_lev_u8(&s, &mut v);
        Pt(v)
    }

    pub fn decompress(pt: Self) -> Result<ECp, CurveError> {
        ECp::try_from(pt)
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pt({})", self.nbr_str())
    }
}

impl Hashable for Pt {
    fn hash(&self, state: &mut Hasher) {
        "Pt".hash(state);
        (*self).bits().hash(state);
    }
}

impl From<ECp> for Pt {
    fn from(pt: ECp) -> Pt {
        let mut afpt = pt;
        norm(&mut afpt);
        let ptx = Fq::from(afpt.x);
        let mut x = U256::from(ptx).to_lev_u8();
        if afpt.y.is_odd() {
            x[31] |= 0x80;
        }
        Pt(x)
    }
}

// ----------------------------------------------------------------

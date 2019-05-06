//! winvec.rs - 4-bit window vectors for curve multipliers in fixed-width windowed multiplication

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

use super::*;
use clear_on_drop::clear::Clear;

// -----------------------------------------------------------------
// window vector of 4-bit values, used for fast multiply of curve points

pub const PANES: usize = 64; // nbr of 4-bit nibbles in 256-bit numbers

pub struct WinVec(pub [i8; PANES], pub bool);

pub const WINVEC_INIT: WinVec = WinVec([0; PANES], false);

impl WinVec {
    pub fn is_safe(&self) -> bool {
        self.1
    }

    pub fn make_safe(&mut self) -> Self {
        self.1 = true;
        self.clone()
    }

    pub fn copy_safe(&mut self, other: &Self) {
        self.1 |= other.1;
    }

    pub fn zap(&mut self) {
        self.0.clear()
    }

    pub fn maybe_zap(&mut self) {
        if self.1 {
            self.0.clear();
        }
    }
}

impl Clone for WinVec {
    fn clone(&self) -> Self {
        WinVec(self.0.clone(), self.1.clone())
    }
}

impl Drop for WinVec {
    fn drop(&mut self) {
        self.maybe_zap();
    }
}

impl<'a> From<&'a Fr> for WinVec {
    fn from(x: &'a Fr) -> WinVec {
        let bits = x.unscaled().bits().to_lev_u8();
        let mut wv = WINVEC_INIT;
        cwin4(&bits, &mut wv.0);
        wv
    }
}

impl From<i64> for WinVec {
    fn from(x: i64) -> WinVec {
        WinVec::from(&Fr::from(x))
    }
}

// convert bignum string to 4-bit LE window vector
impl WinVec {
    pub fn from_str(s: &str) -> WinVec {
        let mut w = WINVEC_INIT;
        let mut qv = [0u8; 32];
        hexstr_to_lev_u8(s, &mut qv);
        cwin4(&qv, &mut w.0);
        w
    }
}

// convert incoming LEV32 (byte vector) into a little endian vector
// of bipolar window values [-8..8)
fn cwin4(qv: &[u8; 32], w: &mut [i8; PANES]) {
    // convert incoming N to bipolar 4-bit window vector - no branching
    let mut cy = 0;
    let mut cvbip = |v_in| {
        let mut v = cy + (v_in as i8);
        cy = v >> 3;
        cy |= cy >> 1;
        cy &= 1;
        v -= cy << 4;
        v
    };

    for ix in 0..32 {
        let byt = qv[ix];
        let v = cvbip(byt & 15);
        let jx = 2 * ix;
        w[jx] = v;
        let v = cvbip(byt >> 4);
        w[jx + 1] = v;
    }
}

// ---------------------------------------------------------

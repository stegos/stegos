// cpt.rs - Compressed Points & main API
//
// DM/Emotiq 10/18
// MIT License
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
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFrINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FrOM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


use super::*;

// ------------------------------------------------------------------------------------------
// Client API - compressed points and simple fields

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Pt([u8;32]);

impl Pt {
    pub fn bits(self) -> [u8;32] {
        self.0
    }

    fn nbr_str(&self) -> String {
        let Pt(qv) = self;
        let v = unsafe { mem::transmute::<[u8;32], [u64;4]>(*qv) };
        basic_nbr_str(&v)
    }

    fn basic_from_ECp(pt : &ECp) -> Pt {
        // only for affine pts
        let ptx = FqUnscaled::from(pt.x);
        let LEV32(mut x) = LEV32::from(U256::from(ptx));
        if pt.y.is_odd() {
            x[31] |= 0x80;
        }
        Pt(x)
    }
}

impl fmt::Display for Pt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pt({})", self.nbr_str())
    }
}

impl From<ECp> for Pt {
    fn from(pt : ECp) -> Pt {
        let mut afpt = pt;
        if !afpt.is_affine() {
            norm(&mut afpt);
        }
        Pt::basic_from_ECp(&afpt)
    }
}

pub fn pt_on_curve(pt : Pt) -> Option<ECp> {
    let mut x = pt.bits();
    let sgn = (x[31] & 0x80) != 0;
    x[31] &= 0x7f;
    if x == [0u8;32] { None } // can't be pt at infinity
    else {
        let xq = Fq51::from(FqUnscaled(U256::from(LEV32(x))));
        match solve_ypt(xq) {
            Some(ysqrt) => {
                let yq = if ysqrt.is_odd() == sgn { ysqrt } else { -ysqrt };
                let newpt = ECp::from_xy(xq, yq);
                // check for small subgroup attack
                if (CURVE_H * newpt).is_inf() { None } else { Some(newpt) }
            },
            None => None
        }
    }
}

fn solve_ypt(xq : Fq51) -> Option<Fq51> {
    let yyq = ((1 + xq) * (1 - xq)) / (1 - xq.sqr() * CURVE_D);
    gsqrt(yyq)
}

impl From<Pt> for ECp {
    fn from(pt : Pt) -> ECp {
        // NOTE: This will panic if invalid point
        pt_on_curve(pt).unwrap()
    }
}

impl From<Hash> for ECp {
    fn from(h : Hash) -> ECp {
        let mut bits = h.bits();
        let sgn = bits[31] & 0x80 != 0;
        bits[31] &= 0x7f;
        let mut x = U256::from(LEV32(bits));
        while x >= Q {
            div2(&mut x.0);
        }
        let mut xq = Fq51::from(FqUnscaled(x));
        let hpt : ECp;
        loop {
            if xq != Fq51::zero() { 
                // can't be pt at inf
                match solve_ypt(xq) {
                    Some(ysqrt) => {
                        // xq must be on curve
                        let yq = if sgn == ysqrt.is_odd() { ysqrt } else { -ysqrt };
                        // avoid small subgroup
                        let pt = CURVE_H * ECp::from_xy(xq, yq);
                        if !pt.is_inf() {
                            hpt = pt;
                            break;
                        }
                    },
                    None => {}
                }
            }
            xq = xq.sqr() + 1;
        }
        hpt
    }
}


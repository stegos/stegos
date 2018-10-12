// fr.rs - Field arithmetic in field of curve1174.
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

// -----------------------------------------------------------------
// Fr is the field on the curve.  |Fr| * GenPt = INF
// |Fr| < |Fq|, both |Fr| and |Fq| are prime.
//
// Type Fr::Scaled is for working directly in the field Fr, using fast Montgomery reduction
// for modular multiply. As such, Fr is scaled by the R_ONE value.
//
// Point multiplication on the curve is performed using windowed vectors of
// unscaled Fr values. For that we have type Fr::Unscaled, to avoid the overhead
// of scaling / descaling.

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Fr {
    Unscaled(U256), // plain bits
    Scaled(U256),   // Montgomery scaling
}

// -------------------------------------------

const ZR_SQUARED: Fr = Fr::Scaled(U256([
    0x32A1CB0B0D0DF74A,
    0x7FE44146DFCFDAF8,
    0xAF59BBB1E8ACC494,
    0x1A6134EBBFC821,
])); // (2^256)^2 mod |Fr|
const FRINV: u64 = 0xCD27F41CB1C5286F; // (-1/|Fr|) mod 2^64
const R_ONE: Fr = Fr::Scaled(U256([0x5D95D0174C9B4780, 0x434D1D90167C65BB, 4, 0])); // = 2^256 mod |Fr|
const ZR_CUBED: Fr = Fr::Scaled(U256([
    0x4BC368544B1323FA,
    0xACA9EEEE6129D3CC,
    0xA005B5D44D4502BD,
    0x11ECFA1EAC284DF,
])); // = (2^256)^3 mod |Fr|

// -------------------------------------------------------------------

impl Fr {
    pub fn zero() -> Fr {
        Fr::Unscaled(U256::zero())
    }

    pub fn one() -> Fr {
        R_ONE
    }

    pub fn bits(self) -> U256 {
        match self {
            Fr::Unscaled(v) => v,
            Fr::Scaled(v) => v,
        }
    }

    pub fn is_same_type(&self, other: &Fr) -> bool {
        match (self, other) {
            (&Fr::Scaled(_), &Fr::Scaled(_)) | (&Fr::Unscaled(_), &Fr::Unscaled(_)) => true,
            _ => false,
        }
    }

    pub fn scaled(self) -> Fr {
        match self {
            Fr::Unscaled(v) => ZR_SQUARED * Fr::Scaled(v),
            _ => self,
        }
    }

    pub fn unscaled(self) -> Fr {
        match self {
            Fr::Scaled(v) => {
                let mut x = v;
                mul_collapse(&mut x.0, &R.0, FRINV);
                Fr::Unscaled(x)
            }
            _ => self,
        }
    }

    pub fn invert(self) -> Fr {
        match self {
            Fr::Scaled(v) => {
                let mut tmp = v;
                U256::invert_mod(&mut tmp, &R);
                ZR_CUBED * Fr::Scaled(tmp)
            }
            Fr::Unscaled(v) => Fr::invert(ZR_SQUARED * Fr::Scaled(v)),
        }
    }

    fn make_same_type(self, val: U256) -> Fr {
        match self {
            Fr::Unscaled(_) => Fr::Unscaled(val),
            _ => Fr::Scaled(val),
        }
    }
}

// -------------------------------------------

impl fmt::Display for Fr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = (*self).unscaled().bits();
        write!(f, "Fr({})", tmp.nbr_str())
    }
}

// -------------------------------------------

impl PartialOrd for Fr {
    fn partial_cmp(&self, other: &Fr) -> Option<Ordering> {
        if self.is_same_type(other) {
            U256::partial_cmp(&(*self).bits(), &(*other).bits())
        } else {
            U256::partial_cmp(&(*self).unscaled().bits(), &(*other).unscaled().bits())
        }
    }
}

impl Ord for Fr {
    fn cmp(&self, other: &Fr) -> Ordering {
        if self.is_same_type(other) {
            U256::cmp(&(*self).bits(), &(*other).bits())
        } else {
            U256::cmp(&(*self).unscaled().bits(), &(*other).unscaled().bits())
        }
    }
}

// -------------------------------------------

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        let mut tmp = self.unscaled().bits();
        U256::neg_mod(&mut tmp, &R);
        Fr::Unscaled(tmp)
    }
}

// -------------------------------------------

impl Add<Fr> for Fr {
    type Output = Fr;
    fn add(self, other: Fr) -> Fr {
        if self.is_same_type(&other) {
            let mut tmp = self.bits();
            U256::add_mod(&mut tmp, &other.bits(), &R);
            self.make_same_type(tmp)
        } else {
            let mut tmp = self.unscaled().bits();
            let b = other.unscaled().bits();
            U256::add_mod(&mut tmp, &b, &R);
            Fr::Unscaled(tmp)
        }
    }
}

impl Add<i64> for Fr {
    type Output = Fr;
    fn add(self, other: i64) -> Fr {
        self + Fr::from(other)
    }
}

impl Add<Fr> for i64 {
    type Output = Fr;
    fn add(self, other: Fr) -> Fr {
        Fr::from(self) + other
    }
}

// -------------------------------------------

impl AddAssign<Fr> for Fr {
    fn add_assign(&mut self, other: Fr) {
        *self = *self + other
    }
}

impl AddAssign<i64> for Fr {
    fn add_assign(&mut self, other: i64) {
        *self += Fr::from(other);
    }
}

// -------------------------------------------

impl Sub<Fr> for Fr {
    type Output = Fr;
    fn sub(self, other: Fr) -> Fr {
        if self.is_same_type(&other) {
            let mut tmp = self.bits();
            U256::sub_mod(&mut tmp, &other.bits(), &R);
            self.make_same_type(tmp)
        } else {
            let mut tmp = self.unscaled().bits();
            let b = other.unscaled().bits();
            U256::sub_mod(&mut tmp, &b, &R);
            Fr::Unscaled(tmp)
        }
    }
}

impl Sub<i64> for Fr {
    type Output = Fr;
    fn sub(self, other: i64) -> Fr {
        self - Fr::from(other)
    }
}

impl Sub<Fr> for i64 {
    type Output = Fr;
    fn sub(self, other: Fr) -> Fr {
        Fr::from(self) - other
    }
}

// -------------------------------------------

impl SubAssign<Fr> for Fr {
    fn sub_assign(&mut self, other: Fr) {
        *self = *self - other;
    }
}

impl SubAssign<i64> for Fr {
    fn sub_assign(&mut self, other: i64) {
        *self -= Fr::from(other);
    }
}

// -------------------------------------------

impl Mul<Fr> for Fr {
    type Output = Fr;
    fn mul(self, other: Fr) -> Fr {
        let mut tmp = self.scaled().bits();
        let b = other.scaled().bits();
        U256::mul_mod(&mut tmp, &b, &R, FRINV);
        Fr::Scaled(tmp)
    }
}

impl Mul<i64> for Fr {
    type Output = Fr;
    fn mul(self, other: i64) -> Fr {
        self * Fr::from(other)
    }
}

impl Mul<Fr> for i64 {
    type Output = Fr;
    fn mul(self, other: Fr) -> Fr {
        other * self
    }
}

// -------------------------------------------

impl MulAssign<Fr> for Fr {
    fn mul_assign(&mut self, other: Fr) {
        *self = *self * other;
    }
}

impl MulAssign<i64> for Fr {
    fn mul_assign(&mut self, other: i64) {
        *self *= Fr::from(other);
    }
}

// -------------------------------------------

impl Div<Fr> for Fr {
    type Output = Fr;
    fn div(self, other: Fr) -> Fr {
        self * Fr::invert(other)
    }
}

impl Div<i64> for Fr {
    type Output = Fr;
    fn div(self, other: i64) -> Fr {
        self / Fr::from(other)
    }
}

impl Div<Fr> for i64 {
    type Output = Fr;
    fn div(self, other: Fr) -> Fr {
        if self == 1 {
            Fr::invert(other)
        } else {
            Fr::from(self) / other
        }
    }
}

// -------------------------------------------

impl DivAssign<Fr> for Fr {
    fn div_assign(&mut self, other: Fr) {
        *self *= Fr::invert(other);
    }
}

impl DivAssign<i64> for Fr {
    fn div_assign(&mut self, other: i64) {
        *self /= Fr::from(other);
    }
}

// -------------------------------------------

impl From<i64> for Fr {
    fn from(x: i64) -> Fr {
        if x >= 0 {
            let z = U256([x as u64, 0, 0, 0]);
            Fr::Unscaled(z)
        } else {
            let tmp = [(-x) as u64, 0, 0, 0];
            let mut tmp2 = R.0;
            sub_noborrow(&mut tmp2, &tmp);
            let z = U256(tmp2);
            Fr::Unscaled(z)
        }
    }
}

impl From<Fr> for U256 {
    fn from(x: Fr) -> U256 {
        x.unscaled().bits()
    }
}

impl Fr {
    pub fn from_str(s: &str) -> Fr {
        let mut ans = U256::from_str(s);
        while ans >= R {
            sub_noborrow(&mut ans.0, &R.0);
        }
        Fr::Unscaled(ans)
    }
}

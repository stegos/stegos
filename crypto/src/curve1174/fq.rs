// fq.rs - field arithmetic in curve embedding field
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
// Fq is the field in which the curve is computed - coords are all elements of Fq
// In Elliptic curve point operations these coordinates are converted to Fq51 representation
//
// Type Fq::Scaled is for working directly in the field Fq, using fast Montgomery reduction
// for modular multiply. As such, Fq is scaled by the Q_ONE value. Coordinate values
// Fq51 must come from unscaled Fq values, and for that we have Fq::Unscaled types to
// help avoid the overhead of scaling / de-scaling.

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Fq {
    Unscaled(U256), // plain bits
    Scaled(U256),   // Montgomery scaling
}

// -------------------------------------------

const ZQ_SQUARED: Fq = Fq::Scaled(U256([0x014400, 0x00, 0x00, 0x00])); // (2^256)^2 mod |Fq|
const FQINV: u64 = 0x8E38E38E38E38E39; // (-1/|Fq|) mod 2^64
const Q_ONE: Fq = Fq::Scaled(U256([0x0120, 0x00, 0x00, 0x00])); // = 2^256 mod |Fq|
const ZQ_CUBED: Fq = Fq::Scaled(U256([0x016C8000, 0x00, 0x00, 0x00])); // = (2^256)^3 mod |Fq|

// -------------------------------------------

impl Fq {
    pub fn zero() -> Fq {
        Fq::Unscaled(U256::zero())
    }

    pub fn one() -> Fq {
        Q_ONE
    }

    pub fn bits(self) -> U256 {
        match self {
            Fq::Unscaled(v) => v,
            Fq::Scaled(v) => v,
        }
    }

    pub fn is_same_type(&self, other: &Fq) -> bool {
        match (self, other) {
            (&Fq::Scaled(_), &Fq::Scaled(_)) | (&Fq::Unscaled(_), &Fq::Unscaled(_)) => true,
            _ => false,
        }
    }

    pub fn scaled(self) -> Fq {
        match self {
            Fq::Unscaled(v) => ZQ_SQUARED * Fq::Scaled(v),
            _ => self,
        }
    }

    pub fn unscaled(self) -> Fq {
        match self {
            Fq::Scaled(v) => {
                let mut x = v;
                mul_collapse(&mut x.0, &Q.0, FQINV);
                Fq::Unscaled(x)
            }
            _ => self,
        }
    }

    pub fn invert(self) -> Fq {
        match self {
            Fq::Scaled(v) => {
                let mut tmp = v;
                U256::invert_mod(&mut tmp, &Q);
                ZQ_CUBED * Fq::Scaled(tmp)
            }
            Fq::Unscaled(v) => Fq::invert(ZQ_SQUARED * Fq::Scaled(v)),
        }
    }

    fn make_same_type(self, val: U256) -> Fq {
        match self {
            Fq::Unscaled(_) => Fq::Unscaled(val),
            _ => Fq::Scaled(val),
        }
    }
}

// -------------------------------------------

impl fmt::Display for Fq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = (*self).unscaled().bits();
        write!(f, "Fq({})", tmp.nbr_str())
    }
}

// -------------------------------------------

impl PartialOrd for Fq {
    fn partial_cmp(&self, other: &Fq) -> Option<Ordering> {
        if self.is_same_type(other) {
            U256::partial_cmp(&(*self).bits(), &(*other).bits())
        } else {
            U256::partial_cmp(&(*self).unscaled().bits(), &(*other).unscaled().bits())
        }
    }
}

impl Ord for Fq {
    fn cmp(&self, other: &Fq) -> Ordering {
        if self.is_same_type(other) {
            U256::cmp(&(*self).bits(), &(*other).bits())
        } else {
            U256::cmp(&(*self).unscaled().bits(), &(*other).unscaled().bits())
        }
    }
}

// -------------------------------------------

impl Neg for Fq {
    type Output = Fq;
    fn neg(self) -> Fq {
        let mut tmp = self.unscaled().bits();
        U256::neg_mod(&mut tmp, &Q);
        Fq::Unscaled(tmp)
    }
}

// -------------------------------------------

impl Add<Fq> for Fq {
    type Output = Fq;
    fn add(self, other: Fq) -> Fq {
        if self.is_same_type(&other) {
            let mut tmp = self.bits();
            U256::add_mod(&mut tmp, &other.bits(), &Q);
            self.make_same_type(tmp)
        } else {
            let mut tmp = self.unscaled().bits();
            let b = other.unscaled().bits();
            U256::add_mod(&mut tmp, &b, &Q);
            Fq::Unscaled(tmp)
        }
    }
}

impl Add<i64> for Fq {
    type Output = Fq;
    fn add(self, other: i64) -> Fq {
        self + Fq::from(other)
    }
}

impl Add<Fq> for i64 {
    type Output = Fq;
    fn add(self, other: Fq) -> Fq {
        Fq::from(self) + other
    }
}

// -------------------------------------------

impl AddAssign<Fq> for Fq {
    fn add_assign(&mut self, other: Fq) {
        *self = *self + other
    }
}

impl AddAssign<i64> for Fq {
    fn add_assign(&mut self, other: i64) {
        *self += Fq::from(other);
    }
}

// -------------------------------------------

impl Sub<Fq> for Fq {
    type Output = Fq;
    fn sub(self, other: Fq) -> Fq {
        let mut tmp = self.bits();
        U256::sub_mod(&mut tmp, &other.bits(), &Q);
        self.make_same_type(tmp)
    }
}

impl Sub<i64> for Fq {
    type Output = Fq;
    fn sub(self, other: i64) -> Fq {
        self - Fq::from(other)
    }
}

impl Sub<Fq> for i64 {
    type Output = Fq;
    fn sub(self, other: Fq) -> Fq {
        Fq::from(self) - other
    }
}

// -------------------------------------------

impl SubAssign<Fq> for Fq {
    fn sub_assign(&mut self, other: Fq) {
        *self = *self - other;
    }
}

impl SubAssign<i64> for Fq {
    fn sub_assign(&mut self, other: i64) {
        *self -= Fq::from(other);
    }
}

// -------------------------------------------

impl Mul<Fq> for Fq {
    type Output = Fq;
    fn mul(self, other: Fq) -> Fq {
        let mut tmp = self.scaled().bits();
        let b = other.scaled().bits();
        U256::mul_mod(&mut tmp, &b, &Q, FQINV);
        Fq::Scaled(tmp)
    }
}

impl Mul<i64> for Fq {
    type Output = Fq;
    fn mul(self, other: i64) -> Fq {
        self * Fq::from(other)
    }
}

impl Mul<Fq> for i64 {
    type Output = Fq;
    fn mul(self, other: Fq) -> Fq {
        other * self
    }
}

// -------------------------------------------

impl MulAssign<Fq> for Fq {
    fn mul_assign(&mut self, other: Fq) {
        *self = *self * other;
    }
}

impl MulAssign<i64> for Fq {
    fn mul_assign(&mut self, other: i64) {
        *self *= Fq::from(other);
    }
}

// -------------------------------------------

impl Div<Fq> for Fq {
    type Output = Fq;
    fn div(self, other: Fq) -> Fq {
        self * Fq::invert(other)
    }
}

impl Div<i64> for Fq {
    type Output = Fq;
    fn div(self, other: i64) -> Fq {
        self / Fq::from(other)
    }
}

impl Div<Fq> for i64 {
    type Output = Fq;
    fn div(self, other: Fq) -> Fq {
        if self == 1 {
            Fq::invert(other)
        } else {
            Fq::from(self) / other
        }
    }
}

// -------------------------------------------

impl DivAssign<Fq> for Fq {
    fn div_assign(&mut self, other: Fq) {
        *self *= Fq::invert(other);
    }
}

impl DivAssign<i64> for Fq {
    fn div_assign(&mut self, other: i64) {
        *self /= Fq::from(other);
    }
}

// -------------------------------------------

impl From<i64> for Fq {
    fn from(x: i64) -> Fq {
        if x >= 0 {
            let z = U256([x as u64, 0, 0, 0]);
            Fq::Unscaled(z)
        } else {
            let tmp = [(-x) as u64, 0, 0, 0];
            let mut tmp2 = Q.0;
            sub_noborrow(&mut tmp2, &tmp);
            let z = U256(tmp2);
            Fq::Unscaled(z)
        }
    }
}

impl From<Fq> for U256 {
    fn from(x: Fq) -> U256 {
        x.unscaled().bits()
    }
}

impl Fq {
    pub fn from_str(s: &str) -> Result<Fq, hex::FromHexError> {
        let mut ans = U256::from_str(s)?;
        while ans >= Q {
            sub_noborrow(&mut ans.0, &Q.0);
        }
        Ok(Fq::Unscaled(ans))
    }
}

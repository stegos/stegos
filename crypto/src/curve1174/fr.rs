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
// Type Fr is for working directly in the field Fr, using fast Montgomery reduction
// for modular multiply. As such, Fr is scaled by the R_ONE value. 
//
// Point multiplication on the curve is performed using windowed vectors of 
// unscaled Fr values. For that we have type FrUnscaled, to avoid the overhead
// of scaling / descaling.

pub struct FrUnscaled(pub U256);

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Fr(U256);

pub const R : U256 = U256([0x8944D45FD166C971, 0xF77965C4DFD30734, 0xFFFFFFFFFFFFFFFF, 0x1FFFFFFFFFFFFFF]); // |Fr|

const ZR_SQUARED : Fr = Fr(U256([0x32A1CB0B0D0DF74A, 0x7FE44146DFCFDAF8, 0xAF59BBB1E8ACC494, 0x1A6134EBBFC821])); // (2^256)^2 mod |Fr|
const FRINV : u64 = 0xCD27F41CB1C5286F; // (-1/|Fr|) mod 2^64
const R_ONE : Fr = Fr(U256([0x5D95D0174C9B4780, 0x434D1D90167C65BB, 4, 0])); // = 2^256 mod |Fr|
const ZR_CUBED : Fr = Fr(U256([0x4BC368544B1323FA, 0xACA9EEEE6129D3CC, 0xA005B5D44D4502BD, 0x11ECFA1EAC284DF]));

impl PartialOrd for Fr {
    fn partial_cmp(&self, other: &Fr) -> Option<Ordering> {
        U256::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for Fr {
    fn cmp(&self, other: &Fr) -> Ordering {
        U256::cmp(&self.0, &other.0)
    }
}

// -------------------------------------------------------------------

impl Fr {
    pub fn zero() -> Fr {
        Fr(U256::zero())
    }

    pub fn one() -> Fr {
        R_ONE
    }

    pub fn invert(self) -> Fr {
        let mut tmp = self;
        U256::invert_mod(&mut tmp.0, &R);
        ZR_CUBED * tmp
    }
}

impl fmt::Display for Fr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let FrUnscaled(tmp) = FrUnscaled::from(*self);
        write!(f, "Fr({})", tmp.nbr_str())
    }
}

impl From<i64> for FrUnscaled {
    fn from(x : i64) -> FrUnscaled {
        if x >= 0 {
            let z = U256([x as u64, 0, 0, 0]);
            FrUnscaled(z)
        } else {
            let tmp = [(-x) as u64, 0, 0, 0];
            let mut tmp2 = R.0;
            sub_noborrow(&mut tmp2, &tmp);
            let z = U256(tmp2);
            FrUnscaled(z)
        }
    }
}

impl From<FrUnscaled> for Fr {
    fn from(x : FrUnscaled) -> Fr {
        let FrUnscaled(z) = x;
        ZR_SQUARED * Fr(z)
    }
}

impl From<i64> for Fr {
    fn from(x : i64) -> Fr {
        Fr::from(FrUnscaled::from(x))
    }
}

impl Add<Fr> for Fr {
    type Output = Fr;
    fn add(self, other: Fr) -> Fr {
        let mut tmp = self;
        U256::add_mod(&mut tmp.0, &other.0, &R);
        tmp
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

impl AddAssign<Fr> for Fr {
    fn add_assign(&mut self, other: Fr) {
        U256::add_mod(&mut self.0, &other.0, &R);
    }
}

impl AddAssign<i64> for Fr {
    fn add_assign(&mut self, other: i64) {
        *self += Fr::from(other);
    }
}

impl Sub<Fr> for Fr {
    type Output = Fr;
    fn sub(self, other: Fr) -> Fr {
        let mut tmp = self;
        U256::sub_mod(&mut tmp.0, &other.0, &R);
        tmp
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

impl SubAssign<Fr> for Fr {
    fn sub_assign(&mut self, other: Fr) {
        U256::sub_mod(&mut self.0, &other.0, &R);
    }
}

impl SubAssign<i64> for Fr {
    fn sub_assign(&mut self, other: i64) {
        *self -= Fr::from(other);
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        let mut tmp = self;
        U256::neg_mod(&mut tmp.0, &R);
        tmp
    }
}

impl Mul<Fr> for Fr {
    type Output = Fr;
    fn mul(self, other: Fr) -> Fr {
        let mut tmp = self;
        U256::mul_mod(&mut tmp.0, &other.0, &R, FRINV);
        tmp
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

impl MulAssign<Fr> for Fr {
    fn mul_assign(&mut self, other: Fr) {
        U256::mul_mod(&mut self.0, &other.0, &R, FRINV);
    }
}

impl MulAssign<i64> for Fr {
    fn mul_assign(&mut self, other: i64) {
        *self *= Fr::from(other);
    }
}

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

impl From<FrUnscaled> for U256 {
    fn from(x: FrUnscaled) -> U256 {
        x.0
    }
}

impl From<Fr> for FrUnscaled {
    fn from(x: Fr) -> FrUnscaled {
        let mut tmp = x.0;
        mul_collapse(&mut tmp.0, &R.0, FRINV);
        FrUnscaled(tmp)
    }
}

pub fn str_to_Fr(s: &str) -> Fr {
    let mut bin : [u64;4] = [0;4];
    str_to_bin64(s, &mut bin);
    let mut ans = U256(bin);
    while ans >= R {
        sub_noborrow(&mut ans.0, &R.0);
    }
    Fr::from(FrUnscaled(ans))
}


//! fq.rs - Field arithmetic in curve embedding field

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

macro_rules! field_impl {
    ($name: ident, $modulus: ident, $rsquared: ident, $rcubed: ident, $one: ident, $inv: ident, $hash: expr, $fmt: expr) => {
        #[derive(Copy, Clone, Debug)]
        // #[repr(C)]
        pub enum $name {
            Unscaled(U256), // plain bits
            Scaled(U256),   // Montgomery scaling
        }

        impl From<$name> for U256 {
            fn from(a: $name) -> Self {
                a.unscaled().bits()
            }
        }

        impl From<i64> for $name {
            fn from(x: i64) -> $name {
                if x >= 0 {
                    let z = U256([x as u64, 0, 0, 0]);
                    $name::Unscaled(z)
                } else {
                    let tmp = [(-x) as u64, 0, 0, 0];
                    let mut tmp2 = (*$modulus).0;
                    sub_noborrow(&mut tmp2, &tmp);
                    let z = U256(tmp2);
                    $name::Unscaled(z)
                }
            }
        }

        impl $name {
            pub fn modulus() -> U256 {
                *$modulus
            }

            pub fn zero() -> $name {
                $name::Unscaled(U256::zero())
            }

            pub fn one() -> $name {
                $one
            }

            pub fn bits(self) -> U256 {
                match self {
                    $name::Unscaled(v) => v,
                    $name::Scaled(v) => v,
                }
            }

            pub fn random() -> $name {
                $name::Unscaled(U256::random_in_range(*$modulus))
            }

            pub fn is_same_type(&self, other: &$name) -> bool {
                match (self, other) {
                    (&$name::Scaled(_), &$name::Scaled(_))
                    | (&$name::Unscaled(_), &$name::Unscaled(_)) => true,
                    _ => false,
                }
            }

            pub fn scaled(self) -> $name {
                match self {
                    $name::Unscaled(v) => $rsquared * $name::Scaled(v),
                    _ => self,
                }
            }

            pub fn unscaled(self) -> $name {
                match self {
                    $name::Scaled(v) => {
                        let mut x = v;
                        mul_collapse(&mut x.0, &(*$modulus).0, $inv);
                        $name::Unscaled(x)
                    }
                    _ => self,
                }
            }

            pub fn invert(self) -> $name {
                match self {
                    $name::Scaled(v) => {
                        let mut tmp = v;
                        U256::invert_mod(&mut tmp, &(*$modulus));
                        $rcubed * $name::Scaled(tmp)
                    }
                    $name::Unscaled(v) => $name::invert($rsquared * $name::Scaled(v)),
                }
            }

            fn make_same_type(self, val: U256) -> $name {
                match self {
                    $name::Unscaled(_) => $name::Unscaled(val),
                    _ => $name::Scaled(val),
                }
            }

            pub fn from_str(s: &str) -> Result<$name, hex::FromHexError> {
                let mut ans = U256::from_str(s)?;
                while ans >= *$modulus {
                    sub_noborrow(&mut ans.0, &(*$modulus).0);
                }
                Ok($name::Unscaled(ans))
            }
        }

        // -------------------------------------------

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let tmp = (*self).unscaled().bits();
                write!(f, $fmt, tmp.nbr_str())
            }
        }

        // --------------------------------------------------------

        impl Hashable for $name {
            fn hash(&self, state: &mut Hasher) {
                match (*self).unscaled() {
                    $name::Unscaled(U256(v)) => {
                        let lv = Lev32 { v64: v };
                        $hash.hash(state);
                        unsafe { lv.v8 }.hash(state);
                    }
                    _ => unreachable!(),
                }
            }
        }

        impl From<Hash> for $name {
            fn from(h: Hash) -> $name {
                let lv = Lev32 { v8: h.bits() };
                let mut x = U256(unsafe { lv.v64 });
                U256::force_to_range(&mut x, *$modulus);
                $name::Unscaled(x)
            }
        }
        // -------------------------------------------

        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                if self.is_same_type(other) {
                    Ordering::Equal == U256::cmp(&(*self).bits(), &(*other).bits())
                } else {
                    Ordering::Equal
                        == U256::cmp(&(*self).unscaled().bits(), &(*other).unscaled().bits())
                }
            }
        }

        impl Eq for $name {}

        // -------------------------------------------

        impl Neg for $name {
            type Output = $name;
            fn neg(self) -> $name {
                let mut tmp = self.unscaled().bits();
                U256::neg_mod(&mut tmp, &Q);
                $name::Unscaled(tmp)
            }
        }

        // -------------------------------------------

        impl Add<$name> for $name {
            type Output = $name;
            fn add(self, other: $name) -> $name {
                if self.is_same_type(&other) {
                    let mut tmp = self.bits();
                    U256::add_mod(&mut tmp, &other.bits(), &Q);
                    self.make_same_type(tmp)
                } else {
                    let mut tmp = self.unscaled().bits();
                    let b = other.unscaled().bits();
                    U256::add_mod(&mut tmp, &b, &Q);
                    $name::Unscaled(tmp)
                }
            }
        }

        impl Add<i64> for $name {
            type Output = $name;
            fn add(self, other: i64) -> $name {
                self + $name::from(other)
            }
        }

        impl Add<$name> for i64 {
            type Output = $name;
            fn add(self, other: $name) -> $name {
                $name::from(self) + other
            }
        }

        // -------------------------------------------

        impl AddAssign<$name> for $name {
            fn add_assign(&mut self, other: $name) {
                *self = *self + other
            }
        }

        impl AddAssign<i64> for $name {
            fn add_assign(&mut self, other: i64) {
                *self += $name::from(other);
            }
        }

        // -------------------------------------------

        impl Sub<$name> for $name {
            type Output = $name;
            fn sub(self, other: $name) -> $name {
                let mut tmp = self.bits();
                U256::sub_mod(&mut tmp, &other.bits(), &Q);
                self.make_same_type(tmp)
            }
        }

        impl Sub<i64> for $name {
            type Output = $name;
            fn sub(self, other: i64) -> $name {
                self - $name::from(other)
            }
        }

        impl Sub<$name> for i64 {
            type Output = $name;
            fn sub(self, other: $name) -> $name {
                $name::from(self) - other
            }
        }

        // -------------------------------------------

        impl SubAssign<$name> for $name {
            fn sub_assign(&mut self, other: $name) {
                *self = *self - other;
            }
        }

        impl SubAssign<i64> for $name {
            fn sub_assign(&mut self, other: i64) {
                *self -= $name::from(other);
            }
        }

        // -------------------------------------------

        impl Mul<$name> for $name {
            type Output = $name;
            fn mul(self, other: $name) -> $name {
                let mut tmp = self.scaled().bits();
                let b = other.scaled().bits();
                U256::mul_mod(&mut tmp, &b, &Q, FQINV);
                $name::Scaled(tmp)
            }
        }

        impl Mul<i64> for $name {
            type Output = $name;
            fn mul(self, other: i64) -> $name {
                self * $name::from(other)
            }
        }

        impl Mul<$name> for i64 {
            type Output = $name;
            fn mul(self, other: $name) -> $name {
                other * self
            }
        }

        // -------------------------------------------

        impl MulAssign<$name> for $name {
            fn mul_assign(&mut self, other: $name) {
                *self = *self * other;
            }
        }

        impl MulAssign<i64> for $name {
            fn mul_assign(&mut self, other: i64) {
                *self *= $name::from(other);
            }
        }

        // -------------------------------------------

        impl Div<$name> for $name {
            type Output = $name;
            fn div(self, other: $name) -> $name {
                self * $name::invert(other)
            }
        }

        impl Div<i64> for $name {
            type Output = $name;
            fn div(self, other: i64) -> $name {
                self / $name::from(other)
            }
        }

        impl Div<$name> for i64 {
            type Output = $name;
            fn div(self, other: $name) -> $name {
                if self == 1 {
                    $name::invert(other)
                } else {
                    $name::from(self) / other
                }
            }
        }

        // -------------------------------------------

        impl DivAssign<$name> for $name {
            fn div_assign(&mut self, other: $name) {
                *self *= $name::invert(other);
            }
        }

        impl DivAssign<i64> for $name {
            fn div_assign(&mut self, other: i64) {
                *self /= $name::from(other);
            }
        }
    };
}

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

const ZQ_SQUARED: Fq = Fq::Scaled(U256([0x014400, 0x00, 0x00, 0x00])); // (2^256)^2 mod |Fq|
const FQINV: u64 = 0x8E38E38E38E38E39; // (-1/|Fq|) mod 2^64
const Q_ONE: Fq = Fq::Scaled(U256([0x0120, 0x00, 0x00, 0x00])); // = 2^256 mod |Fq|
const ZQ_CUBED: Fq = Fq::Scaled(U256([0x016C8000, 0x00, 0x00, 0x00])); // = (2^256)^3 mod |Fq|

field_impl!(Fr, R, ZR_SQUARED, ZR_CUBED, R_ONE, FRINV, "Fr", "Fr({})");
field_impl!(Fq, Q, ZQ_SQUARED, ZQ_CUBED, Q_ONE, FQINV, "Fq", "Fq({})");

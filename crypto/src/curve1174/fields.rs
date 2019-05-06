//! fq.rs - Field arithmetic in curve embedding field

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
//

use super::*;
use crate::utils;
use crate::CryptoError;

macro_rules! field_impl {
    ($name: ident, $modulus: ident, $rsquared: ident, $rcubed: ident, $one: ident, $inv: ident, $hash: expr, $fmt: expr, $min: ident) => {
        #[derive(Clone)]
        pub enum $name {
            Unscaled(U256), // plain bits
            Scaled(U256),   // Montgomery scaling
        }

        impl<'a> From<&'a $name> for U256 {
            fn from(a: &'a $name) -> U256 {
                a.unscaled_bits()
            }
        }

        impl<'a> From<&'a U256> for $name {
            fn from(x: &'a U256) -> $name {
                assert!(*x < *$modulus);
                $name::Unscaled(x.clone())
            }
        }

        impl From<i64> for $name {
            fn from(x: i64) -> $name {
                match x {
                    0 => Self::zero(),
                    1 => Self::one(),
                    -1 => -&Self::one(),
                    _ if x > 0 => {
                        let z = U256([x as u64, 0, 0, 0], false);
                        $name::Unscaled(z)
                    }
                    _ => {
                        let z = U256([(-x) as u64, 0, 0, 0], false);
                        -&$name::Unscaled(z)
                    }
                }
            }
        }

        impl $name {
            pub fn modulus() -> U256 {
                $modulus.clone()
            }

            pub fn zero() -> Self {
                $name::Unscaled(U256::zero())
            }

            pub fn one() -> $name {
                $one
            }

            pub fn is_safe(&self) -> bool {
                match self {
                    $name::Scaled(v) => v.is_safe(),
                    $name::Unscaled(v) => v.is_safe(),
                }
            }

            pub fn make_safe(&mut self) -> Self {
                match self {
                    $name::Scaled(v) => {
                        v.make_safe();
                    }
                    $name::Unscaled(v) => {
                        v.make_safe();
                    }
                }
                self.clone()
            }

            pub fn bits(&self) -> U256 {
                match self {
                    $name::Unscaled(v) => v.clone(),
                    $name::Scaled(v) => v.clone(),
                }
            }

            pub fn unscaled_bits(&self) -> U256 {
                self.unscaled().bits()
            }

            pub fn scaled_bits(&self) -> U256 {
                self.scaled().bits()
            }

            pub fn basic_random() -> Self {
                $name::Unscaled(U256::random_in_range(&*$modulus))
            }

            pub fn random() -> Self {
                let mut r = Self::basic_random();
                let min = $min.clone();
                let max = -&min;
                while r < min || r > max {
                    r = Self::basic_random();
                }
                r
            }

            pub fn is_same_type(&self, other: &Self) -> bool {
                match (self, other) {
                    (&$name::Scaled(_), &$name::Scaled(_))
                    | (&$name::Unscaled(_), &$name::Unscaled(_)) => true,
                    _ => false,
                }
            }

            pub fn scaled(&self) -> Self {
                match self {
                    $name::Unscaled(v) => &$rsquared * &$name::Scaled(v.clone()),
                    _ => self.clone(),
                }
            }

            pub fn unscaled(&self) -> Self {
                match self {
                    $name::Scaled(v) => {
                        let mut x = v.clone();
                        mul_collapse(&mut x.0, &$modulus.0, $inv);
                        $name::Unscaled(x)
                    }
                    _ => self.clone(),
                }
            }

            pub fn invert(&self) -> Self {
                match self {
                    $name::Scaled(v) => {
                        let mut tmp = v.clone();
                        tmp.invert_mod(&*$modulus);
                        &$rcubed * &$name::Scaled(tmp)
                    }
                    $name::Unscaled(_v) => Self::invert(&self.scaled()),
                }
            }

            fn make_same_type(&self, val: &U256) -> Self {
                match self {
                    $name::Unscaled(_) => $name::Unscaled(val.clone()),
                    _ => $name::Scaled(val.clone()),
                }
            }

            pub fn acceptable_minval() -> Self {
                // NOTE: this value is cached in the lazy_static
                let modulus = Lev32::from(&*$modulus);
                let mut minbits = [0u8; 32];
                utils::ushr_le(&modulus.bits(), &mut minbits, 125);
                $name::Unscaled(U256::from(&Lev32(minbits, false)))
            }

            pub fn acceptable_random_rehash(k: &Self) -> Self {
                // to avoid brute force attacks, an acceptable random value, k,
                // is either itself, or a rehash of itself, until the value
                // lies in acceptable range.
                let min = $min.clone(); // cached value
                let max = -&min;
                let mut mk = k.unscaled();
                while mk < min || mk > max {
                    mk = $name::from(&Hash::digest(&mk));
                }
                mk
            }

            pub fn synthetic_random(pref: &str, uniq: &dyn Hashable, h: &Hash) -> Self {
                // Construct a pseudo random field value without using the PRNG
                // This generates so-called "deterministic randomness" and assures
                // random-appearing values that will always be the same for the same
                // input keying. The result will be in the "safe" range for the field.
                let x = Self::from(&Hash::digest_chain(&[&Hash::from_str(pref), uniq, h]));
                Self::acceptable_random_rehash(&x)
            }

            /// Convert to positive i64 (if you can)
            pub fn to_i64(&self) -> Result<i64, CryptoError> {
                let U256(uval, _) = U256::from(&self.unscaled());
                if uval[3] == 0
                    && uval[2] == 0
                    && uval[1] == 0
                    && uval[0] < 0x8000_0000_0000_0000u64
                {
                    return Ok(uval[0] as i64);
                } else {
                    return Err(CryptoError::TooLarge);
                }
            }

            /// Convert into raw bytes.
            pub fn to_lev_u8(&self) -> [u8; 32] {
                self.bits().to_lev_u8()
            }

            /// Convert into raw bytes.
            #[inline]
            pub fn to_bytes(&self) -> [u8; 32] {
                self.clone().to_lev_u8()
            }

            /// Convert from raw bytes.
            pub fn from_lev_u8(bytes: [u8; 32]) -> Self {
                $name::Unscaled(U256::from_lev_u8(bytes, false))
            }

            pub fn from_safe_lev_u8(bytes: [u8; 32]) -> Self {
                let fr = $name::Unscaled(U256::from_lev_u8(bytes, true));
                /* // TODO
                for ix in 0..32 {
                    bytes[ix] = 0;
                }
                */
                fr
            }

            /// Convert from raw bytes.
            #[inline]
            pub fn try_from_bytes(bytes_slice: &[u8]) -> Result<Self, CryptoError> {
                let mut bytes: [u8; 32] = [0u8; 32];
                if bytes_slice.len() != 32 {
                    return Err(CryptoError::InvalidBinaryLength(32, bytes_slice.len()));
                }
                bytes.copy_from_slice(bytes_slice);
                Ok($name::from_lev_u8(bytes))
            }

            /// Convert from raw bytes.
            #[inline]
            pub fn try_safely_from_bytes(bytes_slice: &[u8]) -> Result<Self, CryptoError> {
                let mut bytes: [u8; 32] = [0u8; 32];
                if bytes_slice.len() != 32 {
                    return Err(CryptoError::InvalidBinaryLength(32, bytes_slice.len()));
                }
                bytes.copy_from_slice(bytes_slice);
                Ok($name::from_safe_lev_u8(bytes))
            }

            /// Convert into hex string.
            pub fn to_hex(&self) -> String {
                let tmp = self.clone().unscaled_bits();
                format!("{}", tmp.nbr_str())
            }

            /// Try to convert from hex string.
            pub fn try_from_hex(s: &str) -> Result<Self, CryptoError> {
                let mut ans = U256::try_from_hex(s)?;
                while ans >= *$modulus {
                    sub_noborrow(&mut ans.0, &$modulus.0);
                }
                Ok($name::Unscaled(ans))
            }
        }

        // --------------------------------------------------------

        impl Hashable for $name {
            fn hash(&self, state: &mut Hasher) {
                let x = self.clone().unscaled_bits();
                $hash.hash(state);
                x.to_lev_u8().hash(state)
            }
        }

        impl<'a> From<&'a Hash> for $name {
            fn from(h: &'a Hash) -> Self {
                let lv = Lev32(h.bits(), false);
                let mut x = U256(lv.to_lev_u64(), false);
                x.force_to_range(&*$modulus);
                $name::Unscaled(x)
            }
        }

        // -------------------------------------------

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                if self.is_same_type(other) {
                    self.bits().cmp(&other.bits())
                } else {
                    self.unscaled_bits().cmp(&other.unscaled_bits())
                }
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                if self.is_same_type(other) {
                    self.bits().partial_cmp(&other.bits())
                } else {
                    self.unscaled_bits().partial_cmp(&other.unscaled_bits())
                }
            }
        }

        // -------------------------------------------

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                if self.is_same_type(other) {
                    Ordering::Equal == self.bits().cmp(&other.bits())
                } else {
                    Ordering::Equal == self.unscaled_bits().cmp(&other.unscaled_bits())
                }
            }
        }

        impl Eq for $name {}

        // -------------------------------------------

        impl<'a> Neg for &'a $name {
            type Output = $name;
            fn neg(self) -> $name {
                let mut tmp = self.bits();
                tmp.neg_mod(&*$modulus);
                self.make_same_type(&tmp)
            }
        }

        impl Neg for $name {
            type Output = $name;
            fn neg(self) -> $name {
                let mut tmp = self.bits();
                tmp.neg_mod(&*$modulus);
                self.make_same_type(&tmp)
            }
        }

        // -------------------------------------------

        impl<'a, 'b> Add<&'a $name> for &'b $name {
            type Output = $name;
            fn add(self, other: &'a $name) -> $name {
                if self.is_same_type(&other) {
                    let mut tmp = self.bits();
                    tmp.add_mod(&other.bits(), &*$modulus);
                    self.make_same_type(&tmp)
                } else {
                    let mut tmp = self.unscaled_bits();
                    let b = other.unscaled_bits();
                    tmp.add_mod(&b, &*$modulus);
                    $name::Unscaled(tmp)
                }
            }
        }

        impl<'a> Add<&'a $name> for $name {
            type Output = $name;
            fn add(self, other: &'a $name) -> $name {
                if self.is_same_type(&other) {
                    let mut tmp = self.bits();
                    tmp.add_mod(&other.bits(), &*$modulus);
                    self.make_same_type(&tmp)
                } else {
                    let mut tmp = self.unscaled_bits();
                    let b = other.unscaled_bits();
                    tmp.add_mod(&b, &*$modulus);
                    $name::Unscaled(tmp)
                }
            }
        }

        impl<'b> Add<$name> for &'b $name {
            type Output = $name;
            fn add(self, other: $name) -> $name {
                if self.is_same_type(&other) {
                    let mut tmp = self.bits();
                    tmp.add_mod(&other.bits(), &*$modulus);
                    self.make_same_type(&tmp)
                } else {
                    let mut tmp = self.unscaled_bits();
                    let b = other.unscaled_bits();
                    tmp.add_mod(&b, &*$modulus);
                    $name::Unscaled(tmp)
                }
            }
        }

        impl Add<$name> for $name {
            type Output = $name;
            fn add(self, other: $name) -> $name {
                if self.is_same_type(&other) {
                    let mut tmp = self.bits();
                    tmp.add_mod(&other.bits(), &*$modulus);
                    self.make_same_type(&tmp)
                } else {
                    let mut tmp = self.unscaled_bits();
                    let b = other.unscaled_bits();
                    tmp.add_mod(&b, &*$modulus);
                    $name::Unscaled(tmp)
                }
            }
        }

        impl<'a> Add<i64> for &'a $name {
            type Output = $name;
            fn add(self, other: i64) -> $name {
                self + &$name::from(other)
            }
        }

        impl Add<i64> for $name {
            type Output = $name;
            fn add(self, other: i64) -> $name {
                self + &$name::from(other)
            }
        }

        impl<'a> Add<&'a $name> for i64 {
            type Output = $name;
            fn add(self, other: &'a $name) -> $name {
                &$name::from(self) + other
            }
        }

        impl Add<$name> for i64 {
            type Output = $name;
            fn add(self, other: $name) -> $name {
                &$name::from(self) + other
            }
        }

        // -------------------------------------------

        impl<'a> AddAssign<&'a $name> for $name {
            fn add_assign(&mut self, other: &'a $name) {
                *self = &*self + other
            }
        }

        impl AddAssign<$name> for $name {
            fn add_assign(&mut self, other: $name) {
                *self = &*self + other
            }
        }

        impl AddAssign<i64> for $name {
            fn add_assign(&mut self, other: i64) {
                *self += &$name::from(other);
            }
        }

        // -------------------------------------------

        impl<'a, 'b> Sub<&'a $name> for &'b $name {
            type Output = $name;
            fn sub(self, other: &'a $name) -> $name {
                self + -other
            }
        }

        impl<'b> Sub<$name> for &'b $name {
            type Output = $name;
            fn sub(self, other: $name) -> $name {
                self + -other
            }
        }

        impl<'a> Sub<&'a $name> for $name {
            type Output = $name;
            fn sub(self, other: &'a $name) -> $name {
                self + -other
            }
        }

        impl Sub<$name> for $name {
            type Output = $name;
            fn sub(self, other: $name) -> $name {
                self + -other
            }
        }

        impl<'a> Sub<i64> for &'a $name {
            type Output = $name;
            fn sub(self, other: i64) -> $name {
                self - &$name::from(other)
            }
        }

        impl Sub<i64> for $name {
            type Output = $name;
            fn sub(self, other: i64) -> $name {
                self - &$name::from(other)
            }
        }

        impl<'a> Sub<&'a $name> for i64 {
            type Output = $name;
            fn sub(self, other: &'a $name) -> $name {
                &$name::from(self) - other
            }
        }

        impl Sub<$name> for i64 {
            type Output = $name;
            fn sub(self, other: $name) -> $name {
                &$name::from(self) - other
            }
        }

        // -------------------------------------------

        impl<'a> SubAssign<&'a $name> for $name {
            fn sub_assign(&mut self, other: &'a $name) {
                *self = &*self - other;
            }
        }

        impl SubAssign<$name> for $name {
            fn sub_assign(&mut self, other: $name) {
                *self = &*self - other;
            }
        }

        impl SubAssign<i64> for $name {
            fn sub_assign(&mut self, other: i64) {
                *self -= &$name::from(other);
            }
        }

        // -------------------------------------------

        impl<'a, 'b> Mul<&'a $name> for &'b $name {
            type Output = $name;
            fn mul(self, other: &'a $name) -> $name {
                let mut tmp = self.scaled_bits();
                let b = other.scaled_bits();
                tmp.mul_mod(&b, &*$modulus, $inv);
                $name::Scaled(tmp)
            }
        }

        impl<'a> Mul<&'a $name> for $name {
            type Output = $name;
            fn mul(self, other: &'a $name) -> $name {
                let mut tmp = self.scaled_bits();
                let b = other.scaled_bits();
                tmp.mul_mod(&b, &*$modulus, $inv);
                $name::Scaled(tmp)
            }
        }

        impl<'b> Mul<$name> for &'b $name {
            type Output = $name;
            fn mul(self, other: $name) -> $name {
                let mut tmp = self.scaled_bits();
                let b = other.scaled_bits();
                tmp.mul_mod(&b, &*$modulus, $inv);
                $name::Scaled(tmp)
            }
        }

        impl Mul<$name> for $name {
            type Output = $name;
            fn mul(self, other: $name) -> $name {
                let mut tmp = self.scaled_bits();
                let b = other.scaled_bits();
                tmp.mul_mod(&b, &*$modulus, $inv);
                $name::Scaled(tmp)
            }
        }

        impl<'a> Mul<i64> for &'a $name {
            type Output = $name;
            fn mul(self, other: i64) -> $name {
                match other {
                    0 => $name::zero(),
                    1 => self.clone(),
                    -1 => -self,
                    _ => self * &$name::from(other),
                }
            }
        }

        impl Mul<i64> for $name {
            type Output = $name;
            fn mul(self, other: i64) -> $name {
                match other {
                    0 => $name::zero(),
                    1 => self.clone(),
                    -1 => -self,
                    _ => self * &$name::from(other),
                }
            }
        }

        impl<'a> Mul<&'a $name> for i64 {
            type Output = $name;
            fn mul(self, other: &'a $name) -> $name {
                other * self
            }
        }

        impl Mul<$name> for i64 {
            type Output = $name;
            fn mul(self, other: $name) -> $name {
                other * self
            }
        }

        // -------------------------------------------

        impl<'a> MulAssign<&'a $name> for $name {
            fn mul_assign(&mut self, other: &'a $name) {
                *self = &*self * other;
            }
        }

        impl MulAssign<$name> for $name {
            fn mul_assign(&mut self, other: $name) {
                *self = &*self * other;
            }
        }

        impl MulAssign<i64> for $name {
            fn mul_assign(&mut self, other: i64) {
                *self *= &$name::from(other);
            }
        }

        // -------------------------------------------

        impl<'a, 'b> Div<&'a $name> for &'b $name {
            type Output = $name;
            fn div(self, other: &'a $name) -> $name {
                self * &other.invert()
            }
        }

        impl<'a> Div<&'a $name> for $name {
            type Output = $name;
            fn div(self, other: &'a $name) -> $name {
                self * &other.invert()
            }
        }

        impl<'b> Div<$name> for &'b $name {
            type Output = $name;
            fn div(self, other: $name) -> $name {
                self * &other.invert()
            }
        }

        impl Div<$name> for $name {
            type Output = $name;
            fn div(self, other: $name) -> $name {
                self * &other.invert()
            }
        }

        impl<'a> Div<i64> for &'a $name {
            type Output = $name;
            fn div(self, other: i64) -> $name {
                self / &$name::from(other)
            }
        }

        impl Div<i64> for $name {
            type Output = $name;
            fn div(self, other: i64) -> $name {
                self / &$name::from(other)
            }
        }

        impl<'a> Div<&'a $name> for i64 {
            type Output = $name;
            fn div(self, other: &'a $name) -> $name {
                if self == 1 {
                    other.invert()
                } else {
                    &$name::from(self) / other
                }
            }
        }

        impl Div<$name> for i64 {
            type Output = $name;
            fn div(self, other: $name) -> $name {
                if self == 1 {
                    other.invert()
                } else {
                    &$name::from(self) / other
                }
            }
        }

        // -------------------------------------------

        impl<'a> DivAssign<&'a $name> for $name {
            fn div_assign(&mut self, other: &'a $name) {
                *self *= &other.invert();
            }
        }

        impl DivAssign<$name> for $name {
            fn div_assign(&mut self, other: $name) {
                *self *= &other.invert();
            }
        }

        impl DivAssign<i64> for $name {
            fn div_assign(&mut self, other: i64) {
                *self /= &$name::from(other);
            }
        }

        // -------------------------------------------

        /*
        // nobody wants to see this level of detail unless they are debugging
        // a new implementation of field arithmetic...
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "U256([{:016x}, {:016x}, {:016x}, {:016x}])",
                    self.0[0] as u64, self.0[1] as u64, self.0[2] as u64, self.0[3] as u64
                )
            }
        }
        */

        // show this instead...
        // Problem with Rust: there needs to be more than one level of debug printout
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $fmt, self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let bytes = self.to_hex();
                let nel = bytes.len();
                write!(f, "{}({}..{})", $hash, &bytes[0..7], &bytes[nel - 7..nel])
            }
        }
    };
}

const ZR_SQUARED: Fr = Fr::Scaled(U256(
    [
        0x32A1CB0B0D0DF74A,
        0x7FE44146DFCFDAF8,
        0xAF59BBB1E8ACC494,
        0x1A6134EBBFC821,
    ],
    false,
)); // (2^256)^2 mod |Fr|
const FRINV: u64 = 0xCD27F41CB1C5286F; // (-1/|Fr|) mod 2^64
const R_ONE: Fr = Fr::Scaled(U256([0x5D95D0174C9B4780, 0x434D1D90167C65BB, 4, 0], false)); // = 2^256 mod |Fr|
const ZR_CUBED: Fr = Fr::Scaled(U256(
    [
        0x4BC368544B1323FA,
        0xACA9EEEE6129D3CC,
        0xA005B5D44D4502BD,
        0x11ECFA1EAC284DF,
    ],
    false,
)); // = (2^256)^3 mod |Fr|

const ZQ_SQUARED: Fq = Fq::Scaled(U256([0x014400, 0x00, 0x00, 0x00], false)); // (2^256)^2 mod |Fq|
const FQINV: u64 = 0x8E38E38E38E38E39; // (-1/|Fq|) mod 2^64
const Q_ONE: Fq = Fq::Scaled(U256([0x0120, 0x00, 0x00, 0x00], false)); // = 2^256 mod |Fq|
const ZQ_CUBED: Fq = Fq::Scaled(U256([0x016C8000, 0x00, 0x00, 0x00], false)); // = (2^256)^3 mod |Fq|

field_impl!(Fr, R, ZR_SQUARED, ZR_CUBED, R_ONE, FRINV, "Fr", "Fr({})", RMIN);
field_impl!(Fq, Q, ZQ_SQUARED, ZQ_CUBED, Q_ONE, FQINV, "Fq", "Fq({})", QMIN);

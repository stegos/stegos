// Test Fast Implementation of Edwards Curve Curve1174
// DM/Emotiq 08/18
/* -------------------------------------------------------------------------
The MIT License

Copyright (c) 2018 Emotiq AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
----------------------------------------------------------------------------
Internally, ECC point multiplication depends on projective coordinates expressed 
as 4 components (x, y, z, t), each of which is expressed as 51-bit integer fragments 
of a 256 bit number. This permits very fast addition/subtraction of field elements, 
with overflows spilling into the upper bits of each 64-bit fragment. During multiply 
operations these overflows are reapportioned to higher fragments.

Externally the field elements of the coordinates are held as 256 bit bignums in 
little-endian order, normally expressed as quads of 64-bit unsigned fragments. When 
necessary, these are forcibly viewed through an "unsafe" transformation to/from 32-bytes.

---------------------------------------------------------------------------- */

extern crate stegos_crypto;

use std::fmt;
use std::mem;

// #[macro_use]
// extern crate derive_more;
extern crate bn;
extern crate libc;
use libc::{c_int, size_t};

extern crate rand;
// extern crate crypto;
extern crate sha3;

use rand::prelude::*;
// use crypto::digest::Digest;
// use crypto::sha3::Sha3;
use sha3::{Digest, Sha3_256};
use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign, DivAssign};
use std::cmp::Ordering;

// extern crate field;
// use field::*;

// -----------------------------------------------------------------

const WINDOW : usize  =  4; // using 4-bit fixed windows

const BOT_51_BITS : i64 = ((1 << 51) - 1); // FQ51 frames contain 51 bits
const BOT_47_BITS : i64 = ((1 << 47) - 1); // MSB frame only has 47 bits
const CURVE_D     : i64 = -1174; // the d value in the curve equation

// nbr of precomputed point multiples
const NPREP: usize = 1 + (1 << (WINDOW-1));

// -----------------------------------------------------------------
// window vector of 4-bit values

const PANES  : usize  = 64; // nbr of 4-bit nibbles in 256-bit numbers

#[repr(C)]
struct WinVec([i8;PANES]);

const WINVEC_INIT: WinVec = WinVec([0;PANES]);

/* --- */
// -----------------------------------------------------------------
// type LEV32 represents a 256-bit bignum as a little-endian 32-byte vector

#[derive(Copy, Clone)]
#[repr(C)]
struct LEV32([u8;32]);

impl fmt::Display for LEV32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LEV32({})", self.nbr_str())
    }
}

impl LEV32 {
    fn nbr_str(&self) -> String {
        let LEV32(qv) = self;
        let v = unsafe { mem::transmute::<[u8;32], [u64;4]>(*qv) };
        basic_nbr_str(&v)
    }
}

// -----------------------------------------------------------------
// U256 word chunks represent a 256-bit bignum as a little-endian u64 vector

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
struct U256([u64;4]);

impl U256 {
    fn zero() -> U256 {
        U256([0;4])
    }

    fn one() -> U256 {
        U256([1,0,0,0])
    }

    fn nbr_str(&self) -> String {
        basic_nbr_str(&self.0)
    }

    fn add_mod(&mut self, other: &U256, modulo: &U256) {
        add_nocarry(&mut self.0, &other.0);
        if *self >= *modulo {
            sub_noborrow(&mut self.0, &modulo.0);
        }
    }

    fn sub_mod(&mut self, other: &U256, modulo: &U256) {
        if *self < *other {
            add_nocarry(&mut self.0, &modulo.0);
        }
        sub_noborrow(&mut self.0, &other.0);
    }

    fn neg_mod(&mut self, modulo: &U256) {
        if *self > Self::zero() {
            let mut tmp = modulo.0;
            sub_noborrow(&mut tmp, &self.0);
            self.0 = tmp;
        }
    }

    /// Multiply `self` by `other` (mod `modulo`) via the Montgomery
    /// multiplication method.
    fn mul_mod(&mut self, other: &U256, modulo: &U256, inv: u64) {
        mul_reduce(&mut self.0, &other.0, &modulo.0, inv);

        if *self >= *modulo {
            sub_noborrow(&mut self.0, &modulo.0);
        }
    }

    #[inline]
    fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }

    /// Turn `self` into its multiplicative inverse (mod `modulo`)
    fn invert_mod(&mut self, modulo: &U256) {
        // Guajardo Kumar Paar Pelzl
        // Efficient Software-Implementation of Finite Fields with Applications to Cryptography
        // Algorithm 16 (BEA for Inversion in Fp)

        let mut u = *self;
        let mut v = *modulo;
        let mut b = U256::one();
        let mut c = U256::zero();

        while u != U256::one() && v != U256::one() {
            while u.is_even() {
                div2(&mut u.0);

                if b.is_even() {
                    div2(&mut b.0);
                } else {
                    add_nocarry(&mut b.0, &modulo.0);
                    div2(&mut b.0);
                }
            }
            while v.is_even() {
                div2(&mut v.0);

                if c.is_even() {
                    div2(&mut c.0);
                } else {
                    add_nocarry(&mut c.0, &modulo.0);
                    div2(&mut c.0);
                }
            }

            if u >= v {
                sub_noborrow(&mut u.0, &v.0);
                b.sub_mod(&c, modulo);
            } else {
                sub_noborrow(&mut v.0, &u.0);
                c.sub_mod(&b, modulo);
            }
        }

        if u == U256::one() {
            self.0 = b.0;
        } else {
            self.0 = c.0;
        }
    }

    fn to_FQ51(self) -> FQ51 {
        let mut tmp = FQ51::zero();
        bin_to_elt(&self, &mut tmp);
        tmp
    }

    fn to_winvec(self) -> WinVec {
        let qv: [u8;32] = unsafe { mem::transmute::<[u64;4], [u8;32]>(self.0) };
        let mut wv = WINVEC_INIT;
        cwin4(&LEV32(qv), &mut wv);
        wv
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()).rev() {
            if *a < *b {
                return Ordering::Less;
            }
            else if *a > *b {
                return Ordering::Greater;
            }
        }
        return Ordering::Equal;
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "U256([{:016x}, {:016x}, {:016x}, {:016x}])", 
            self.0[0] as u64,
            self.0[1] as u64,
            self.0[2] as u64,
            self.0[3] as u64)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "U256({})", self.nbr_str())
    }
}

impl From<FR> for U256 {
    fn from(x: FR) -> U256 {
        let mut tmp = x.0;
        mul_collapse(&mut tmp.0, &R.0, FRINV);
        tmp
    }
}

// -------------------------------------------------------------------------
// Primitive ops for U256, on raw arrays of 4 x u64

/// Divide by two
#[inline]
fn div2(a: &mut [u64; 4]) {
    let mut t = a[3] << 63;
    a[3] = a[3] >> 1;
    let b = a[2] << 63;
    a[2] >>= 1;
    a[2] |= t;
    t = a[1] << 63;
    a[1] >>= 1;
    a[1] |= b;
    a[0] >>= 1;
    a[0] |= t;
}

/// Multiply by two
#[inline]
fn mul2(a: &mut [u64; 4]) {
    let mut last = 0;
    for i in a {
        let tmp = *i >> 63;
        *i <<= 1;
        *i |= last;
        last = tmp;
    }
}

fn split_u64(i : u64) -> (u64, u64) {
    (i >> 32, i & ((1 << 32) - 1))
}

fn combine_u64(hi: u64, lo: u64) -> u64 {
    (hi << 32) | lo
}

fn adc(a: u64, b: u64, carry: &mut u64) -> u64 {
    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c, r0) = split_u64(a0 + b0 + *carry);
    let (c, r1) = split_u64(a1 + b1 + c);
    *carry = c;

    combine_u64(r1, r0)
}

fn add_nocarry(a: &mut [u64;4], b: &[u64; 4]) {
    let mut carry = 0;
    for (a, b) in a.into_iter().zip(b.iter()) {
        *a = adc(*a, *b, &mut carry);
    }
    debug_assert!(0 == carry);
}

fn sub_noborrow(a: &mut [u64;4], b: &[u64;4]) {
    fn sbb(a: u64, b: u64, borrow: &mut u64) -> u64 {
        let (a1,a0) = split_u64(a);
        let (b1,b0) = split_u64(b);
        let (b, r0) = split_u64((1 << 32) + a0 - b0 - *borrow);
        let (b, r1) = split_u64((1 << 32) + a1 - b1 - ((b == 0) as u64));
        *borrow = (b == 0) as u64;
        combine_u64(r1, r0)
    }

    let mut borrow = 0;
    for (a, b) in a.into_iter().zip(b.iter()) {
        *a = sbb(*a, *b, &mut borrow);
    }
    debug_assert!(0 == borrow);
}

fn mac_digit(acc: &mut [u64], b: &[u64], c: u64)
{
    #[inline]
    fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u64) -> u64 {
        let (b_hi, b_lo) = split_u64(b);
        let (c_hi, c_lo) = split_u64(c);

        let (a_hi, a_lo) = split_u64(a);
        let (carry_hi, carry_lo) = split_u64(*carry);
        let (x_hi, x_lo) = split_u64(b_lo * c_lo + a_lo + carry_lo);
        let (y_hi, y_lo) = split_u64(b_lo * c_hi);
        let (z_hi, z_lo) = split_u64(b_hi * c_lo);
        let (r_hi, r_lo) = split_u64(x_hi + y_lo + z_lo + a_hi + carry_hi);

        *carry = (b_hi * c_hi) + r_hi + y_hi + z_hi;

        combine_u64(r_lo, x_lo)
    }

    if c == 0 {
        return;
    }

    let mut b_iter = b.iter();
    let mut carry = 0;

    for ai in acc.iter_mut() {
        if let Some(bi) = b_iter.next() {
            *ai = mac_with_carry(*ai, *bi, c, &mut carry);
        } else if carry != 0 {
            *ai = mac_with_carry(*ai, 0, c, &mut carry);
        } else {
            break;
        }
    }

    debug_assert!(carry == 0);
}

#[inline]
fn mul_reduce(
    this: &mut [u64; 4],
    by: &[u64; 4],
    modulus: &[u64; 4],
    inv: u64
)
{
    // This function produces the Montgomery reduction of the product
    // of a = `this` and b = `by`, modulo m = `modulus`. That means that 
    // we get
    //
    //       result = ((a * b)/Z) mod m
    //
    // where Z = 2^256 mod m. Parameter `inv` = -1/m mod 2^64.
    //
    // If a and b are pre-scaled by Z, then so is their product.
    // To convert back to raw form (non-prescale), perform a multiply with
    // a unit vector [1,0,0,0].
    //
    // The Montgomery reduction here is based on Algorithm 14.32 in
    // Handbook of Applied Cryptography
    // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

    let mut res = [0; 2*4];
    for (i, xi) in this.iter().enumerate() {
        // this produces a double-wide product in `res`
        mac_digit(&mut res[i..], by, *xi);
    }

    for i in 0..4 {
        // Montgomery reduction
        let k = inv.wrapping_mul(res[i]);
        mac_digit(&mut res[i..], modulus, k);
    }

    this.copy_from_slice(&res[4..]);
}

fn mul_collapse(this: &mut [u64;4], modulus: &[u64;4], inv: u64) {
    // this is a short circuiting function for removing the Montgomery prescaling
    // slightly faster than a full multiply by [1,0,0,0]
    let mut res = [0; 2*4];
    for (i, xi) in this.iter().enumerate() {
        res[i] = *xi;
    }
    for i in 0..4 {
        // Montgomery reduction
        let k = inv.wrapping_mul(res[i]);
        mac_digit(&mut res[i..], modulus, k);
    }
    this.copy_from_slice(&res[4..]);
}

// produce a 256-bit bignum string from a LEV of [u64;4]
fn basic_nbr_str(x: &[u64;4]) -> String {
    format!("{:016x}{:016x}{:016x}{:016x}", 
        x[3], x[2], x[1], x[0])
}

// -----------------------------------------------------------------
// FR is the field on the curve.  |FR| * GenPt = INF
// |FR| < |FQ|, both |FR| and |FQ| are prime.

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
struct FR(U256);

const R : U256 = U256([0x8944D45FD166C971, 0xF77965C4DFD30734, 0xFFFFFFFFFFFFFFFF, 0x1FFFFFFFFFFFFFF]); // |FR|

const Z_SQUARED : FR = FR(U256([0x32A1CB0B0D0DF74A, 0x7FE44146DFCFDAF8, 0xAF59BBB1E8ACC494, 0x1A6134EBBFC821])); // (2^256)^2 mod |FR|
const FRINV : u64 = 0xCD27F41CB1C5286F; // (-1/|FR|) mod 2^64
const R_ONE : FR = FR(U256([0x5D95D0174C9B4780, 0x434D1D90167C65BB, 4, 0])); // = 2^256 mod |FR|
const Z_CUBED : FR = FR(U256([0x4BC368544B1323FA, 0xACA9EEEE6129D3CC, 0xA005B5D44D4502BD, 0x11ECFA1EAC284DF]));

impl PartialOrd for FR {
    fn partial_cmp(&self, other: &FR) -> Option<Ordering> {
        U256::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for FR {
    fn cmp(&self, other: &FR) -> Ordering {
        U256::cmp(&self.0, &other.0)
    }
}
/* --- */

// -------------------------------------------------------------------

impl FR {
    fn zero() -> FR {
        FR(U256::zero())
    }

    fn one() -> FR {
        R_ONE
    }

    fn to_winvec(self) -> WinVec {
        let tmp = U256::from(self);
        U256::to_winvec(tmp)
    }

    fn invert(self) -> FR {
        let mut tmp = self;
        U256::invert_mod(&mut tmp.0, &R);
        Z_CUBED * tmp
    }

    fn i64_to_U256(x: i64) -> U256 {
        if x >= 0 {
            U256([x as u64, 0, 0, 0])
        }
        else {
            let tmp = [(-x) as u64, 0, 0, 0];
            let mut tmp2 = R.0;
            sub_noborrow(&mut tmp2, &tmp);
            U256(tmp2)
        }
    }

    fn i64_to_winvec(x: i64) -> WinVec {
        U256::to_winvec(Self::i64_to_U256(x))
    }

    fn i64_to_FR(x: i64) -> FR {
        FR(Self::i64_to_U256(x))
    }
}

impl fmt::Display for FR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = U256::from(*self);
        write!(f, "FR({})", tmp.nbr_str())
    }
}

impl From<i64> for FR {
    fn from(x: i64) -> FR {
        Z_SQUARED * FR::i64_to_FR(x)
    }
}

impl From<U256> for FR {
    fn from(x: U256) -> FR {
        Z_SQUARED * FR(x)
    }
}

impl Add<FR> for FR {
    type Output = FR;
    fn add(self, other: FR) -> FR {
        let mut tmp = self;
        U256::add_mod(&mut tmp.0, &other.0, &R);
        tmp
    }
}

impl Add<i64> for FR {
    type Output = FR;
    fn add(self, other: i64) -> FR {
        self + FR::from(other)
    }
}

impl Add<FR> for i64 {
    type Output = FR;
    fn add(self, other: FR) -> FR {
        FR::from(self) + other
    }
}

impl AddAssign<FR> for FR {
    fn add_assign(&mut self, other: FR) {
        U256::add_mod(&mut self.0, &other.0, &R);
    }
}

impl AddAssign<i64> for FR {
    fn add_assign(&mut self, other: i64) {
        *self += FR::from(other);
    }
}

impl Sub<FR> for FR {
    type Output = FR;
    fn sub(self, other: FR) -> FR {
        let mut tmp = self;
        U256::sub_mod(&mut tmp.0, &other.0, &R);
        tmp
    }
}

impl Sub<i64> for FR {
    type Output = FR;
    fn sub(self, other: i64) -> FR {
        self - FR::from(other)
    }
}

impl Sub<FR> for i64 {
    type Output = FR;
    fn sub(self, other: FR) -> FR {
        FR::from(self) - other
    }
}

impl SubAssign<FR> for FR {
    fn sub_assign(&mut self, other: FR) {
        U256::sub_mod(&mut self.0, &other.0, &R);
    }
}

impl SubAssign<i64> for FR {
    fn sub_assign(&mut self, other: i64) {
        *self -= FR::from(other);
    }
}

impl Neg for FR {
    type Output = FR;
    fn neg(self) -> FR {
        let mut tmp = self;
        U256::neg_mod(&mut tmp.0, &R);
        tmp
    }
}

impl Mul<FR> for FR {
    type Output = FR;
    fn mul(self, other: FR) -> FR {
        let mut tmp = self;
        U256::mul_mod(&mut tmp.0, &other.0, &R, FRINV);
        tmp
    }
}

impl Mul<i64> for FR {
    type Output = FR;
    fn mul(self, other: i64) -> FR {
        self * FR::from(other)
    }
}

impl Mul<FR> for i64 {
    type Output = FR;
    fn mul(self, other: FR) -> FR {
        other * self
    }
}

impl MulAssign<FR> for FR {
    fn mul_assign(&mut self, other: FR) {
        U256::mul_mod(&mut self.0, &other.0, &R, FRINV);
    }
}

impl MulAssign<i64> for FR {
    fn mul_assign(&mut self, other: i64) {
        *self *= FR::from(other);
    }
}

impl Div<FR> for FR {
    type Output = FR;
    fn div(self, other: FR) -> FR {
        self * FR::invert(other)
    }
}

impl Div<i64> for FR {
    type Output = FR;
    fn div(self, other: i64) -> FR {
        self / FR::from(other)
    }
}

impl Div<FR> for i64 {
    type Output = FR;
    fn div(self, other: FR) -> FR {
        if self == 1 {
            FR::invert(other)
        } else {
            FR::from(self) / other
        }
    }
}

impl DivAssign<FR> for FR {
    fn div_assign(&mut self, other: FR) {
        *self *= FR::invert(other);
    }
}

impl DivAssign<i64> for FR {
    fn div_assign(&mut self, other: i64) {
        *self /= FR::from(other);
    }
}

// -----------------------------------------------------------------
// FQ is the field in which the curve is computed - coords are all elements of FQ
// In Elliptic curve point operations these coordinates are converted to FQ51 representation

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
struct FQ(U256);

const Q : U256 = U256([0xFFFFFFFFFFFFFFF7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFF]); // |FQ|

impl PartialOrd for FQ {
    fn partial_cmp(&self, other: &FQ) -> Option<Ordering> {
        U256::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for FQ {
    fn cmp(&self, other: &FQ) -> Ordering {
        U256::cmp(&self.0, &other.0)
    }
}

impl FQ {
    fn to_FQ51(self) -> FQ51 {
        U256::to_FQ51(self.0)
    }
}

// -----------------------------------------------------------------
// field FQ51 is FQ broken into 51-bit frames 
// in little-endian order, of i64 (vs u64 in FQ)
// 47 bits in last frame

#[derive(Copy, Clone, PartialEq)]
#[repr(C)]
struct FQ51([i64;5]);

const FQ51_0 : FQ51 = FQ51([0;5]);
const FQ51_1 : FQ51 = FQ51([1,0,0,0,0]);

impl FQ51 {
    fn zero() -> FQ51 {
        FQ51_0
    }

    fn one() -> FQ51 {
        FQ51_1
    }

    fn sqr(self) -> FQ51 {
        let mut tmp = FQ51::zero();
        gsqr(&self, &mut tmp);
        tmp
    }

    fn nbr_str(&self) -> String {
        let mut y: U256 = U256::zero();
        elt_to_bin(self, &mut y);
        let U256(yv) = y;
        basic_nbr_str(&yv)
    }

    fn to_FQ(self) -> FQ {
        FQ(Self::to_U256(self))
    }

   fn to_U256(self) -> U256 {
        let mut tmp = U256::zero();
        elt_to_bin(&self, &mut tmp);
        tmp
   }
}


impl fmt::Debug for FQ51 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FQ51([{:016x}, {:016x}, {:016x}, {:016x}, {:016x}])",
          self.0[0] as u64, 
          self.0[1] as u64,
          self.0[2] as u64,
          self.0[3] as u64,
          self.0[4] as u64)
    }
}

impl fmt::Display for FQ51 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FQ51({})", self.nbr_str())
    }
}

impl Add<FQ51> for FQ51 {
    type Output = FQ51;
    fn add(self, other: FQ51) -> FQ51 {
        let mut dst = FQ51::zero();
        for i in 0..5 {
            dst.0[i] = self.0[i] + other.0[i];
        }
        dst
    }
}

impl Add<i64> for FQ51 {
    type Output = FQ51;
    fn add(self, other: i64) -> FQ51 {
        let mut dst = self;
        dst.0[0] += other;
        dst
    }
}

impl AddAssign<FQ51> for FQ51 {
    fn add_assign(&mut self, other: FQ51) {
        for i in 0..5 {
            self.0[i] += other.0[i];
        }
    }
}

impl AddAssign<i64> for FQ51 {
    fn add_assign(&mut self, other: i64) {
        self.0[0] += other;
    }
}

impl Sub<FQ51> for FQ51 {
    type Output = FQ51;
    fn sub(self, other: FQ51) -> FQ51 {
        let mut dst = FQ51::zero();
        for i in 0..5 {
            dst.0[i] = self.0[i] - other.0[i];
        }
        dst
    }
}

impl Sub<i64> for FQ51 {
    type Output = FQ51;
    fn sub(self, other: i64) -> FQ51 {
        let mut dst = self;
        dst.0[0] -= other;
        dst
    }
}

impl SubAssign<FQ51> for FQ51 {
    fn sub_assign(&mut self, other: FQ51) {
        for i in 0..5 {
            self.0[i] -= other.0[i];
        }
    }
}

impl SubAssign<i64> for FQ51 {
    fn sub_assign(&mut self, other: i64) {
        self.0[0] -= other;
    }
}

impl Neg for FQ51 {
    type Output = FQ51;
    fn neg(self) -> FQ51 {
        let mut dst = FQ51::zero();
        for i in 0..5 {
            dst.0[i] = -self.0[i];
        }
        dst
    }
}

impl Mul<FQ51> for FQ51 {
    type Output = FQ51;
    fn mul(self, other: FQ51) -> FQ51 {
        let mut dst = FQ51::zero();
        if self == other {
            gsqr(&self, &mut dst)
        } else {
            gmul(&self, &other, &mut dst);
        }
        dst
    }
}

impl MulAssign<FQ51> for FQ51 {
    fn mul_assign(&mut self, other: FQ51) {
        let tmp = *self;
        if *self == other {
            gsqr(&tmp, self)
        } else {
            gmul(&tmp, &other, self);
        }
    }
}

impl Mul<FQ51> for i64 {
    type Output = FQ51;
    fn mul(self, other: FQ51) -> FQ51 {
        let mut dst = other;
        gmuli(&mut dst, self);
        dst
    }
}

impl Mul<i64> for FQ51 {
    type Output = FQ51;
    fn mul(self, other: i64) -> FQ51 {
        let mut dst = self;
        gmuli(&mut dst, other);
        dst
    }
}

impl MulAssign<i64> for FQ51 {
    fn mul_assign(&mut self, other: i64) {
        gmuli(self, other);
    }
}

// ---------------------------------------------------------
// Group primitive operators

fn gadd(x: &FQ51, y: &FQ51, w: &mut FQ51) {
    w.0[0] = x.0[0] + y.0[0];
    w.0[1] = x.0[1] + y.0[1];
    w.0[2] = x.0[2] + y.0[2];
    w.0[3] = x.0[3] + y.0[3];
    w.0[4] = x.0[4] + y.0[4];
}

fn gsub(x: &FQ51, y: &FQ51, w: &mut FQ51) {
    w.0[0] = x.0[0] - y.0[0];
    w.0[1] = x.0[1] - y.0[1];
    w.0[2] = x.0[2] - y.0[2];
    w.0[3] = x.0[3] - y.0[3];
    w.0[4] = x.0[4] - y.0[4];
}

fn gdec(x: &FQ51, w: &mut FQ51) {
    w.0[0] -= x.0[0];
    w.0[1] -= x.0[1];
    w.0[2] -= x.0[2];
    w.0[3] -= x.0[3];
    w.0[4] -= x.0[4];
}

fn gneg(w: &FQ51, x: &mut FQ51) {
    x.0[0] = -w.0[0];
    x.0[1] = -w.0[1];
    x.0[2] = -w.0[2];
    x.0[3] = -w.0[3];
    x.0[4] = -w.0[4];
}

// w*=2
fn gmul2(w: &mut FQ51) {
    w.0[0] *= 2;
    w.0[1] *= 2;
    w.0[2] *= 2;
    w.0[3] *= 2;
    w.0[4] *= 2;
}

// w-=2*x
fn gsb2(x: &FQ51, w: &mut FQ51) {
    w.0[0] -= 2*x.0[0];
    w.0[1] -= 2*x.0[1];
    w.0[2] -= 2*x.0[2];
    w.0[3] -= 2*x.0[3];
    w.0[4] -= 2*x.0[4];
}

// reduce w - Short Coefficient Reduction
fn scr(w: &mut FQ51) {
    let w0 = w.0[0];
    let t0 = w0 & BOT_51_BITS;
 
    let t1 = w.0[1] + (w0 >> 51);
    w.0[1] = t1 & BOT_51_BITS;

    let t2 = w.0[2] + (t1 >> 51);
    w.0[2] = t2 & BOT_51_BITS;

    let t3 = w.0[3] + (t2 >> 51);
    w.0[3] = t3 & BOT_51_BITS;

    let t4 = w.0[4] + (t3 >> 51);
    w.0[4] = t4 & BOT_47_BITS;
    w.0[0] = t0 + 9*(t4 >> 47);
}

// multiply w by a constant, w*=i

fn gmuli(w: &mut FQ51, i: i64) {
    let ii = i as i128;
    let t0 = (w.0[0] as i128) * ii;
    w.0[0] = (t0 as i64) & BOT_51_BITS;

    let t1 = (w.0[1] as i128) * ii + (t0 >> 51);
    w.0[1] = (t1 as i64) & BOT_51_BITS;

    let t2 = (w.0[2] as i128) * ii + (t1 >> 51);
    w.0[2] = (t2 as i64) & BOT_51_BITS;

    let t3 = (w.0[3] as i128) * ii + (t2 >> 51);
    w.0[3] = (t3 as i64) & BOT_51_BITS;

    let t4 = (w.0[4] as i128) * ii + (t3 >> 51);
    w.0[4] = (t4 as i64) & BOT_47_BITS;
    w.0[0] += (9 * (t4 >> 47)) as i64;
}

// z=x^2

fn gsqr(x: &FQ51, z: &mut FQ51) {
    let t4 = 2*((x.0[0] as i128) * (x.0[4] as i128) +
                (x.0[1] as i128) * (x.0[3] as i128)) +
            (x.0[2] as i128) * (x.0[2] as i128);
    z.0[4] = (t4 as i64) & BOT_47_BITS;

    let t0 = (x.0[0] as i128)*(x.0[0] as i128) +
                 288*((x.0[1] as i128)*(x.0[4] as i128) +
                      (x.0[2] as i128)*(x.0[3] as i128)) +
                   9*(t4 >> 47);
    z.0[0] = (t0 as i64) & BOT_51_BITS;
    
    let t1 = 2*(x.0[0] as i128)*(x.0[1] as i128) +
         288*(x.0[2] as i128)*(x.0[4] as i128) +
         144*(x.0[3] as i128)*(x.0[3] as i128) +
         (t0 >> 51);
    z.0[1] = (t1 as i64) & BOT_51_BITS;

    let t2 = (x.0[1] as i128)*(x.0[1] as i128) +
         2*(x.0[0] as i128)*(x.0[2] as i128) +
         288*(x.0[3] as i128)*(x.0[4] as i128) +
         (t1 >> 51);
    z.0[2] = (t2 as i64) & BOT_51_BITS;

    let t3 = 144*(x.0[4] as i128)*(x.0[4] as i128) +
           2*((x.0[0] as i128)*(x.0[3] as i128) +
              (x.0[1] as i128)*(x.0[2] as i128)) +
         (t2 >> 51);
    z.0[3] = (t3 as i64) & BOT_51_BITS;

    let t4 = (z.0[4] as i128) + (t3 >> 51);
    z.0[4] = (t4 as i64) & BOT_47_BITS;
    z.0[0] += (9*(t4 >> 47)) as i64;
}

fn gmul(x: &FQ51, y: &FQ51, z: &mut FQ51) {
	// 5M + 4A
    let t4 = (x.0[0] as i128)*(y.0[4] as i128) +
        (x.0[4] as i128)*(y.0[0] as i128) +
        (x.0[1] as i128)*(y.0[3] as i128) +
        (x.0[3] as i128)*(y.0[1] as i128) +
        (x.0[2] as i128)*(y.0[2] as i128);
    z.0[4] = (t4 as i64) & BOT_47_BITS;
    
	// 7M + 5A
    let t0 = (x.0[0] as i128)*(y.0[0] as i128) +
        144*((x.0[1] as i128)*(y.0[4] as i128) +
             (x.0[4] as i128)*(y.0[1] as i128) +
             (x.0[2] as i128)*(y.0[3] as i128) +
             (x.0[3] as i128)*(y.0[2] as i128)) +
        9*(t4 >> 47);
    z.0[0] = (t0 as i64) & BOT_51_BITS;

	// 6M + 5A
    let t1 = (x.0[0] as i128)*(y.0[1] as i128) +
         (x.0[1] as i128)*(y.0[0] as i128) +
         144*((x.0[3] as i128)*(y.0[3] as i128) +
              (x.0[2] as i128)*(y.0[4] as i128) +
              (x.0[4] as i128)*(y.0[2] as i128)) +
         (t0 >> 51);
    z.0[1] = (t1 as i64) & BOT_51_BITS;
    
    // 6M + 5A
    let t2 = (x.0[1] as i128)*(y.0[1] as i128) +
         (x.0[0] as i128)*(y.0[2] as i128) +
         (x.0[2] as i128)*(y.0[0] as i128) +
         144*((x.0[3] as i128)*(y.0[4] as i128) +
              (x.0[4] as i128)*(y.0[3] as i128)) +
         (t1 >> 51);
    z.0[2] = (t2 as i64) & BOT_51_BITS;
    
    // 6M + 5A
    let t3 = 144*((x.0[4] as i128)*(y.0[4] as i128)) +
         (x.0[0] as i128)*(y.0[3] as i128) +
         (x.0[3] as i128)*(y.0[0] as i128) +
         (x.0[1] as i128)*(y.0[2] as i128) +
         (x.0[2] as i128)*(y.0[1] as i128) +
         (t2 >> 51);
    z.0[3] = (t3 as i64) & BOT_51_BITS;

    // -------- to this point = 30M + 24A => this clocks as faster than Granger's method for Curve1174
    let t4 = (z.0[4] as i128) + (t3 >> 51);
    z.0[4] = (t4 as i64) & BOT_47_BITS;
    z.0[0] += (9*(t4 >> 47)) as i64;
}

// Inverse x = 1/x = x^(p-2) mod p
// the exponent (p-2) = "07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5"
// (61 F's)

fn ginv(x: &mut FQ51) {
    let mut w  = FQ51_0;
    let mut t1 = FQ51_0;
    let mut t2;
    let mut x3 = FQ51_0;
    let mut x5 = FQ51_0;
    
    // --------------------------------------
    // 205*M
    gsqr(x, &mut w);      // w = x^2
    gmul(x, &w, &mut x3);   // x3 = x^3 = x^(2^2-1)
    gmul(&w, &x3, &mut x5);  // x5 = x^5

    gsqr(&x3, &mut w);
    gsqr(&w, &mut t1);     // t1 = x^(2^4-4)
    gmul(&x3, &t1, &mut w);  // w = x^(2^4-1)

    gsqr(&w, &mut t1);
    gsqr(&t1, &mut w);     // w = x^(2^6-4)
    gmul(&x3, &w, &mut t1);  // t1 = x^(2^6-1)
    t2 = t1;
    for _ in 0..3 {
	gsqr(&t1, &mut w);
	gsqr(&w, &mut t1);
    }
    gmul(&t1, &t2, &mut w);  // w = x^(2^12-1)
    
    gsqr(&w, &mut t1);
    gsqr(&t1, &mut w);     // w = x^(2^14-4)
    gmul(&x3, &w, &mut t1);  // t1 = x^(2^14-1)
    t2 = t1;
    for _ in 0..7 {
	gsqr(&t1, &mut w);
	gsqr(&w, &mut t1);
    }
    gmul(&t1, &t2, &mut w);  // w = x^(2^28-1)
    
    gsqr(&w, &mut t1);
    gsqr(&t1, &mut w);     // w = x^(2^30-4)
    gmul(&x3, &w, &mut t1);  // t1 = x^(2^30-1)
    t2 = t1;
    for _ in 0..15 {
	gsqr(&t1, &mut w);
	gsqr(&w, &mut t1);
    }
    gmul(&t1, &t2, &mut w);  // w = x^(2^60-1)
    
    t2 = w;
    for _ in 0..30 {
	gsqr(&w, &mut t1);
	gsqr(&t1, &mut w);
    }
    gmul(&w, &t2, &mut t1);  // t1 = x^(2^120-1)
    
    gsqr(&t1, &mut w);
    gsqr(&w, &mut t1);     // t1 = x^(2^122 - 4)
    gmul(&x3, &t1, &mut w);  // w = x^(2^122-1)
    t2 = w;
    for _ in 0..61 {
	gsqr(&w, &mut t1);
	gsqr(&t1, &mut w);
    }
    gmul(&w, &t2, &mut t1);  // t1 = x^(2^244-1)
    
    gsqr(&t1, &mut w);     // w = x^(2^245-2)
    gmul(&x, &w, &mut t1);   // t1 = x^(2^245-1)
    gsqr(&t1, &mut w);      
    gsqr(&w, &mut t1);     // t1 = x^(2^247-4)
    gmul(&x3, &t1, &mut w);  // w = x^(2^247-1)
    
    gsqr(&w, &mut t1);
    gsqr(&t1, &mut w);
    gsqr(&w, &mut t1);
    gsqr(&t1, &mut w);     // w = x^(2^251-16)
    gmul(&x5, &w, x);   // x = x^(2^251-11)
}

fn gdec2(x: &mut FQ51) {
    x.0[0] -= 2;
}

// -------------------------------------------------------------------------
// Point Structure

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
struct ECp { x: FQ51,
             y: FQ51,
             z: FQ51,
             t: FQ51 }

const PT_INF: ECp  = ECp { x: FQ51_0,
                           y: FQ51_1,
                           z: FQ51_1,
                           t: FQ51_0 };

impl ECp {
    fn inf() -> ECp {
        PT_INF
    }

    fn new(x: FQ, y: FQ) -> ECp {
        let fq51_x = x.to_FQ51();
        let fq51_y = y.to_FQ51();
        ECp { x: fq51_x,
              y: fq51_y,
              z: FQ51::one(),
              t: fq51_x * fq51_y }
    }
}

impl fmt::Display for ECp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ECp {{\n x: {},\n y: {},\n z: {},\n t: {} }}", 
            self.x, self.y, self.z, self.t)
    }
}

impl Add<ECp> for ECp {
    type Output = ECp;
    fn add(self, other: ECp) -> ECp {
        let mut tmp = PT_INF;
        add_proj(&self, &other, &mut tmp);
        tmp
    }
}

impl AddAssign<ECp> for ECp {
    fn add_assign(&mut self, other: ECp) {
        let tmp = *self;
        add_proj(&tmp, &other, self);
    }
}

impl Neg for ECp {
    type Output = ECp;
    fn neg(self) -> ECp {
        let mut tmp = ECp::inf();
        tmp.x = -self.x;
        tmp.y =  self.y;
        tmp.z =  self.z;
        tmp.t = -self.t;
        tmp
    }
}

impl Sub<ECp> for ECp {
    type Output = ECp;
    fn sub(self, other: ECp) -> ECp {
        self + (- other)
    }
}

impl SubAssign<ECp> for ECp {
    fn sub_assign(&mut self, other: ECp) {
        *self += -other;
    }
}

impl Mul<FR> for ECp {
    type Output = ECp;
    fn mul(self, other: FR) -> ECp {
        let wv = other.to_winvec();
        let mut tmp = self;
        ecp_mul(&wv, &mut tmp);
        tmp
    }
}

impl Mul<ECp> for FR {
    type Output = ECp;
    fn mul(self, other: ECp) -> ECp {
        other * self
    }
}

impl MulAssign<FR> for ECp {
    fn mul_assign(&mut self, other: FR) {
        let wv = other.to_winvec();
        ecp_mul(&wv, self);
    }
}

impl Mul<i64> for ECp {
    type Output = ECp;
    fn mul(self, other: i64) -> ECp {
        match other {
            0 => ECp::inf(),
            1 => self,
            _ => {
                    let wv = FR::i64_to_winvec(other);
                    let mut tmp = self;
                    ecp_mul(&wv, &mut tmp);
                    tmp
            }
        }
    }
}

impl Mul<ECp> for i64 {
    type Output = ECp;
    fn mul(self, other: ECp) -> ECp {
        other * self
    }
}

impl MulAssign<i64> for ECp {
    fn mul_assign(&mut self, other: i64) {
        match other {
            0 => *self = ECp::inf(),
            1 => (),
            _ => {
                    let wv = FR::i64_to_winvec(other);
                    ecp_mul(&wv, self);
            }
        }
    }
}

impl Div<FR> for ECp {
    type Output = ECp;
    fn div(self, other: FR) -> ECp {
        self * FR::invert(other)
    }
}

impl DivAssign<FR> for ECp {
    fn div_assign(&mut self, other: FR) {
        *self *= FR::invert(other);
    }
}

impl Div<i64> for ECp {
    type Output = ECp;
    fn div(self, other: i64) -> ECp {
        self / FR::from(other)
    }
}

impl DivAssign<i64> for ECp {
    fn div_assign(&mut self, other: i64) {
        *self /= FR::from(other);
    }
}

// --------------------------------------------------------
// Point Operators

// P+=P

fn double_1(pt: &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let e = 2 * pt.t;
    let g = a + b;
    let f = g - 2;
    let h = a - b;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = g * (g - 2);
    pt.t = e * h;
 }

fn double_2(pt: &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let c = 2 * pt.z.sqr();
    let g = a + b;
    let h = a - b;
    let f = g - c;
    let e = (pt.x + pt.y).sqr() - g;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = f * g;
}

fn double_3(pt : &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let c = 2 * pt.z.sqr();
    let g = a + b;
    let h = a - b;
    let f = g - c;
    let e = (pt.x + pt.y).sqr() - g;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = f * g;
    pt.t = e * h;
}

//P+=Q;

fn add_1(qpt: &ECp, ppt: &mut ECp) {
    let a = ppt.x * qpt.x;
    let b = ppt.y * qpt.y;
    let c = ppt.t * qpt.t;
    let f = ppt.z - c;  // reversed sign as d is negative
    let g = ppt.z + c;
    let h = b - a;
    let c = ppt.x + ppt.y;
    let d = qpt.x + qpt.y;
    let e = (c * d) - a - b;
    ppt.x = e * f;
    ppt.y = g * h;
    ppt.z = f * g;
    ppt.t = e * h;
}

fn add_2(qpt: &ECp, ppt: &mut ECp) {
    let a = ppt.x * qpt.x;
    let b = ppt.y * qpt.y;
    let c = ppt.t * qpt.t;
    let d = ppt.z * qpt.z;
    let f = d - c; // reversed sign as d is negative
    let g = d + c;
    let h = b - a;
    let c = ppt.x + ppt.y;
    let d = qpt.x + qpt.y;
    let e = (c * d) - a - b;
    ppt.x = e * f;
    ppt.y = g * h;
    ppt.z = f * g;
}

//P=0

// Initialise P
// incoming x,y coordinates -> ECp in projective coords

fn init(x: &FQ51, y: &FQ51, pt: &mut ECp) {
    (*pt).x = *x;
    (*pt).y = *y;
    (*pt).z = FQ51::one();
    gmul(x, y, &mut pt.t);
}

// P=-Q

fn ecp_neg(qpt: &ECp, ppt: &mut ECp) {
    gneg(&qpt.x, &mut ppt.x);
    ppt.y = qpt.y;
    ppt.z = qpt.z;
    gneg(&qpt.t, &mut ppt.t);
}
   
// Make Affine

fn norm(pt: &mut ECp) {
    let mut w = pt.z;
    ginv(&mut w);
    // (*pt).z = FQ51::one();

    let mut tmp = pt.x * w;
    scr(&mut tmp);
    pt.x = tmp;

    let mut tmp = pt.y * w;
    scr(&mut tmp);
    pt.y = tmp;

    let mut tmp = pt.z * w;
    scr(&mut tmp);
    pt.z = tmp;

    let mut tmp = pt.t * w;
    scr(&mut tmp);
    pt.t = tmp;
}

// Precomputation

fn precomp(pt: &ECp, wpts: &mut [ECp]) {
    let mut tmp1 = *pt;
    gmuli(&mut tmp1.t, CURVE_D);

    let mut tmp2 = *pt;
    double_1(&mut tmp2);
    
    let mut tmp3 = tmp2;
    add_1(&tmp1, &mut tmp3);

    let mut tmp4 = tmp2;
    double_3(&mut tmp4);

    let mut tmp5 = tmp4;
    add_1(&tmp1, &mut tmp5);

    let mut tmp6 = tmp3;
    double_3(&mut tmp6);

    let mut tmp7 = tmp6;
    add_1(&tmp1, &mut tmp7);

    let mut tmp8 = tmp4;
    double_3(&mut tmp8);
    
    // premultiply t parameter by curve constant
    tmp2.t *= CURVE_D;
    tmp3.t *= CURVE_D;
    tmp4.t *= CURVE_D;
    tmp5.t *= CURVE_D;
    tmp6.t *= CURVE_D;
    tmp7.t *= CURVE_D;
    tmp8.t *= CURVE_D;

    wpts[0] = PT_INF;
    wpts[1] = tmp1;
    wpts[2] = tmp2;
    wpts[3] = tmp3;
    wpts[4] = tmp4;
    wpts[5] = tmp5;
    wpts[6] = tmp6;
    wpts[7] = tmp7;
    wpts[8] = tmp8;
}

// Window of width 4

fn window(qpt: &ECp, ppt: &mut ECp) {
    double_2(ppt);
    double_2(ppt);
    double_2(ppt);
    double_3(ppt);
    add_2(qpt, ppt);
}

// Constant time table look-up - borrowed from ed25519 

fn fe_cmov(f: &mut FQ51, g: &FQ51, ib: i8) {
    let b = -ib as i64;
    let FQ51(fv) = f;
    let FQ51(gv) = g;
    fv[0] ^= (fv[0] ^ gv[0]) & b;
    fv[1] ^= (fv[1] ^ gv[1]) & b;
    fv[2] ^= (fv[2] ^ gv[2]) & b;
    fv[3] ^= (fv[3] ^ gv[3]) & b;
    fv[4] ^= (fv[4] ^ gv[4]) & b;
}

fn cmov(w: &mut ECp, u: &ECp, b: i8) {
  fe_cmov(&mut w.x, &u.x, b);
  fe_cmov(&mut w.y, &u.y, b);
  fe_cmov(&mut w.z, &u.z, b);
  fe_cmov(&mut w.t, &u.t, b);
}

// return 1 if b==c, no branching
// must ensure that b, c >= 0
// does not work for negative arguments
// used only for windowing purposes with input values 0..8
fn equal(b: u8, c: u8) -> i8 {
    let x = ((b ^ c) as i8) - 1; // if (b^c) = 0, x now -1
    ((x >> 7) & 1)
}

fn select(tpt: &mut ECp, wpts: &[ECp], b: i8) {
    // incoming window values range from [-8..+8)
    let m = b >> 7;
    let babs = ((b ^ m) - m) as u8;

    cmov(tpt, &wpts[0], equal(babs,0));  // conditional move
    cmov(tpt, &wpts[1], equal(babs,1));
    cmov(tpt, &wpts[2], equal(babs,2));
    cmov(tpt, &wpts[3], equal(babs,3));
    cmov(tpt, &wpts[4], equal(babs,4));
    cmov(tpt, &wpts[5], equal(babs,5));
    cmov(tpt, &wpts[6], equal(babs,6));
    cmov(tpt, &wpts[7], equal(babs,7));
    cmov(tpt, &wpts[8], equal(babs,8)); 
    
    let mtpt = -(*tpt);
    cmov(tpt, &mtpt, m & 1);
}

// Point Multiplication - exponent is 251 bits

// multiply incoming projective point, 
// return result in projective coords
fn mul_to_proj(w: &WinVec, ppt: &mut ECp) {
    let mut wpts = [PT_INF; NPREP];
    precomp(ppt, &mut wpts);

    let WinVec(wv) = w;
    let ix = w.0[PANES-1] as usize;
    *ppt = wpts[ix];
    let mut jx = PANES-1;
    let mut qpt = PT_INF;
    for _ in 0..(PANES-1) {
        jx -= 1;
        select(&mut qpt, &wpts, w.0[jx]);
        window(&qpt, ppt);
    }
}

// multiply incoming projective point,
// return result in affine coords
fn ecp_mul(w: &WinVec, ppt: &mut ECp) {
    mul_to_proj(w, ppt);
    norm(ppt);
}

// convert incoming LEV32 (byte vector) into a little endian vector
// of bipolar window values [-8..8)
fn cwin4(q: &LEV32, w: &mut WinVec) {
    // convert incoming N to bipolar 4-bit window vector - no branching
    let mut cy = 0;
    let mut cvbip = | v_in | {
        let mut v = cy + (v_in as i8);
        cy = v >> 3;
        cy |= cy >> 1;
        cy &= 1;
        v -= cy << 4;
        v
    };
    
    for ix in 0..32 {
        let byt = q.0[ix];
        let v = cvbip(byt & 15);
        let jx = 2*ix;
        w.0[jx] = v;
        let v = cvbip(byt >> 4);
        w.0[jx+1] = v;
    }
}

// point additon of two projective points
fn add_proj(qpt: &ECp, ppt: &ECp, zpt: &mut ECp) {
    // Add Q to P, both in projective (X,Y,Z) coordinates. We don't use T here.
    let a = qpt.z * ppt.z;
    let b = a.sqr();
    let c = qpt.x * ppt.x;
    let d = qpt.y * ppt.y;
    let e = CURVE_D * c * d;
    let f = b - e;
    let g = b + e;
    let x3 = qpt.x + qpt.y;
    let y3 = ppt.x + ppt.y;
    let z3 = x3 * y3;
    let y3 = z3 - c;
    let x3 = y3 - d;
    let y3 = f * x3;
    let x3 = a * y3;
    let y3 = d - c;
    let z3 = g * y3;
    let y3 = a * z3;
    let z3 = f * g; // c = 1
    zpt.x = x3;
    zpt.y = y3;
    zpt.z = z3;
    zpt.t = FQ51::zero();
}

// -------------------------------------------------------------------------------
fn main() {
    pbc_echo(b"This is a test!");

    let smul = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
    let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";  // *ed-gen* x
    let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";  // *ed-gen* y

    let gx = str_to_FQ(sx);
    let gy = str_to_FQ(sy);
    let mx = str_to_FR(smul);
    let mut pt2 : ECp = ECp::inf();
    for _ in 0..100 {
        let pt1 = ECp::new(gx, gy);
        pt2 = pt1 * mx;
    }
    println!("pt2: {}", pt2);

    let pt1 = ECp::new(gx, gy);
    let pt2 = pt1 + pt1;
    println!("ptsum {}", pt2);

    // --------------------------------------------
    // multiplier in 4-bit window form
    let mut w = WINVEC_INIT;
    str_to_winvec(smul, &mut w);

    let mut gen_x = FQ51::zero();
    let mut gen_y = FQ51::zero();
    str_to_elt(sx, &mut gen_x); // *ed-gen*
    str_to_elt(sy, &mut gen_y);

    println!("The Generator Point");
    println!("gen_x: {}", gen_x);
    println!("gen_y: {}", gen_y);

    let mut pt1 = PT_INF;
    for _ in 0..100 {
        init(&gen_x, &gen_y, &mut pt1);
        ecp_mul(&w, &mut pt1);
    }
   
    println!("Result as Bignums");
    println!("pt: {}", pt1);
    
    println!("Result as FQ51s");
    println!("pt: {:#?}", pt1);

    let tmp = FR::from(2);
    let tmp2 = 1 / tmp;
    // println!("1/mul: {}", 1/FR::from(2));
    // println!("unity? {}", (1/FR::from(2)) * 2);
    println!("mul: {}", tmp);
    println!("1/2 = {}", tmp2);
    println!("R = {}", R);
    println!("mx: {}", tmp * tmp2);
    /* */
    let _ = StdRng::from_entropy();
    let mut r = StdRng::from_rng(thread_rng()).unwrap();
    let mut x: [u8;32] = [0;32];
    for _ in 0..10 {
        r.fill_bytes(&mut x);
        println!("{:?}", &x);
    }
    /* */
    let mut hasher = Sha3_256::new();
    hasher.input(b"");
    let hex = hasher.result();
    println!("Hash = {:?}", hex);
    /* */
    /*
    let mut hasher = Sha3_256::default();
    hasher.input(b"");
    let out = hasher.result();
    println!("{:x}", out);
    */
    println!("x+y: {}", gen_x + gen_y)
    /* */
} 

// -------------------------------------------------------------------------------
// Binary/frames conversions

// convert a frame FQ51 from 51-bit representation into
// into a collection of 64-bit cells
fn elt_to_bin(x: &FQ51, y: &mut U256) {
    let mut xx = *x;
    scr(&mut xx);
    let mut s  = xx.0[0] as u128;
    s += (xx.0[1] as u128) << 51;
    y.0[0] = s as u64;
    s >>= 64;
    s += (xx.0[2] as u128) << (2*51-64);
    y.0[1] = s as u64;
    s >>= 64;
    s += (xx.0[3] as u128) << (3*51-128);
    y.0[2] = s as u64;
    s >>= 64;
    s += (xx.0[4] as u128) << (4*51-192);
    y.0[3] = s as u64;
}

// convert consecutive (little-endian) 64-bit cells
// into 51-bit representation
fn bin_to_elt(y: &U256, x: &mut FQ51) {
    {
        let mut s = y.0[0] as u128;
        x.0[0] = (s as i64) & BOT_51_BITS;
        s >>= 51;
        s += (y.0[1] as u128) << (64-51);
        x.0[1] = (s as i64) & BOT_51_BITS;
        s >>= 51;
        s += (y.0[2] as u128) << (128-2*51);
        x.0[2] = (s as i64) & BOT_51_BITS;
        s >>= 51;
        s += (y.0[3] as u128) << (192-3*51);
        x.0[3] = (s as i64) & BOT_51_BITS;
        s >>= 51;
        x.0[4] = s as i64;
    }
    scr(x);
}

// -----------------------------------------------------------------------
// Input string conversions

// collect a vector of 8-bit values from a hex string.
// the vector has little-endian order
fn str_to_bin8(s: &str, x: &mut [u8]) {
    let nx = x.len();
    let mut bf = 0;
    let mut bw = 0;
    let mut val: u8 = 0;
    for c in s.chars().rev() {
        match c.to_digit(16) {
            Some(d) => {
                val |= (d as u8) << bf;
                bf += 4;
                if bf == 8 {
                    if bw < nx {
                        x[bw] = val;
                    }
                    bf = 0;
                    bw += 1;
                    val = 0;
                }
            },
            None => panic!("Invalid hex digit")
        }
    }
    if bf > 0 && bw < nx {
        x[bw] = val;
    }
}

// collect a vector of 64-bit cells from a hex string
// the vector has little-endian order
fn str_to_bin64(s: &str, x: &mut [u64]) {
    let nx = x.len();
    let mut bf = 0;
    let mut bw = 0;
    let mut val: u64 = 0;
    for c in s.chars().rev() {
        match c.to_digit(16) {
            Some(d) => {
                val |= (d as u64) << bf;
                bf += 4;
                if bf == 64 {
                    if bw < nx {
                        x[bw] = val;
                    }
                    bf = 0;
                    bw += 1;
                    val = 0;
                }
            },
            None => panic!("Invalid hex digit")
        }
    }
    if bf > 0 && bw < nx {
        x[bw] = val;
    }
}

fn str_to_FQ(s: &str) -> FQ {
    let mut bin : [u64;4] = [0;4];
    str_to_bin64(s, &mut bin);
    let mut ans = U256(bin);
    loop {
        if ans >= Q {
            sub_noborrow(&mut ans.0, &Q.0);
        } else { break; }
    }
    FQ(ans)
}

fn str_to_FR(s: &str) -> FR {
    let mut bin : [u64;4] = [0;4];
    str_to_bin64(s, &mut bin);
    let mut ans = U256(bin);
    loop {
        if ans >= R {
            sub_noborrow(&mut ans.0, &R.0);
        } else { break; }
    }
    FR::from(ans)
}

// convert bignm string to FQ51
fn str_to_elt(s: &str, e: &mut FQ51) {
    let mut bin: [u64;4] = [0;4];
    str_to_bin64(s, &mut bin);
    bin_to_elt(&U256(bin), e);
}

// convert bignum string to 4-bit LE window vector
fn str_to_winvec(s: &str, w: &mut WinVec) {
    let mut qv: [u8;32] = [0;32];
    str_to_bin8(s, &mut qv);
    println!("multiplier: {}", LEV32(qv));
    cwin4(&LEV32(qv), w);
}

// -------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn tst_equal() {
        assert!(1 == equal(1,1));
        assert!(0 == equal(1,2));
    }

    #[test]
    fn tst_hex() {
        let s = "0123456789abcdefABCDEF";
        let mut v: [u8;22] = [0;22];
        let mut ix = 0;
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) =>
                    {
                        v[ix] = d as u8; 
                        ix += 1;
                    }
                None => panic!("Invalid hex digit")
            }
        }
        assert!(v == [0,1,2,3,4,5,6,7,8,9,
                      10,11,12,13,14,15,
                      10,11,12,13,14,15]);
    }

    #[test]
    #[should_panic]
    fn tst_badhex() {
        let s = "ghijk";
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) => println!("{}", d),
                None    => panic!("Invalid hex digit")
            }
        }
    }

    #[test]
    fn tst_str_to_elt() {
        let mut e = FQ51_0;
        str_to_elt("123", &mut e);
        let FQ51(ev) = e;
        assert!(ev == [0x123,0,0,0,0]);
    }
    
    #[test]
    fn test_new_point() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let mut gen_x = FQ51::zero();
        let mut gen_y = FQ51::zero();
        str_to_elt(sx, &mut gen_x); // *ed-gen*
        str_to_elt(sy, &mut gen_y);
        
        let mut pt1 : ECp = ECp::inf();
        init(&gen_x, &gen_y, &mut pt1);

        let gx = str_to_FQ(sx);
        let gy = str_to_FQ(sy);
        let pt2 = ECp::new(gx, gy);

        assert_eq!(pt1, pt2);
    }

    #[test]
    fn test_add() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let mut gen_x = FQ51::zero();
        let mut gen_y = FQ51::zero();
        str_to_elt(sx, &mut gen_x); // *ed-gen*
        str_to_elt(sy, &mut gen_y);
        
        let mut sum = FQ51::zero();
        gadd(&gen_x, &gen_y, &mut sum);

        let gx = str_to_FQ(sx);
        let gy = str_to_FQ(sy);
        let gz = gx.to_FQ51() + gy.to_FQ51();
    
        assert_eq!(gz, sum);
    }

}


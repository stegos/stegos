//! u256.rs - Little endian data vectors of [i64; 4] used by Fr and Fq

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
use rand::thread_rng;
use rand::{Rng, ThreadRng};

// -----------------------------------------------------------------
// U256 word chunks represent a 256-bit bignum as a little-endian u64 vector
//
// This is a low-level internal representation of raw bits. And as such,
// it is used for both raw Field values, and Montgomery-scaled Field values.
// One must be careful to distinguish by context at this low level. Field values
// should never be mixed without careful consideration.

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub fn zero() -> U256 {
        U256([0; 4])
    }

    pub fn one() -> U256 {
        U256([1, 0, 0, 0])
    }

    pub fn bits(self) -> [u64; 4] {
        self.0
    }

    pub fn random() -> U256 {
        let mut rng: ThreadRng = thread_rng();
        U256(rng.gen::<[u64; 4]>())
    }

    pub fn force_to_range(&mut self, range: U256) {
        while *self >= range {
            div2(&mut self.0);
        }
    }

    pub fn random_in_range(range: U256) -> U256 {
        let mut x = Self::random();
        Self::force_to_range(&mut x, range);
        x
    }

    pub fn nbr_str(&self) -> String {
        basic_nbr_str(&self.0)
    }

    pub fn to_lev_u8(self) -> [u8; 32] {
        let mut ans = [0u8; 32];
        ans[0] = (self.0[0] & 0x0ff) as u8;
        ans[1] = ((self.0[0] >> 8) & 0x0ff) as u8;
        ans[2] = ((self.0[0] >> 16) & 0x0ff) as u8;
        ans[3] = ((self.0[0] >> 24) & 0x0ff) as u8;
        ans[4] = ((self.0[0] >> 32) & 0x0ff) as u8;
        ans[5] = ((self.0[0] >> 40) & 0x0ff) as u8;
        ans[6] = ((self.0[0] >> 48) & 0x0ff) as u8;
        ans[7] = ((self.0[0] >> 56) & 0x0ff) as u8;

        ans[8] = (self.0[1] & 0x0ff) as u8;
        ans[9] = ((self.0[1] >> 8) & 0x0ff) as u8;
        ans[10] = ((self.0[1] >> 16) & 0x0ff) as u8;
        ans[11] = ((self.0[1] >> 24) & 0x0ff) as u8;
        ans[12] = ((self.0[1] >> 32) & 0x0ff) as u8;
        ans[13] = ((self.0[1] >> 40) & 0x0ff) as u8;
        ans[14] = ((self.0[1] >> 48) & 0x0ff) as u8;
        ans[15] = ((self.0[1] >> 56) & 0x0ff) as u8;

        ans[16] = (self.0[2] & 0x0ff) as u8;
        ans[17] = ((self.0[2] >> 8) & 0x0ff) as u8;
        ans[18] = ((self.0[2] >> 16) & 0x0ff) as u8;
        ans[19] = ((self.0[2] >> 24) & 0x0ff) as u8;
        ans[20] = ((self.0[2] >> 32) & 0x0ff) as u8;
        ans[21] = ((self.0[2] >> 40) & 0x0ff) as u8;
        ans[22] = ((self.0[2] >> 48) & 0x0ff) as u8;
        ans[23] = ((self.0[2] >> 56) & 0x0ff) as u8;

        ans[24] = (self.0[3] & 0x0ff) as u8;
        ans[25] = ((self.0[3] >> 8) & 0x0ff) as u8;
        ans[26] = ((self.0[3] >> 16) & 0x0ff) as u8;
        ans[27] = ((self.0[3] >> 24) & 0x0ff) as u8;
        ans[28] = ((self.0[3] >> 32) & 0x0ff) as u8;
        ans[29] = ((self.0[3] >> 40) & 0x0ff) as u8;
        ans[30] = ((self.0[3] >> 48) & 0x0ff) as u8;
        ans[31] = ((self.0[3] >> 56) & 0x0ff) as u8;

        ans
    }

    pub fn add_mod(&mut self, other: &U256, modulo: &U256) {
        add_nocarry(&mut self.0, &other.0);
        if *self >= *modulo {
            sub_noborrow(&mut self.0, &modulo.0);
        }
    }

    pub fn sub_mod(&mut self, other: &U256, modulo: &U256) {
        if *self < *other {
            add_nocarry(&mut self.0, &modulo.0);
        }
        sub_noborrow(&mut self.0, &other.0);
    }

    pub fn neg_mod(&mut self, modulo: &U256) {
        if *self > Self::zero() {
            let mut tmp = modulo.0;
            sub_noborrow(&mut tmp, &self.0);
            self.0 = tmp;
        }
    }

    /// Multiply `self` by `other` (mod `modulo`) via the Montgomery
    /// multiplication method.
    pub fn mul_mod(&mut self, other: &U256, modulo: &U256, inv: u64) {
        mul_reduce(&mut self.0, &other.0, &modulo.0, inv);

        if *self >= *modulo {
            sub_noborrow(&mut self.0, &modulo.0);
        }
    }

    #[inline]
    pub fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }

    /// Turn `self` into its multiplicative inverse (mod `modulo`)
    pub fn invert_mod(&mut self, modulo: &U256) {
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
}

// -------------------------------------------

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "U256([{:016x}, {:016x}, {:016x}, {:016x}])",
            self.0[0] as u64, self.0[1] as u64, self.0[2] as u64, self.0[3] as u64
        )
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "U256({})", self.nbr_str())
    }
}

// -------------------------------------------

impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()).rev() {
            if *a < *b {
                return Ordering::Less;
            } else if *a > *b {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// -------------------------------------------------------------------------
// Primitive ops for U256, on raw arrays of 4 x u64

/// Divide by two
#[inline]
pub fn div2(a: &mut [u64; 4]) {
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

pub fn shr(a: &mut [u64; 4], n: usize) {
    for _ in 0..n {
        div2(a);
    }
}

/// Multiply by two
#[inline]
pub fn mul2(a: &mut [u64; 4]) {
    let mut last = 0;
    for i in a {
        let tmp = *i >> 63;
        *i <<= 1;
        *i |= last;
        last = tmp;
    }
}

fn split_u64(i: u64) -> (u64, u64) {
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

fn add_nocarry(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = 0;
    for (a, b) in a.into_iter().zip(b.iter()) {
        *a = adc(*a, *b, &mut carry);
    }
    debug_assert!(0 == carry);
}

pub fn sub_noborrow(a: &mut [u64; 4], b: &[u64; 4]) {
    fn sbb(a: u64, b: u64, borrow: &mut u64) -> u64 {
        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
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

fn mac_digit(acc: &mut [u64], b: &[u64], c: u64) {
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
fn mul_reduce(this: &mut [u64; 4], by: &[u64; 4], modulus: &[u64; 4], inv: u64) {
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

    let mut res = [0; 2 * 4];
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

pub fn mul_collapse(this: &mut [u64; 4], modulus: &[u64; 4], inv: u64) {
    // this is a short circuiting function for removing the Montgomery prescaling
    // slightly faster than a full multiply by [1,0,0,0]
    let mut res = [0; 2 * 4];
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

// -------------------------------------------

// produce a 256-bit bignum string from a Lev of [u64;4]
pub fn basic_nbr_str(x: &[u64; 4]) -> String {
    format!("{:016x}{:016x}{:016x}{:016x}", x[3], x[2], x[1], x[0])
}

// -------------------------------------------

impl From<Lev32> for U256 {
    fn from(v: Lev32) -> U256 {
        U256(v.to_lev_u64())
    }
}

impl From<U256> for Lev32 {
    fn from(v: U256) -> Lev32 {
        Lev32(v.to_lev_u8())
    }
}

// collect a vector of 64-bit cells from a hex string
// the vector has little-endian order

impl U256 {
    pub fn from_str(s: &str) -> Result<U256, hex::FromHexError> {
        // construct a little-endian [u64;4] from a hexstring
        let mut x = [0u8; 32];
        hexstr_to_lev_u8(s, &mut x)?;
        let v = Lev32(x);
        Ok(U256::from(v))
    }
}

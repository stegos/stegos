//! ecpt.rs - Bernstein algorithm for elliptic curve arithmetic

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
use crate::CryptoError;
use rayon::prelude::*;

// -----------------------------------------------------------------------------------

const WINDOW: usize = 4; // using 4-bit fixed windows

// nbr of precomputed point multiples
const NPREP: usize = 1 + (1 << (WINDOW - 1));

// -------------------------------------------------------------------------
// Point Structure

pub type Coord = Fq51;

#[derive(Copy, Clone, Debug)]
pub struct ECp {
    pub x: Fq51,
    pub y: Fq51,
    pub z: Fq51,
    pub t: Fq51,
}

pub const PT_INF: ECp = ECp {
    x: FQ51_0,
    y: FQ51_1,
    z: FQ51_1,
    t: FQ51_0,
};

impl ECp {
    pub fn inf() -> Self {
        PT_INF
    }

    pub fn is_inf(&self) -> bool {
        self.x.is_zero()
    }

    pub fn is_affine(&self) -> bool {
        self.z == FQ51_1
    }

    pub fn try_from_xy(x: &Fq, y: &Fq) -> Result<Self, CryptoError> {
        let x51 = Fq51::from(x.clone());
        let y51 = Fq51::from(y.clone());
        if !Self::is_valid_pt(&x51, &y51) {
            return Err(CryptoError::PointNotOnCurve);
        }
        Self::make_valid_pt(&x51, &y51)
    }

    fn is_valid_pt(x: &Fq51, y: &Fq51) -> bool {
        let xsq = x.sqr();
        let ysq = y.sqr();
        (xsq + ysq == 1 + CURVE_D * xsq * ysq)
    }

    fn make_valid_pt(x: &Fq51, y: &Fq51) -> Result<Self, CryptoError> {
        // avoid small subgroup
        // this assumes cofactor CURVE_H = 4
        let newpt = Self::new_from_xy51(x, y);
        let newpt2 = newpt + newpt;
        let newpt4 = newpt2 + newpt2;
        if newpt4.is_inf() {
            return Err(CryptoError::InSmallSubgroup);
        }
        Ok(newpt4)
    }

    fn solve_y(xq: &Fq51) -> Result<Fq51, CryptoError> {
        // CURVE_D is non-square in Fq, so division here is unquestionably safe
        let xqsq = xq.sqr();
        let ysq = (xqsq - 1) / (xqsq * CURVE_D - 1);
        gsqrt(&ysq)
    }

    fn new_from_xy51(x: &Fq51, y: &Fq51) -> Self {
        let mut pt = Self::inf();
        init(&x, &y, &mut pt);
        pt
    }

    /// Try to convert from raw bytes.
    pub fn try_from_bytes(mut x: [u8; 32]) -> Result<Self, CryptoError> {
        let sgn = (x[31] & 0x80) != 0;
        x[31] &= 0x7f;
        let x256 = U256::from(Lev32(x, false));
        if !(x256 < *Q) {
            return Err(CryptoError::TooLarge);
        }
        let xq = Fq51::from(Fq::from(x256));
        let ysqrt = Self::solve_y(&xq)?;
        let yq = if ysqrt.is_odd() == sgn { ysqrt } else { -ysqrt };
        Self::make_valid_pt(&xq, &yq)
    }

    // internal routine for hashing onto the curve,
    // and for selecting random points. We ensure that
    // nobody will have any idea what the log_r(Pt) will be.
    fn from_random_bits(bits: &[u8; 32]) -> Self {
        let mut tmp: [u8; 32] = *bits;
        let sgn = tmp[31] & 0x80 != 0;
        tmp[31] &= 0x7f;
        let mut x = U256::from(Lev32(tmp, false));
        while x >= *Q {
            div2(&mut x.0);
        }
        let mut xq = Fq51::from(Fq::from(x));
        let hpt: Self;
        loop {
            if !xq.is_zero() {
                // can't be pt at inf
                match Self::solve_y(&xq) {
                    // xq must be on curve
                    Ok(ysqrt) => {
                        let yq = if sgn == ysqrt.is_odd() { ysqrt } else { -ysqrt };
                        // avoid small subgroup
                        // this assumes cofactor CURVE_H = 4
                        let pt = Self::new_from_xy51(&xq, &yq);
                        let pt2 = pt + pt;
                        let pt4 = pt2 + pt2;
                        if !pt4.is_inf() {
                            hpt = pt4;
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
            xq = xq.sqr() + 1;
        }
        hpt
    }

    pub fn random() -> Self {
        Self::from_random_bits(&random::<[u8; 32]>())
    }

    /// Convert into raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut afpt = *self;
        norm(&mut afpt);
        let ptx = Fq::from(afpt.x);
        let mut x = U256::from(ptx).to_lev_u8();
        if afpt.y.is_odd() {
            x[31] |= 0x80;
        }
        x
    }

    /// Convert into compressed point.
    #[inline]
    pub fn compress(&self) -> Pt {
        Pt::compress(self)
    }
}

impl From<Hash> for ECp {
    fn from(h: Hash) -> Self {
        Self::from_random_bits(&h.bits())
    }
}

// --------------------------------------------------------

impl Hashable for ECp {
    fn hash(&self, state: &mut Hasher) {
        let pt = Pt::from(*self);
        pt.hash(state);
    }
}

// --------------------------------------------------------

impl Eq for ECp {}

impl PartialEq for ECp {
    fn eq(&self, b: &Self) -> bool {
        self.x * b.z == self.z * b.x && self.y * b.z == self.z * b.y
    }
}

// ---------------------------------------------------------

impl<'a, 'b> Add<&'a ECp> for &'a ECp {
    type Output = ECp;
    fn add(self, other: &'a ECp) -> ECp {
        let mut tmp = ECp::inf();
        add_proj(self, other, &mut tmp);
        tmp
    }
}

impl<'a> Add<&'a ECp> for ECp {
    type Output = ECp;
    fn add(self, other: &'a ECp) -> ECp {
        &self + other
    }
}

impl<'b> Add<ECp> for &'b ECp {
    type Output = ECp;
    fn add(self, other: ECp) -> ECp {
        self + &other
    }
}

impl Add<ECp> for ECp {
    type Output = ECp;
    fn add(self, other: ECp) -> ECp {
        &self + &other
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
        let mut tmp = self.clone();
        tmp.x = -tmp.x;
        tmp.t = -tmp.t;
        tmp
    }
}

impl Sub<ECp> for ECp {
    type Output = ECp;
    fn sub(self, other: ECp) -> ECp {
        self + (-other)
    }
}

impl SubAssign<ECp> for ECp {
    fn sub_assign(&mut self, other: ECp) {
        *self += -other;
    }
}

// ------------------------------------------------

impl<'a, 'b> Mul<&'a Fr> for &'b ECp {
    type Output = ECp;
    fn mul(self, other: &'a Fr) -> ECp {
        let wv = WinVec::from(other);
        let mut tmp = self.clone();
        mul_to_proj(&wv, &mut tmp);
        tmp
    }
}

impl<'a> Mul<&'a Fr> for ECp {
    type Output = ECp;
    fn mul(self, other: &'a Fr) -> ECp {
        &self * other
    }
}

impl<'b> Mul<Fr> for &'b ECp {
    type Output = ECp;
    fn mul(self, other: Fr) -> ECp {
        self * &other
    }
}

impl Mul<Fr> for ECp {
    type Output = ECp;
    fn mul(self, other: Fr) -> ECp {
        &self * &other
    }
}

// ------------------------------------------------

// A window vector representing the Fr(1/4) scale factor
// as prescale on compression of ECC points.
const WV_4: WinVec = WinVec(
    [
        5, 1, 7, 1, -3, 1, -3, -2, -8, 5, -1, -6, 4, -1, 7, 6, 7, 6, 5, 4, -2, -2, -8, -5, 4, 5,
        -4, 1, -5, -6, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, -8, 2, 0,
    ],
    false,
);

pub fn prescale_for_compression(pt: &ECp) -> ECp {
    let mut tmp = pt.clone();
    mul_to_proj(&WV_4, &mut tmp);
    tmp
}

// ------------------------------------------------

impl<'a, 'b> Mul<&'a ECp> for &'b Fr {
    type Output = ECp;
    fn mul(self, other: &'a ECp) -> ECp {
        other * self
    }
}

impl<'a> Mul<&'a ECp> for Fr {
    type Output = ECp;
    fn mul(self, other: &'a ECp) -> ECp {
        other * &self
    }
}

impl<'b> Mul<ECp> for &'b Fr {
    type Output = ECp;
    fn mul(self, other: ECp) -> ECp {
        &other * self
    }
}

impl Mul<ECp> for Fr {
    type Output = ECp;
    fn mul(self, other: ECp) -> ECp {
        &other * &self
    }
}

// ------------------------------------------------

impl<'a> MulAssign<&'a Fr> for ECp {
    fn mul_assign(&mut self, other: &'a Fr) {
        let wv = WinVec::from(other);
        mul_to_proj(&wv, self);
    }
}

impl MulAssign<Fr> for ECp {
    fn mul_assign(&mut self, other: Fr) {
        *self *= &other;
    }
}

// ------------------------------------------------

impl Mul<i64> for ECp {
    type Output = Self;
    fn mul(self, other: i64) -> Self {
        match other {
            0 => ECp::inf(),
            1 => self,
            -1 => -self,
            2 => self + self,
            3 => self + self + self,
            _ => {
                let wv = WinVec::from(other);
                let mut tmp = self;
                mul_to_proj(&wv, &mut tmp);
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
            -1 => *self = -*self,
            _ => {
                let wv = WinVec::from(other);
                mul_to_proj(&wv, self);
            }
        }
    }
}

// ------------------------------------------------

impl<'a, 'b> Div<&'a Fr> for &'b ECp {
    type Output = ECp;
    fn div(self, other: &'a Fr) -> ECp {
        self * other.clone().invert()
    }
}

impl<'a> Div<&'a Fr> for ECp {
    type Output = ECp;
    fn div(self, other: &'a Fr) -> ECp {
        &self / other
    }
}

impl<'b> Div<Fr> for &'b ECp {
    type Output = ECp;
    fn div(self, other: Fr) -> ECp {
        self / &other
    }
}

impl Div<Fr> for ECp {
    type Output = ECp;
    fn div(self, other: Fr) -> ECp {
        &self / &other
    }
}

// ------------------------------------------------

impl<'a> DivAssign<&'a Fr> for ECp {
    fn div_assign(&mut self, other: &'a Fr) {
        *self *= other.clone().invert();
    }
}

impl DivAssign<Fr> for ECp {
    fn div_assign(&mut self, other: Fr) {
        *self /= &other;
    }
}

// ------------------------------------------------

impl Div<i64> for ECp {
    type Output = Self;
    fn div(self, other: i64) -> Self {
        self / Fr::from(other)
    }
}

impl DivAssign<i64> for ECp {
    fn div_assign(&mut self, other: i64) {
        *self /= Fr::from(other);
    }
}

// --------------------------------------------------------
// Point Operators

// P+=P

/*
fn double_1(pt: &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let e = 2 * pt.t;
    let g = a + b;
    let f = g - 2;
    let h = a - b;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = g.sqr() - 2 * g;
    pt.t = e * h;
    scr(&mut pt.z);
}
*/

fn double_1(pt: &mut ECp) {
    let mut a = Fq51::zero();
    let mut b = Fq51::zero();
    gsqr(&pt.x, &mut a);
    gsqr(&pt.y, &mut b);

    let mut e = pt.t;
    gmul2(&mut e);

    let mut g = Fq51::zero();
    gadd(&a, &b, &mut g);

    let mut f = g;
    f.0[0] -= 2;

    let mut h = Fq51::zero();
    gsub(&a, &b, &mut h);

    gmul(&e, &f, &mut pt.x);
    gmul(&g, &h, &mut pt.y);

    let mut tmp = Fq51::zero();
    gsqr(&g, &mut tmp);
    gmul2(&mut g);
    gsub(&tmp, &g, &mut pt.z);
    gmul(&e, &h, &mut pt.t);
}

/*
fn double_2(pt: &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let c = 2 * pt.z.sqr();
    let g = pt.x + pt.y;
    let e = g.sqr() - a - b;
    let g = a + b;
    let f = g - c;
    let h = a - b;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = f * g;
}
*/

fn double_2(pt: &mut ECp) {
    let mut a = Fq51::zero();
    let mut b = Fq51::zero();
    let mut c = Fq51::zero();
    gsqr(&pt.x, &mut a);
    gsqr(&pt.y, &mut b);
    gsqr(&pt.z, &mut c);
    gmul2(&mut c);

    let mut g = Fq51::zero();
    let mut e = Fq51::zero();
    let mut tmp = Fq51::zero();
    gadd(&pt.x, &pt.y, &mut tmp);
    gadd(&a, &b, &mut g);
    let mut tmp2 = Fq51::zero();
    gsqr(&tmp, &mut tmp2);
    gsub(&tmp2, &g, &mut e);

    let mut f = Fq51::zero();
    gsub(&g, &c, &mut f);
    let mut h = Fq51::zero();
    gsub(&a, &b, &mut h);

    gmul(&e, &f, &mut pt.x);
    gmul(&g, &h, &mut pt.y);
    gmul(&f, &g, &mut pt.z);
}

/*
fn double_3(pt: &mut ECp) {
    let a = pt.x.sqr();
    let b = pt.y.sqr();
    let c = 2 * pt.z.sqr();
    let g = pt.x + pt.y;
    let e = g.sqr() - a - b;
    let g = a + b;
    let f = g - c;
    let h = a - b;
    pt.x = e * f;
    pt.y = g * h;
    pt.z = f * g;
    pt.t = e * h;
}
*/

fn double_3(pt: &mut ECp) {
    let mut a = Fq51::zero();
    let mut b = Fq51::zero();
    let mut c = Fq51::zero();
    gsqr(&pt.x, &mut a);
    gsqr(&pt.y, &mut b);

    gsqr(&pt.z, &mut c);
    gmul2(&mut c);
    let mut g = Fq51::zero();
    let mut e = Fq51::zero();
    let mut tmp = Fq51::zero();
    gadd(&pt.x, &pt.y, &mut tmp);
    gadd(&a, &b, &mut g);
    let mut tmp2 = Fq51::zero();
    gsqr(&tmp, &mut tmp2);
    gsub(&tmp2, &g, &mut e);

    let mut f = Fq51::zero();
    gsub(&g, &c, &mut f);
    let mut h = Fq51::zero();
    gsub(&a, &b, &mut h);
    gmul(&e, &f, &mut pt.x);
    gmul(&g, &h, &mut pt.y);

    gmul(&f, &g, &mut pt.z);
    gmul(&e, &h, &mut pt.t);
}

//P+=Q;
/*
fn add_1(qpt: &ECp, ppt: &mut ECp) {
    let a = ppt.x * qpt.x;
    let b = ppt.y * qpt.y;
    let c = ppt.t * qpt.t;
    let f = ppt.z - c; // reversed sign as d is negative
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
*/

fn add_1(qpt: &ECp, ppt: &mut ECp) {
    let mut a = Fq51::zero();
    gmul(&ppt.x, &qpt.x, &mut a);

    let mut b = Fq51::zero();
    gmul(&ppt.y, &qpt.y, &mut b);

    let mut c = Fq51::zero();
    gmul(&ppt.t, &qpt.t, &mut c);

    let mut f = Fq51::zero();
    gsub(&ppt.z, &c, &mut f);

    let mut g = Fq51::zero();
    gadd(&ppt.z, &c, &mut g);

    let mut h = Fq51::zero();
    gsub(&b, &a, &mut h);

    gadd(&ppt.x, &ppt.y, &mut c);
    let mut d = Fq51::zero();
    gadd(&qpt.x, &qpt.y, &mut d);

    let mut tmp = Fq51::zero();
    gadd(&a, &b, &mut tmp);
    let mut tmp2 = Fq51::zero();
    gmul(&c, &d, &mut tmp2);

    let mut e = Fq51::zero();
    gsub(&tmp2, &tmp, &mut e);

    gmul(&e, &f, &mut ppt.x);
    gmul(&g, &h, &mut ppt.y);
    gmul(&f, &g, &mut ppt.z);
    gmul(&e, &h, &mut ppt.t);
}

/*
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
*/

fn add_2(qpt: &ECp, ppt: &mut ECp) {
    let mut a = Fq51::zero();
    gmul(&ppt.x, &qpt.x, &mut a);
    let mut b = Fq51::zero();
    gmul(&ppt.y, &qpt.y, &mut b);
    let mut c = Fq51::zero();
    gmul(&ppt.t, &qpt.t, &mut c);
    let mut d = Fq51::zero();
    gmul(&ppt.z, &qpt.z, &mut d);

    let mut f = Fq51::zero();
    gsub(&d, &c, &mut f);

    let mut g = Fq51::zero();
    gadd(&d, &c, &mut g);

    let mut h = Fq51::zero();
    gsub(&b, &a, &mut h);

    gadd(&ppt.x, &ppt.y, &mut c);
    gadd(&qpt.x, &qpt.y, &mut d);

    let mut tmp = Fq51::zero();
    gadd(&a, &b, &mut tmp);
    let mut tmp2 = Fq51::zero();
    gmul(&c, &d, &mut tmp2);
    let mut e = Fq51::zero();
    gsub(&tmp2, &tmp, &mut e);

    gmul(&e, &f, &mut ppt.x);
    gmul(&g, &h, &mut ppt.y);
    gmul(&f, &g, &mut ppt.z);
}

//P=0

// Initialise P
// incoming x,y coordinates -> ECp in projective coords

fn init(x: &Fq51, y: &Fq51, pt: &mut ECp) {
    (*pt).x = *x;
    (*pt).y = *y;
    (*pt).z = Fq51::one();
}

// P=-Q

fn ecp_neg(qpt: &ECp, ppt: &mut ECp) {
    gneg(&qpt.x, &mut ppt.x);
    ppt.y = qpt.y;
    ppt.z = qpt.z;
    gneg(&qpt.t, &mut ppt.t);
}

// Make Affine

pub fn norm(pt: &mut ECp) {
    if !pt.is_affine() {
        let mut w = pt.z;
        ginv(&mut w);

        pt.x *= w;
        pt.y *= w;
        pt.z = Fq51::one();
    }
}

// Precomputation

fn precomp(pt: &mut ECp, wpts: &mut [ECp]) {
    norm(pt); // must start with affine form
              // pt mult is the only place where pt.t is used
    pt.t = pt.x * pt.y;

    let mut tmp1 = *pt;
    tmp1.t *= CURVE_D;

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

fn fe_cmov(f: &mut Fq51, g: &Fq51, ib: i8) {
    let b = -ib as i64;
    let Fq51(fv) = f;
    let Fq51(gv) = g;
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

// return 1 if b == c, no branching
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

    cmov(tpt, &wpts[0], equal(babs, 0)); // conditional move
    cmov(tpt, &wpts[1], equal(babs, 1));
    cmov(tpt, &wpts[2], equal(babs, 2));
    cmov(tpt, &wpts[3], equal(babs, 3));
    cmov(tpt, &wpts[4], equal(babs, 4));
    cmov(tpt, &wpts[5], equal(babs, 5));
    cmov(tpt, &wpts[6], equal(babs, 6));
    cmov(tpt, &wpts[7], equal(babs, 7));
    cmov(tpt, &wpts[8], equal(babs, 8));

    let mtpt = -(*tpt);
    cmov(tpt, &mtpt, m & 1);
}

// Point Multiplication - exponent is 251 bits

// multiply incoming projective point,
// return result in projective coords
fn mul_to_proj(w: &WinVec, ppt: &mut ECp) {
    let mut wpts = [PT_INF; NPREP];
    precomp(ppt, &mut wpts);

    let WinVec(wv, _) = w;
    let ix = w.0[PANES - 1] as usize;
    *ppt = wpts[ix];
    let mut qpt = PT_INF;
    for jx in (0..(PANES - 1)).rev() {
        select(&mut qpt, &wpts, wv[jx]);
        window(&qpt, ppt);
    }
}

// point additon of two projective points
/*
pub fn add_proj(qpt: &ECp, ppt: &ECp, zpt: &mut ECp) {
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
    let z3 = f * g; // Curve1174 C = 1
    zpt.x = x3;
    zpt.y = y3;
    zpt.z = z3;
}
*/
pub fn add_proj(qpt: &ECp, ppt: &ECp, zpt: &mut ECp) {
    // Add Q to P, both in projective (X,Y,Z) coordinates. We don't use T here.
    let mut a = Fq51::zero();
    gmul(&qpt.z, &ppt.z, &mut a);

    let mut b = Fq51::zero();
    gsqr(&a, &mut b);

    let mut c = Fq51::zero();
    gmul(&qpt.x, &ppt.x, &mut c);

    let mut d = Fq51::zero();
    gmul(&qpt.y, &ppt.y, &mut d);

    let mut e = Fq51::zero();
    gmul(&c, &d, &mut e);
    gmuli(&mut e, CURVE_D);

    let mut f = Fq51::zero();
    gsub(&b, &e, &mut f);

    let mut g = Fq51::zero();
    gadd(&b, &e, &mut g);

    let mut x3 = Fq51::zero();
    gadd(&qpt.x, &qpt.y, &mut x3);

    let mut y3 = Fq51::zero();
    gadd(&ppt.x, &ppt.y, &mut y3);

    let mut z3 = Fq51::zero();
    gmul(&x3, &y3, &mut z3);

    gsub(&z3, &c, &mut y3);
    gsub(&y3, &d, &mut x3);
    gmul(&f, &x3, &mut y3);
    gmul(&a, &y3, &mut zpt.x);
    gsub(&d, &c, &mut y3);
    gmul(&g, &y3, &mut z3);
    gmul(&a, &z3, &mut zpt.y);
    gmul(&f, &g, &mut zpt.z);
}

// -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() -> Result<(), CryptoError> {
        let smul = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA"; // *ed-gen* x
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E"; // *ed-gen* y
                                                                                     // --------------------------------------------
                                                                                     // multiplier in 4-bit window form
        let mut w = WinVec::from_str(&smul);

        let gen_x = Fq::try_from_hex(&sx, false)?;
        let gen_y = Fq::try_from_hex(&sy, false)?;

        println!("The Generator Point");
        println!("gen_x: {:?}", gen_x);
        println!("gen_y: {:?}", gen_y);

        let mut pt1 = ECp::inf();
        for _ in 0..100 {
            pt1 = ECp::try_from_xy(&gen_x, &gen_y).unwrap();
            mul_to_proj(&w, &mut pt1);
        }

        println!("Result as Fq51s");
        println!("pt: {:#?}", pt1);
        Ok(())
    }

    #[test]
    pub fn check_pt_compression() {
        // exercise the entire process from ECp generation
        // through point compression, and back again.
        // This tests curve solving, square roots, random hashing
        // onto curve, etc.
        for _ in 0..1_000 {
            let pt = ECp::random();
            let cpt = Pt::from(pt);
            let ept = cpt.decompress().unwrap();
            assert!(ept == pt);
        }
        for _ in 0..1_000 {
            let x = Fr::random();
            let pt = x * (*G);
            let cpt = Pt::from(pt);
            let ept = cpt.decompress().unwrap();
            assert!(ept == pt);
        }

        println!("WV(1/4)");
        let wv = WinVec::from(&Fr::invert(&Fr::from(4)));
        for ix in 0..4 {
            let kx = ix * 16;
            let s = format!(
                "{}, {}, {}, {}, {}, {}, {}, {},  {}, {}, {}, {}, {}, {}, {}, {}",
                wv.0[kx],
                wv.0[kx + 1],
                wv.0[kx + 2],
                wv.0[kx + 3],
                wv.0[kx + 4],
                wv.0[kx + 5],
                wv.0[kx + 6],
                wv.0[kx + 7],
                wv.0[kx + 8],
                wv.0[kx + 9],
                wv.0[kx + 10],
                wv.0[kx + 11],
                wv.0[kx + 12],
                wv.0[kx + 13],
                wv.0[kx + 14],
                wv.0[kx + 15]
            );
            println!("{}", s);
        }
    }
}

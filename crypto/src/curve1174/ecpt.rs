// ecpt.rs - Bernstein algorithm for elliptic curve arithmetic
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

// -----------------------------------------------------------------------------------

const WINDOW: usize = 4; // using 4-bit fixed windows

// nbr of precomputed point multiples
const NPREP: usize = 1 + (1 << (WINDOW - 1));

// -------------------------------------------------------------------------
// Point Structure

pub type Coord = Fq51;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
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
    pub fn inf() -> ECp {
        PT_INF
    }

    pub fn is_inf(&self) -> bool {
        self.x.is_zero()
    }

    pub fn is_affine(&self) -> bool {
        self.z.is_one()
    }

    pub fn from_xy51(x: &Fq51, y: &Fq51) -> ECp {
        let mut pt = ECp::inf();
        init(&x, &y, &mut pt);
        pt
    }

    pub fn from_xy(x: &Fq, y: &Fq) -> ECp {
        Self::from_xy51(&Fq51::from(*x), &Fq51::from(*y))
    }
}

impl fmt::Display for ECp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ECp {{\n x: {},\n y: {},\n z: {},\n t: {} }}",
            self.x, self.y, self.z, self.t
        )
    }
}

impl Eq for ECp {}
impl PartialEq for ECp {
    fn eq(&self, b: &ECp) -> bool {
        let mut tmpa = *self;
        let mut tmpb = *b;
        norm(&mut tmpa);
        norm(&mut tmpb);
        (tmpa.x == tmpb.x) && (tmpa.y == tmpb.y) && (tmpa.z == tmpb.z) && (tmpa.t == tmpb.t)
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
        tmp.y = self.y;
        tmp.z = self.z;
        tmp.t = -self.t;
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

impl Mul<Fr> for ECp {
    type Output = ECp;
    fn mul(self, other: Fr) -> ECp {
        let wv = WinVec::from(other);
        let mut tmp = self;
        ecp_mul(&wv, &mut tmp);
        tmp
    }
}

impl Mul<ECp> for Fr {
    type Output = ECp;
    fn mul(self, other: ECp) -> ECp {
        other * self
    }
}

impl MulAssign<Fr> for ECp {
    fn mul_assign(&mut self, other: Fr) {
        let wv = WinVec::from(other);
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
                let wv = WinVec::from(other);
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
                let wv = WinVec::from(other);
                ecp_mul(&wv, self);
            }
        }
    }
}

impl Div<Fr> for ECp {
    type Output = ECp;
    fn div(self, other: Fr) -> ECp {
        self * Fr::invert(other)
    }
}

impl DivAssign<Fr> for ECp {
    fn div_assign(&mut self, other: Fr) {
        *self *= Fr::invert(other);
    }
}

impl Div<i64> for ECp {
    type Output = ECp;
    fn div(self, other: i64) -> ECp {
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

fn double_3(pt: &mut ECp) {
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

fn init(x: &Fq51, y: &Fq51, pt: &mut ECp) {
    (*pt).x = *x;
    (*pt).y = *y;
    (*pt).z = Fq51::one();
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

pub fn norm(pt: &mut ECp) {
    let mut w = pt.z;
    ginv(&mut w);
    // (*pt).z = Fq51::one();

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

    let WinVec(wv) = w;
    let ix = w.0[PANES - 1] as usize;
    *ppt = wpts[ix];
    let mut jx = PANES - 1;
    let mut qpt = PT_INF;
    for _ in 0..(PANES - 1) {
        jx -= 1;
        select(&mut qpt, &wpts, wv[jx]);
        window(&qpt, ppt);
    }
}

// multiply incoming projective point,
// return result in affine coords
pub fn ecp_mul(w: &WinVec, ppt: &mut ECp) {
    mul_to_proj(w, ppt);
    norm(ppt);
}

// point additon of two projective points
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
    let z3 = f * g; // c = 1
    zpt.x = x3;
    zpt.y = y3;
    zpt.z = z3;
    zpt.t = Fq51::zero();
}

impl From<Pt> for ECp {
    fn from(pt: Pt) -> ECp {
        // NOTE: This will panic if invalid point
        pt_on_curve(pt).unwrap()
    }
}

impl From<Hash> for ECp {
    fn from(h: Hash) -> ECp {
        ECp::from_random_bits(&h.bits())
    }
}

impl ECp {
    // internal routine for hashing onto the curve,
    // and for selecting random points. We ensure that
    // nobody will have any idea what the log_r(Pt) will be.
    fn from_random_bits(bits: &[u8; 32]) -> ECp {
        let mut tmp: [u8; 32] = *bits;
        let sgn = tmp[31] & 0x80 != 0;
        tmp[31] &= 0x7f;
        let mut x = U256::from(Lev32 { v8: tmp });
        while x >= Q {
            div2(&mut x.0);
        }
        let mut xq = Fq51::from(Fq::Unscaled(x));
        let hpt: ECp;
        loop {
            if !xq.is_zero() {
                // can't be pt at inf
                match solve_y(&xq) {
                    // xq must be on curve
                    Some(ysqrt) => {
                        let yq = if sgn == ysqrt.is_odd() { ysqrt } else { -ysqrt };
                        // avoid small subgroup
                        let pt = CURVE_H * ECp::from_xy51(&xq, &yq);
                        if !pt.is_inf() {
                            hpt = pt;
                            break;
                        }
                    }
                    None => {}
                }
            }
            xq = xq.sqr() + 1;
        }
        hpt
    }

    pub fn random() -> ECp {
        ECp::from_random_bits(&random::<[u8; 32]>())
    }
}

// -------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() {
        let smul = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA"; // *ed-gen* x
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E"; // *ed-gen* y
                                                                                     // --------------------------------------------
                                                                                     // multiplier in 4-bit window form
        let mut w = WinVec::from_str(&smul);

        let gen_x = Coord::from_str(&sx);
        let gen_y = Coord::from_str(&sy);

        println!("The Generator Point");
        println!("gen_x: {}", gen_x);
        println!("gen_y: {}", gen_y);

        let mut pt1 = ECp::inf();
        for _ in 0..100 {
            pt1 = ECp::from_xy51(&gen_x, &gen_y);
            ecp_mul(&w, &mut pt1);
        }

        println!("Result as Bignums");
        println!("pt: {}", pt1);

        println!("Result as Fq51s");
        println!("pt: {:#?}", pt1);
    }
}

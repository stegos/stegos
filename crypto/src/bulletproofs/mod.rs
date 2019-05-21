//! mod.rs - Bulletproofs on Curve1174

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

#![allow(non_snake_case)]
#![allow(unused)]

use crate::curve1174::*;
use crate::hash::*;
use crate::utils::*;

use crate::CryptoError;
use lazy_static::lazy_static;
use log::*;
use rand::prelude::*;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Debug;
use std::mem;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::time::{Duration, SystemTime};

// ----------------------------------------------------------------

pub const NBASIS: usize = 64; // max bit size of validatable items - must be 2^N
pub const L2_NBASIS: usize = 6; // must equal log2(NBASIS)

type Int = Fr;
type Point = ECp;

type BasisVect = [Point; NBASIS];
type ScalarVect = Vec<Int>;

macro_rules! bpvec {
    ($elt: expr) => {
        [$elt; NBASIS]
    };
}

pub struct BulletproofBasis {
    pub G: Point,      // for cloaking factor of Pedersen Commitment
    pub H: Point,      // for amount factor of Pedersen Commitment
    pub GV: BasisVect, // BP cloaking basis vector
    pub HV: BasisVect, // BP amount basis vector
}

lazy_static! {
    pub static ref INIT : bool = {
        let mut n = NBASIS;
        let mut logn = 0;
        while (1 & n) == 0 {
            logn += 1;
            n >>= 1;
        }
        assert!(n == 1, "NBASIS not 2^N");
        assert!(logn == L2_NBASIS, "L2_NBASIS not equal Log2(NBASIS)");
        true
    };
    pub static ref TWOS : ScalarVect = pow_vec(&Int::from(2));
    pub static ref MASK : Int =
        // NOTE: the mask value needs to = ((1 << NBASIS)-1)
        // ... one bit in mask for every valid bit of value range
        vec_sum(&(*TWOS));
    pub static ref BP: BulletproofBasis = make_bulletproof_basis();
    pub static ref LR_INIT : [LR; L2_NBASIS] = [
        { let zpt = Point::inf().compress();
        LR {
            l: zpt.clone(),
            r: zpt.clone(),
        }}
    ; L2_NBASIS];
    pub static ref TLR : TransLR = TransLR {
                l: Point::inf(),
                r: Point::inf(),
                x: Int::zero(),
                xinv: Int::zero(),
            };
}

fn make_bulletproof_basis() -> BulletproofBasis {
    let mut gen_hash = Hash::digest(&*G);
    let h = Point::from(gen_hash);
    let mut gv = bpvec!(Point::inf());
    let mut hv = bpvec!(Point::inf());
    for ix in 0..NBASIS {
        gen_hash = Hash::digest(&gen_hash);
        gv[ix] = Point::from(gen_hash);
        gen_hash = Hash::digest(&gen_hash);
        hv[ix] = Point::from(gen_hash);
    }
    BulletproofBasis {
        G: *G,
        H: h,
        GV: gv,
        HV: hv,
    }
}

// ---------------------------------------------------------
// Vector constructors

fn const_vec(z: &Int) -> ScalarVect {
    let mut v = Vec::<Int>::new();
    for _ in 0..NBASIS {
        v.push(z.clone());
    }
    v
}

fn pow_vec(n: &Int) -> ScalarVect {
    let mut v = Vec::<Int>::new();
    v.push(Int::one());
    let ns = n.scaled();
    for ix in 1..NBASIS {
        v.push(&ns * &v[ix - 1]);
    }
    v
}

fn bits_vec(x: i64) -> ScalarVect {
    // assert!(x >= 0);
    let mut v = Vec::<Int>::new();
    let mut one = Int::one();
    one.set_wau();
    let mut bits = x as u64;
    for ix in 0..NBASIS {
        let mut bit = ((bits & 1) as i64) * &one;
        v.push(bit);
        bits >>= 1;
    }
    v
}

fn random_vec() -> ScalarVect {
    let mut v = Vec::<Int>::new();
    for ix in 0..NBASIS {
        let mut tmp = Int::random();
        tmp.set_wau();
        v.push(tmp.scaled());
    }
    v
}

// -----------------------------------------------------------
// vector operators over indefinitely sized vectors

fn vec_add<'a, T>(vdst: &'a mut [T], vsrc: &'a [T])
where
    T: AddAssign<&'a T>,
{
    for (pdst, psrc) in vdst.into_iter().zip(vsrc.iter()) {
        *pdst += psrc;
    }
}

fn vec_sub<'a, T>(vdst: &'a mut [T], vsrc: &'a [T])
where
    T: SubAssign<&'a T>,
{
    for (pdst, psrc) in vdst.into_iter().zip(vsrc.iter()) {
        *pdst -= psrc;
    }
}

fn hadamard_prod<'a, T>(vdst: &'a mut [T], vsrc: &'a [Int])
where
    T: MulAssign<&'a Int>,
{
    for (pdst, psrc) in vdst.into_iter().zip(vsrc.iter()) {
        *pdst *= psrc;
    }
}

fn vec_incr<'a, T>(vdst: &'a mut [T], k: &'a T)
where
    T: AddAssign<&'a T>,
{
    for pdst in vdst.into_iter() {
        *pdst += &k;
    }
}

fn vec_decr<'a, T>(vdst: &'a mut [T], k: &'a T)
where
    T: SubAssign<&'a T>,
{
    for pdst in vdst.into_iter() {
        *pdst -= &k;
    }
}

fn vec_scale<'a, T>(vdst: &'a mut [T], k: &'a Int)
where
    T: MulAssign<&'a Int>,
{
    for pdst in vdst.into_iter() {
        *pdst *= &k;
    }
}

fn vec_inv(vdst: &mut [Int]) {
    for pdst in vdst.into_iter() {
        *pdst = 1 / &*pdst;
    }
}

// ----------------------------------------------------

trait HasZero<T> {
    fn zero() -> T;
}

impl HasZero<Int> for Int {
    fn zero() -> Self {
        Int::zero()
    }
}

impl HasZero<Point> for Point {
    fn zero() -> Self {
        Self::inf()
    }
}

#[inline]
fn is_even(x: usize) -> bool {
    0 == (x & 1)
}

fn dot_prod_pi(vp: &[Point], vi: &[Int]) -> Point {
    // Parallelized version for cross-domain dot-product
    let nel = vp.len();
    if nel == 1 {
        vp[0] * &vi[0]
    } else if is_even(nel) {
        // don't worry, we never get handed empty vectors
        let n2 = nel >> 1;
        let mut lsum = Point::zero();
        let mut rsum = Point::zero();
        let fnL = || {
            lsum = dot_prod_pi(&vp[0..n2], &vi[0..n2]);
        };
        let fnR = || {
            rsum = dot_prod_pi(&vp[n2..nel], &vi[n2..nel]);
        };
        rayon::join(fnL, fnR);
        lsum + rsum
    } else {
        vp.iter()
            .zip(vi.iter())
            .fold(Point::zero(), |sum, (a, b)| sum + a * b)
    }
}

fn dot_prod<'a, T>(v1: &'a [T], v2: &'a [Int]) -> T
where
    T: Clone + Add<T, Output = T> + Mul<&'a Int, Output = T> + HasZero<T>,
{
    v1.iter()
        .zip(v2.iter())
        .fold(T::zero(), |sum, (a, b)| sum + a.clone() * b)
}

fn vec_sum<'a, T>(v: &'a [T]) -> T
where
    T: Add<&'a T, Output = T> + HasZero<T>,
{
    v.iter().fold(T::zero(), |sum, x| sum + x)
}

// ---------------------------------------------------------
// Pedersen Commitments

pub fn simple_commit(blind: &Int, val: &Int) -> Point {
    // blinding on G, value on H
    blind * BP.G + val * BP.H
}

pub fn fee_a(val: i64) -> Point {
    val * BP.H
}

fn vec_commit(
    gpt: &Point,
    gpts: &[Point],
    hpts: &[Point],
    blind: &Int,
    blindvec: &[Int],
    valvec: &[Int],
) -> Point {
    // blinding on G, value on H
    // blind * gpt + dot_prod(gpts, blindvec) + dot_prod(hpts, valvec)
    let dst0 = blind * gpt;
    let mut dstg = Point::zero();
    let mut dsth = Point::zero();
    let fng = || {
        dstg = dot_prod_pi(gpts, blindvec);
    };
    let fnh = || {
        dsth = dot_prod_pi(hpts, valvec);
    };
    rayon::join(fng, fnh);
    dst0 + dstg + dsth
}

pub fn pedersen_commitment(x: i64) -> (Point, Int) {
    // User API: for amount x, compute a Pedersen Commitment on G, H
    // Return commitment point, and random cloaking factor on G
    let mut zr = Int::random();
    zr.set_wau();
    let mut frx = Int::from(x);
    frx.set_wau();
    (simple_commit(&zr, &frx), zr)
}

// -----------------------------------------------------------
// 3-element vectors used for polynomial proofs

fn poly_dot_prod(poly_l: &[ScalarVect; 2], poly_r: &[ScalarVect; 2]) -> [Int; 3] {
    [
        dot_prod(&poly_l[0], &poly_r[0]),
        dot_prod(&poly_l[0], &poly_r[1]) + dot_prod(&poly_l[1], &poly_r[0]),
        dot_prod(&poly_l[1], &poly_r[1]),
    ]
}

fn poly_eval(poly: &[ScalarVect; 2], x: &Int) -> ScalarVect {
    let mut ans = poly[1].clone();
    vec_scale(&mut ans, x);
    vec_add(&mut ans, &poly[0]);
    ans
}

// ---------------------------------------------------------------------
// Estimated sizes in store (untagged byte vectors):
// Pt = 32 bytes
// Fr = Int = 32
// LR = 3 * 32 = 96
// DotProof = 4 * 32 + 6 * 96 = 704
// BulletProof = 11 * 32 + 704 = 1056

#[derive(Clone)]
pub struct BulletProof {
    pub vcmt: Pt, // main commitment value - used by transactions as "the" Pedersen commitment
    pub acmt: Pt, // commitment on the value bit pattern
    pub scmt: Pt, // commitment on the cloaking factors
    pub t1_cmt: Pt, // commitment on the polynomial challenges for pow 1,2
    pub t2_cmt: Pt,
    pub tau_x: Int,
    pub mu: Int,
    pub t_hat: Int,
    pub dot_proof: DotProof, // composite dot-product proof
}

#[derive(Clone, Debug)]
pub struct DotProof {
    // represents the composite proof on the dot product
    pub u: Pt,
    pub pcmt: Pt,
    pub a: Int,
    pub b: Int,
    pub xlrs: [LR; L2_NBASIS],
}

#[derive(Copy, Clone, Debug)]
pub struct LR {
    // represents one component of the proof for each power-of-2 folding
    pub l: Pt,
    pub r: Pt,
}

// --------------------------------------------------------

impl Debug for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BP(vcmt: {:?}, ...)", self.vcmt)
    }
}

// --------------------------------------------------------

impl Hashable for LR {
    fn hash(&self, state: &mut Hasher) {
        "LR".hash(state);
        self.l.hash(state);
        self.r.hash(state);
    }
}

impl Hashable for DotProof {
    fn hash(&self, state: &mut Hasher) {
        "DP".hash(state);
        self.u.hash(state);
        self.pcmt.hash(state);
        self.a.hash(state);
        self.b.hash(state);
        for lr in self.xlrs.iter() {
            lr.hash(state);
        }
    }
}

impl Hashable for BulletProof {
    fn hash(&self, state: &mut Hasher) {
        "BP".hash(state);
        self.vcmt.hash(state);
        self.acmt.hash(state);
        self.scmt.hash(state);
        self.t1_cmt.hash(state);
        self.t2_cmt.hash(state);
        self.tau_x.hash(state);
        self.mu.hash(state);
        self.t_hat.hash(state);
        self.dot_proof.hash(state);
    }
}

impl BulletProof {
    pub fn pedersen_commitment(&self) -> Pt {
        self.vcmt
    }
}

// ------------------------------------------------------------------

pub fn make_range_proof(v: i64) -> (BulletProof, Int) {
    fn make_lr_dot_proof(
        y: &Int,
        mu: &Int,
        t_hat: &Int,
        lvec: &mut ScalarVect,
        rvec: &mut ScalarVect,
    ) -> DotProof {
        fn fold_halves<'a, T>(n: usize, v: &'a mut [T], lscale: &'a Int, rscale: &'a Int)
        where
            T: Clone + Mul<&'a Int, Output = T> + Add<T, Output = T>,
        {
            let n_2 = n >> 1;
            for (jx, kx) in (0..n_2).zip(n_2..n) {
                v[jx] = v[jx].clone() * lscale + v[kx].clone() * rscale;
            }
        }

        // --------------------------------------------------------------------
        // Avoid heap allocations. Since we are shrinking as we go,
        // we can allocate the mutable vectors at their largest size at the outset,
        // and just reuse their storage in each iteration.

        // G, [G'_i] = [G_i] o [1/y^n], [H_i]
        let (gpt, mut gv, mut hv) = basis_vectors(y);

        // compute commitment to [L],[R]:
        //  P = mu*G + [R].([G_i] o [1/y^n]) + [L].[H_i]
        let pcmt = vec_commit(&gpt, &gv, &hv, &mu, rvec, lvec);

        let u = (mu / t_hat) * gpt; // the cloaking point for all following commitments

        let mut acc = *LR_INIT; // preallocate the LR list accumulator
        let mut aix = 0; // accumulator (iteration) index

        let mut n = NBASIS; // starting vector size

        while n > 1 {
            // for as long as we can halve vectors...
            let n2 = n >> 1; // half-vector size

            macro_rules! VL {
                ($v: expr) => {
                    &$v[0..n2]
                }; // Left half-vector
            }
            macro_rules! VR {
                ($v: expr) => {
                    &$v[n2..n]
                }; // Right half-vector
            }

            // L = cl*U + [R>].[G'<] + [L<].[H>]
            let l = {
                let cl = dot_prod(VL!(lvec), VR!(rvec)); // cl = [L<].[R>]
                vec_commit(&u, VL!(gv), VR!(hv), &cl, VR!(rvec), VL!(lvec))
            };

            // R = cr*U + [R<].[G'>] + [L>].[H<]
            let r = {
                let cr = dot_prod(VR!(lvec), VL!(rvec)); // cr = [L>].[R<]
                vec_commit(&u, VR!(gv), VL!(hv), &cr, VL!(rvec), VR!(lvec))
            };

            let x = Int::from(Hash::digest_chain(&[&l, &r])); // hash challenge value

            // save this portion of the proof into list accumulator
            acc[aix] = LR {
                l: l.compress(),
                r: r.compress(),
            };

            let xs = x.scaled(); // do the scaling, unscaling just once = speedup below
            let xinv = 1 / &xs;
            let xinvu = xinv.unscaled();

            // form half-size vectors for next pass
            fold_halves(n, &mut gv, &x, &xinvu); // [G'] <- x*[G'<] + [G'>]/x
            fold_halves(n, &mut hv, &xinvu, &x); // [H]  <- [H<]/x + x*[H>]
            fold_halves(n, lvec, &xs, &xinv); // [L] <- x*[L<] + [L>]/x
            fold_halves(n, rvec, &xinv, &xs); // [R] <- [R<]/x + x*[R>]

            aix += 1;
            n = n2;
        }
        // final dot-product composite proof
        DotProof {
            u: u.compress(),
            pcmt: pcmt.compress(),
            a: lvec[0].unscaled(),
            b: rvec[0].unscaled(),
            xlrs: acc,
        }
    }
    // ---------------------------------------------------------------

    assert!(*INIT, "Can't happen");

    let (vcmt, gamma) = pedersen_commitment(v);
    let (gpt, gv, hv) = (BP.G, BP.GV, BP.HV);

    // Left/Right -- left (H) for values, right (G) for cloaking

    // a_l = bits of value
    // a_r = ones complement of a_l
    let mut a_l = bits_vec(v);
    let mut a_r = a_l.clone();
    vec_decr(&mut a_r, &Int::one());
    let mut alpha = Int::random();
    alpha.set_wau();
    // A = alpha*G + [a_r].[G_i] + [a_l].[H_i]
    let acmt = vec_commit(&gpt, &gv, &hv, &alpha, &a_r, &a_l);

    // form blinding factors
    let s_l = random_vec();
    let s_r = random_vec();
    let mut rho = Int::random();
    rho.set_wau();
    // S = rho*G + [s_r].[G_i] + [s_l].[H_i]
    let scmt = vec_commit(&gpt, &gv, &hv, &rho, &s_r, &s_l);

    // get challenge values: y, z
    let h = Hash::digest_chain(&[&vcmt, &acmt, &scmt]);
    let y = Int::from(h).scaled();

    let h = Hash::digest(&h);
    let z = Int::from(h).scaled();

    // form poly_l: l(X) = ([a_l] - z*[1]) + [s_l]*X
    let mut poly_l0 = a_l;
    vec_decr(&mut poly_l0, &z);
    let poly_l1 = s_l;
    let poly_l = [poly_l0, poly_l1];

    // form poly_r: r(X) = [y^n] o ([a_r] + z*[1] + [s_r]*X) + z^2*[2^n]
    let yvec = pow_vec(&y);
    let zsq = &z * &z;
    let mut poly_r0 = a_r;
    vec_incr(&mut poly_r0, &z);
    hadamard_prod(&mut poly_r0, &yvec);
    let mut vprod_2 = TWOS.clone();
    vec_scale(&mut vprod_2, &zsq);
    vec_add(&mut poly_r0, &vprod_2);

    let mut poly_r1 = s_r;
    hadamard_prod(&mut poly_r1, &yvec);
    let poly_r = [poly_r0, poly_r1];

    // form the dot-prod polynoomial between poly_l and poly_r
    // t(X) = l(X) . r(X) = t_0 + t_1 * X + t_2 * X^2
    let poly_t = poly_dot_prod(&poly_l, &poly_r);
    let t1 = poly_t[1].clone();
    let t2 = poly_t[2].clone();

    let mut tau1 = Int::random();
    tau1.set_wau();
    let mut tau2 = Int::random();
    tau2.set_wau();

    let t1_cmt = simple_commit(&tau1, &t1); // T_1 = tau_1 * G + t_1 * H
    let t2_cmt = simple_commit(&tau2, &t2); // T_2 = tau_2 * G + t_2 * H

    // get challenge value: x
    let x = Int::from(Hash::digest_chain(&[&t1_cmt, &t2_cmt])).scaled();

    // eval poly_l and poly_r at x
    let mut lvec = poly_eval(&poly_l, &x); // [L] = [PL_0] + x*[PL_1]
    let mut rvec = poly_eval(&poly_r, &x); // [R] = [PR_0] + x*[PR_1]

    let t_hat = dot_prod(&lvec, &rvec); // t_hat = [L].[R]
    let tau_x = &gamma * zsq + tau1 * &x + tau2 * &x * &x; // tau_x = gamma * z^2 + tau_1 * x + tau_2 * x^2
    let mu = alpha + rho * x;

    (
        BulletProof {
            vcmt: vcmt.compress(), // this is the main commitment value
            acmt: acmt.compress(),
            scmt: scmt.compress(),
            t1_cmt: t1_cmt.compress(),
            t2_cmt: t2_cmt.compress(),
            tau_x: tau_x.unscaled(),
            mu: mu.unscaled(),
            t_hat: t_hat.unscaled(),
            dot_proof: make_lr_dot_proof(&y, &mu, &t_hat, &mut lvec, &mut rvec),
        },
        gamma.unscaled(),
    )
}

fn basis_vectors(y: &Int) -> (Point, BasisVect, BasisVect) {
    let mut gv = BP.GV;
    hadamard_prod(&mut gv, &pow_vec(&(1 / y)));
    (BP.G, gv, BP.HV)
}

// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TransLR {
    pub l: Point,
    pub r: Point,
    pub x: Int,
    pub xinv: Int,
}

pub fn validate_range_proof(bp: &BulletProof) -> bool {
    fn try_validate_range_proof(bp: &BulletProof) -> Result<bool, CryptoError> {
        fn expand_bp(
            xlrs: &[LR; L2_NBASIS],
            txlrs: &mut [TransLR; L2_NBASIS],
        ) -> Result<(), CryptoError> {
            // pre-expansion to avoid redundant point decompression and hashing
            /*
            for ix in 0..L2_NBASIS {
                let l = xlrs[ix].l.decompress()?;
                let r = xlrs[ix].r.decompress()?;
                txlrs[ix].l = l;
                txlrs[ix].r = r;
                let x = Int::from(Hash::digest_chain(&[&l, &r])).scaled();
                txlrs[ix].xinv = 1 / &x;
                txlrs[ix].x = x;
            }
            */
            fn get_pt(cpt: &Pt) -> Point {
                match cpt.decompress() {
                    Ok(p) => p,
                    Err(_) => Point::inf(),
                }
            }

            txlrs
                .par_iter_mut()
                .zip_eq(xlrs.par_iter())
                .for_each(|(tx, x)| {
                    let l = get_pt(&x.l);
                    let r = get_pt(&x.r);
                    tx.l = l;
                    tx.r = r;
                    let x = Int::from(Hash::digest_chain(&[&l, &r])).scaled();
                    tx.xinv = 1 / &x;
                    tx.x = x;
                });
            Ok(())
        }

        fn compute_iter_commit(
            xlrs: &[TransLR; L2_NBASIS],
            init: Point,
        ) -> Result<Point, CryptoError> {
            // this is a point arithmetic computation
            /*
            let mut sum = init;
            for triple in xlrs.iter() {
                let l = triple.l;
                let r = triple.r;
                let x = &triple.x;
                let xinv = &triple.xinv;
                let xsq = x * x;
                let xinvsq = xinv * xinv;
                sum += &xsq * l + r * &xinvsq;
            }
            Ok(sum)
            */
            let mut dst = [Point::zero(); L2_NBASIS];
            xlrs.par_iter()
                .zip_eq(dst.par_iter_mut())
                .for_each(|(xlr, d)| {
                    let l = xlr.l;
                    let r = xlr.r;
                    let x = &xlr.x;
                    let xinv = &xlr.xinv;
                    let xsq = x * x;
                    let xinvsq = xinv * xinv;
                    *d = &xsq * l + r * &xinvsq;
                });
            Ok(init + vec_sum(&dst))
            /* */
        }

        fn compute_svec(xlrs: &[TransLR; L2_NBASIS]) -> Result<ScalarVect, CryptoError> {
            // this is a pure Fr field computation
            let mut svec = TWOS.clone();
            /*
            for ix in 0..NBASIS {
                let mut prod = Int::one();
                let mut jx = 0;
                for triple in xlrs.iter().rev() {
                    prod *= if (ix & (1 << jx)) != 0 {
                        &triple.x
                    } else {
                        &triple.xinv
                    };
                    jx += 1;
                }
                svec[ix] = prod;
            }
            */
            let mut ixvec = Vec::<usize>::new();
            for ix in 0..NBASIS {
                ixvec.push(ix)
            }
            svec.par_iter_mut()
                .zip_eq(ixvec.par_iter())
                .for_each(|(sv, ix)| {
                    let mut prod = Int::one();
                    let mut jx = 0;
                    for triple in xlrs.iter().rev() {
                        prod *= if (ix & (1 << jx)) != 0 {
                            &triple.x
                        } else {
                            &triple.xinv
                        };
                        jx += 1;
                    }
                    *sv = prod;
                });
            Ok(svec)
        }

        // -------------------------------------------------------------
        // Preamble Timing: 0.77 ms
        if false {
            let start = SystemTime::now();
            for _ in 0..1000 {
                let vcmt = bp.vcmt.decompress()?;
                let acmt = bp.acmt.decompress()?;
                let scmt = bp.scmt.decompress()?;
                let t1cmt = bp.t1_cmt.decompress()?;
                let t2cmt = bp.t2_cmt.decompress()?;

                // get challenge values: x, y, z
                let x = Int::from(Hash::digest_chain(&[&t1cmt, &t2cmt])).scaled();

                let h = Hash::digest_chain(&[&vcmt, &acmt, &scmt]);
                let y = Int::from(h).scaled();

                let h = Hash::digest(&h);
                let z = Int::from(h).scaled();

                let yvec = pow_vec(&y);
                let zsq = &z * &z;
                let delta = (&z - &zsq) * vec_sum(&yvec) - &*MASK * &z * &zsq;

                let xsq = &x * &x;
                let chk_v_r = &zsq * vcmt + delta * BP.H + &x * t1cmt + xsq * t2cmt;

                let chk_v_l = simple_commit(&bp.tau_x, &bp.t_hat);

                // check that: t_hat = t_0 + t_1 * x + t_2 * x^2
                if chk_v_l != chk_v_r {
                    return Ok(false);
                }
            }
            let timing = start.elapsed().expect("ok");
            println!("head section time = {:?}", timing / 1000);
        }

        let vcmt = bp.vcmt.decompress()?;
        let acmt = bp.acmt.decompress()?;
        let scmt = bp.scmt.decompress()?;
        let t1cmt = bp.t1_cmt.decompress()?;
        let t2cmt = bp.t2_cmt.decompress()?;

        // get challenge values: x, y, z
        let x = Int::from(Hash::digest_chain(&[&t1cmt, &t2cmt])).scaled();

        let h = Hash::digest_chain(&[&vcmt, &acmt, &scmt]);
        let y = Int::from(h).scaled();

        let h = Hash::digest(&h);
        let z = Int::from(h).scaled();

        let yvec = pow_vec(&y);
        let zsq = &z * &z;
        let delta = (&z - &zsq) * vec_sum(&yvec) - &*MASK * &z * &zsq;

        let xsq = &x * &x;
        let chk_v_r = &zsq * vcmt + delta * BP.H + &x * t1cmt + xsq * t2cmt;

        let chk_v_l = simple_commit(&bp.tau_x, &bp.t_hat);

        // check that: t_hat = t_0 + t_1 * x + t_2 * x^2
        if chk_v_l != chk_v_r {
            return Ok(false);
        }

        // -------------------------------------------------------------
        // MidSection Timing: 6.5 ms

        if false {
            let start = SystemTime::now();
            for _ in 0..1000 {
                let (_, mut gv, mut hv) = basis_vectors(&y);

                let mut gpows = yvec.clone();
                vec_scale(&mut gpows, &z.clone());
                let mut gp2 = TWOS.clone();
                vec_scale(&mut gp2, &zsq);
                vec_add(&mut gpows, &gp2);

                let hpows = const_vec(&(-z.clone()));

                let chk_p_l = acmt + vec_commit(&scmt, &gv, &hv, &x, &gpows, &hpows);
                let dot_proof = bp.dot_proof.clone();
                let p = dot_proof.pcmt.decompress()?;

                // check that commitment to [L], [R] equal l(x), r(x)
                if chk_p_l != p {
                    return Ok(false);
                }
            }
            let timing = start.elapsed().expect("ok");
            println!("midsection time = {:?}", timing / 1000);
        }

        let (_, mut gv, mut hv) = basis_vectors(&y);

        let mut gpows = yvec;
        vec_scale(&mut gpows, &z);
        let mut gp2 = TWOS.clone();
        vec_scale(&mut gp2, &zsq);
        vec_add(&mut gpows, &gp2);

        let hpows = const_vec(&(-z));

        let chk_p_l = acmt + vec_commit(&scmt, &gv, &hv, &x, &gpows, &hpows);
        let dot_proof = bp.dot_proof.clone();
        let p = dot_proof.pcmt.decompress()?;

        // check that commitment to [L], [R] equal l(x), r(x)
        if chk_p_l != p {
            return Ok(false);
        }

        // -------------------------------------------------------------
        // Tail Section Timing: 9.0 ms

        if false {
            let start = SystemTime::now();
            for _ in 0..1000 {
                let u = dot_proof.u.decompress()?;
                let a = dot_proof.a.scaled();
                let b = dot_proof.b.scaled();

                let mut txlrs = [
                    TLR.clone(),
                    TLR.clone(),
                    TLR.clone(),
                    TLR.clone(),
                    TLR.clone(),
                    TLR.clone(),
                ];
                expand_bp(&dot_proof.xlrs, &mut txlrs)?;

                let mut sv = compute_svec(&txlrs)?;
                let mut svinv = sv.clone();
                vec_inv(&mut svinv);
                vec_scale(&mut sv, &a);
                vec_scale(&mut svinv, &b);
                let chk_l = vec_commit(&u, &gv, &hv, &(a * b), &svinv, &sv);
                let chk_r = compute_iter_commit(&txlrs, p)?;

                if (chk_l.clone() != chk_r.clone()) {
                    return Ok(false);
                }
            }
            let timing = start.elapsed().expect("ok");
            println!("tail section time = {:?}", timing / 1000);
        }

        let u = dot_proof.u.decompress()?;
        let a = dot_proof.a.scaled();
        let b = dot_proof.b.scaled();

        let mut txlrs = [
            TLR.clone(),
            TLR.clone(),
            TLR.clone(),
            TLR.clone(),
            TLR.clone(),
            TLR.clone(),
        ];
        expand_bp(&dot_proof.xlrs, &mut txlrs)?;

        let mut sv = compute_svec(&txlrs)?;
        let mut svinv = sv.clone();
        vec_inv(&mut svinv);
        vec_scale(&mut sv, &a);
        vec_scale(&mut svinv, &b);
        let chk_l = vec_commit(&u, &gv, &hv, &(a * b), &svinv, &sv);
        let chk_r = compute_iter_commit(&txlrs, p)?;

        Ok(chk_l == chk_r)
    }
    // --------------------------------------------------------------

    assert!(*INIT, "Can't happen");

    match try_validate_range_proof(bp) {
        Ok(tf) => tf, // did or did not validate
        _ => false,   // invalid points encountered
    }
}

// ---------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn check_bp_init() {
        debug!("G: {:?}", (*G).compress());
        debug!("H: {:?}", BP.H.compress());
        for ix in 0..NBASIS {
            debug!("GV{} = {:?}", ix, BP.GV[ix].compress());
            debug!("HV{} = {:?}", ix, BP.HV[ix].compress());
        }
    }

    #[test]
    pub fn test_vector_operations() {
        let mut v1 = [Int::zero(), Int::one(), Int::from(2)];
        vec_incr(&mut v1, &Int::one());
        assert!(v1[0] == Int::one());
        assert!(v1[1] == Int::from(2));
        assert!(v1[2] == Int::from(3));
        let v2 = [Int::one(), Int::one(), Int::one()];
        vec_add(&mut v1, &v2);
        assert!(v1[0] == Int::from(2));
        assert!(v1[1] == Int::from(3));
        assert!(v1[2] == Int::from(4));
    }

    #[test]
    pub fn test_commitments() {
        for _ in 0..1000 {
            let x = {
                let x = random::<i64>();
                if x < 0 {
                    -x
                } else {
                    x
                }
            };
            let (cmt, _gamma) = pedersen_commitment(x);
            let cpt = cmt.compress();
            let ept = cpt.decompress().unwrap();
            assert!(ept == cmt);
        }
    }

    #[test]
    pub fn test_Int_commitments() {
        for _ in 0..1000 {
            let x = Int::random();
            let mut gamma = Int::random();
            gamma.set_wau();
            let cmt = simple_commit(&gamma, &x);
            let cpt = cmt.compress();
            let ept = cpt.decompress().unwrap();
            assert!(ept == cmt);
        }
    }

    struct Data {
        cmt: Pt,
    }

    #[test]
    pub fn test_Int_packed_commitments() {
        for _ in 0..1000 {
            let x = Int::random();
            let mut gamma = Int::random();
            gamma.set_wau();
            let cmt = simple_commit(&gamma, &x);
            let data = Data {
                cmt: cmt.compress(),
            };
            let ept = data.cmt.decompress().unwrap();
            assert!(ept == cmt);
        }
    }

    #[test]
    fn check_poly_dot_prod() {
        // show that the dot product of two vector polynomials,
        // evaluated at some x,
        // is the same, for all x, as the evaluation of the dot-product
        // polynomial, at that same x.

        // form random vector polynomial, pl
        let pl0 = random_vec();
        let pl1 = random_vec();
        let pl = [pl0, pl1];

        // form random vector polynomial, pr
        let pr0 = random_vec();
        let pr1 = random_vec();
        let pr = [pr0, pr1];

        // form the dot-prod polynomial
        let pt = poly_dot_prod(&pl, &pr);

        let x = Int::random(); // NOS test value

        // eval pl, pr at x
        let l = poly_eval(&pl, &x);
        let r = poly_eval(&pr, &x);

        // now take dot product: pl dot pr
        let lr = dot_prod(&l, &r);

        // eval the dot-product polynomial at x
        let t = &pt[0] + &x * &pt[1] + &x * &x * &pt[2];

        assert!(lr == t);
    }

    #[test]
    fn check_scaled_unscaled_field() {
        let x = Int::random();
        let xuinv = 1 / x.unscaled();
        let xinv = 1 / x.scaled();
        assert!(xuinv == xinv);

        let xs = x.scaled();
        let xu = x.unscaled();
        assert!(-&xs == -&xu);
        assert!(-xs.unscaled() == -xu.scaled());
    }

    #[test]
    fn check_bulletproofs() {
        let (proof, _gamma) = make_range_proof(1234567890);
        assert!(validate_range_proof(&proof));
    }

    #[test]
    #[should_panic]
    fn check_bad_bulletproofs() {
        let (proof, _gamma) = make_range_proof(-1);
        assert!(validate_range_proof(&proof));
    }

    #[test]
    fn test_bp_quadrants() {
        // show that interpreting the sign of compressed points
        // incorrectly, invalidates a BulletProof
        //
        // This is a partial quadrant test. Ideally we also
        // want to test -X on decompression, but I don't know
        // how to override decompress() during testing...

        let (proof, _gamma) = make_range_proof(1234567890);
        assert!(validate_range_proof(&proof));

        let mut dum = proof.clone();

        fn diddle_cmts(proof: &mut BulletProof) {
            Pt::flip_sign(&mut proof.vcmt);
            Pt::flip_sign(&mut proof.acmt);
            Pt::flip_sign(&mut proof.scmt);
            Pt::flip_sign(&mut proof.t1_cmt);
            Pt::flip_sign(&mut proof.t2_cmt);
        }

        diddle_cmts(&mut dum);
        assert!(!validate_range_proof(&dum));
    }
}

// ------------------------------------------------------------
pub fn bulletproofs_tests() {
    /// run this code using:
    ///   cargo run -p stegos_crypto --example bulletproofs --release
    ///
    let (proof, gamma) = make_range_proof(-1); // to pre-compute constants
    println!("Start BulletProofs");
    let mut niter = 1;
    let start = SystemTime::now();
    if true {
        niter = 1000;
        for _ in 1..niter {
            make_range_proof(1234567890);
        }
    }
    let (proof, gamma) = make_range_proof(1234567890);
    let timing = start.elapsed().expect("ok");
    println!("proof = {:#?}", proof);
    println!("gamma = {:?}", gamma);
    println!("BP construction time: {:?}", timing / niter);
    println!("");

    let niter = 1000;
    let cpt = Point::random().compress();
    let start = SystemTime::now();
    for _ in 0..niter {
        cpt.decompress();
    }
    let timing = start.elapsed().expect("ok");
    println!("decompress: {:?}", timing / niter);

    let pt = cpt.decompress().expect("okay");
    let start = SystemTime::now();
    for _ in 0..niter {
        pt.compress();
    }
    let timing = start.elapsed().expect("ok");
    println!("compress: {:?}", timing / niter);

    println!("Start Validation");
    let mut niter = 1;
    let start = SystemTime::now();
    let ans = validate_range_proof(&proof);
    if true {
        niter = 1000;
        for _ in 1..niter {
            validate_range_proof(&proof);
        }
    }
    let timing = start.elapsed().expect("ok");
    println!("Check = {}", ans);
    println!("BP validation time: {:?}", timing / niter);
}

// -------------------------------------------------------------

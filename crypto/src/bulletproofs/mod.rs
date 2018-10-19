//! mod.rs - Bulletproofs on Curve1174

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

#![allow(non_snake_case)]
#![allow(unused)]

use rand::prelude::*;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use std::fmt;
use std::mem;

use hex;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use curve1174::cpt::Pt;
use curve1174::ecpt::ECp;
use curve1174::fields::*;
use curve1174::*;
use hash::*;
use std::cmp::Ordering;
use utils::*;

use lazy_static::*;

// ----------------------------------------------------------------

pub const NBASIS: usize = 64; // max bit size of validatable items - must be 2^N
pub const L2_NBASIS: usize = 6; // must equal log2(NBASIS)

pub struct BulletproofBasis {
    pub G: ECp,            // for cloaking factor of Pedersen Commitment
    pub H: ECp,            // for amount factor of Pedersen Commitment
    pub GV: [ECp; NBASIS], // BP cloaking basis vector
    pub HV: [ECp; NBASIS], // BP amount basis vector
}

lazy_static! {
    pub static ref BP: BulletproofBasis = make_bulletproof_basis();
}

fn make_bulletproof_basis() -> BulletproofBasis {
    let mut gen_hash = Hash::digest(&*G);
    let h = ECp::from(gen_hash);
    let mut gv = [ECp::inf(); NBASIS];
    let mut hv = [ECp::inf(); NBASIS];
    for ix in 0..NBASIS {
        gen_hash = Hash::digest(&gen_hash);
        gv[ix] = ECp::from(gen_hash);
        gen_hash = Hash::digest(&gen_hash);
        hv[ix] = ECp::from(gen_hash);
    }
    BulletproofBasis {
        G: *G,
        H: h,
        GV: gv,
        HV: hv,
    }
}

// ---------------------------------------------------------

fn simple_commit(gpt: ECp, hpt: ECp, blind: Fr, val: Fr) -> ECp {
    blind * gpt + val * hpt
}

fn vec_commit(gpt: ECp, blind: Fr, gs: &[ECp], gvec: &[Fr], hs: &[ECp], hvec: &[Fr]) -> ECp {
    gvec.iter()
        .zip(hvec.iter().zip(gs.iter().zip(hs.iter())))
        .fold(blind * gpt, |sum, (gs, (hs, (gp, hp)))| {
            sum + *gs * *gp + *hs * *hp
        })
}

pub fn pedersen_commitment(x: i64) -> (ECp, Fr) {
    // User API: for amount x, compute a Pedersen Commitment on G, H
    // Return commitment point, and random cloaking factor on G
    let zr = Fr::random();
    (simple_commit((*BP).G, (*BP).H, zr, Fr::from(x)), zr)
}

// ---------------------------------------------------------

fn zero_vec() -> [Fr; NBASIS] {
    [Fr::zero().scaled(); NBASIS]
}

fn ones_vec() -> [Fr; NBASIS] {
    [Fr::one(); NBASIS]
}

macro_rules! pow_vec_impl {
    ($name: ident, $size: expr) => {
        fn $name(n: Fr) -> [Fr; $size] {
            let mut v = [Fr::one(); $size];
            let nr = Fr::from(n).scaled();
            for ix in 1..$size {
                v[ix] = nr * v[ix - 1];
            }
            v
        }
    };
}

pow_vec_impl!(pow_vec, NBASIS);
pow_vec_impl!(pow_vec3, 3);

fn twos_vec() -> [Fr; NBASIS] {
    pow_vec(Fr::from(2))
}

fn bits_vec(x: i64) -> [Fr; NBASIS] {
    let mut v = zero_vec();
    let mut bits = x as u64;
    for ix in 0..NBASIS {
        if (bits & 1) != 0 {
            v[ix] = Fr::one();
        }
        bits >>= 1;
    }
    v
}

fn random_vec() -> [Fr; NBASIS] {
    let mut v = zero_vec();
    for ix in 0..NBASIS {
        v[ix] = Fr::random().scaled();
    }
    v
}

// -----------------------------------------------------------
// 3-element vectors used for polynomial proofs

fn poly_dot_prod(poly_l: &[[Fr; NBASIS]; 2], poly_r: &[[Fr; NBASIS]; 2]) -> [Fr; 3] {
    [
        vv_dot_prod(&poly_l[0], &poly_r[0]),
        vv_dot_prod(&poly_l[0], &poly_r[1]) + vv_dot_prod(&poly_l[1], &poly_r[0]),
        vv_dot_prod(&poly_l[1], &poly_r[1]),
    ]
}

// -----------------------------------------------------------
// vector operators over indefinitely sized vectors

fn vec_incr(v: &[Fr], k: Fr, vdst: &mut [Fr]) {
    for (dst, src) in vdst.into_iter().zip(v.iter()) {
        *dst = *src + k;
    }
}

fn vec_decr(v: &[Fr], k: Fr, vdst: &mut [Fr]) {
    for (dst, src) in vdst.into_iter().zip(v.iter()) {
        *dst = *src - k;
    }
}

fn vec_scale(v: &[Fr], k: Fr, vdst: &mut [Fr]) {
    let ks = k.scaled();
    for (dst, src) in vdst.into_iter().zip(v.iter()) {
        *dst = *src * ks;
    }
}

fn vec_add(v1: &[Fr], v2: &[Fr], vdst: &mut [Fr]) {
    for (dst, (src1, src2)) in vdst.into_iter().zip(v1.iter().zip(v2.iter())) {
        *dst = *src1 + *src2;
    }
}

fn vec_sub(v1: &[Fr], v2: &[Fr], vdst: &mut [Fr]) {
    for (dst, (src1, src2)) in vdst.into_iter().zip(v1.iter().zip(v2.iter())) {
        *dst = *src1 - *src2;
    }
}

macro_rules! hadamard_impl {
    ($name: ident, $typ1: ident, $typ2: ident) => {
        fn $name(v1: &[$typ1], v2: &[$typ2], vdst: &mut [$typ2]) {
            for (dst, (src1, src2)) in vdst.into_iter().zip(v1.iter().zip(v2.iter())) {
                *dst = *src1 * *src2;
            }
        }
    };
}

hadamard_impl!(hadamard_prod, Fr, Fr);
hadamard_impl!(pt_hadamard_prod, Fr, ECp);

macro_rules! dotprod_impl {
    ($name: ident, $typ1: ident, $typ2: ident, $init: expr) => {
        fn $name(v1: &[$typ1], v2: &[$typ2]) -> $typ2 {
            v1.iter()
                .zip(v2.iter())
                .fold($init, |sum, (a, b)| sum + *a * *b)
        }
    };
}

dotprod_impl!(vv_dot_prod, Fr, Fr, Fr::zero().scaled());
dotprod_impl!(vpt_dot_prod, Fr, ECp, ECp::inf());

// --------------------------------------------------------------------

// ---------------------------------------------------------------------
// Estimated sizes in store (untagged byte vectors):
// Pt = 32 bytes
// Fr = 32
// LR = 3 * 32 = 96
// DotProof = 4 * 32 + 6 * 96 = 704
// BulletProof = 11 * 32 + 704 = 1056

#[derive(Copy, Clone)]
pub struct BulletProof {
    pub vcmt: Pt, // main commitment value - used by transactions as "the" Pedersen commitment
    pub acmt: Pt, // commitment on the value bit pattern
    pub scmt: Pt, // commitment on the cloaking factors
    pub t1_cmt: Pt, // commitment on the polynomial challenges for pow 1,2
    pub t2_cmt: Pt,
    pub tau_x: Fr,
    pub mu: Fr,
    pub t_hat: Fr,
    pub dot_proof: DotProof, // composite dot-product proof
    pub x: Fr,               // x,y,z are hash challenge values mapped to Fr field
    pub y: Fr,
    pub z: Fr,
}

#[derive(Copy, Clone)]
pub struct DotProof {
    // represents the composite proof on the dot product
    pub u: Pt,
    pub pcmt: Pt,
    pub a: Fr,
    pub b: Fr,
    pub xlrs: [LR; L2_NBASIS],
}

#[derive(Copy, Clone)]
pub struct LR {
    // represents one component of the proof for each power-of-2 folding
    pub x: Fr,
    pub l: Pt,
    pub r: Pt,
}

// --------------------------------------------------------

impl Hashable for LR {
    fn hash(&self, state: &mut Hasher) {
        "LR".hash(state);
        self.x.hash(state);
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
        self.x.hash(state);
        self.y.hash(state);
        self.z.hash(state);
    }
}

// ------------------------------------------------------------------

pub fn make_range_proof(v: i64) -> (BulletProof, Fr) {
    let gamma = Fr::random();
    let vfr = Fr::from(v);
    let vcmt = simple_commit((*BP).G, (*BP).H, gamma, vfr);
    let mut a_l = bits_vec(v);
    let mut a_r = zero_vec();
    vec_decr(&a_l, Fr::one(), &mut a_r);
    let alpha = Fr::random();

    // ---------------------------------------------
    if false {
        let start = SystemTime::now();
        for _ in 0..1563 {
            // simple_commit((*BP).G, (*BP).H, gamma, vfr);
            vec_commit((*BP).G, alpha, &(*BP).GV, &a_l, &(*BP).HV, &a_r);
        }
        println!("simple_commit: {:?}", start.elapsed());
    }
    // ---------------------------------------------

    let acmt = vec_commit((*BP).G, alpha, &(*BP).GV, &a_l, &(*BP).HV, &a_r);

    let s_l = random_vec();
    let s_r = random_vec();
    let rho = Fr::random();
    let scmt = vec_commit((*BP).G, rho, &(*BP).GV, &s_l, &(*BP).HV, &s_r);

    let h = Hash::digest_chain(&[&vcmt, &acmt, &scmt]);
    let y = Fr::from(h);

    let h = Hash::digest(&h);
    let z = Fr::from(h).scaled();

    let mut poly_l0 = zero_vec();
    vec_decr(&a_l, z, &mut poly_l0);
    let poly_l1 = s_l;
    let poly_l = [poly_l0, poly_l1];

    let yvec = pow_vec(y);
    let zsq = z * z;

    let mut poly_r0 = zero_vec();
    let mut vprod = zero_vec();
    let mut a_rincr = zero_vec();
    vec_incr(&a_r, z, &mut a_rincr);
    hadamard_prod(&yvec, &a_rincr, &mut vprod);
    let mut vprod2 = zero_vec();
    vec_scale(&twos_vec(), zsq, &mut vprod2);
    vec_add(&vprod, &vprod2, &mut poly_r0);
    let mut poly_r1 = zero_vec();
    hadamard_prod(&yvec, &s_r, &mut poly_r1);
    let poly_r = [poly_r0, poly_r1];

    let poly_t = poly_dot_prod(&poly_l, &poly_r);
    let t1 = poly_t[1];
    let t2 = poly_t[2];

    let tau1 = Fr::random();
    let tau2 = Fr::random();

    let t1_cmt = simple_commit((*BP).G, (*BP).H, tau1, t1);
    let t2_cmt = simple_commit((*BP).G, (*BP).H, tau2, t2);

    let x = Fr::from(Hash::digest_chain(&[&t1_cmt, &t2_cmt]));

    let mut lvec = zero_vec();
    let mut l1 = zero_vec();
    vec_scale(&poly_l1, x, &mut l1);
    vec_add(&l1, &poly_l0, &mut lvec);

    let mut rvec = zero_vec();
    let mut r1 = zero_vec();
    vec_scale(&poly_r1, x, &mut r1);
    vec_add(&r1, &poly_r0, &mut rvec);

    let t_hat = vv_dot_prod(&lvec, &rvec);
    let tau_x = vv_dot_prod(&pow_vec3(x), &[gamma * zsq, tau1, tau2]);
    let mu = alpha + (rho * x);

    (
        BulletProof {
            vcmt: Pt::from(vcmt), // this is the main commitment value
            acmt: Pt::from(acmt),
            scmt: Pt::from(scmt),
            t1_cmt: Pt::from(t1_cmt),
            t2_cmt: Pt::from(t2_cmt),
            tau_x: tau_x.unscaled(),
            mu: mu.unscaled(),
            t_hat: t_hat.unscaled(),
            dot_proof: make_lr_dot_proof(y, mu, t_hat, &lvec, &rvec),
            x: x.unscaled(), // hash challenge values x,y,z
            y: y.unscaled(),
            z: z.unscaled(),
        },
        gamma.unscaled(),
    )
}

fn make_lr_dot_proof(
    y: Fr,
    mu: Fr,
    t_hat: Fr,
    lvec: &[Fr; NBASIS],
    rvec: &[Fr; NBASIS],
) -> DotProof {
    // do our best to avoid heap allocations. Since we are shrinking as we go,
    // we can allocate the mutable vectors at their largest size at the outset,
    // and just reuse their storage in each iteration.
    let mut gg = (*BP).GV; // compute the bent cloaking basis vector
    pt_hadamard_prod(&pow_vec(1 / y), &(*BP).GV, &mut gg);
    let mut hh = (*BP).HV; // the starting amount basis vector

    let u = (mu / t_hat) * (*BP).G; // the cloaking point for all following commitments
    let mut pcmt = vec_commit((*BP).G, mu, &gg, lvec, &hh, rvec); // initial commitment

    let mut a = *lvec; // copy the left/right vectors
    let mut b = *rvec;
    let mut acc = [LR {
        x: Fr::zero(), // preallocate the LR list accumulator
        l: Pt::from(u),
        r: Pt::from(u),
    }; L2_NBASIS];
    let mut aix = 0; // accumulator (iteration) index

    let mut gl = [ECp::inf(); NBASIS >> 1]; // preallocate the sub-vectors
    let mut gr = [ECp::inf(); NBASIS >> 1];
    let mut hl = [ECp::inf(); NBASIS >> 1];
    let mut hr = [ECp::inf(); NBASIS >> 1];
    let mut al = [Fr::zero(); NBASIS >> 1];
    let mut ar = [Fr::zero(); NBASIS >> 1];
    let mut bl = [Fr::zero(); NBASIS >> 1];
    let mut br = [Fr::zero(); NBASIS >> 1];
    let mut n = NBASIS; // starting vector size

    while n > 1 {
        // for as long as we can halve vectors...
        let n2 = n >> 1; // half-vector size
        for jx in 0..n2 {
            // copy ranges into L/R halves
            let kx = jx + n2;
            gl[jx] = gg[jx];
            gr[jx] = gg[kx];
            hl[jx] = hh[jx];
            hr[jx] = hh[kx];
            al[jx] = a[jx];
            ar[jx] = a[kx];
            bl[jx] = b[jx];
            br[jx] = b[kx];
        }
        let cl = vv_dot_prod(&al[..n2], &br[..n2]);
        let cr = vv_dot_prod(&ar[..n2], &bl[..n2]);
        let l = vec_commit(u, cl, &gr[..n2], &al[..n2], &hl[..n2], &br[..n2]);
        let r = vec_commit(u, cr, &gl[..n2], &ar[..n2], &hr[..n2], &bl[..n2]);
        let x = Fr::from(Hash::digest_chain(&[&l, &r])); // hash challenge value
        let xs = x.scaled();
        let xinv = 1 / xs;
        let xinvu = xinv.unscaled();
        for jx in 0..n2 {
            // compute new basis sub-vectors
            gg[jx] = xinvu * gl[jx] + x * gr[jx];
            hh[jx] = x * hl[jx] + xinvu * hr[jx];
            a[jx] = xs * al[jx] + xinv * ar[jx];
            b[jx] = xinv * bl[jx] + xs * br[jx];
        }

        let xsq = xs * xs;
        let xsqinv = 1 / xsq;
        pcmt += xsq * l + xsqinv * r; // update the commitment value

        // save this portion of the proof into list accumulator
        acc[aix] = LR {
            x: x.unscaled(),
            l: Pt::from(l),
            r: Pt::from(r),
        };

        aix += 1;
        n = n2;
    }
    // final dot-product composite proof
    DotProof {
        u: Pt::from(u),
        pcmt: Pt::from(pcmt),
        a: a[0].unscaled(),
        b: b[0].unscaled(),
        xlrs: acc,
    }
}

// ---------------------------------------------------------------------
pub fn validate_range_proof(bp: &BulletProof) -> bool {
    // TODO: fill in this stub
    true
}

// ---------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn check_bp_init() {
        println!("G: {}", Pt::from(*G));
        println!("H: {}", Pt::from((*BP).H));
        for ix in 0..NBASIS {
            println!("GV{} = {}", ix, Pt::from((*BP).GV[ix]));
            println!("HV{} = {}", ix, Pt::from((*BP).HV[ix]));
        }
    }

    #[test]
    pub fn test_vector_operations() {
        let v1 = [Fr::zero(), Fr::one(), Fr::from(2)];
        let mut v2 = [Fr::zero(); 3];
        vec_incr(&v1, Fr::from(1), &mut v2);
        assert!(v2[0] == Fr::one());
        assert!(v2[1] == Fr::from(2));
        assert!(v2[2] == Fr::from(3));
        let mut v3 = [Fr::zero(); 3];
        vec_add(&v1, &v2, &mut v3);
        assert!(v3[0] == Fr::one());
        assert!(v3[1] == Fr::from(3));
        assert!(v3[2] == Fr::from(5));
    }
}

// ------------------------------------------------------------
pub fn bulletproofs_tests() {
    println!("G: {}", Pt::from(*G));
    println!("H: {}", Pt::from((*BP).H));
    for ix in 0..NBASIS {
        println!("GV{} = {}", ix, Pt::from((*BP).GV[ix]));
        println!("HV{} = {}", ix, Pt::from((*BP).HV[ix]));
    }

    let v1 = [Fr::zero(), Fr::one(), Fr::from(2)];
    let mut v2 = [Fr::zero(); 3];
    vec_incr(&v1, Fr::from(1), &mut v2);
    assert!(v2[0] == Fr::one());
    assert!(v2[1] == Fr::from(2));
    assert!(v2[2] == Fr::from(3));
    let mut v3 = [Fr::zero(); 3];
    vec_add(&v1, &v2, &mut v3);
    assert!(v3[0] == Fr::one());
    assert!(v3[1] == Fr::from(3));
    assert!(v3[2] == Fr::from(5));

    println!("Start BulletProofs");
    let start = SystemTime::now();
    // let (proof, gamma) = make_range_proof(-1);
    if false {
        for _ in 0..999 {
            make_range_proof(1234567890);
        }
    }
    let (proof, gamma) = make_range_proof(1234567890);
    let timing = start.elapsed();
    println!("proof = {:#?}", proof);
    println!("gamma = {}", gamma);
    println!("Time: {:?}", timing);
}

// -------------------------------------------------------------

impl Debug for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BP(vcmt: {}, ...)", self.vcmt)
    }
}

impl fmt::Display for BulletProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}


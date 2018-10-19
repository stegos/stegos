//! mod.rs - Single-curve ECC on Curve1174

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

use std::fmt;
use std::mem;

use hex;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use hash::*;
use std::cmp::Ordering;
use utils::*;

mod winvec; // window vectors for point multiplication
use self::winvec::*;

mod lev32; // little-endian byte vector represetation
use self::lev32::*;

mod u256; // internal represntation of field elements
use self::u256::*;

mod fr; // additive field over the curve
use self::fr::*;

mod fq; // field in which curve is embedded
use self::fq::*;

mod fq51; // coord representation for Elliptic curve points
use self::fq51::*;

mod ecpt; // uncompressed points, affine & projective coords
use self::ecpt::*;

mod cpt; // compressed point representation
use self::cpt::*;

// -------------------------------------------------------
// Curve1174 General Constants
// Curve is Edwards curve:  x^2 + y^2 = 1 + d*x^2*y^2
// embedded with cofactor, h, into prime field Fq,
// with additive field Fr on curve.

pub const CURVE_D: i64 = -1174; // the d value in the curve equation
pub const CURVE_H: i64 = 4; // cofactor of curve group
pub const R: U256 = U256([
    0x8944D45FD166C971,
    0xF77965C4DFD30734,
    0xFFFFFFFFFFFFFFFF,
    0x1FFFFFFFFFFFFFF,
]); // |Fr|
pub const Q: U256 = U256([
    0xFFFFFFFFFFFFFFF7,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFF,
]); // |Fq|
pub const GEN_1174_X: Fq = Fq::Unscaled(U256([
    0x16123F27BCE29EDA,
    0xC021D96A492ECD65,
    0x9343AEE7C029A190,
    0x037FBB0CEA308C47,
]));
pub const GEN_1174_Y: Fq = Fq::Unscaled(U256([
    0xA4CCB1BF9B46360E,
    0x4FE2DEE2AF3F976B,
    0x6656841169840E0C,
    0x06B72F82D47FB7CC,
]));

// Generator as a compressed point
pub const GEN_1174: &str = "037fbb0cea308c479343aee7c029a190c021d96a492ecd6516123f27bce29eda";

// -------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_hex() {
        let s = "0123456789abcdefABCDEF";
        let mut v: [u8; 22] = [0; 22];
        let mut ix = 0;
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) => {
                    v[ix] = d as u8;
                    ix += 1;
                }
                None => panic!("Invalid hex digit"),
            }
        }
        assert!(
            v == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    #[should_panic]
    fn tst_badhex() {
        let s = "ghijk";
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) => println!("{}", d),
                None => panic!("Invalid hex digit"),
            }
        }
    }

    #[test]
    fn tst_str_to_elt() -> Result<(), hex::FromHexError> {
        let Fq51(ev) =
            Coord::from_str("0000000000000000000000000000000000000000000000000000000000000123")?;
        assert!(ev == [0x123, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn test_new_point() -> Result<(), hex::FromHexError> {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Coord::from_str(sx)?;
        let gen_y = Coord::from_str(sy)?;
        let pt1 = ECp::from_xy51(&gen_x, &gen_y);

        let gx = Coord::from_str(&sx)?;
        let gy = Coord::from_str(&sy)?;
        let pt2 = ECp::from_xy51(&gx, &gy);

        assert_eq!(pt1, pt2);
        Ok(())
    }

    #[test]
    fn test_add() -> Result<(), hex::FromHexError> {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Coord::from(GEN_1174_X);
        let gen_y = Coord::from(GEN_1174_Y);

        let mut sum = Coord::zero();
        gadd(&gen_x, &gen_y, &mut sum);

        let gx = Coord::from_str(&sx)?;
        let gy = Coord::from_str(&sy)?;
        let gz = gx + gy;

        assert_eq!(gz, sum);
        Ok(())
    }

}

// ------------------------------------------------------------------------------------------

pub fn curve1174_tests() -> Result<(), hex::FromHexError> {
    let smul = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
    let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA"; // *ed-gen* x
    let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E"; // *ed-gen* y

    let gx = Fq::from_str(&sx)?;
    let gy = Fq::from_str(&sy)?;
    let mx = Fr::from_str(&smul)?;
    let mut pt2: ECp = ECp::inf();
    for _ in 0..100 {
        let pt1 = ECp::from_xy(&gx, &gy);
        pt2 = pt1 * mx;
    }
    println!("pt2: {}", pt2);

    let pt1 = ECp::from_xy(&gx, &gy);
    let pt2 = pt1 + pt1;
    println!("ptsum {}", pt2);

    let tmp = Fr::from(2);
    let tmp2 = 1 / tmp;
    // println!("1/mul: {}", 1/Fr::from(2));
    // println!("unity? {}", (1/Fr::from(2)) * 2);
    println!("mul: {}", tmp);
    println!("1/2 = {}", tmp2);
    println!("R = {}", R);
    println!("mx: {}", tmp * tmp2);
    /* */
    let _ = StdRng::from_entropy();
    let mut r = StdRng::from_rng(thread_rng()).unwrap();
    let mut x = [0u8; 32];
    for _ in 0..10 {
        r.fill_bytes(&mut x);
        println!("{:?}", &x);
    }
    /*
    let mut hasher = Sha3_256::new();
    hasher.input(b"");
    let hex = hasher.result();
    println!("Hash = {:?}", hex);
    */
    /*
    let mut hasher = Sha3_256::default();
    hasher.input(b"");
    let out = hasher.result();
    println!("{:x}", out);
    */
    let gen_x = Coord::from_str(&sx)?;
    let gen_y = Coord::from_str(&sy)?;
    assert!(is_valid_pt(&gen_x, &gen_y));

    println!("The Generator Point");
    println!("gen_x: {}", gen_x);
    println!("gen_y: {}", gen_y);
    println!("gen_pt: {}", ECp::from_xy51(&gen_x, &gen_y));

    println!("x+y: {}", gen_x + gen_y);
    /* */
    let ept = ECp::from(Hash::from_vector(b"Testing12")); // produces an odd Y
    let cpt = Pt::from(ept); // MSB should be set
    let ept2 = ECp::from(cpt);
    println!("hash -> {}", ept);
    println!("hash -> {}", cpt);
    println!("hash -> {}", ept2);

    let gen = ECp::from_xy(&GEN_1174_X, &GEN_1174_Y);
    println!("gen cmpr = {}", Pt::from(gen));
    let gen = Pt::from_str(&GEN_1174);
    println!("gen from str = {}", gen);
    let ept = ECp::from(gen);
    println!("gen51 = {}", ept);

    let mut gen_bytes = [0u8; 32];
    hexstr_to_lev_u8(&GEN_1174, &mut gen_bytes);
    let hgen_bytes = Hash::from_vector(&gen_bytes);
    let hgen = Pt::from(ECp::from(hgen_bytes));
    println!("hgen = {}", hgen);
    let mut g_bpvec = Vec::<Pt>::new();
    let mut hbytes = hgen_bytes.bits();
    for ix in 0..64 {
        let h = Hash::from_vector(&hbytes);
        let pt = ECp::from(h);
        let cpt = Pt::from(pt);
        g_bpvec.push(cpt);
        hbytes = h.bits();
        println!("g{}: {}", ix, cpt);
    }
    let mut h_bpvec = Vec::<Pt>::new();
    for ix in 0..64 {
        let h = Hash::from_vector(&hbytes);
        let pt = ECp::from(h);
        let cpt = Pt::from(pt);
        h_bpvec.push(cpt);
        hbytes = h.bits();
        println!("h{}: {}", ix, cpt);
    }
    Ok(())
}

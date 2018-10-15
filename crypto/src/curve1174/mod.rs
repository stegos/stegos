// Single-curve ECC on Curve1174
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

#![allow(non_snake_case)]
#![allow(unused)]

use rand::prelude::*;

use std::fmt;
use std::mem;

use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign, DivAssign};

use hash::*;
use std::cmp::Ordering;

mod winvec;
use self::winvec::*;

mod lev32;
use self::lev32::*;

mod u256;
use self::u256::*;

mod fr;
use self::fr::*;

mod fq;
use self::fq::*;

mod fq51;
use self::fq51::*;

mod ecpt;
use self::ecpt::*;

mod cpt;
use self::cpt::*;

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
        let Fq51(ev) = e;
        assert!(ev == [0x123,0,0,0,0]);
    }
    
    #[test]
    fn test_new_point() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let mut gen_x = Fq51::zero();
        let mut gen_y = Fq51::zero();
        str_to_elt(sx, &mut gen_x); // *ed-gen*
        str_to_elt(sy, &mut gen_y);
        
        let mut pt1 : ECp = ECp::inf();
        init(&gen_x, &gen_y, &mut pt1);

        let gx = str_to_Fq(sx);
        let gy = str_to_Fq(sy);
        let pt2 = ECp::new(gx, gy);

        assert_eq!(pt1, pt2);
    }

    #[test]
    fn test_add() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let mut gen_x = Fq51::zero();
        let mut gen_y = Fq51::zero();
        str_to_elt(sx, &mut gen_x); // *ed-gen*
        str_to_elt(sy, &mut gen_y);
        
        let mut sum = Fq51::zero();
        gadd(&gen_x, &gen_y, &mut sum);

        let gx = str_to_Fq(sx);
        let gy = str_to_Fq(sy);
        let gz = Fq51::from(gx) + Fq51::from(gy);
    
        assert_eq!(gz, sum);
    }

}

// ------------------------------------------------------------------------------------------

pub fn curve1174_tests() {
    let smul = "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
    let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";  // *ed-gen* x
    let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";  // *ed-gen* y

    let gx = str_to_Fq(sx);
    let gy = str_to_Fq(sy);
    let mx = str_to_Fr(smul);
    let mut pt2 : ECp = ECp::inf();
    for _ in 0..100 {
        let pt1 = ECp::new(gx, gy);
        pt2 = pt1 * mx;
    }
    println!("pt2: {}", pt2);

    let pt1 = ECp::new(gx, gy);
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
    let mut x: [u8;32] = [0;32];
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
    let mut gen_x = Fq51::zero();
    let mut gen_y = Fq51::zero();
    str_to_elt(sx, &mut gen_x); // *ed-gen*
    str_to_elt(sy, &mut gen_y);

    println!("The Generator Point");
    println!("gen_x: {}", gen_x);
    println!("gen_y: {}", gen_y);

    println!("x+y: {}", gen_x + gen_y);
    /* */
    let ept = ECp::from(hash(b"Testing12")); // produces an odd Y
    let cpt = Pt::from(ept);                 // MSB should be set
    let ept2 = ECp::from(cpt.clone());
    println!("hash -> {}", ept);
    println!("hash -> {}", cpt);
    println!("hash -> {}", ept2);
} 


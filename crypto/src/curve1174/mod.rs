//! mod.rs - Single-curve ECC on Curve1174

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

use lazy_static::lazy_static;
use rand::prelude::*;
use std::cmp::Ordering;
use std::fmt;
use std::mem;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::hash::*;
use crate::utils::*;

mod winvec; // window vectors for point multiplication
use self::winvec::*;

mod lev32; // little-endian byte vector represetation
use self::lev32::*;

mod u256; // internal represntation of field elements
use self::u256::*;

pub mod fields;
use self::fields::*;

mod fq51; // coord representation for Elliptic curve points
use self::fq51::*;

pub mod ecpt; // uncompressed points, affine & projective coords
use self::ecpt::*;

pub mod cpt; // compressed point representation
use self::cpt::*;

// -------------------------------------------------------------------
// Signature Public Key - for checking curve constants validity
//
// Unit test: check_init() - validates the curve constants shown
// here for Curve1174.
//
// The ECC init won't succeed unless they checksum to the value
// shown below for HASH_CONSTS. That serves as a first line of defense
// against accidental corruption.
//
// For defense against intentional corruption with crafted curves,
// the unit test, check_init(), verifies the hash of these string
// constants against the known BLS signature, SIG_1174, using the
// public key, SIG_PKEY, shown here.

const SIG_PKEY : &str = "21aa87b48c3fce1699ffd0b4be79fb6ad2eb0b941ffd2b45a08ef12939885bcad095484e8a3fbf0ebee88f3874a07cc4570bc439fa5c5457d73c10ef131d42d601";
const SIG_1174: &str = "936cc106fed4b44ec9c9793eff701486eee6237347a4bca1d5a04314e484024401";

// -------------------------------------------------------
// Curve1174 General Constants
// Curve is Edwards curve:  x^2 + y^2 = 1 + d*x^2*y^2
// embedded with cofactor, h, into prime field Fq,
// with additive field Fr on curve.

pub const CURVE_D: i64 = -1174; // the d value in the curve equation
pub const CURVE_H: i64 = 4; // cofactor of curve group

pub const CURVE_R: &str = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C971";
pub const CURVE_Q: &str = "07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7";
pub const GEN_X: &str = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
pub const GEN_Y: &str = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";
pub const HASH_CONSTS: &str = "f68bce5c9388a3f20c8b3429ddd75333d156488a60a80ac373720f1d2d9d8313";

lazy_static! {
    pub static ref INIT: bool = {
        let mut state = Hasher::new();
        CURVE_R.hash(&mut state);
        CURVE_Q.hash(&mut state);
        GEN_X.hash(&mut state);
        GEN_Y.hash(&mut state);
        format!("D{} H{}", CURVE_D, CURVE_H).hash(&mut state);
        let h = state.result();
        let chk = Hash::try_from_hex(&HASH_CONSTS).expect("Invalid hexstr: HASH_CONSTS");
        assert!(h == chk, "Invalid curve constants checksum");
        check_prng();
        true
    };
    pub static ref R: U256 = {
        assert!(*INIT, "can't happen");
        U256::try_from_hex(CURVE_R).expect("Invalid hexstr: R")
    };
    pub static ref RMIN: Fr = {
        assert!(*INIT, "can't happen");
        Fr::acceptable_minval()
    };
    pub static ref Q: U256 = {
        assert!(*INIT, "can't happen");
        U256::try_from_hex(CURVE_Q).expect("Invalid hexstr: Q")
    };
    pub static ref QMIN: Fq = {
        assert!(*INIT, "can't happen");
        Fq::acceptable_minval()
    };
    pub static ref G: ECp = {
        assert!(*INIT, "can't happen");
        let gen_x = Fq::try_from_hex(GEN_X).expect("Invalid Gen X hexstr");
        let gen_y = Fq::try_from_hex(GEN_Y).expect("Invalid Gen Y hexstr");
        ECp::try_from_xy(&gen_x, &gen_y).expect("Invalid generator description")
    };
}

fn check_prng() {
    use std::f32;
    let mut rng: ThreadRng = thread_rng();
    let n = 1_000_000;
    let (sum, sumsq) = (0..n).fold((0.0f32, 0.0f32), |(s, s2), _| {
        let x = rng.gen::<f32>() - 0.5;
        (s + x, s2 + x * x)
    });
    let mn = sum / (n as f32);
    let stdev = f32::sqrt(sumsq / (n as f32));
    let invrt12 = 1.0 / f32::sqrt(12.0);
    let delta = 5.0 * invrt12 / f32::sqrt(n as f32);
    // approx 5-sigma bounds
    // could still fail on legitimate system, but only 1 in 3.5 million plausible
    let msg = "plausible PRNG failure";
    assert!(f32::abs(mn) < delta, msg);
    assert!(f32::abs(stdev - invrt12) < delta, msg);
}

// -------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::dbg;

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
    fn tst_str_to_elt() {
        let Fq51(ev) =
            Coord::from_str("0000000000000000000000000000000000000000000000000000000000000123")
                .unwrap();
        assert!(ev == [0x123, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_point() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Fq::try_from_hex(sx).unwrap();
        let gen_y = Fq::try_from_hex(sy).unwrap();
        let pt1 = ECp::try_from_xy(&gen_x, &gen_y).unwrap();
        dbg!((gen_x, gen_y, pt1));

        let gx = Fq::try_from_hex(&sx).unwrap();
        let gy = Fq::try_from_hex(&sy).unwrap();
        let pt2 = ECp::try_from_xy(&gx, &gy).unwrap();

        assert_eq!(pt1, pt2);
    }

    #[test]
    fn test_add() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Coord::from_str(sx).unwrap();
        let gen_y = Coord::from_str(sy).unwrap();

        let mut sum = Coord::zero();
        gadd(&gen_x, &gen_y, &mut sum);

        let gx = Coord::from_str(&sx).unwrap();
        let gy = Coord::from_str(&sy).unwrap();
        let gz = gx + gy;

        assert_eq!(gz, sum);
    }

    #[test]
    #[should_panic]
    fn check_bad_compression() {
        let pt = ECp::inf().compress();
        let ept = pt.decompress().unwrap();
    }

    #[test]
    fn chk_init() {
        use crate::pbc::secure;
        let sig_pkey =
            secure::PublicKey::try_from_hex(&SIG_PKEY).expect("Invalid hexstr: SIG_PKEY");
        let sig = secure::Signature::try_from_hex(&SIG_1174).expect("Invalid hexstr: SIG_1174");
        let h = Hash::try_from_hex(&HASH_CONSTS).expect("Invalid hexstr: HASH_CONSTS");
        secure::check_hash(&h, &sig, &sig_pkey).expect("Invalid Curve1174 init contants");
    }

    #[test]
    fn chk_encryption() {
        use crate::hash;
        let (skey, pkey) = make_random_keys();
        check_keying(&skey, &pkey).expect("Random keying failed");
        let msg = hash::hash_nbytes(72, b"This is a test");
        let mchk = Hash::from_vector(&msg);
        let payload = aes_encrypt(&msg, &pkey).expect("AES Encryption failed");
        let echk = Hash::from_vector(&payload.ctxt);
        assert!(mchk != echk, "AES Encryption produced identity mapping");
        let dmsg = aes_decrypt(&payload, &skey).unwrap();
        let dchk = Hash::from_vector(&dmsg);
        assert!(mchk == dchk, "AES Decryption failed");
    }

    #[test]
    fn chk_random() {
        let x1 = Fr::random();
        let x2 = Fr::random();
        assert!(
            x1 != x2,
            "Random generator not working in the expected manner"
        );
    }

    #[test]
    fn chk_scalar_conversion() {
        let x = 6i64;
        let fx = Fr::from(x);
        let uval = U256::from(fx.unscaled());
        dbg!(&uval);
        let xx = fx.to_i64();
        dbg!(&xx);
        assert!(xx.expect("Can't convert") == x);
    }
}

// ------------------------------------------------------------------------------------------

pub fn curve1174_tests() {
    let smul = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
    let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA"; // *ed-gen* x
    let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E"; // *ed-gen* y

    let gx = Fq::try_from_hex(&sx).unwrap();
    let gy = Fq::try_from_hex(&sy).unwrap();
    let mx = Fr::try_from_hex(&smul).unwrap();
    let mut pt2: ECp = ECp::inf();
    for _ in 0..100 {
        let pt1 = ECp::try_from_xy(&gx, &gy).unwrap();
        pt2 = pt1 * mx;
    }
    println!("pt2: {:?}", pt2);

    let pt1 = ECp::try_from_xy(&gx, &gy).unwrap();
    let pt2 = pt1 + pt1;
    println!("ptsum {:?}", pt2);

    let tmp = Fr::from(2);
    let tmp2 = 1 / tmp;
    // println!("1/mul: {}", 1/Fr::from(2));
    // println!("unity? {}", (1/Fr::from(2)) * 2);
    println!("mul: {:?}", tmp);
    println!("1/2 = {:?}", tmp2);
    println!("R = {:?}", *R);
    println!("mx: {:?}", tmp * tmp2);
    /* */
    let _ = StdRng::from_entropy();
    let mut r = StdRng::from_rng(thread_rng()).unwrap();
    let mut x = [0u8; 32];
    for _ in 0..10 {
        r.fill_bytes(&mut x);
        println!("{:?}", &x);
    }

    let gen_x = Fq::try_from_hex(&sx).unwrap();
    let gen_y = Fq::try_from_hex(&sy).unwrap();
    let pt = ECp::try_from_xy(&gen_x, &gen_y).unwrap();

    println!("The Generator Point");
    println!("gen_x: {:?}", gen_x);
    println!("gen_y: {:?}", gen_y);
    println!("gen_pt: {:?}", pt);

    println!("x+y: {:?}", gen_x + gen_y);
    /* */
    let ept = ECp::from(Hash::from_vector(b"Testing12")); // produces an odd Y
    let cpt = Pt::from(ept); // MSB should be set
    let ept2 = cpt.decompress().unwrap();
    println!("hash -> {:?}", ept);
    println!("hash -> {:?}", cpt);
    println!("hash -> {:?}", ept2);

    // ---------------------------------------------------------------
    let (skey, pkey) = make_deterministic_keys(b"Testing");
    check_keying(&skey, &pkey).expect("Bad keying");
    println!("pkey = {:?}", pkey);

    let delta = Fr::random();
    println!("delta = {:?}", delta);

    let ept = pkey.decompress().unwrap() + delta * *G;
    let delta_pkey = PublicKey::from(ept);
    println!("delta_key = {:?}", Pt::from(delta_pkey));

    let delta_skey = SecretKey::from(Fr::from(skey.clone()) + delta);

    let hmsg = Hash::try_from_hex(&HASH_CONSTS).unwrap();
    let sig = sign_hash(&hmsg, &skey);
    println!("sig = (u: {:?}, K: {:?})", sig.u, sig.K);

    use crate::hash;
    let msg = hash::hash_nbytes(72, b"This is a test");
    println!("msg = {}", Hash::from_vector(&msg));
    let payload = aes_encrypt(&msg, &pkey).unwrap();
    println!("cmsg = {}", Hash::from_vector(&payload.ctxt));
    let dmsg = aes_decrypt(&payload, &skey).unwrap();
    println!("dmsg = {}", Hash::from_vector(&dmsg));
    assert!(dmsg == msg, "Failure of encrypt/decrypt cycle");
}

// Test PBC Interface with Lynn's PBC Library and our LispPBCIntf glue layer.
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
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![allow(non_snake_case)]

use rand::prelude::*;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::consts::U8;

use std::fmt;
use std::mem;
use sha3::{Digest, Sha3_256, Shake256};

use std::sync::{Mutex, Arc};
use std::rc::Rc;
use std::thread;
use std::marker;
use std::vec::*;
use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign, DivAssign};

use rust_libpbc;

pub mod secure;
pub mod fast;

// -------------------------------------------------------------------
// Fast AR160 curves, but low security 2^80

const PBC_CONTEXT_AR160 : u8 = 0;
const NAME_AR160 : &str = "AR160";
const INIT_TEXT_AR160 : &str = "type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1";
const ORDER_AR160 : &str = "730750818665451621361119245571504901405976559617";
const G1_AR160 : &str = "797EF95B4B2DED79B0F5E3320D4C38AE2617EB9CD8C0C390B9CCC6ED8CFF4CEA4025609A9093D4C3F58F37CE43C163EADED39E8200C939912B7F4B047CC9B69300";
const G2_AR160 : &str = "A4913CAB767684B308E6F71D3994D65C2F1EB1BE4C9E96E276CD92E4D2B16A2877AA48A8A34CE5F1892CD548DE9106F3C5B0EBE7E13ACCB8C41CC0AE8D110A7F01";
const ZR_SIZE_AR160 : usize = 20;
const G1_SIZE_AR160 : usize = 65;
const G2_SIZE_AR160 : usize = 65;
const GT_SIZE_AR160 : usize = 128;

// -------------------------------------------------------------------
// Secure BN curves, security approx 2^128

const PBC_CONTEXT_FR256 : u8 = 1;
const NAME_FR256 : &str = "FR256";
const INIT_TEXT_FR256 : &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";
const ORDER_FR256 : &str = "115792089237314936872688561244471742058035595988840268584488757999429535617037";
const G1_FR256 : &str = "ff8f256bbd48990e94d834fba52da377b4cab2d3e2a08b6828ba6631ad4d668500";
const G2_FR256 : &str = "e20543135c81c67051dc263a2bc882b838da80b05f3e1d7efa420a51f5688995e0040a12a1737c80def47c1a16a2ecc811c226c17fb61f446f3da56c420f38cc01";
const ZR_SIZE_FR256 : usize = 32;
const G1_SIZE_FR256 : usize = 33;
const G2_SIZE_FR256 : usize = 65;
const GT_SIZE_FR256 : usize = 384;

// -------------------------------------------------------------------

pub struct PBCInfo {
    pub context      : u8, // which slot in the gluelib context table
    pub name         : *const str,
    pub text         : *const str,
    pub g1_size      : usize,
    pub g2_size      : usize,
    pub pairing_size : usize,
    pub field_size   : usize,
    pub order        : *const str,
    pub g1           : *const str,
    pub g2           : *const str
}

pub const CURVES : &[PBCInfo] = &[
    PBCInfo {
        context      : PBC_CONTEXT_AR160,
        name         : NAME_AR160,
        text         : INIT_TEXT_AR160,
        g1_size      : G1_SIZE_AR160,
        g2_size      : G2_SIZE_AR160,
        pairing_size : GT_SIZE_AR160,
        field_size   : ZR_SIZE_AR160,
        order        : ORDER_AR160,
        g1           : G1_AR160,
        g2           : G2_AR160},

    PBCInfo {
        context      : PBC_CONTEXT_FR256,
        name         : NAME_FR256,
        text         : INIT_TEXT_FR256,
        g1_size      : G1_SIZE_FR256,
        g2_size      : G2_SIZE_FR256,
        pairing_size : GT_SIZE_FR256,
        field_size   : ZR_SIZE_FR256,
        order        : ORDER_FR256,
        g1           : G1_FR256,
        g2           : G2_FR256},
];        

// -------------------------------------------------------------------
// collect a vector of 8-bit values from a hex string.
pub fn hexstr_to_u8v(s: &str, x: &mut [u8]) {
    let nx = x.len();
    let mut pos = 0;
    let mut val: u8 = 0;
    let mut cct = 0;
    for c in s.chars() {
        if pos < nx {
            match c.to_digit(16) {
                Some(d) => {
                    val += d as u8;
                    cct += 1;
                    if (cct & 1) == 0 {
                        x[pos] = val;
                        pos += 1;
                        val = 0;
                    }
                    else {
                        val <<= 4;
                    }
                },
                None => panic!("Invalid hex digit")
            }
        }
        else {
            break;
        }
    }
    for ix in pos..nx {
        x[ix] = val;
        val = 0;
    }
}

pub fn u8v_to_hexstr(x : &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0 .. x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

fn u8v_to_typed_str(pref : &str, vec : &[u8]) -> String {
    // produce a type-prefixed hexnum from a byte vector
    let mut s = String::from(pref);
    s.push_str("(");
    s.push_str(&u8v_to_hexstr(&vec));
    s.push_str(")");
    s
}

pub fn u8v_from_str(s : &str) -> Vec<u8> {
    let mut v : Vec<u8> = Vec::new();
    for c in s.chars() {
        v.push(c as u8);
    }
    v
}


// // -------------------------------------------------------------------

// fn main() {

//     fn init_pairings() {
//         for info in CURVES {
//             let context = info.context as u64;
//             unsafe {
//                 println!("Init curve {}", (*info.name).to_string());
//                 println!("Context: {}", context);
//                 println!("{}", (*info.text).to_string());

//                 let mut psize = [0u64;4];
//                 let ans = rust_libpbc::init_pairing(
//                     context,
//                     info.text as *mut _,
//                     (*info.text).len() as u64,
//                     psize.as_ptr() as *mut _);
//                 assert_eq!(ans, 0);
                
//                 assert_eq!(psize[0], info.g1_size as u64);
//                 assert_eq!(psize[1], info.g2_size as u64);
//                 assert_eq!(psize[2], info.pairing_size as u64);
//                 assert_eq!(psize[3], info.field_size as u64);

//                 let mut v1 = vec![0u8; info.g1_size];
//                 hexstr_to_u8v(&(*info.g1), &mut v1);
//                 println!("G1: {}", u8v_to_hexstr(&v1));
//                 let len = rust_libpbc::set_g1(
//                     context,
//                     v1.as_ptr() as *mut _);
//                 // returns nbr bytes read, should equal length of G1
//                 assert_eq!(len, info.g1_size as i64);

//                 let mut v1 = vec![0u8; info.g1_size];
//                 let len = rust_libpbc::get_g1(
//                     context,
//                     v1.as_ptr() as *mut _,
//                     info.g1_size as u64);
//                 assert_eq!(len, info.g1_size as u64);
//                 println!("G1 readback: {}", u8v_to_hexstr(&v1));
                
//                 let mut v2 = vec![0u8; info.g2_size];
//                 hexstr_to_u8v(&(*info.g2), &mut v2);
//                 println!("G2: {}", u8v_to_hexstr(&v2));
//                 let len = rust_libpbc::set_g2(
//                     context,
//                     v2.as_ptr() as *mut _);
//                 // returns nbr bytes read, should equal length of G2
//                 assert_eq!(len, info.g2_size as i64);

//                 let mut v2 = vec![0u8; info.g2_size];
//                 let len = rust_libpbc::get_g2(
//                     context,
//                     v2.as_ptr() as *mut _,
//                     info.g2_size as u64);
//                 assert_eq!(len, info.g2_size as u64);
//                 println!("G2 readback: {}", u8v_to_hexstr(&v2));
                
//             }
//             println!("");
//         }
//     }
//     // ------------------------------------------------------------------------
//     // check connection to PBC library
//     println!("Hello, world!");
//     let input = "hello!".as_bytes();
//     let output = vec![0u8; input.len()];
//     unsafe {
//         let echo_out = rust_libpbc::echo(
//             input.len() as u64,
//             input.as_ptr() as *mut _,
//             output.as_ptr() as *mut _,
//         );
//         assert_eq!(echo_out, input.len() as u64);
//         assert_eq!(input.to_vec(), output);
//     }
//     let out_str: String = std::str::from_utf8(&output).unwrap().to_string();
//     println!("Echo Output: {}", out_str);
//     println!("");

//     // init PBC library -- must only be performed once
//     let init = Mutex::new(false);
//     {
//         let mut done = init.lock().unwrap();
//         if ! *done {
//             *done = true;
//             init_pairings();
//         }
//     }

//     // test hashing
//     let h = Hash::from_vector(b"");
//     println!("hash(\"\") = {}", h.to_str());
//     assert_eq!(h.to_str(), "H(a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a)");
//     println!("");

//     // -------------------------------------
//     // on Secure pairings
//     // test PRNG
//     println!("rand Zr = {}", secure::get_random_Zr());

//     // test keying...
//     let (skey, pkey, sig) = secure::make_deterministic_keys(b"Testing");
//     println!("skey = {}", skey);
//     println!("pkey = {}", pkey);
//     println!("sig  = {}", sig);
//     assert!(secure::check_keying(&pkey, &sig));
//     println!("");

//     // -------------------------------------
//     // on Fast pairings
//     // test PRNG
//     println!("rand Zr = {}", fast::get_random_Zr());

//     // test keying...
//     let (skey, pkey, sig) = fast::make_deterministic_keys(b"Testing");
//     println!("skey = {}", skey);
//     println!("pkey = {}", pkey);
//     println!("sig  = {}", sig);
//     assert!(fast::check_keying(&pkey, &sig));

//     // -------------------------------------
//     // check some arithmetic on the Fast curves
//     let a = 0x123456789i64;
//     println!("chk Zr: 0x{:x} -> {}", a, fast::Zr::from_int(a));
//     println!("chk Zr: -1 -> {}", fast::Zr::from_int(-1));
//     println!("chk Zr: -1 + 1 -> {}", fast::Zr::from(-1) + 1);

//     // -------------------------------------------
//     let h = hash_nbytes(10, b"Testing");
//     println!("h = {}", u8v_to_hexstr(&h));
//     let h = hash_nbytes(64, b"Testing");
//     println!("h = {}", u8v_to_hexstr(&h));
 


// }

// -----------------------------------------------------
// Hashing with SHA3

const HASH_SIZE : usize = 32;

#[derive(Copy, Clone)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_vector(msg : &[u8]) -> Hash {
        hash(msg)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

pub fn hash(msg : &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    let out = hasher.result();
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&out[.. HASH_SIZE]);
    Hash(h)
}

pub fn hash_nbytes(nb : usize, msg : &[u8]) -> Vec<u8> {
    let nmsg = msg.len();
    let mut ct = nb;
    let mut ans = vec![0u8; nb];
    let mut jx = 0;
    let mut kx = 0u8;
    while ct > 0 {
        let mut inp = vec![kx];
        for ix in 0 .. nmsg {
            inp.push(msg[ix]);
        }
        let mut hasher = Sha3_256::new();
        hasher.input(inp);
        let out = hasher.result();
        let end = if ct > HASH_SIZE {
                    HASH_SIZE
                } else {
                    ct
                };
        for ix in 0 .. end {
            ans[jx + ix] = out[ix];
        }
        jx += end;
        ct -= end;
        kx += 1;
    }
    ans
}




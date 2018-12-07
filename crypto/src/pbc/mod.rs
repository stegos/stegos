//! PBC Crypto for Rust, atop Ben Lynn's PBCliib

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
#![allow(dead_code)]

pub mod fast;
pub mod secure;
use crate::hash::*;
use crate::utils::*;

use lazy_static::lazy_static;
use rust_libpbc;
use std::fmt;
use std::vec::*;

// -------------------------------------------------------------------
// Signature Public Key - for checking curve constants validity
//
// Unit test: check_pbc_init() - validates the curve constants shown
// here for AR160 and FR256.
//
// The PBC init won't succeed unless they checksum to the values
// shown below for HASH_AR160 and HASH_FR256. That serves as a first
// line of defense against accidental corruption.
//
// For defense against intentional corruption with crafted curves,
// the unit test, check_pbc_init(), verifies the hash of these string
// constants against known BLS signatures, SIG_AR160 and SIG_FR256,
// using the public key, SIG_PKEY, shown here.

const SIG_PKEY : &str = "21aa87b48c3fce1699ffd0b4be79fb6ad2eb0b941ffd2b45a08ef12939885bcad095484e8a3fbf0ebee88f3874a07cc4570bc439fa5c5457d73c10ef131d42d601";
const SIG_AR160: &str = "92c30db345bf5c867ca22a439a2a3d9373147a87f18dfc5d9ba727f8363bbd8500";
const SIG_FR256: &str = "f33bed0d86a668fb1768aa9b5f55020f92fa2a533e5a009316f1a35b0a78a9b800";

// -------------------------------------------------------------------
// Fast AR160 curves, but low security 2^80

const PBC_CONTEXT_AR160: u64 = 0;
const NAME_AR160: &str = "AR160";
const INIT_TEXT_AR160 : &str = "type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1";
const ORDER_AR160: &str = "8000000000000800000000000000000000000001";
const G1_AR160 : &str = "797EF95B4B2DED79B0F5E3320D4C38AE2617EB9CD8C0C390B9CCC6ED8CFF4CEA4025609A9093D4C3F58F37CE43C163EADED39E8200C939912B7F4B047CC9B69300";
const G2_AR160 : &str = "A4913CAB767684B308E6F71D3994D65C2F1EB1BE4C9E96E276CD92E4D2B16A2877AA48A8A34CE5F1892CD548DE9106F3C5B0EBE7E13ACCB8C41CC0AE8D110A7F01";
const ZR_SIZE_AR160: usize = 20;
const G1_SIZE_AR160: usize = 65;
const G2_SIZE_AR160: usize = 65;
const GT_SIZE_AR160: usize = 128;
const HASH_AR160: &str = "970faebc98c5ddf8798e4223ba517177547b0a31c0b4fec7d83ff5916b4891dc";

// -------------------------------------------------------------------
// Secure BN curves, security approx 2^128

const PBC_CONTEXT_FR256: u64 = 1;
const NAME_FR256: &str = "FR256";
const INIT_TEXT_FR256: &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";
const ORDER_FR256: &str = "FFFFFFFFFFFCF0CD46E5F25EEE71A49E0CDC65FB1299921AF62D536CD10B500D";
const G1_FR256: &str = "ff8f256bbd48990e94d834fba52da377b4cab2d3e2a08b6828ba6631ad4d668500";
const G2_FR256 : &str = "e20543135c81c67051dc263a2bc882b838da80b05f3e1d7efa420a51f5688995e0040a12a1737c80def47c1a16a2ecc811c226c17fb61f446f3da56c420f38cc01";
const ZR_SIZE_FR256: usize = 32;
const G1_SIZE_FR256: usize = 33;
const G2_SIZE_FR256: usize = 65;
const GT_SIZE_FR256: usize = 384;
const HASH_FR256: &str = "89e9ab4061400136bcf7bf15dac687966837b8b8ffad433768acc0351ecfe699";

// -------------------------------------------------------------------

lazy_static! {
    pub static ref INIT: bool = {
        private_init_pairings(
            PBC_CONTEXT_AR160,
            INIT_TEXT_AR160,
            G1_SIZE_AR160,
            G2_SIZE_AR160,
            GT_SIZE_AR160,
            ZR_SIZE_AR160,
            G1_AR160,
            G2_AR160,
            ORDER_AR160,
            HASH_AR160,
        );
        private_init_pairings(
            PBC_CONTEXT_FR256,
            INIT_TEXT_FR256,
            G1_SIZE_FR256,
            G2_SIZE_FR256,
            GT_SIZE_FR256,
            ZR_SIZE_FR256,
            G1_FR256,
            G2_FR256,
            ORDER_FR256,
            HASH_FR256,
        );
        true
    };
    pub static ref CONTEXT_FR256: u64 = {
        assert!(*INIT, "Can't happen");
        PBC_CONTEXT_FR256
    };
    pub static ref CONTEXT_AR160: u64 = {
        assert!(*INIT, "Can't happen");
        PBC_CONTEXT_AR160
    };
    pub static ref ORD_FR256: [u8; ZR_SIZE_FR256] = {
        assert!(*INIT, "Can't happen");
        let mut ord = [0u8; ZR_SIZE_FR256];
        hexstr_to_bev_u8(&ORDER_FR256, &mut ord).expect("Invalid HexString");
        ord
    };
    pub static ref MIN_FR256: secure::Zr = secure::Zr::acceptable_minval();
    pub static ref MAX_FR256: secure::Zr = secure::Zr::acceptable_maxval();
    pub static ref ORD_AR160: [u8; ZR_SIZE_AR160] = {
        assert!(*INIT, "Can't happen");
        let mut ord = [0u8; ZR_SIZE_AR160];
        hexstr_to_bev_u8(&ORDER_AR160, &mut ord).expect("Invalid HexString");
        ord
    };
    pub static ref MIN_AR160: fast::Zr = fast::Zr::acceptable_minval();
    pub static ref MAX_AR160: fast::Zr = fast::Zr::acceptable_maxval();
}

// -------------------------------------------------------------------

fn private_init_pairings(
    context: u64,
    text: &str,
    g1_size: usize,
    g2_size: usize,
    pairing_size: usize,
    field_size: usize,
    g1: &str,
    g2: &str,
    order: &str,
    hchk: &str,
) {
    // First, check that the text constants haven't changed
    let mut state = Hasher::new();
    text.hash(&mut state);
    order.hash(&mut state);
    g1.hash(&mut state);
    g2.hash(&mut state);
    let h = state.result();
    let chk = Hash::try_from_hex(hchk).expect("Invalid check hash");
    assert!(h == chk, "Init constants have changed");

    // yes - all the assert!() should panic fail. We are useless without PBC.
    let psize = [0u64; 4];
    unsafe {
        let ans = rust_libpbc::init_pairing(
            context,
            text.as_ptr() as *mut _,
            text.len() as u64,
            psize.as_ptr() as *mut _,
        );
        assert_eq!(ans, 0, "PBC Init Failure");
    }
    assert_eq!(psize[0], g1_size as u64, "Invalid G1 size");
    assert_eq!(psize[1], g2_size as u64, "Invalid G2 size");
    assert_eq!(psize[2], pairing_size as u64, "Invalid GT size");
    assert_eq!(psize[3], field_size as u64, "Invalid Zr size");

    let mut v1 = vec![0u8; g1_size];
    hexstr_to_bev_u8(g1, &mut v1).expect("Invalid G1 hexstring");
    let len = unsafe { rust_libpbc::set_g1(context, v1.as_ptr() as *mut _) };
    // returns nbr bytes read, should equal length of G1
    assert_eq!(len, g1_size as i64, "Set G1 failure");

    let v1 = vec![0u8; g1_size];
    let len = unsafe { rust_libpbc::get_g1(context, v1.as_ptr() as *mut _, g1_size as u64) };
    assert_eq!(len, g1_size as u64, "Get G1 failure");

    let mut v2 = vec![0u8; g2_size];
    hexstr_to_bev_u8(g2, &mut v2).expect("Invalid G2 hexstring");
    let len = unsafe { rust_libpbc::set_g2(context, v2.as_ptr() as *mut _) };
    // returns nbr bytes read, should equal length of G2
    assert_eq!(len, g2_size as i64, "Set G2 failure");

    let v2 = vec![0u8; g2_size];
    let len = unsafe { rust_libpbc::get_g2(context, v2.as_ptr() as *mut _, g2_size as u64) };
    assert_eq!(len, g2_size as u64, "Get G2 failure");
}

// --------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn check_pbc_connection() {
        // show that we correctly connect to LispPBCIntf lib
        let input = "hello!".as_bytes();
        let output = vec![0u8; input.len()];
        unsafe {
            let echo_out = rust_libpbc::echo(
                input.len() as u64,
                input.as_ptr() as *mut _,
                output.as_ptr() as *mut _,
            );
            assert_eq!(echo_out, input.len() as u64);
        }
        assert_eq!(input.to_vec(), output);
    }

    #[test]
    fn check_pbc_init() {
        use rand::rngs::ThreadRng;
        use rand::thread_rng;
        use rand::Rng;

        let sig_pkey =
            secure::PublicKey::try_from_hex(&SIG_PKEY).expect("Invalid hexstring: SIG_PKEY");

        let h = Hash::try_from_hex(&HASH_AR160).expect("Invalid hexstring: HASH_AR160");
        let sig =
            secure::Signature::try_from_hex(&SIG_AR160).expect("Invalid hexstring: SIG_AR160");
        assert!(
            secure::check_hash(&h, &sig, &sig_pkey),
            "Invalid curve constants for AR160"
        );

        let h = Hash::try_from_hex(&HASH_FR256).expect("Invalid hexstring: HASH_FR256");
        let sig = secure::Signature::try_from_hex(SIG_FR256).expect("Invalid hexstring: SIG_FR256");
        assert!(
            secure::check_hash(&h, &sig, &sig_pkey),
            "Invalid curve constants for FR256"
        );

        // check to be sure make_deterministic_keys() stil works properly
        let mut rng: ThreadRng = thread_rng();
        let seed = rng.gen::<[u8; 32]>();
        let (_skey, pkey, sig) = secure::make_deterministic_keys(&seed);
        assert!(secure::check_keying(&pkey, &sig), "Invalid keying");
        fast::G2::generator();
    }
}

// ---------------------------------------------------------------------

//! AONT Transform.

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

use crate::hash::*;
use crate::CryptoError;
use std::iter::repeat;

use crypto::aes;
use rand::thread_rng;
use rand::Rng;

const CANARY: &[u8] = b"*** AONT Canary ****";

pub fn aont_encrypt(msg: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = rng.gen::<[u8; 32]>();

    let mut aes_enc = aes::ctr(aes::KeySize::KeySize128, &key[..16], &key[16..]);
    let nel = msg.len();
    let cnel = nel + 16;
    let mut xmsg = Vec::<u8>::new();
    for ix in 0..nel {
        xmsg.push(msg[ix]);
    }
    for ix in 0..16 {
        xmsg.push(CANARY[ix]);
    }
    let mut ctxt: Vec<u8> = repeat(0).take(cnel).collect();
    aes_enc.process(&xmsg, &mut ctxt);
    for ix in 0..cnel {
        xmsg[ix] = 0;
    }
    let h = Hash::digest(&ctxt).bits();
    for ix in 0..32 {
        ctxt.push(h[ix] ^ key[ix]);
        key[ix] = 0;
    }
    ctxt
}

pub fn aont_decrypt(ctxt: &[u8], msg: &mut Vec<u8>) -> Result<(), CryptoError> {
    // caller must provide destination vector so that we can
    // zap intermediate result after transfer
    let tnel = ctxt.len();
    let cnel = tnel - 32;
    let nel = cnel - 16;
    let h = Hash::digest(&ctxt[..cnel]).bits();
    let mut key: Vec<u8> = repeat(0).take(32).collect();
    for ix in 0..32 {
        key[ix] = ctxt[cnel + ix] ^ h[ix];
    }
    let mut aes_enc = aes::ctr(aes::KeySize::KeySize128, &key[..16], &key[16..]);
    let mut cmsg: Vec<u8> = repeat(0).take(cnel).collect();
    aes_enc.process(&ctxt[..cnel], &mut cmsg);
    for ix in 0..32 {
        key[ix] = 0;
    }
    for ix in 0..16 {
        if cmsg[nel + ix] != CANARY[ix] {
            return Err(CryptoError::InvalidAontDecryption.into());
        }
    }
    msg.clear();
    for ix in 0..nel {
        msg.push(cmsg[ix]);
        cmsg[ix] = 0;
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn aont() {
        let msg = b"Test message";
        println!("msg = {:?}", msg);
        let ctxt = aont_encrypt(msg);
        println!("ctxt = {:?}", ctxt);
        let mut dmsg = Vec::<u8>::new();
        aont_decrypt(&ctxt, &mut dmsg).expect("Good decryption");
        println!("dmsg = {:?}", dmsg);
        for ix in 0..msg.len() {
            assert!(msg[ix] == dmsg[ix]);
        }
    }
}

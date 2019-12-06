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

use aes_ctr::{
    stream_cipher::{NewStreamCipher, SyncStreamCipher},
    Aes128Ctr,
};
use rand::thread_rng;
use rand::Rng;

const CANARY: &[u8] = b"*** AONT Canary ****";

pub fn aont_encrypt(msg: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = rng.gen::<[u8; 32]>();

    let mut aes_enc = Aes128Ctr::new_var(&key[..16], &key[16..]).unwrap();
    let nel = msg.len();
    let mut xmsg = Vec::<u8>::new();
    for ix in 0..nel {
        xmsg.push(msg[ix]);
    }
    for ix in 0..16 {
        xmsg.push(CANARY[ix]);
    }
    aes_enc.apply_keystream(&mut xmsg);

    let h = Hash::digest(&xmsg).bits();
    for ix in 0..32 {
        xmsg.push(h[ix] ^ key[ix]);
        key[ix] = 0;
    }
    xmsg
}

pub fn aont_decrypt(ctxt: &mut Vec<u8>) -> Result<(), CryptoError> {
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
    let mut aes_enc = Aes128Ctr::new_var(&key[..16], &key[16..]).unwrap();
    aes_enc.apply_keystream(&mut ctxt[..cnel]);
    for ix in 0..32 {
        key[ix] = 0;
        ctxt[cnel + ix] = 0;
    }
    for ix in 0..16 {
        if ctxt[nel + ix] != CANARY[ix] {
            return Err(CryptoError::InvalidAontDecryption.into());
        }
    }
    ctxt.resize(nel, 0);
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn aont() {
        let msg = b"Test message";
        println!("msg = {:?}", msg);
        let mut ctxt = aont_encrypt(msg);
        println!("ctxt = {:?}", ctxt);
        aont_decrypt(&mut ctxt).expect("Good decryption");
        println!("dmsg = {:?}", ctxt);
        for ix in 0..msg.len() {
            assert!(msg[ix] == ctxt[ix]);
        }
    }
}

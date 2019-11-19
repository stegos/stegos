#![allow(unused)]

use base64;
use crypto::aes::{self, KeySize};
use rand::{thread_rng, RngCore};
use std::iter::repeat;
use std::mem::forget;
use std::slice;
use stegos_crypto;

#[inline]
fn min(a: usize, b: usize) -> usize {
    if a > b {
        b
    } else {
        a
    }
}

fn alloc_buf(nel: usize) -> Vec<u8> {
    repeat(0u8).take(nel).collect()
}

fn decode64(txtin: *const u8, nin: usize) -> Result<Vec<u8>, base64::DecodeError> {
    let msgin = unsafe { slice::from_raw_parts(txtin, nin) };
    let ans = base64::decode(&msgin);
    forget(msgin);
    ans
}

fn copy_to_outbuf(bytes: &[u8], txtout: *mut u8, nout: usize) -> isize {
    let nin = bytes.len();
    let nout = min(nin, nout);
    if nout > 0 {
        let outbuf = unsafe { slice::from_raw_parts_mut(txtout, nout) };
        outbuf[..nout].copy_from_slice(&bytes[..nout]);
        forget(outbuf);
    }
    nin as isize // return how many should have been in outbuf
}

const INVALID_HEX64: isize = -1;
const INVALID_CRYPTOTEXT: isize = -2;

#[no_mangle]
pub extern "C" fn bytes_from_hex64(
    txtin: *const u8,
    nin: usize,
    txtout: *mut u8,
    nout: usize,
) -> isize {
    // Needed for reading key from file
    let dmsgin = match decode64(txtin, nin) {
        Ok(bytes) => bytes,
        _ => {
            return INVALID_HEX64; // invalid base64 string
        }
    };
    copy_to_outbuf(&dmsgin, txtout, nout)
}

#[no_mangle]
pub extern "C" fn api_decode(
    txtin: *const u8,
    nin: usize,
    key: *const u8, // expected to be 16 bytes
    txtout: *mut u8,
    nout: usize,
) -> isize {
    // Decode an API vector of bytes into a json string
    // json = aes128::decrypt(base64::decode(vec))

    let dmsgin = match decode64(txtin, nin) {
        Ok(bytes) => bytes,
        _ => {
            return INVALID_HEX64; // invalid base64 string
        }
    };

    let mut nel = dmsgin.len();
    if nel < 16 {
        return INVALID_CRYPTOTEXT; // invalid cryptotext
    }
    nel -= 16;
    if nel > 0 && nout > 0 {
        let key = unsafe { slice::from_raw_parts(key, 16) };
        let mut cipher = aes::ctr(KeySize::KeySize128, &key, &dmsgin[..16]);
        forget(key);

        let nout = min(nel, nout);
        let mut output = unsafe { slice::from_raw_parts_mut(txtout, nout) };
        cipher.process(&dmsgin[16..nout + 16], &mut output);
        forget(output);
    }
    nel as isize // how many bytes should have been in output
}

#[no_mangle]
pub extern "C" fn api_encode(
    txtin: *const u8,
    nin: usize,
    key: *const u8, // expected to be 16 bytes
    txtout: *mut u8,
    nout: usize,
) -> isize {
    // Encode a json string into an API vector
    //  vec = base64::encode(aes128::encrypt(json))
    let mut gen = thread_rng();
    let mut output = alloc_buf(nin + 16);
    gen.fill_bytes(&mut output[..16]);

    if nin > 0 {
        let key = unsafe { slice::from_raw_parts(key, 16) };
        let mut cipher = aes::ctr(KeySize::KeySize128, &key, &output[..16]);
        forget(key);

        let plaintext = unsafe { slice::from_raw_parts(txtin, nin) };
        cipher.process(&plaintext, &mut output[16..]);
        forget(plaintext);
    }
    let encmsg = base64::encode(&output).into_bytes();
    copy_to_outbuf(&encmsg, txtout, nout)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}


#[no_mangle]
pub extern "C" fn call_from_c() {
    println!("Just called a Rust function from C!");
    let pt = stegos_crypto::scc::Pt::inf();
    println!("Pt = {}", pt); 
}

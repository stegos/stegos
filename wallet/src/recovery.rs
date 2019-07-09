//
// Copyright (c) 2019 Stegos AG
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

use stegos_crypto::keying::{convert_int_to_wordlist, convert_wordlist_to_int};
use stegos_crypto::scc;
use stegos_keychain::KeyError;

fn checksum(bytes: &[u8]) -> u8 {
    let mut chk: u8 = 0;
    for b in bytes {
        chk ^= *b;
    }
    chk
}

pub fn account_skey_to_recovery(skey: &scc::SecretKey) -> String {
    let skey = skey.to_bytes();
    let mut bytes = [08; 33];
    bytes[0..32].copy_from_slice(&skey[..]);
    bytes[32] = checksum(&skey[..]);
    let words = convert_int_to_wordlist(&bytes);
    words[..].join(" ")
}

pub fn recovery_to_account_skey(recovery: &str) -> Result<scc::SecretKey, KeyError> {
    let words: Vec<&str> = recovery.split(' ').collect();
    let bytes = convert_wordlist_to_int(&words).map_err(|_| KeyError::InvalidRecoveryPhrase)?;
    if checksum(&bytes[0..32]) != bytes[32] {
        return Err(KeyError::InvalidRecoveryPhrase);
    }
    scc::SecretKey::try_from_bytes(&bytes[0..32]).map_err(|e| KeyError::InvalidRecoveryKey(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode() {
        let (skey, _pkey) = scc::make_random_keys();
        let words = account_skey_to_recovery(&skey);
        let skey2 = recovery_to_account_skey(&words).expect("invalid");
        assert_eq!(skey, skey2);

        // Check invalid checksum.
        let words: Vec<&str> = words.split(' ').collect();
        let mut bytes = convert_wordlist_to_int(&words).expect("valid");
        bytes[32] = !bytes[32]; // mutate checksum.
        let words = convert_int_to_wordlist(&bytes);
        let words = words[..].join(" ");
        let e = recovery_to_account_skey(&words).expect_err("invalid");
        match e {
            KeyError::InvalidRecoveryPhrase => {}
            _ => panic!("Invalid error"),
        }
    }
}

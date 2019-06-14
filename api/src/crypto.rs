//! WebSocket API - Messages encryption.

//
// MIT License
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

use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use rand::{thread_rng, RngCore};
use std::iter::repeat;

/// Key size for API token
pub const API_TOKENSIZE: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct ApiToken(pub(crate) [u8; API_TOKENSIZE]);

impl ApiToken {
    pub fn new() -> Self {
        let mut gen = thread_rng();
        let mut key = ApiToken([0u8; API_TOKENSIZE]);
        gen.fill_bytes(&mut key.0[..]);
        key
    }
}

// Encrypts the plaintext with given 32-byte key
// returns encrypted payload with 16-byte IV prepended
pub fn encrypt(key: &ApiToken, plaintext: &[u8]) -> Vec<u8> {
    let mut gen = thread_rng();
    let mut nonce: Vec<u8> = repeat(0u8).take(16).collect();
    gen.fill_bytes(&mut nonce[..]);
    let mut cipher = aes::ctr(KeySize::KeySize128, &key.0[..], &nonce);
    let mut output: Vec<u8> = repeat(0u8).take(16 + plaintext.len()).collect();
    output[..16].copy_from_slice(&nonce[..]);
    cipher.process(&plaintext, &mut output[16..]);
    output
}

pub fn decrypt(key: &ApiToken, ciphertext: &[u8]) -> Vec<u8> {
    let mut iv: Vec<u8> = repeat(0u8).take(16).collect();
    iv[..].copy_from_slice(&ciphertext[..16]);
    let mut cipher = aes::ctr(KeySize::KeySize128, &key.0[..], &iv);
    let mut output: Vec<u8> = repeat(0u8).take(ciphertext.len() - 16).collect();
    cipher.process(&ciphertext[16..], &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, ApiToken};
    use lipsum::lipsum_words;

    #[test]
    fn check_aes_crypto() {
        let text = lipsum_words(256);
        let token = ApiToken::new();
        let encrypted_text = encrypt(&token, &text.as_bytes());
        let text2 = decrypt(&token, &encrypted_text);

        assert_eq!(text.as_bytes(), &text2[..]);
    }
}

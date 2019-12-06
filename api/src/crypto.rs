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

use crate::error::KeyError;
use aes_ctr::{
    stream_cipher::{NewStreamCipher, SyncStreamCipher},
    Aes128Ctr,
};
use log::info;
use rand::{thread_rng, RngCore};
use std::fs;
use std::iter::repeat;
use std::path::Path;

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

    pub fn from_base64(token: &str) -> Result<Self, KeyError> {
        let token = base64::decode(token).map_err(|e| KeyError::ParseError(String::new(), e))?;
        if token.len() != API_TOKENSIZE {
            return Err(KeyError::InvalidKeySize(API_TOKENSIZE, token.len()).into());
        }
        let mut token2 = [0u8; API_TOKENSIZE];
        token2.copy_from_slice(&token);
        Ok(ApiToken(token2))
    }
}

// Encrypts the plaintext with given 32-byte key
// returns encrypted payload with 16-byte IV prepended
pub fn encrypt(key: &ApiToken, plaintext: &[u8]) -> Vec<u8> {
    let mut gen = thread_rng();
    let mut nonce: Vec<u8> = repeat(0u8).take(16).collect();
    gen.fill_bytes(&mut nonce[..]);
    let mut aes_enc = Aes128Ctr::new_var(&key.0[..], &nonce).unwrap();

    let mut output: Vec<u8> = repeat(0u8).take(16 + plaintext.len()).collect();
    output[..16].copy_from_slice(&nonce[..]);
    output[16..].copy_from_slice(plaintext);
    aes_enc.apply_keystream(&mut output[16..]);
    output
}

pub fn decrypt(key: &ApiToken, ciphertext: &[u8]) -> Vec<u8> {
    let mut iv: Vec<u8> = repeat(0u8).take(16).collect();
    iv[..].copy_from_slice(&ciphertext[..16]);
    let mut aes_enc = Aes128Ctr::new_var(&key.0[..], &iv).unwrap();
    let mut output: Vec<u8> = ciphertext[16..].to_vec();
    aes_enc.apply_keystream(&mut output);
    output
}

// Load API Key from file, generate new key, if file is missing
pub fn load_or_create_api_token(token_file: &Path) -> Result<ApiToken, KeyError> {
    if !token_file.exists() {
        info!("API Key file is missing, generating new one");
        let token = ApiToken::new();
        fs::write(token_file.clone(), base64::encode(&token.0))
            .map_err(|e| KeyError::InputOutputError(token_file.to_string_lossy().to_string(), e))?;
        return Ok(token);
    } else {
        return load_api_token(token_file);
    }
}

/// Load API token from a file.
pub fn load_api_token(token_file: &Path) -> Result<ApiToken, KeyError> {
    let token = fs::read_to_string(token_file)
        .map_err(|e| KeyError::InputOutputError(token_file.to_string_lossy().to_string(), e))?;
    let token = base64::decode(&token)
        .map_err(|e| KeyError::ParseError(token_file.to_string_lossy().to_string(), e))?;
    if token.len() != API_TOKENSIZE {
        return Err(KeyError::InvalidKeySize(API_TOKENSIZE, token.len()).into());
    }
    let mut token2 = [0u8; API_TOKENSIZE];
    token2.copy_from_slice(&token);
    Ok(ApiToken(token2))
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

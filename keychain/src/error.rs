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

use crate::pem;
use failure::{Error, Fail};
use stegos_crypto::CryptoError;

#[derive(Debug, Fail)]
pub enum KeyError {
    #[fail(display = "Input/Output Error: file={}, error={:?}", _0, _1)]
    InputOutputError(String, std::io::Error),
    #[fail(display = "Failed to parse PEM file: file={}, error={:?}", _0, _1)]
    ParseError(String, pem::ErrorKind),
    #[fail(display = "Invalid PEM tag: file={}, expected={}, got={}", _0, _1, _2)]
    InvalidTag(String, String, String),
    #[fail(display = "Invalid payload: file={}, error={:?}", _0, _1)]
    InvalidPayload(String, Error),
    #[fail(display = "Invalid password: file={}", _0)]
    InvalidPasswordPhrase(String),
    #[fail(display = "Invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[fail(display = "Invalid recover key: error={}", _0)]
    InvalidRecoveryKey(CryptoError),
    #[fail(display = "Invalid key: file={}, error={}", _0, _1)]
    InvalidKey(String, CryptoError),
    #[fail(display = "Invalid keying: skey_file={}, pkey_file={}", _0, _1)]
    InvalidKeying(String, String),
}

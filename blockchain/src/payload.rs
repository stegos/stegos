//! Transaction Payload.

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

use stegos_crypto::curve1174::cpt::{aes_encrypt, PublicKey};
use stegos_crypto::curve1174::fields::Fr;

// Re-export symbols needed for public API
pub use stegos_crypto::curve1174::cpt::EncryptedPayload;
pub use stegos_crypto::curve1174::CurveError;

/// Create a new monetary transaction.
pub fn new_monetary(
    delta: Fr,
    gamma: Fr,
    amount: i64,
    pkey: PublicKey,
) -> Result<EncryptedPayload, CurveError> {
    // Convert amount to BE vector.
    use std::mem::transmute;
    let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_be()) };

    let gamma_bytes: [u8; 32] = gamma.bits().to_lev_u8();
    let delta_bytes: [u8; 32] = delta.bits().to_lev_u8();

    let payload: Vec<u8> = [&amount_bytes[..], &delta_bytes[..], &gamma_bytes[..]].concat();

    // Ensure that the total length of package is 72 bytes.
    assert_eq!(payload.len(), 72);

    // String together a gamma, delta, and Amount (i64) all in one long vector and encrypt it.
    aes_encrypt(&payload, &pkey)
}

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

use std::fmt;
use stegos_crypto::hash::*;
use stegos_crypto::pbc::secure::PublicKey;
use stegos_crypto::pbc::secure::RVal;
use stegos_crypto::pbc::secure::ibe_encrypt;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::pbc::fast::Zr;
use stegos_crypto::utils::*;

#[derive(Clone)]
pub struct EncryptedPayload {
    rval: RVal,
    cmsg: Vec<u8>,
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "rval={} cmsg={}",
            self.rval.to_str(),
            u8v_to_hexstr(&self.cmsg)
        )
    }
}

impl fmt::Display for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Hashable for EncryptedPayload {
    fn hash(&self, state: &mut Hasher) {
        self.rval.hash(state);
        self.cmsg[..].hash(state);
    }
}

/// Package id for payments.
/// Must be four-byte long.
static PAYLOAD_PAYMENT_ID: [u8; 4] = *b"pmnt";

impl EncryptedPayload {
    pub fn new_payment(delta: Zr, gamma: Fr, amount: i64, pkey: PublicKey) -> EncryptedPayload {
        // Convert amount to BE vector.
        use std::mem::transmute;
        let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_be()) };
        let gamma_bytes: [u8; 32] = gamma.bits().to_lev_u8();

        let payload: Vec<u8> = [&amount_bytes[..], delta.base_vector(), &gamma_bytes[..]].concat();
        // Ensure that the total length of package is 64.
        assert_eq!(PAYLOAD_PAYMENT_ID.len() + payload.len(), 64);

        // String together a gamma, delta, and Amount (i64) all in one long vector and encrypt it.
        let packet = ibe_encrypt(&payload, &pkey, &PAYLOAD_PAYMENT_ID);

        EncryptedPayload {
            rval: packet.rval().clone(),
            cmsg: packet.cmsg().clone(),
        }
    }
}

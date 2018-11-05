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
use stegos_crypto::curve1174::cpt::*;
use stegos_crypto::hash::*;
use stegos_crypto::utils::*;

#[derive(Clone)]
pub struct EncryptedPayload {
    apkg: Pt,
    ag: Pt,
    cmsg: Vec<u8>,
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "apkg={} ag={} cmsg={}",
            self.apkg,
            self.ag,
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
        "Encr".hash(state);
        self.apkg.hash(state);
        self.ag.hash(state);
        self.cmsg[..].hash(state);
    }
}

impl EncryptedPayload {
    /// Returns some garbage for tests.
    // TODO: remove
    pub fn garbage() -> EncryptedPayload {
        let (_, pkey, _) = make_deterministic_keys(b"A test seed");
        let pkg = aes_encrypt(b"This is a test", &pkey).unwrap();
        EncryptedPayload {
            apkg: pkg.apkg,
            ag: pkg.ag,
            cmsg: pkg.ctxt,
        }
    }
}

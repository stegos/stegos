//
// Copyright (c) 2019 Stegos
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

use failure::{bail, Error};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;

/// Message that should be sended to facilitator.
// TODO: Replace with real message
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Message {
    pub pkey: secure::PublicKey,
}

/// Message that is broadcasted by facilitator, after timeout
// TODO: Replace with real message
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PoolInfo {
    pub accumulator: Vec<Message>,
    pub pkey: secure::PublicKey,
    pub sig: secure::Signature,
}

impl PoolInfo {
    pub fn new(
        accumulator: Vec<Message>,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> Self {
        let msg_hash = Self::hash(&accumulator, &pkey);
        let sig = secure::sign_hash(&msg_hash, skey);
        PoolInfo {
            sig,
            pkey,
            accumulator,
        }
    }

    fn hash(accumulator: &[Message], pkey: &secure::PublicKey) -> Hash {
        let mut hasher = Hasher::new();
        for m in accumulator {
            m.hash(&mut hasher);
        }
        pkey.hash(&mut hasher);
        hasher.result()
    }

    pub fn validate(&self) -> Result<(), Error> {
        let hash = Self::hash(&self.accumulator, &self.pkey);
        let msg_valid = secure::check_hash(&hash, &self.sig, &self.pkey);
        if msg_valid {
            Ok(())
        } else {
            bail!("Invalid Pool info received.")
        }
    }
}

impl Hashable for PoolInfo {
    fn hash(&self, state: &mut Hasher) {
        for message in &self.accumulator {
            message.hash(state);
        }

        self.pkey.hash(state);
        self.sig.hash(state);
    }
}

impl Hashable for Message {
    fn hash(&self, state: &mut Hasher) {
        self.pkey.hash(state);
    }
}

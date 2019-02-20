//! message.rs - ValueShuffle Messages.

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
//

use std::collections::HashMap;
use stegos_blockchain::Output;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SchnorrSig;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::dicemix::DcMatrix;
use stegos_crypto::dicemix::ParticipantID;
use stegos_crypto::hash::Hash;
use stegos_crypto::hash::Hashable;
use stegos_crypto::hash::Hasher;

#[derive(Debug)]
pub(crate) enum Message {
    Example { payload: String },
}

impl Hashable for Message {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Message::Example { payload } => {
                "Example".hash(state);
                payload.hash(state);
            }
        }
    }
}

//! message.rs - Snowball Messages.

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
use std::fmt;
use stegos_crypto::dicemix::DcMatrix;
use stegos_crypto::dicemix::ParticipantID;
use stegos_crypto::hash::Hash;
use stegos_crypto::hash::Hashable;
use stegos_crypto::hash::Hasher;
use stegos_crypto::scc::Fr;
use stegos_crypto::scc::Pt;
use stegos_crypto::scc::PublicKey;
use stegos_crypto::scc::SchnorrSig;
use stegos_crypto::scc::SecretKey;

#[derive(Clone)]
pub(crate) enum SnowballPayload {
    // Message payload types that are of interest to various phases
    // of Snowball
    SharedKeying {
        pkey: PublicKey,
        ksig: Pt,
        fee: i64,
    },
    Commitment {
        cmt: Hash,
        parts: Vec<ParticipantID>,
    },
    CloakedVals {
        matrix: DcMatrix,
        gamma_sum: Fr,
        cloaks: HashMap<ParticipantID, Hash>,
    },
    Signature {
        sig: SchnorrSig,
    },
    SecretKeying {
        skey: SecretKey,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SnowballMessage {
    // this kind of message could also deliver items
    // of interest to Snowball phases.
    pub sid: Hash,
    pub source: ParticipantID,
    pub destination: ParticipantID,
    pub payload: SnowballPayload,
}

impl fmt::Display for SnowballPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnowballPayload::SharedKeying { pkey, ksig, fee } => write!(
                f,
                "SnowballPayload::SharedKeying( pkey: {:?}, ksig: {:?}, fee: {:?})",
                pkey, ksig, fee
            ),
            SnowballPayload::Commitment { cmt, .. } => {
                write!(f, "SnowballPayload::Commitment( cmt: {})", cmt)
            }
            SnowballPayload::CloakedVals { .. } => write!(f, "SnowballPayload::CloakedVals(...)"),
            SnowballPayload::Signature { sig } => {
                write!(f, "SnowballPayload::Signature( sig: {:?})", sig)
            }
            SnowballPayload::SecretKeying { skey, .. } => {
                write!(f, "SnowballPayload::SecretKeying( skey: {:?})", skey)
            }
        }
    }
}

impl fmt::Debug for SnowballPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnowballPayload::SharedKeying { pkey, ksig, fee } => write!(
                f,
                "SnowballPayload::SharedKeying( pkey: {:?}, ksig: {:?}, fee: {:?})",
                pkey, ksig, fee
            ),
            SnowballPayload::Commitment { cmt, .. } => {
                write!(f, "SnowballPayload::Commitment( cmt: {})", cmt)
            }
            SnowballPayload::CloakedVals { .. } => write!(f, "SnowballPayload::CloakedVals(...)"),
            SnowballPayload::Signature { sig } => {
                write!(f, "SnowballPayload::Signature( sig: {:?})", sig)
            }
            SnowballPayload::SecretKeying { skey, .. } => {
                write!(f, "SnowballPayload::SecretKeying( skey: {:?})", skey)
            }
        }
    }
}

impl fmt::Display for SnowballMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.payload)
    }
}

impl Hashable for SnowballMessage {
    fn hash(&self, state: &mut Hasher) {
        "SnowballMessage".hash(state);
        self.sid.hash(state);
        self.source.hash(state);
        self.destination.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for SnowballPayload {
    fn hash(&self, state: &mut Hasher) {
        fn hash_cloaks(cloaks: &HashMap<ParticipantID, Hash>, state: &mut Hasher) {
            // Hashes on collections can't be consistent
            // unless the collections are pre-sorted
            let mut skeys: Vec<ParticipantID> = cloaks.keys().map(|&k| k).collect();
            skeys.sort();
            skeys.iter().for_each(|p| {
                p.hash(state);
                cloaks.get(p).unwrap().hash(state);
            });
        }
        match self {
            SnowballPayload::SharedKeying { pkey, ksig, fee } => {
                pkey.hash(state);
                ksig.hash(state);
                fee.hash(state);
            }
            SnowballPayload::Commitment { cmt, parts } => {
                cmt.hash(state);
                let mut lcl_parts = parts.clone();
                lcl_parts.sort();
                lcl_parts.iter().for_each(|p| p.hash(state));
            }
            SnowballPayload::CloakedVals {
                matrix,
                gamma_sum,
                cloaks,
            } => {
                for p in matrix {
                    for r in p {
                        for c in r {
                            c.hash(state);
                        }
                    }
                }
                gamma_sum.hash(state);
                hash_cloaks(cloaks, state);
            }
            SnowballPayload::Signature { sig } => {
                sig.hash(state);
            }
            SnowballPayload::SecretKeying { skey } => {
                skey.hash(state);
            }
        }
    }
}

//! message.rs - QueryShuffle Messages.

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
pub(crate) enum QueryShufflePayload {
    // Message payload types that are of interest to various phases
    // of QueryShuffle
    SharedKeying {
        pkey: PublicKey,
        fee: i64,
    },
    Commitment {
        cmt: Hash,
    },
    CloakedVals {
        matrix: DcMatrix,
        cloaks: HashMap<ParticipantID, Hash>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct QueryShuffleMessage {
    // this kind of message could also deliver items
    // of interest to QueryShuffle phases.
    pub sid: Hash,
    pub source: ParticipantID,
    pub destination: ParticipantID,
    pub payload: QueryShufflePayload,
}

impl fmt::Display for QueryShufflePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryShufflePayload::SharedKeying { pkey, fee } => write!(
                f,
                "QueryShufflePayload::SharedKeying( pkey: {:?}, fee: {:?})",
                pkey, fee
            ),
            QueryShufflePayload::Commitment { cmt } => {
                write!(f, "QueryShufflePayload::Commitment( cmt: {})", cmt)
            }
            QueryShufflePayload::CloakedVals { .. } => {
                write!(f, "QueryShufflePayload::CloakedVals(...)")
            }
        }
    }
}

impl fmt::Debug for QueryShufflePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryShufflePayload::SharedKeying { pkey, fee } => write!(
                f,
                "VsPayload::SharedKeying( pkey: {:?}, fee: {:?})",
                pkey, fee
            ),
            QueryShufflePayload::Commitment { cmt } => {
                write!(f, "VsPayload::Commitment( cmt: {})", cmt)
            }
            QueryShufflePayload::CloakedVals { .. } => write!(f, "VsPayload::CloakedVals(...)"),
        }
    }
}

impl fmt::Display for QueryShuffleMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.payload)
    }
}

impl Hashable for QueryShuffleMessage {
    fn hash(&self, state: &mut Hasher) {
        "QueryShuffleMessage".hash(state);
        self.sid.hash(state);
        self.source.hash(state);
        self.destination.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for QueryShufflePayload {
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
            QueryShufflePayload::SharedKeying { pkey, fee } => {
                pkey.hash(state);
                fee.hash(state);
            }
            QueryShufflePayload::Commitment { cmt } => {
                cmt.hash(state);
            }
            QueryShufflePayload::CloakedVals { matrix, cloaks } => {
                for p in matrix {
                    for r in p {
                        for c in r {
                            c.hash(state);
                        }
                    }
                }
                hash_cloaks(cloaks, state);
            }
        }
    }
}

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum VsMsgExpectedType {
    // used to indicate what kind of message payloads are wanted
    // in a collection pause between ValueShuffle phases.
    None, // when msg_state == None the participants list is complete
    SharedKeying,
    Commitment,
    CloakedVals,
    Signature,
    SecretKeying,
}

#[derive(Debug, Clone)]
pub(crate) enum VsPayload {
    // Message payload types that are of interest to various phases
    // of ValueShuffle
    SharedKeying {
        pkey: PublicKey,
        ksig: Pt,
    },
    Commitment {
        cmt: Hash,
    },
    CloakedVals {
        matrix: DcMatrix,
        gamma_sum: Fr,
        fee_sum: Fr,
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
pub(crate) enum Message {
    // types of messages delivered by the event system
    VsMessage {
        // this is the kind of message, whose payload
        // may be of interest to waiting phases in ValueShuffle
        sid: Hash,
        payload: VsPayload,
    },
    VsRestart {
        without_part: ParticipantID,
        session_id: Hash,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct DirectMessage {
    // this kind of message could also deliver items
    // of interest to ValueShuffle phases.
    // it acts as an addressed envelope for contained Message.
    pub source: ParticipantID,
    pub destination: ParticipantID,
    pub message: Message,
}

impl fmt::Display for VsPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VsPayload::SharedKeying { pkey, ksig } => write!(
                f,
                "VsPayload::SharedKeying( pkey: {:?}, ksig: {:?})",
                pkey, ksig
            ),
            VsPayload::Commitment { cmt } => write!(f, "VsPayload::Commitment( cmt: {})", cmt),
            VsPayload::CloakedVals { .. } => write!(f, "VsPayload::CloakedVals(...)"),
            VsPayload::Signature { sig } => write!(f, "VsPayload::Signature( sig: {:?})", sig),
            VsPayload::SecretKeying { skey, .. } => {
                write!(f, "VsPayload::SecretKeying( skey: {:?})", skey)
            }
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::VsMessage { payload, .. } => write!(f, "{}", payload),
            Message::VsRestart {
                without_part,
                session_id,
            } => write!(
                f,
                "VsRestart( without_part: {}, session_id: {})",
                without_part, session_id
            ),
        }
    }
}

impl Hashable for Message {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Message::VsMessage { sid, payload } => {
                "VsMessage".hash(state);
                sid.hash(state);
                payload.hash(state);
            }
            Message::VsRestart {
                without_part,
                session_id,
            } => {
                "VsRestart".hash(state);
                session_id.hash(state);
                without_part.hash(state);
            }
        }
    }
}

impl Hashable for VsPayload {
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
            VsPayload::SharedKeying { pkey, ksig } => {
                pkey.hash(state);
                ksig.hash(state);
            }
            VsPayload::Commitment { cmt } => {
                cmt.hash(state);
            }
            VsPayload::CloakedVals {
                matrix,
                gamma_sum,
                fee_sum,
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
                fee_sum.hash(state);
                hash_cloaks(cloaks, state);
            }
            VsPayload::Signature { sig } => {
                sig.hash(state);
            }
            VsPayload::SecretKeying { skey } => {
                skey.hash(state);
            }
        }
    }
}

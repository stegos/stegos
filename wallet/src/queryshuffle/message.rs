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
use stegos_crypto::scc::PublicKey;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum QsMsgType {
    None, // when msg_state == None the participants list is complete
    SharedKeying,
    Commitment,
    CloakedVals,
}

#[derive(Debug, Clone)]
pub(crate) enum QsPayload {
    SharedKeying {
        pkey: PublicKey,
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
pub(crate) enum QMessage {
    QsMessage {
        sid: Hash,
        payload: QsPayload,
    },
    QsRestart {
        without_part: ParticipantID,
        session_id: Hash,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct DirectQMessage {
    pub source: ParticipantID,
    pub destination: ParticipantID,
    pub message: QMessage,
}

impl fmt::Display for QsPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QsPayload::SharedKeying { pkey } => {
                write!(f, "QsPayload::SharedKeying( pkey: {:?} )", pkey)
            }
            QsPayload::Commitment { cmt } => write!(f, "QsPayload::Commitment( cmt: {})", cmt),
            QsPayload::CloakedVals { .. } => write!(f, "QsPayload::CloakedVals(...)"),
        }
    }
}

impl fmt::Display for QMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QMessage::QsMessage { payload, .. } => write!(f, "{}", payload),
            QMessage::QsRestart {
                without_part,
                session_id,
            } => write!(
                f,
                "QsRestart( without_part: {}, session_id: {})",
                without_part, session_id
            ),
        }
    }
}

impl Hashable for QMessage {
    fn hash(&self, state: &mut Hasher) {
        match self {
            QMessage::QsMessage { sid, payload } => {
                "QsMessage".hash(state);
                sid.hash(state);
                payload.hash(state);
            }
            QMessage::QsRestart {
                without_part,
                session_id,
            } => {
                "QsRestart".hash(state);
                session_id.hash(state);
                without_part.hash(state);
            }
        }
    }
}

impl Hashable for QsPayload {
    fn hash(&self, state: &mut Hasher) {
        match self {
            QsPayload::SharedKeying { pkey } => {
                pkey.hash(state);
            }
            QsPayload::Commitment { cmt } => {
                cmt.hash(state);
            }
            QsPayload::CloakedVals { matrix, cloaks } => {
                for p in matrix {
                    for r in p {
                        for c in r {
                            c.hash(state);
                        }
                    }
                }
                for (p, h) in cloaks {
                    // Q: does delivery maintain send order?
                    p.hash(state);
                    h.hash(state);
                }
            }
        }
    }
}

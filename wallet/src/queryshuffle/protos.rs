//! message.rs - QueryShuffle Protobuf Encoding.

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

use super::message::*;
use failure::Error;
use stegos_blockchain::protos::ProtoError;
use stegos_serialization::traits::*;

use crate::protos::queryshuffle;
use stegos_crypto::protos::crypto;

use std::collections::HashMap;
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::{Fr, PublicKey};

type DcRow = Vec<Fr>;
type DcSheet = Vec<DcRow>;
type ParticipantID = dicemix::ParticipantID;

impl ProtoConvert for QsPayload {
    type Proto = queryshuffle::QsPayload;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = queryshuffle::QsPayload::new();
        match self {
            QsPayload::SharedKeying { pkey } => {
                msg.set_sharedkeying(pkey.into_proto());
            }
            QsPayload::Commitment { cmt } => {
                msg.set_commitment(cmt.into_proto());
            }
            QsPayload::CloakedVals { matrix, cloaks } => {
                let mut body = queryshuffle::QCloakedVals::new();
                let mut dcsheets = queryshuffle::DcMatrix::new();
                for sheet in matrix {
                    let mut dcrows = queryshuffle::DcSheet::new();
                    for row in sheet {
                        let mut dccols = queryshuffle::DcRow::new();
                        for col in row {
                            dccols.cols.push(col.into_proto());
                        }
                        dcrows.rows.push(dccols);
                    }
                    dcsheets.sheets.push(dcrows);
                }
                body.set_matrix(dcsheets);
                for (p, h) in cloaks {
                    body.parts.push(p.into_proto());
                    body.cloaks.push(h.into_proto());
                }
                msg.set_cloakedvals(body);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.body {
            Some(queryshuffle::QsPayload_oneof_body::sharedkeying(ref msg)) => {
                QsPayload::SharedKeying {
                    pkey: PublicKey::from_proto(msg)?,
                }
            }
            Some(queryshuffle::QsPayload_oneof_body::commitment(ref msg)) => {
                QsPayload::Commitment {
                    cmt: Hash::from_proto(msg)?,
                }
            }
            Some(queryshuffle::QsPayload_oneof_body::cloakedvals(ref msg)) => {
                let mut matrix = Vec::<DcSheet>::new();
                for rowmsg in msg.get_matrix().get_sheets() {
                    let mut rows = Vec::<DcRow>::new();
                    for row in rowmsg.get_rows() {
                        let mut cols = Vec::<Fr>::new();
                        for col in row.get_cols() {
                            cols.push(Fr::from_proto(col)?);
                        }
                        rows.push(cols);
                    }
                    matrix.push(rows);
                }
                let mut cloaks: HashMap<ParticipantID, Hash> = HashMap::new();
                for (part, hash) in msg.parts.iter().zip(msg.cloaks.iter()) {
                    let p = ParticipantID::from_proto(part)?;
                    let h = Hash::from_proto(hash)?;
                    cloaks.insert(p, h);
                }
                QsPayload::CloakedVals { matrix, cloaks }
            }
            None => {
                return Err(
                    ProtoError::MissingField("body".to_string(), "body".to_string()).into(),
                );
            }
        };
        Ok(payload)
    }
}

impl ProtoConvert for QMessage {
    type Proto = queryshuffle::QMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = queryshuffle::QMessage::new();
        match self {
            QMessage::QsMessage { sid, payload } => {
                let mut msg = queryshuffle::QsMessage::new();
                msg.set_sid(sid.into_proto());
                msg.set_payload(payload.into_proto());
                proto.set_vsmessage(msg);
            }
            QMessage::QsRestart {
                without_part,
                session_id,
            } => {
                let mut msg = queryshuffle::QsRestart::new();
                msg.set_session_id(session_id.into_proto());
                msg.set_without_part(without_part.into_proto());
                proto.set_vsrestart(msg);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(queryshuffle::QMessage_oneof_body::vsmessage(ref msg)) => QMessage::QsMessage {
                sid: Hash::from_proto(msg.get_sid())?,
                payload: QsPayload::from_proto(msg.get_payload())?,
            },
            Some(queryshuffle::QMessage_oneof_body::vsrestart(ref msg)) => QMessage::QsRestart {
                without_part: ParticipantID::from_proto(msg.get_without_part())?,
                session_id: Hash::from_proto(msg.get_session_id())?,
            },
            None => {
                return Err(
                    ProtoError::MissingField("body".to_string(), "body".to_string()).into(),
                );
            }
        };
        Ok(msg)
    }
}

impl ProtoConvert for DirectQMessage {
    type Proto = queryshuffle::DirectQMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = queryshuffle::DirectQMessage::new();
        proto.set_source(self.source.into_proto());
        proto.set_destination(self.destination.into_proto());
        proto.set_message(self.message.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let source = dicemix::ParticipantID::from_proto(proto.get_source())?;
        let destination = dicemix::ParticipantID::from_proto(proto.get_destination())?;
        let message = QMessage::from_proto(proto.get_message())?;
        Ok(DirectQMessage {
            source,
            destination,
            message,
        })
    }
}

// -----------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::dbg;
    use stegos_crypto::scc::make_random_keys;

    #[test]
    fn qs_serialization() {
        let (_skey, pkey) = make_random_keys();
        let sid = Hash::digest("test");
        let msg = QMessage::QsMessage {
            sid,
            payload: QsPayload::SharedKeying { pkey },
        };
        let smsg = msg.into_buffer().expect("can't into_buffer()");
        // dbg!(&smsg);
        let xmsg = QMessage::from_buffer(&smsg).expect("can't deserialize msg");
        dbg!(&xmsg);
        match xmsg {
            QMessage::QsMessage {
                sid: xsid,
                payload: xpayload,
            } => {
                assert!(xsid == sid);
                match xpayload {
                    QsPayload::SharedKeying { pkey: xpkey } => {
                        assert!(xpkey == pkey);
                    }
                    _ => {
                        panic!("Improper payload deserialization");
                    }
                }
            }
            _ => {
                panic!("Improper message deserialization");
            }
        }
    }

}

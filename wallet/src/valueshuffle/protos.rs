//! message.rs - ValueShuffle Protobuf Encoding.

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

use crate::protos::valueshuffle;

use std::collections::HashMap;
use stegos_crypto::curve1174::{Fr, Pt, PublicKey, SchnorrSig, SecretKey};
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;

type DcRow = Vec<Fr>;
type DcSheet = Vec<DcRow>;
type ParticipantID = dicemix::ParticipantID;
impl ProtoConvert for VsPayload {
    type Proto = valueshuffle::VsPayload;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = valueshuffle::VsPayload::new();
        match self {
            VsPayload::SharedKeying { pkey, ksig } => {
                let mut body = valueshuffle::SharedKeying::new();
                body.set_pkey(pkey.into_proto());
                body.set_ksig(ksig.into_proto());
                msg.set_sharedkeying(body);
            }
            VsPayload::Commitment { cmt } => {
                let mut body = valueshuffle::Commitment::new();
                body.set_cmt(cmt.into_proto());
                msg.set_commitment(body);
            }
            VsPayload::CloakedVals {
                matrix,
                gamma_sum,
                fee_sum,
                cloaks,
            } => {
                let mut body = valueshuffle::CloakedVals::new();
                let mut dcsheets = valueshuffle::DcMatrix::new();
                for sheet in matrix {
                    let mut dcrows = valueshuffle::DcSheet::new();
                    for row in sheet {
                        let mut dccols = valueshuffle::DcRow::new();
                        for col in row {
                            dccols.cols.push(col.into_proto());
                        }
                        dcrows.rows.push(dccols);
                    }
                    dcsheets.sheets.push(dcrows);
                }
                body.set_matrix(dcsheets);
                body.set_gamma_sum(gamma_sum.into_proto());
                body.set_fee_sum(fee_sum.into_proto());
                for (p, h) in cloaks {
                    body.parts.push(p.into_proto());
                    body.cloaks.push(h.into_proto());
                }
                msg.set_cloakedvals(body);
            }
            VsPayload::Signature { sig } => {
                let mut body = valueshuffle::Signature::new();
                body.set_sig(sig.into_proto());
                msg.set_signature(body);
            }
            VsPayload::SecretKeying { skey } => {
                let mut body = valueshuffle::SecretKeying::new();
                body.set_skey(skey.into_proto());
                msg.set_secretkeying(body);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.body {
            Some(valueshuffle::VsPayload_oneof_body::sharedkeying(ref msg)) => {
                VsPayload::SharedKeying {
                    pkey: PublicKey::from_proto(msg.get_pkey())?,
                    ksig: Pt::from_proto(msg.get_ksig())?,
                }
            }
            Some(valueshuffle::VsPayload_oneof_body::commitment(ref msg)) => {
                VsPayload::Commitment {
                    cmt: Hash::from_proto(msg.get_cmt())?,
                }
            }
            Some(valueshuffle::VsPayload_oneof_body::cloakedvals(ref msg)) => {
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
                let gamma_sum = Fr::from_proto(msg.get_gamma_sum())?;
                let fee_sum = Fr::from_proto(msg.get_fee_sum())?;
                VsPayload::CloakedVals {
                    matrix,
                    gamma_sum,
                    fee_sum,
                    cloaks,
                }
            }
            Some(valueshuffle::VsPayload_oneof_body::signature(ref msg)) => VsPayload::Signature {
                sig: SchnorrSig::from_proto(msg.get_sig())?,
            },
            Some(valueshuffle::VsPayload_oneof_body::secretkeying(ref msg)) => {
                VsPayload::SecretKeying {
                    skey: SecretKey::from_proto(msg.get_skey())?,
                }
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

impl ProtoConvert for Message {
    type Proto = valueshuffle::Message;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = valueshuffle::Message::new();
        match self {
            Message::VsMessage { sid, payload } => {
                let mut msg = valueshuffle::VsMessage::new();
                msg.set_sid(sid.into_proto());
                msg.set_payload(payload.into_proto());
                proto.set_vsmessage(msg);
            }
            Message::VsRestart {
                without_part,
                session_id,
            } => {
                let mut msg = valueshuffle::VsRestart::new();
                msg.set_session_id(session_id.into_proto());
                msg.set_without_part(without_part.into_proto());
                proto.set_vsrestart(msg);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(valueshuffle::Message_oneof_body::vsmessage(ref msg)) => Message::VsMessage {
                sid: Hash::from_proto(msg.get_sid())?,
                payload: VsPayload::from_proto(msg.get_payload())?,
            },
            Some(valueshuffle::Message_oneof_body::vsrestart(ref msg)) => Message::VsRestart {
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

impl ProtoConvert for DirectMessage {
    type Proto = valueshuffle::DirectMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = valueshuffle::DirectMessage::new();
        proto.set_source(self.source.into_proto());
        proto.set_destination(self.destination.into_proto());
        proto.set_message(self.message.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let source = dicemix::ParticipantID::from_proto(proto.get_source())?;
        let destination = dicemix::ParticipantID::from_proto(proto.get_destination())?;
        let message = Message::from_proto(proto.get_message())?;
        Ok(DirectMessage {
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
    use stegos_crypto::bulletproofs::simple_commit;
    use stegos_crypto::curve1174::make_random_keys;

    #[test]
    fn vs_serialization() {
        let (_skey, pkey) = make_random_keys();
        let sid = Hash::digest("test");
        let ksig = simple_commit(&Fr::one(), &Fr::zero());
        let msg = Message::VsMessage {
            sid,
            payload: VsPayload::SharedKeying { pkey, ksig },
        };
        let smsg = msg.into_buffer().expect("can't into_buffer()");
        // dbg!(&smsg);
        let xmsg = Message::from_buffer(&smsg).expect("can't deserialize msg");
        dbg!(&xmsg);
        match xmsg {
            Message::VsMessage {
                sid: xsid,
                payload: xpayload,
            } => {
                assert!(xsid == sid);
                match xpayload {
                    VsPayload::SharedKeying {
                        pkey: xpkey,
                        ksig: xksig,
                    } => {
                        assert!(xpkey == pkey);
                        assert!(xksig == ksig);
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

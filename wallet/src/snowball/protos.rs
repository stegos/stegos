//! message.rs - Snowball Protobuf Encoding.

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

use crate::protos::snowball;

use std::collections::HashMap;
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::{Fr, Pt, PublicKey, SchnorrSig, SecretKey};

type DcRow = Vec<Fr>;
type DcSheet = Vec<DcRow>;
type ParticipantID = dicemix::ParticipantID;
impl ProtoConvert for SnowballPayload {
    type Proto = snowball::SnowballPayload;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = snowball::SnowballPayload::new();
        match self {
            SnowballPayload::SharedKeying { pkey, ksig } => {
                let mut body = snowball::SharedKeying::new();
                body.set_pkey(pkey.into_proto());
                body.set_ksig(ksig.into_proto());
                msg.set_sharedkeying(body);
            }
            SnowballPayload::Commitment { cmt } => {
                let mut body = snowball::Commitment::new();
                body.set_cmt(cmt.into_proto());
                msg.set_commitment(body);
            }
            SnowballPayload::CloakedVals {
                matrix,
                gamma_sum,
                fee_sum,
                cloaks,
            } => {
                let mut body = snowball::CloakedVals::new();
                let mut dcsheets = snowball::DcMatrix::new();
                for sheet in matrix {
                    let mut dcrows = snowball::DcSheet::new();
                    for row in sheet {
                        let mut dccols = snowball::DcRow::new();
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
                cloaks.iter().for_each(|(p, h)| {
                    body.drops.push(p.into_proto());
                    body.cloaks.push(h.into_proto());
                });
                msg.set_cloakedvals(body);
            }
            SnowballPayload::Signature { sig } => {
                let mut body = snowball::Signature::new();
                body.set_sig(sig.into_proto());
                msg.set_signature(body);
            }
            SnowballPayload::SecretKeying { skey } => {
                let mut body = snowball::SecretKeying::new();
                body.set_skey(skey.into_proto());
                msg.set_secretkeying(body);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.body {
            Some(snowball::SnowballPayload_oneof_body::sharedkeying(ref msg)) => {
                SnowballPayload::SharedKeying {
                    pkey: PublicKey::from_proto(msg.get_pkey())?,
                    ksig: Pt::from_proto(msg.get_ksig())?,
                }
            }
            Some(snowball::SnowballPayload_oneof_body::commitment(ref msg)) => {
                SnowballPayload::Commitment {
                    cmt: Hash::from_proto(msg.get_cmt())?,
                }
            }
            Some(snowball::SnowballPayload_oneof_body::cloakedvals(ref msg)) => {
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
                let gamma_sum = Fr::from_proto(msg.get_gamma_sum())?;
                let fee_sum = Fr::from_proto(msg.get_fee_sum())?;
                let mut cloaks: HashMap<ParticipantID, Hash> = HashMap::new();
                for (drop, hash) in msg.drops.iter().zip(msg.cloaks.iter()) {
                    let p = ParticipantID::from_proto(drop)?;
                    let h = Hash::from_proto(hash)?;
                    cloaks.insert(p, h);
                }
                SnowballPayload::CloakedVals {
                    matrix,
                    gamma_sum,
                    fee_sum,
                    cloaks,
                }
            }
            Some(snowball::SnowballPayload_oneof_body::signature(ref msg)) => {
                SnowballPayload::Signature {
                    sig: SchnorrSig::from_proto(msg.get_sig())?,
                }
            }
            Some(snowball::SnowballPayload_oneof_body::secretkeying(ref msg)) => {
                SnowballPayload::SecretKeying {
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

impl ProtoConvert for SnowballMessage {
    type Proto = snowball::Message;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = snowball::Message::new();
        match self {
            SnowballMessage::VsMessage { sid, payload } => {
                let mut msg = snowball::SnowballMessage::new();
                msg.set_sid(sid.into_proto());
                msg.set_payload(payload.into_proto());
                proto.set_message(msg);
            }
            SnowballMessage::VsRestart {
                without_part,
                session_id,
            } => {
                let mut msg = snowball::SnowballRestart::new();
                msg.set_session_id(session_id.into_proto());
                msg.set_without_part(without_part.into_proto());
                proto.set_restart(msg);
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let msg = match proto.body {
            Some(snowball::Message_oneof_body::message(ref msg)) => SnowballMessage::VsMessage {
                sid: Hash::from_proto(msg.get_sid())?,
                payload: SnowballPayload::from_proto(msg.get_payload())?,
            },
            Some(snowball::Message_oneof_body::restart(ref msg)) => SnowballMessage::VsRestart {
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
    type Proto = snowball::DirectMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = snowball::DirectMessage::new();
        proto.set_source(self.source.into_proto());
        proto.set_destination(self.destination.into_proto());
        proto.set_message(self.message.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let source = dicemix::ParticipantID::from_proto(proto.get_source())?;
        let destination = dicemix::ParticipantID::from_proto(proto.get_destination())?;
        let message = SnowballMessage::from_proto(proto.get_message())?;
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
    use stegos_crypto::scc::make_random_keys;

    #[test]
    fn snowball_serialization() {
        let (_skey, pkey) = make_random_keys();
        let sid = Hash::digest("test");
        let ksig = simple_commit(&Fr::one(), &Fr::zero());
        let msg = SnowballMessage::VsMessage {
            sid,
            payload: SnowballPayload::SharedKeying { pkey, ksig },
        };
        let smsg = msg.into_buffer().expect("can't into_buffer()");
        // dbg!(&smsg);
        let xmsg = SnowballMessage::from_buffer(&smsg).expect("can't deserialize msg");
        dbg!(&xmsg);
        match xmsg {
            SnowballMessage::VsMessage {
                sid: xsid,
                payload: xpayload,
            } => {
                assert!(xsid == sid);
                match xpayload {
                    SnowballPayload::SharedKeying {
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

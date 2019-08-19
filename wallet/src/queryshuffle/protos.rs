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
use super::*;
use crate::protos::queryshuffle;
use failure::Error;
use stegos_blockchain::protos::ProtoError;
use stegos_serialization::traits::*;

use std::collections::HashMap;
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::{Fr, Pt, PublicKey, SchnorrSig, SecretKey};

type DcRow = Vec<Fr>;
type DcSheet = Vec<DcRow>;
type ParticipantID = dicemix::ParticipantID;

impl ProtoConvert for QueryShufflePayload {
    type Proto = queryshuffle::QueryShufflePayload;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = queryshuffle::QueryShufflePayload::new();
        match self {
            QueryShufflePayload::SharedKeying { pkey, fee } => {
                let mut body = queryshuffle::SharedKeying::new();
                body.set_pkey(pkey.into_proto());
                body.set_fee(*fee);
                msg.set_sharedkeying(body);
            }
            QueryShufflePayload::Commitment { cmt } => {
                let mut body = queryshuffle::Commitment::new();
                body.set_cmt(cmt.into_proto());
                msg.set_commitment(body);
            }
            QueryShufflePayload::CloakedVals { matrix, cloaks } => {
                let mut body = queryshuffle::CloakedVals::new();
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
                cloaks.iter().for_each(|(p, h)| {
                    body.drops.push(p.into_proto());
                    body.cloaks.push(h.into_proto());
                });
                msg.set_cloakedvals(body);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.body {
            Some(queryshuffle::QueryShufflePayload_oneof_body::sharedkeying(ref msg)) => {
                QueryShufflePayload::SharedKeying {
                    pkey: PublicKey::from_proto(msg.get_pkey())?,
                    fee: msg.get_fee(),
                }
            }
            Some(queryshuffle::QueryShufflePayload_oneof_body::commitment(ref msg)) => {
                QueryShufflePayload::Commitment {
                    cmt: Hash::from_proto(msg.get_cmt())?,
                }
            }
            Some(queryshuffle::QueryShufflePayload_oneof_body::cloakedvals(ref msg)) => {
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
                for (drop, hash) in msg.drops.iter().zip(msg.cloaks.iter()) {
                    let p = ParticipantID::from_proto(drop)?;
                    let h = Hash::from_proto(hash)?;
                    cloaks.insert(p, h);
                }
                QueryShufflePayload::CloakedVals { matrix, cloaks }
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

impl ProtoConvert for QueryShuffleMessage {
    type Proto = queryshuffle::QueryShufflelMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = queryshuffle::QueryShufflelMessage::new();
        proto.set_sid(self.sid.into_proto());
        proto.set_source(self.source.into_proto());
        proto.set_destination(self.destination.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let sid = Hash::from_proto(proto.get_sid())?;
        let source = dicemix::ParticipantID::from_proto(proto.get_source())?;
        let destination = dicemix::ParticipantID::from_proto(proto.get_destination())?;
        let payload = QueryShufflePayload::from_proto(proto.get_payload())?;
        Ok(QueryShuffleMessage {
            sid,
            source,
            destination,
            payload,
        })
    }
}

// -----------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use stegos_crypto::bulletproofs::simple_commit;
    use stegos_crypto::hash::{Hash, Hashable};
    use stegos_crypto::{pbc, scc};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn queryshuffle_serialization() {
        let mut rng = thread_rng();
        let (_wallet_skey, wallet_pkey) = scc::make_random_keys();
        let (_network_skey, network_pkey) = pbc::make_random_keys();
        let sid = Hash::digest("test");
        let source = dicemix::ParticipantID::new(network_pkey, rng.gen::<[u8; 32]>());
        let destination = dicemix::ParticipantID::new(network_pkey, rng.gen::<[u8; 32]>());
        let msg = QueryShuffleMessage {
            sid,
            source,
            destination,
            payload: QueryShufflePayload::SharedKeying {
                pkey: wallet_pkey,
                fee: 15,
            },
        };
        roundtrip(&msg);
    }
}

//! protos.rs - Wallet storage protobuf encoding.

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

#![allow(bare_trait_objects)]

use failure::Error;
use stegos_serialization::traits::*;

// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use super::storage::{LogEntry, OutputValue, PaymentValue};
use crate::storage::{PaymentCertificate, PaymentTransactionValue};
use stegos_blockchain::{
    PaymentOutput, PaymentPayloadData, PaymentTransaction, PublicPaymentOutput,
};
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::{Fr, PublicKey};
use stegos_node::TransactionStatus;

// -----------------------------------------------------------

impl ProtoConvert for LogEntry {
    type Proto = account_log::LogEntry;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::LogEntry::new();
        match self {
            LogEntry::Outgoing { tx } => {
                let mut enum_value = account_log::Outgoing::new();
                enum_value.set_value(tx.into_proto());
                msg.set_outgoing(enum_value);
            }
            LogEntry::Incoming { output } => {
                let mut enum_value = account_log::Incoming::new();
                enum_value.set_output(output.into_proto());

                msg.set_incoming(enum_value);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.enum_value {
            Some(account_log::LogEntry_oneof_enum_value::incoming(ref msg)) => {
                let output = OutputValue::from_proto(msg.get_output())?;

                LogEntry::Incoming { output }
            }
            Some(account_log::LogEntry_oneof_enum_value::outgoing(ref msg)) => {
                let tx = PaymentTransactionValue::from_proto(msg.get_value())?;
                LogEntry::Outgoing { tx }
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

impl ProtoConvert for PaymentValue {
    type Proto = account_log::PaymentValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::PaymentValue::new();
        msg.set_output(self.output.into_proto());
        msg.set_amount(self.amount);
        let mut payload = account_log::PaymentPayload::new();
        match self.data {
            PaymentPayloadData::Comment(ref s) => {
                payload.set_comment(s.clone());
            }
            PaymentPayloadData::ContentHash(ref h) => {
                payload.set_hash(h.into_proto());
            }
        }
        msg.set_payload(payload);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let output = PaymentOutput::from_proto(proto.get_output())?;
        let amount = proto.get_amount();

        let data = match proto.get_payload().data {
            Some(account_log::PaymentPayload_oneof_data::comment(ref msg)) => {
                PaymentPayloadData::Comment(msg.clone())
            }
            Some(account_log::PaymentPayload_oneof_data::hash(ref msg)) => {
                let hash = Hash::from_proto(msg)?;
                PaymentPayloadData::ContentHash(hash)
            }
            None => {
                return Err(
                    ProtoError::MissingField("payload".to_string(), "payload".to_string()).into(),
                );
            }
        };

        let value = PaymentValue {
            output,
            amount,
            data,
        };

        Ok(value)
    }
}

impl ProtoConvert for OutputValue {
    type Proto = account_log::OutputValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::OutputValue::new();
        match self {
            OutputValue::Payment(p) => msg.set_payment(p.into_proto()),
            OutputValue::PublicPayment(p) => msg.set_public_payment(p.into_proto()),
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.enum_value {
            Some(account_log::OutputValue_oneof_enum_value::payment(ref msg)) => {
                let output = PaymentValue::from_proto(msg)?;
                output.into()
            }
            Some(account_log::OutputValue_oneof_enum_value::public_payment(ref msg)) => {
                let output = PublicPaymentOutput::from_proto(msg)?;
                output.into()
            }
            None => {
                return Err(ProtoError::MissingField(
                    "enum_value".to_string(),
                    "enum_value".to_string(),
                )
                .into());
            }
        };

        Ok(payload)
    }
}

impl ProtoConvert for PaymentCertificate {
    type Proto = account_log::PaymentCertificate;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::PaymentCertificate::new();
        msg.set_id(self.id);
        msg.set_recipient(self.recipient.into_proto());
        msg.set_rvalue(self.rvalue.into_proto());
        msg.set_amount(self.amount);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let id = proto.get_id();
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let rvalue = Fr::from_proto(proto.get_rvalue())?;
        let amount = proto.get_amount();

        let payload = PaymentCertificate {
            id,
            recipient,
            rvalue,
            amount,
        };

        Ok(payload)
    }
}

impl ProtoConvert for PaymentTransactionValue {
    type Proto = account_log::PaymentTransactionValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::PaymentTransactionValue::new();
        msg.set_tx(self.tx.into_proto());
        for certificate in &self.certificates {
            msg.certificates.push(certificate.into_proto());
        }
        let mut status = account_log::TransactionStatus::new();
        match self.status {
            TransactionStatus::Accepted { .. } => status.set_accepted(vec![0]),
            TransactionStatus::Created { .. } => status.set_created(vec![0]),
            TransactionStatus::Rejected { ref error } => status.set_rejected(error.clone()),
            TransactionStatus::Committed { epoch } => {
                let mut epoch_with_offset = account_log::EpochWithOffset::new();
                epoch_with_offset.set_epoch(epoch);
                status.set_committed(epoch_with_offset);
            }
            TransactionStatus::Conflicted { epoch, offset } => {
                let mut epoch_with_offset = account_log::EpochWithOffset::new();
                epoch_with_offset.set_epoch(epoch);
                if let Some(offset) = offset {
                    epoch_with_offset.set_offset(offset)
                } else {
                    epoch_with_offset.set_offset(u32::max_value())
                }
                status.set_conflicted(epoch_with_offset);
            }
            TransactionStatus::Prepare { epoch, offset } => {
                let mut epoch_with_offset = account_log::EpochWithOffset::new();
                epoch_with_offset.set_epoch(epoch);
                epoch_with_offset.set_offset(offset);
                status.set_prepare(epoch_with_offset);
            }
            TransactionStatus::Rollback { epoch, offset } => {
                let mut epoch_with_offset = account_log::EpochWithOffset::new();
                epoch_with_offset.set_epoch(epoch);
                epoch_with_offset.set_offset(offset);
                status.set_rollback(epoch_with_offset);
            }
        }
        msg.set_status(status);
        msg.set_amount(self.amount);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let tx = PaymentTransaction::from_proto(proto.get_tx())?;
        let mut certificates = Vec::<PaymentCertificate>::with_capacity(proto.certificates.len());
        for certificate in proto.certificates.iter() {
            certificates.push(PaymentCertificate::from_proto(certificate)?);
        }
        let status = match proto.get_status().enum_value {
            Some(account_log::TransactionStatus_oneof_enum_value::created(ref _msg)) => {
                TransactionStatus::Created {}
            }
            Some(account_log::TransactionStatus_oneof_enum_value::accepted(ref _msg)) => {
                TransactionStatus::Accepted {}
            }
            Some(account_log::TransactionStatus_oneof_enum_value::rejected(ref msg)) => {
                TransactionStatus::Rejected { error: msg.clone() }
            }
            Some(account_log::TransactionStatus_oneof_enum_value::committed(ref msg)) => {
                let epoch = msg.get_epoch();
                TransactionStatus::Committed { epoch }
            }
            Some(account_log::TransactionStatus_oneof_enum_value::prepare(ref msg)) => {
                let epoch = msg.get_epoch();
                let offset = msg.get_offset();
                TransactionStatus::Prepare { epoch, offset }
            }
            Some(account_log::TransactionStatus_oneof_enum_value::rollback(ref msg)) => {
                let epoch = msg.get_epoch();
                let offset = msg.get_offset();
                TransactionStatus::Rollback { epoch, offset }
            }
            Some(account_log::TransactionStatus_oneof_enum_value::conflicted(ref msg)) => {
                let epoch = msg.get_epoch();
                let offset = msg.get_offset();
                let offset = if offset == u32::max_value() {
                    None
                } else {
                    Some(offset)
                };
                TransactionStatus::Conflicted { epoch, offset }
            }
            None => {
                return Err(ProtoError::MissingField(
                    "enum_value".to_string(),
                    "enum_value".to_string(),
                )
                .into());
            }
        };
        let amount = proto.get_amount();
        let payload = PaymentTransactionValue {
            tx,
            status,
            amount,
            certificates,
        };
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use stegos_crypto::hash::{Hash, Hashable};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn transaction_status() {
        let tx = PaymentTransaction::dum();
        let epoch = 12;
        let offset = 43;
        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Accepted {},
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Rejected {
                error: "e".to_string(),
            },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Created {},
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Committed { epoch },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Prepare { epoch, offset },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Rollback { epoch, offset },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            certificates: vec![],
            status: TransactionStatus::Conflicted {
                epoch,
                offset: offset.into(),
            },
        };
        roundtrip(&request);
    }
}

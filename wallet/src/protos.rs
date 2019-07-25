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
use crate::storage::{ExtendedOutputValue, PaymentTransactionValue};
use stegos_blockchain::{
    PaymentOutput, PaymentPayloadData, PaymentTransaction, PublicPaymentOutput,
};
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
            LogEntry::Incoming { output, is_change } => {
                let mut enum_value = account_log::Incoming::new();
                enum_value.set_output(output.into_proto());
                enum_value.set_is_change(*is_change);
                msg.set_incoming(enum_value);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.enum_value {
            Some(account_log::LogEntry_oneof_enum_value::incoming(ref msg)) => {
                let output = OutputValue::from_proto(msg.get_output())?;
                let is_change = msg.get_is_change();
                LogEntry::Incoming { output, is_change }
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
        msg.set_payload(self.data.into_proto());
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let output = PaymentOutput::from_proto(proto.get_output())?;
        let amount = proto.get_amount();
        let data = PaymentPayloadData::from_proto(proto.get_payload())?;

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

impl ProtoConvert for ExtendedOutputValue {
    type Proto = account_log::ExtendedOutputValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::ExtendedOutputValue::new();
        msg.set_recipient(self.recipient.into_proto());
        msg.set_amount(self.amount);
        if let Some(ref rvalue) = self.rvalue {
            msg.set_rvalue(rvalue.into_proto());
        }
        if let Some(ref data) = self.data {
            msg.set_data(data.into_proto());
        }
        msg.set_is_change(self.is_change);
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let amount = proto.get_amount();
        let data = if proto.has_data() {
            Some(PaymentPayloadData::from_proto(proto.get_data())?)
        } else {
            None
        };
        let rvalue = if proto.has_rvalue() {
            Some(Fr::from_proto(proto.get_rvalue())?)
        } else {
            None
        };

        let is_change = proto.get_is_change();
        let payload = ExtendedOutputValue {
            recipient,
            amount,
            rvalue,
            data,
            is_change,
        };

        Ok(payload)
    }
}

impl ProtoConvert for PaymentTransactionValue {
    type Proto = account_log::PaymentTransactionValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = account_log::PaymentTransactionValue::new();
        msg.set_tx(self.tx.into_proto());
        for output in &self.outputs {
            msg.outputs.push(output.into_proto());
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
            TransactionStatus::Prepared { epoch, offset } => {
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
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let tx = PaymentTransaction::from_proto(proto.get_tx())?;
        let mut outputs = Vec::<ExtendedOutputValue>::with_capacity(proto.outputs.len());
        for output in proto.outputs.iter() {
            outputs.push(ExtendedOutputValue::from_proto(output)?);
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
                TransactionStatus::Prepared { epoch, offset }
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
        let payload = PaymentTransactionValue {
            tx,
            status,
            outputs,
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
            outputs: vec![],
            status: TransactionStatus::Accepted {},
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Rejected {
                error: "e".to_string(),
            },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Created {},
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Committed { epoch },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Prepared { epoch, offset },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Rollback { epoch, offset },
        };
        roundtrip(&request);

        let request = PaymentTransactionValue {
            tx: tx.clone(),
            outputs: vec![],
            status: TransactionStatus::Conflicted {
                epoch,
                offset: offset.into(),
            },
        };
        roundtrip(&request);
    }
}

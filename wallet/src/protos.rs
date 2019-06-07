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
use stegos_crypto::curve1174::{Fr, PublicKey};

// -----------------------------------------------------------

impl ProtoConvert for LogEntry {
    type Proto = wallet_log::LogEntry;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = wallet_log::LogEntry::new();
        match self {
            LogEntry::Outgoing { tx } => {
                let mut enum_value = wallet_log::Outgoing::new();
                enum_value.set_value(tx.into_proto());
                msg.set_outgoing(enum_value);
            }
            LogEntry::Incoming { output } => {
                let mut enum_value = wallet_log::Incoming::new();
                enum_value.set_output(output.into_proto());

                msg.set_incoming(enum_value);
            }
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.enum_value {
            Some(wallet_log::LogEntry_oneof_enum_value::incoming(ref msg)) => {
                let output = OutputValue::from_proto(msg.get_output())?;

                LogEntry::Incoming { output }
            }
            Some(wallet_log::LogEntry_oneof_enum_value::outgoing(ref msg)) => {
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
    type Proto = wallet_log::PaymentValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = wallet_log::PaymentValue::new();
        msg.set_output(self.output.into_proto());
        msg.set_amount(self.amount);
        msg.set_comment(String::from("test"));
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let output = PaymentOutput::from_proto(proto.get_output())?;
        let amount = proto.get_amount();
        let comment = String::from("test");
        let payload = PaymentValue {
            output,
            amount,
            data: PaymentPayloadData::Comment(comment),
        };

        Ok(payload)
    }
}

impl ProtoConvert for OutputValue {
    type Proto = wallet_log::OutputValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = wallet_log::OutputValue::new();
        match self {
            OutputValue::Payment(p) => msg.set_payment(p.into_proto()),
            OutputValue::PublicPayment(p) => msg.set_public_payment(p.into_proto()),
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload = match proto.enum_value {
            Some(wallet_log::OutputValue_oneof_enum_value::payment(ref msg)) => {
                let output = PaymentValue::from_proto(msg)?;
                output.into()
            }
            Some(wallet_log::OutputValue_oneof_enum_value::public_payment(ref msg)) => {
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
    type Proto = wallet_log::PaymentCertificate;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = wallet_log::PaymentCertificate::new();
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
    type Proto = wallet_log::PaymentTransactionValue;
    fn into_proto(&self) -> Self::Proto {
        let mut msg = wallet_log::PaymentTransactionValue::new();
        msg.set_tx(self.tx.into_proto());
        for certificate in &self.certificates {
            msg.certificates.push(certificate.into_proto());
        }
        msg
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let tx = PaymentTransaction::from_proto(proto.get_tx())?;
        let mut certificates = Vec::<PaymentCertificate>::with_capacity(proto.certificates.len());
        for certificate in proto.certificates.iter() {
            certificates.push(PaymentCertificate::from_proto(certificate)?);
        }

        let payload = PaymentTransactionValue { tx, certificates };
        Ok(payload)
    }
}

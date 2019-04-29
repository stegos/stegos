//! Protobuf Definitions.

//
// Copyright (c) 2018 Stegos AG
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

use stegos_serialization::traits::*;
// link protobuf dependencies
use crate::loader::{ChainLoaderMessage, RequestBlocks, ResponseBlocks};
use crate::transaction::{Transaction, TransactionBody};
use failure::{format_err, Error};
use protobuf::RepeatedField;
use stegos_blockchain::protos::*;
use stegos_blockchain::Output;
use stegos_crypto::curve1174::cpt;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::protos::*;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for Transaction {
    type Proto = transaction::Transaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = transaction::Transaction::new();

        for txin in &self.body.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.body.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_gamma(self.body.gamma.into_proto());
        proto.set_fee(self.body.fee);
        proto.set_sig(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let fee = proto.get_fee();
        let sig = cpt::SchnorrSig::from_proto(proto.get_sig())?;

        Ok(Transaction {
            body: TransactionBody {
                txins,
                txouts,
                gamma,
                fee,
            },
            sig,
        })
    }
}

impl ProtoConvert for RequestBlocks {
    type Proto = loader::RequestBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::RequestBlocks::new();
        proto.set_starting_height(self.starting_height);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let starting_height = proto.get_starting_height();
        Ok(RequestBlocks { starting_height })
    }
}

impl ProtoConvert for ResponseBlocks {
    type Proto = loader::ResponseBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ResponseBlocks::new();
        proto.set_height(self.height);
        let blocks: Vec<_> = self.blocks.iter().map(ProtoConvert::into_proto).collect();
        proto.set_blocks(RepeatedField::from_vec(blocks));
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let height = proto.get_height();
        let blocks: Result<Vec<_>, _> = proto
            .get_blocks()
            .iter()
            .map(ProtoConvert::from_proto)
            .collect();
        let blocks = blocks?;
        Ok(ResponseBlocks { height, blocks })
    }
}

impl ProtoConvert for ChainLoaderMessage {
    type Proto = loader::ChainLoaderMessage;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ChainLoaderMessage::new();
        match self {
            ChainLoaderMessage::Request(r) => proto.set_request(r.into_proto()),
            ChainLoaderMessage::Response(r) => proto.set_response(r.into_proto()),
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let ref body = proto
            .body
            .as_ref()
            .ok_or_else(|| format_err!("No variants in ChainLoaderMessage found"))?;
        let chain_message = match body {
            loader::ChainLoaderMessage_oneof_body::request(ref r) => {
                ChainLoaderMessage::Request(RequestBlocks::from_proto(r)?)
            }
            loader::ChainLoaderMessage_oneof_body::response(ref r) => {
                ChainLoaderMessage::Response(ResponseBlocks::from_proto(r)?)
            }
        };
        Ok(chain_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use stegos_crypto::hash::{Hash, Hashable};

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    fn mktransaction() -> Transaction {
        let (skey0, _pkey0) = cpt::make_random_keys();
        let (skey1, pkey1) = cpt::make_random_keys();
        let (_skey2, pkey2) = cpt::make_random_keys();

        let timestamp = SystemTime::now();
        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _delta0) =
            Output::new_payment(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) =
            Output::new_payment(timestamp, &skey1, &pkey2, amount).expect("keys are valid");

        roundtrip(&output11);
        roundtrip(&gamma11);

        let outputs_gamma = gamma11;

        let tx = Transaction::new(&skey1, &inputs1, &[output11], outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs1).unwrap();

        let tx2 = roundtrip(&tx);
        tx2.validate(&inputs1).unwrap();

        tx
    }

    #[test]
    fn transactions() {
        let tx = mktransaction();
        roundtrip(&tx);

        let mut buf = tx.into_buffer().unwrap();
        buf.pop();
        Transaction::from_buffer(&buf).expect_err("error");
    }

    #[test]
    fn chain_loader() {
        let request = ChainLoaderMessage::Request(RequestBlocks::new(1));
        roundtrip(&request);
    }
}

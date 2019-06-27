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

#![allow(bare_trait_objects)]
use stegos_crypto::protos::*;

use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use crate::loader::{ChainLoaderMessage, RequestBlocks, ResponseBlocks};
use failure::{format_err, Error};
use protobuf::RepeatedField;

use stegos_blockchain::PaymentOutput;
use stegos_crypto::hash::Hash;
use stegos_crypto::scc::SchnorrSig;
use stegos_crypto::{dicemix, CryptoError};

use crate::txpool::messages::{ParticipantTXINMap, PoolInfo, PoolJoin, PoolNotification};

impl ProtoConvert for RequestBlocks {
    type Proto = loader::RequestBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::RequestBlocks::new();
        proto.set_epoch(self.epoch);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let epoch = proto.get_epoch();
        Ok(RequestBlocks { epoch })
    }
}

impl ProtoConvert for ResponseBlocks {
    type Proto = loader::ResponseBlocks;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = loader::ResponseBlocks::new();
        let blocks: Vec<_> = self.blocks.iter().map(ProtoConvert::into_proto).collect();
        proto.set_blocks(RepeatedField::from_vec(blocks));
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let blocks: Result<Vec<_>, _> = proto
            .get_blocks()
            .iter()
            .map(ProtoConvert::from_proto)
            .collect();
        let blocks = blocks?;
        Ok(ResponseBlocks { blocks })
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

type TXIN = Hash;
type UTXO = PaymentOutput;

impl ProtoConvert for PoolJoin {
    type Proto = txpool::PoolJoin;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::PoolJoin::new();
        for txin in &self.txins {
            proto.txins.push((*txin).into_proto());
        }
        for utxo in &self.utxos {
            proto.utxos.push((*utxo).into_proto());
        }
        proto.set_ownsig(self.ownsig.into_proto());
        proto.set_seed(self.seed.to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<TXIN>::new();
        for txin in proto.get_txins() {
            txins.push(TXIN::from_proto(txin)?);
        }
        let mut utxos = Vec::<UTXO>::new();
        for utxo in proto.get_utxos() {
            utxos.push(UTXO::from_proto(utxo)?);
        }
        let seed_slice = proto.get_seed();
        if seed_slice.len() != 32 {
            return Err(CryptoError::InvalidBinaryLength(32, seed_slice.len()).into());
        }
        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(seed_slice);
        let ownsig = SchnorrSig::from_proto(proto.get_ownsig())?;
        Ok(PoolJoin {
            txins,
            utxos,
            seed,
            ownsig,
        })
    }
}

impl ProtoConvert for ParticipantTXINMap {
    type Proto = txpool::ParticipantTXINMap;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::ParticipantTXINMap::new();
        proto.set_participant(self.participant.into_proto());
        proto.set_ownsig(self.ownsig.into_proto());
        for txin in &self.txins {
            proto.txins.push((*txin).into_proto());
        }
        for utxo in &self.utxos {
            proto.utxos.push((*utxo).into_proto());
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let participant = dicemix::ParticipantID::from_proto(proto.get_participant())?;
        let mut txins = Vec::<TXIN>::new();
        let mut utxos = Vec::<UTXO>::new();
        for txin in proto.get_txins() {
            txins.push(TXIN::from_proto(txin)?);
        }
        for utxo in proto.get_utxos() {
            utxos.push(UTXO::from_proto(utxo)?);
        }
        let ownsig = SchnorrSig::from_proto(proto.get_ownsig())?;
        Ok(ParticipantTXINMap {
            participant,
            txins,
            utxos,
            ownsig,
        })
    }
}

impl ProtoConvert for PoolInfo {
    type Proto = txpool::PoolInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::PoolInfo::new();
        for elt in &self.participants {
            proto.participants.push((*elt).into_proto());
        }
        proto.set_session_id(self.session_id.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut participants = Vec::<ParticipantTXINMap>::new();
        for elt in proto.get_participants() {
            participants.push(ParticipantTXINMap::from_proto(elt)?);
        }
        let session_id = Hash::from_proto(proto.get_session_id())?;
        Ok(PoolInfo {
            participants,
            session_id,
        })
    }
}

impl ProtoConvert for PoolNotification {
    type Proto = txpool::PoolNotification;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = txpool::PoolNotification::new();
        match self {
            PoolNotification::Started(r) => proto.set_started(r.into_proto()),
            PoolNotification::Canceled => proto.set_canceled(txpool::PoolCanceled::new()),
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let ref body = proto
            .body
            .as_ref()
            .ok_or_else(|| format_err!("No variants in PoolNotification found"))?;
        let chain_message = match body {
            txpool::PoolNotification_oneof_body::started(ref r) => {
                PoolNotification::Started(PoolInfo::from_proto(r)?)
            }
            txpool::PoolNotification_oneof_body::canceled(_) => PoolNotification::Canceled,
        };
        Ok(chain_message)
    }
}

#[cfg(test)]
mod tests {
    /*
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
    fn message() {
        let message = PoolJoin { txins: Vec::<TXIN>::new(),
        ownsig: SchnorrSig::new() };
        roundtrip(&message);
    }

    #[test]
    fn pool_info() {
        let (_, pkey) = pbc::make_random_keys();
        let (_, pkey1) = pbc::make_random_keys();

        let session_id = Hash::digest(&1u64);
        let mut participants: Vec<pbc::PublicKey> = Vec::new();
        participants.push((pkey.clone(), Vec::new(), scc::SchnorrSig::new()));
        participants.push(pkey1);
        let pool = PoolInfo {
            participants,
            session_id,
        };
        roundtrip(&pool);
    }
    */
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
    fn chain_loader() {
        let request = ChainLoaderMessage::Request(RequestBlocks::new(1));
        roundtrip(&request);
    }
}

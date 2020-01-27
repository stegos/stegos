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

use failure::{format_err, Error};
use stegos_blockchain::PaymentOutput;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc;
use stegos_crypto::{dicemix, CryptoError};

/// A topic used for Join requests.
pub const POOL_JOIN_TOPIC: &'static str = "txpool_join";
/// A topic for PoolInfo messages.
pub const POOL_ANNOUNCE_TOPIC: &'static str = "txpool_announce";

type TXIN = Hash;
type UTXO = PaymentOutput;
type SchnorrSig = scc::SchnorrSig;
type ParticipantID = dicemix::ParticipantID;

use stegos_serialization::traits::*;
// link protobuf dependencies
use stegos_blockchain::protos::*;
use stegos_crypto::protos::*;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

// --------------------------------------------------

/// Send when node wants to join TxPool.
#[derive(Debug, Clone)]
pub struct PoolJoin {
    pub txins: Vec<TXIN>,
    pub utxos: Vec<UTXO>,
    pub seed: [u8; 32],
    pub ownsig: SchnorrSig,
}

/// Sent when a new transaction pool is formed.
#[derive(Debug, Clone)]
pub struct ParticipantTXINMap {
    pub participant: ParticipantID,
    pub txins: Vec<TXIN>,
    pub utxos: Vec<UTXO>,
    pub ownsig: SchnorrSig,
}

#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub participants: Vec<ParticipantTXINMap>,
    pub session_id: Hash,
}

#[derive(Debug, Clone)]
pub enum PoolNotification {
    /// Pool formed, information about pool.
    Started(PoolInfo),
    /// Pool canceled, in case of new facilitator.
    Canceled,
}

// --------------------------------------------------

impl Hashable for PoolJoin {
    fn hash(&self, state: &mut Hasher) {
        "PoolJoin".hash(state);
        for txin in &self.txins {
            txin.hash(state);
        }
        self.seed.hash(state);
        self.ownsig.hash(state);
    }
}

impl Hashable for ParticipantTXINMap {
    fn hash(&self, state: &mut Hasher) {
        "ParticipantTXINMap".hash(state);
        self.participant.hash(state);
        for txin in &self.txins {
            txin.hash(state);
        }
        for utxo in &self.utxos {
            utxo.hash(state);
        }
        self.ownsig.hash(state);
    }
}
impl Hashable for PoolInfo {
    fn hash(&self, state: &mut Hasher) {
        "PoolInfo".hash(state);
        for elt in &self.participants {
            elt.hash(state);
        }
        self.session_id.hash(state);
    }
}

impl Hashable for PoolNotification {
    fn hash(&self, state: &mut Hasher) {
        match self {
            PoolNotification::Started(r) => {
                "PoolNotification::Started".hash(state);
                r.hash(state)
            }
            PoolNotification::Canceled => "PoolNotification::Canceled".hash(state),
        }
    }
}

impl From<PoolInfo> for PoolNotification {
    fn from(info: PoolInfo) -> PoolNotification {
        PoolNotification::Started(info)
    }
}

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

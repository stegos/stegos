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

use stegos_blockchain::PaymentOutput;
use stegos_crypto::dicemix;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc;

/// A topic used for Join requests.
pub const POOL_JOIN_TOPIC: &'static str = "txpool_join";
/// A topic for PoolInfo messages.
pub const POOL_ANNOUNCE_TOPIC: &'static str = "txpool_announce";

/// A topic used for QueryPoolJoin requests.
pub const QUERYPOOL_JOIN_TOPIC: &'static str = "qpool_join";
/// A topic for QueryPool PoolInfo messages.
pub const QUERYPOOL_ANNOUNCE_TOPIC: &'static str = "qpool_announce";

type TXIN = Hash;
type UTXO = PaymentOutput;
type SchnorrSig = scc::SchnorrSig;
type ParticipantID = dicemix::ParticipantID;

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

// -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct QueryPoolJoin {
    pub seed: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct QueryPoolInfo {
    pub participants: Vec<ParticipantID>,
    pub session_id: Hash,
}

#[derive(Debug, Clone)]
pub enum QueryPoolNotification {
    /// Pool formed, information about pool.
    Started(QueryPoolInfo),
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

// ----------------------------------------------------------

impl Hashable for QueryPoolJoin {
    fn hash(&self, state: &mut Hasher) {
        "QueryPoolJoin".hash(state);
        self.seed.hash(state);
    }
}

impl Hashable for QueryPoolInfo {
    fn hash(&self, state: &mut Hasher) {
        "QueryPoolInfo".hash(state);
        for part in &self.participants {
            part.hash(state);
        }
        self.session_id.hash(state);
    }
}

impl From<QueryPoolInfo> for QueryPoolNotification {
    fn from(info: QueryPoolInfo) -> QueryPoolNotification {
        QueryPoolNotification::Started(info)
    }
}

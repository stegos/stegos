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

#![deny(warnings)]

pub mod protos;
pub use self::protos::*;

use futures::channel::mpsc;
use futures::{
    task::{Context, Poll},
    Future, StreamExt,
};
use log::*;
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;
use stegos_blockchain::PaymentOutput;
use stegos_crypto::dicemix;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;
use stegos_network::{Network, UnicastMessage};
use stegos_serialization::traits::*;
use tokio::time::{self, Interval};

pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_PARTICIPANTS: usize = 3;
pub const MAX_PARTICIPANTS: usize = 20;

type TXIN = Hash;
type UTXO = PaymentOutput;
type SchnorrSig = scc::SchnorrSig;
type ParticipantID = dicemix::ParticipantID;

pub struct TransactionPoolService {
    network: Network,
    participants: HashMap<ParticipantID, (Vec<TXIN>, Vec<UTXO>, SchnorrSig)>,
    timer: Interval,
    pool_join_rx: mpsc::UnboundedReceiver<UnicastMessage>,
}

impl TransactionPoolService {
    /// Crates new TransactionPool.
    pub fn new(network: Network) -> TransactionPoolService {
        let participants = HashMap::new();
        let timer = time::interval(MESSAGE_TIMEOUT);
        // Unicast messages from other nodes
        let pool_join_rx = network.subscribe_unicast(POOL_JOIN_TOPIC).unwrap();
        TransactionPoolService {
            network,
            participants,
            timer,
            pool_join_rx,
        }
    }

    fn add_participant(&mut self, pkey: pbc::PublicKey, data: PoolJoin) -> bool {
        match self.participants.insert(
            ParticipantID::new(pkey, data.seed),
            (data.txins, data.utxos, data.ownsig),
        ) {
            None => true,
            _ => false,
        }
    }

    fn try_to_form_pool(&mut self) -> bool {
        if self.participants.len() < MIN_PARTICIPANTS {
            debug!(
                "Found no enough participants, skipping pool formation: pool_len={}, min_len={}",
                self.participants.len(),
                MIN_PARTICIPANTS
            );
            return false;
        }

        // after timeout facilitator should broadcast message to each node.
        let participants = std::mem::replace(&mut self.participants, HashMap::new());
        let participants_pkeys: Vec<pbc::PublicKey> =
            participants.keys().map(|k| k.pkey.clone()).collect();
        let participants: Vec<ParticipantTXINMap> = participants
            .into_iter()
            .map(|(participant, (txins, utxos, ownsig))| ParticipantTXINMap {
                participant,
                txins,
                utxos,
                ownsig,
            })
            .collect();

        let session_id = Hash::random();
        info!(
            "Formed a new pool: session_id={}, participants={:?}",
            session_id, &participants
        );
        let info = PoolInfo {
            participants,
            session_id,
        };
        let msg: PoolNotification = info.into();
        let msg = msg.into_buffer().unwrap();
        for dest in participants_pkeys {
            if let Err(e) = self.network.send(dest, POOL_ANNOUNCE_TOPIC, msg.clone()) {
                error!("Failed to send PoolInfo to {}: {}", dest, e);
            }
        }
        true
    }

    /// Receive message of other nodes from unicast channel.
    fn handle_join_message(&mut self, data: PoolJoin, from: pbc::PublicKey) {
        if self.add_participant(from, data) {
            info!("Added a new member: pkey={}", from);
            if self.participants.len() >= MAX_PARTICIPANTS {
                self.try_to_form_pool();
            }
        }
    }
}

impl Drop for TransactionPoolService {
    // WARN! Don't move pool_join_rx or timer in drop, allso all drop code should be located in `inner_drop`,
    // to ensure that you didn't move anything
    fn drop(&mut self) {
        if self.try_to_form_pool() {
            return;
        }
        let info = PoolNotification::Canceled;
        let data = info.into_buffer().unwrap();
        for part in self.participants.keys() {
            if let Err(e) = self
                .network
                .send(part.pkey, POOL_ANNOUNCE_TOPIC, data.clone())
            {
                error!("Failed to send PoolCanceled message {}: {}", part.pkey, e);
            }
        }
    }
}

impl Future for TransactionPoolService {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        //
        // Poll PoolJoin messages.
        //
        loop {
            match self.pool_join_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => {
                    debug!("Received join message: from={}", msg.from);
                    let pj_rec = match PoolJoin::from_buffer(&msg.data) {
                        Ok(pj_rec) => pj_rec,
                        Err(e) => {
                            error!("Failed to decode PoolJoin message: {}", e);
                            continue;
                        }
                    };
                    self.handle_join_message(pj_rec, msg.from);
                }
                Poll::Ready(None) => return Poll::Ready(()), // shutdown.
                Poll::Pending => break,
            }
        }

        //
        // Poll timer.
        //
        match self.timer.poll_next_unpin(cx) {
            Poll::Ready(Some(_)) => {
                self.try_to_form_pool();
            }
            Poll::Ready(None) => return Poll::Ready(()), // shutdown.
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

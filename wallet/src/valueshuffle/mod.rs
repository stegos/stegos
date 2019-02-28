//! lib.rs - DiceMix for secure and anonymous info exchange

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
//

#![allow(unused)]
#![deny(warnings)]

mod error;
pub use error::*;

mod message;
use message::*;

mod protos;
use protos::*;

use crate::error::*;
use failure::format_err;
use failure::Error;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use futures_stream_select_all_send::select_all;
use log::*;
use std::collections::HashMap;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SchnorrSig;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::dicemix::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_network::Network;
use stegos_node::Node;
use stegos_serialization::traits::ProtoConvert;
use stegos_txpool::PoolInfo;
use stegos_txpool::PoolJoin;
use stegos_txpool::POOL_ANNOUNCE_TOPIC;
use stegos_txpool::POOL_JOIN_TOPIC;

/// A topic used for ValueShuffle unicast communication.
pub const VALUE_SHUFFLE_TOPIC: &'static str = "valueshuffle";

#[derive(Debug)]
/// ValueShuffle Events.
enum ValueShuffleEvent {
    FacilitatorChanged(ParticipantID),
    PoolFormed(ParticipantID, Vec<u8>),
    MessageReceived(ParticipantID, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
/// ValueShuffle State.
enum State {
    Offline,
    PoolWait,
    PoolFormed,
}

type TXIN = Hash;

/// ValueShuffle Service.
pub struct ValueShuffle {
    /// Secret Key.
    skey: SecretKey,
    /// Public Key.
    pkey: PublicKey,
    /// Faciliator's public key
    facilitator_pkey: ParticipantID,
    /// State.
    state: State,
    /// My public txpool's key.
    participant_key: ParticipantID,
    /// Public keys of txpool's members,
    participants: Vec<ParticipantID>,
    /// Session ID.
    session_id: Hash,
    /// Network API.
    network: Network,
    /// Incoming events.
    events: Box<Stream<Item = ValueShuffleEvent, Error = ()> + Send>,
}

impl ValueShuffle {
    // ----------------------------------------------------------------------------------------------
    // Public API.
    // ----------------------------------------------------------------------------------------------

    /// Create a new ValueShuffle instance.
    pub fn new(
        skey: SecretKey,
        pkey: PublicKey,
        participant_key: ParticipantID,
        network: Network,
        node: Node,
    ) -> ValueShuffle {
        //
        // State.
        //
        let facilitator_pkey: ParticipantID = secure::G2::generator().into(); // some fake key
        let participants: Vec<ParticipantID> = Vec::new();
        let session_id: Hash = Hash::random();
        let state = State::Offline;

        //
        // Events.
        //
        let mut events: Vec<Box<Stream<Item = ValueShuffleEvent, Error = ()> + Send>> = Vec::new();

        // Network.
        let pool_formed = network
            .subscribe_unicast(VALUE_SHUFFLE_TOPIC)
            .expect("connected")
            .map(|m| ValueShuffleEvent::MessageReceived(m.from, m.data));
        events.push(Box::new(pool_formed));

        // Facilitator elections.
        let facilitator_changed = node
            .subscribe_epoch()
            .expect("connected")
            .map(|epoch| ValueShuffleEvent::FacilitatorChanged(epoch.facilitator));
        events.push(Box::new(facilitator_changed));

        // Pool formation.
        let pool_formed = network
            .subscribe_unicast(POOL_ANNOUNCE_TOPIC)
            .expect("connected")
            .map(|m| ValueShuffleEvent::PoolFormed(m.from, m.data));
        events.push(Box::new(pool_formed));

        let events = select_all(events);

        ValueShuffle {
            skey,
            pkey,
            facilitator_pkey,
            state,
            participant_key,
            participants,
            session_id,
            network,
            events,
        }
    }

    /// Called by Wallet.
    pub fn queue_transaction(
        &mut self,
        txins: Vec<Output>,
        txouts: Vec<Output>,
        gamma: Fr,
        fee: i64,
    ) -> Result<(), Error> {
        if txouts.len() > MAX_UTXOS {
            return Err(VsError::VsTooManyUTXO.into());
        }

        // Send PoolJoin on the first request.
        if self.state == State::Offline {
            self.send_pool_join()?;
            self.state = State::PoolWait;
        }

        // TODO: save transaction in self.xxx.

        Ok(())
    }

    // ----------------------------------------------------------------------------------------------
    // TxPool Membership
    // ----------------------------------------------------------------------------------------------

    // When a wallet wants to participate in a ValueShuffle session,
    // it should advertise its desire by sending a message to the Facilitator
    // node, along with its network ID (currently a pbc::secure::PublicKey).
    //
    // When the Facilitator has accumulated a sufficient number of requestor
    // nodes, it collects those ID's and sends a message to each of them, to
    // start a ValueShuffle session. The Facilitator should send that list of
    // node ID's along with an initial unique session ID (sid).

    /// Called when facilitator has been changed.
    fn on_facilitator_changed(&mut self, facilitator: ParticipantID) -> Result<(), Error> {
        debug!("Changed facilitator: facilitator={:?}", facilitator);
        self.facilitator_pkey = facilitator;
        Ok(())
    }

    /// Sends a request to join tx pool.
    fn send_pool_join(&self) -> Result<(), Error> {
        let join = PoolJoin {};
        let msg = join.into_buffer()?;
        self.network
            .send(self.facilitator_pkey, POOL_JOIN_TOPIC, msg)?;
        info!(
            "Sent pool join request facilitator={}",
            self.facilitator_pkey
        );
        Ok(())
    }

    /// Called when a new txpool is formed.
    fn on_pool_formed(&mut self, from: ParticipantID, pool_info: Vec<u8>) -> Result<(), Error> {
        if from != self.facilitator_pkey {
            return Err(format_err!(
                "Invalid facilitator: expected={:?}, got={:?}",
                self.facilitator_pkey,
                from
            ));
        };

        let pool_info = PoolInfo::from_buffer(&pool_info)?;
        let mut participants = pool_info.participants;
        participants.sort();
        participants.dedup();
        info!("Formed txpool: members={}", participants.len());
        for pkey in &participants {
            info!("{}", pkey);
        }

        self.participants = participants;
        self.session_id = pool_info.session_id;
        self.state = State::PoolFormed;

        // TODO: start processing queued transactions....
        self.send_example("Hello".into());

        Ok(())
    }

    // ----------------------------------------------------------------------------------------------
    // TxPool Communication
    // ----------------------------------------------------------------------------------------------

    /// Sends a message to all txpool members via unicast.
    fn send_message(&self, msg: Message) -> Result<(), Error> {
        let msg = msg.into_buffer()?;
        for pkey in &self.participants {
            self.network
                .send(pkey.clone(), VALUE_SHUFFLE_TOPIC, msg.clone())?;
        }
        Ok(())
    }

    /// Called when a new message is received via unicast.
    fn on_message_received(&mut self, from: ParticipantID, msg: Vec<u8>) -> Result<(), Error> {
        let msg = Message::from_buffer(&msg)?;
        match msg {
            Message::Example { payload } => self.on_example_received(from, payload),
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Example Stage
    // ----------------------------------------------------------------------------------------------

    /// Sends Example message.
    fn send_example(&self, payload: String) -> Result<(), Error> {
        let msg = Message::Example { payload };
        self.send_message(msg)?;
        info!("Example sent");
        Ok(())
    }

    /// Invoked when Example message is received.
    fn on_example_received(&mut self, from: ParticipantID, payload: String) -> Result<(), Error> {
        info!("Example received: from={}, payload={}", from, payload);
        Ok(())
    }
}

impl Future for ValueShuffle {
    type Item = ();
    type Error = ();

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    let result: Result<(), Error> = match event {
                        ValueShuffleEvent::FacilitatorChanged(facilitator) => {
                            self.on_facilitator_changed(facilitator)
                        }
                        ValueShuffleEvent::PoolFormed(from, msg) => self.on_pool_formed(from, msg),
                        ValueShuffleEvent::MessageReceived(from, msg) => {
                            self.on_message_received(from, msg)
                        }
                    };
                    if let Err(error) = result {
                        error!("Error: {:?}", error)
                    }
                }
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

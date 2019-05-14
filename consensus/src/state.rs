//! pBFT Consensus - States and Transitions.

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

use crate::error::*;
use crate::message::*;
use crate::metrics;
use bitvector::BitVector;
use log::*;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::mem;
use stegos_blockchain::create_multi_signature;
use stegos_blockchain::{check_supermajority, ElectionResult};
use stegos_crypto::hash::{Hash, Hashable};
use stegos_crypto::pbc;

struct LockedRound<Request, Proof> {
    precommits: BTreeMap<pbc::PublicKey, pbc::Signature>,
    request: Request,
    proof: Proof,
}

#[derive(Debug, PartialEq, Eq)]
enum ConsensusState {
    /// Propose state.
    Propose,
    /// Prevote state.
    Prevote,
    /// Precommit state.
    Precommit,
    /// Commit state.
    Commit,
}

impl ConsensusState {
    /// Enum to string.
    fn name(&self) -> &'static str {
        match *self {
            ConsensusState::Propose => "Propose",
            ConsensusState::Prevote => "Prevote",
            ConsensusState::Precommit => "Precommit",
            ConsensusState::Commit => "Commit",
        }
    }
}

/// Consensus State.
pub struct Consensus<Request, Proof> {
    //
    // Network node keys
    //
    /// Public key of current node.
    skey: pbc::SecretKey,
    /// Public key of current node.
    pkey: pbc::PublicKey,
    //
    // Consensus params.
    //
    /// Public keys and slots count of participating nodes.
    validators: BTreeMap<pbc::PublicKey, i64>,
    /// total number of slots for specific node.
    total_slots: i64,
    //
    // Current blockchain state
    //
    /// Identifier of current session.
    height: u64,
    /// Current epoch number.
    epoch: u64,
    /// Result of election.
    election_result: ElectionResult,
    //
    // Current consensus state
    //
    /// Consensus State.
    state: ConsensusState,
    /// Current consensus round.
    round: u32,
    /// Proposed request.
    request: Option<Request>,
    /// A proof need to validate request.
    proof: Option<Proof>,
    /// This state is used when some validator collect majority of prevotes.
    /// At this phase node is
    /// locked to some round, and didn't produce any new proposes.
    locked_round: Option<LockedRound<Request, Proof>>,
    /// Collected Prevotes.
    prevotes: BTreeMap<pbc::PublicKey, pbc::Signature>,
    /// Collected Precommits.
    precommits: BTreeMap<pbc::PublicKey, pbc::Signature>,

    //
    // External events
    //
    /// Pending messages.
    inbox: Vec<ConsensusMessage<Request, Proof>>,
    /// Outgoing messages.
    pub outbox: Vec<ConsensusMessage<Request, Proof>>,
}

impl<Request: Hashable + Clone + Debug + Eq, Proof: Hashable + Clone + Debug>
    Consensus<Request, Proof>
{
    ///
    /// Start a new consensus protocol.
    ///
    /// # Arguments
    ///
    /// * `height` - identifier of session.
    /// * `epoch` - current consensus epoch.
    /// * `skey` - BLS Secret Key of this node.
    /// * `pkey` - BLS Public Key of this node.
    /// * `starting_view_change` - blockchain view_change number.
    /// * `election_result` - result of the previous election.
    /// * `validators` - voting members of consensus.
    pub fn new(
        height: u64,
        epoch: u64,
        skey: pbc::SecretKey,
        pkey: pbc::PublicKey,
        election_result: ElectionResult,
        validators: BTreeMap<pbc::PublicKey, i64>,
    ) -> Self {
        assert!(validators.contains_key(&pkey));
        let state = ConsensusState::Propose;
        debug!("New => {}({}:{})", state.name(), height, 0);
        let prevotes: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let precommits: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let total_slots = validators.iter().map(|v| v.1).sum();
        let request = None;
        let proof = None;
        let locked_round = None;
        let round = 0;
        let inbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        let outbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        Consensus {
            skey,
            pkey,
            validators,
            total_slots,
            state,
            election_result,
            height,
            round,
            epoch,
            request,
            proof,
            locked_round,
            prevotes,
            precommits,
            inbox,
            outbox,
        }
    }

    fn lock(&mut self) {
        assert_eq!(self.state, ConsensusState::Precommit);

        self.state = ConsensusState::Propose;
        let locked_round = LockedRound {
            precommits: mem::replace(&mut self.precommits, BTreeMap::new()),
            request: self.request.take().expect("expected some propose"),
            proof: self.proof.take().expect("expected some proof"),
        };

        self.prevotes.clear();
        self.locked_round = Some(locked_round);
        self.proof = None;
        self.outbox.clear();
        self.process_inbox();
    }

    fn reset(&mut self) {
        self.state = ConsensusState::Propose;
        self.prevotes.clear();
        self.precommits.clear();
        self.request = None;
        self.proof = None;
        self.outbox.clear();
        self.process_inbox();
    }

    ///
    /// Reset the current state and start a new round of consensus.
    ///
    pub fn next_round(&mut self) {
        assert_ne!(self.state, ConsensusState::Commit);
        info!(
            "{}({}:{}) Going to next round.",
            self.state.name(),
            self.height,
            self.round
        );
        self.round += 1;
        // if our last state was Precommit, keep lock in the state.
        if self.state == ConsensusState::Precommit {
            self.lock()
        } else {
            self.reset()
        }
        debug!(
            "New => {}({}:{})",
            self.state.name(),
            self.height,
            self.round
        );
    }

    ///
    /// Propose a new request with a proof.
    /// If Consensus is locked at some state, then it should rebroadcast existing propose.
    /// If not, then `propose_creator` is called to produce new propose.
    ///
    /// # Arguments
    ///
    /// * `propose_creator` - is a function that should create propose, if called.
    ///
    pub fn propose<F>(&mut self, propose_creator: F)
    where
        F: FnOnce() -> (Request, Proof),
    {
        assert!(self.is_leader(), "only leader can propose");
        assert_eq!(self.state, ConsensusState::Propose, "at propose state");
        let (request, proof) = match &self.locked_round {
            Some(locked_round) => (locked_round.request.clone(), locked_round.proof.clone()),
            _ => propose_creator(),
        };
        let request_hash = Hash::digest(&request);
        debug!(
            "{}({}:{}): propose request={:?}",
            self.state.name(),
            self.height,
            self.round,
            &request_hash
        );
        let body = ConsensusMessageBody::Proposal { request, proof };
        let msg = ConsensusMessage::new(
            self.height,
            self.round,
            request_hash,
            &self.skey,
            &self.pkey,
            body,
        );
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Pre-vote the request.
    ///
    /// # Arguments
    ///
    /// * `request_hash` - a request's hash to ensure that the right request is pre-voted.
    ///
    fn prevote(&mut self, request_hash: Hash) {
        assert_eq!(self.state, ConsensusState::Prevote);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.prevotes.contains_key(&self.pkey));
        debug!(
            "{}({}:{}): pre-vote request={:?}",
            self.state.name(),
            self.height,
            self.round,
            &request_hash
        );
        let body = ConsensusMessageBody::Prevote {};
        let msg = ConsensusMessage::new(
            self.height,
            self.round,
            request_hash,
            &self.skey,
            &self.pkey,
            body,
        );
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Pre-commit the request.
    ///
    /// # Arguments
    ///
    /// * `request_hash` - a request's hash to ensure that the right request is pre-voted.
    ///
    fn precommit(&mut self, request_hash: Hash) {
        assert_eq!(self.state, ConsensusState::Precommit);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        debug!(
            "{}({}:{}): pre-commit request={:?}",
            self.state.name(),
            self.height,
            self.round,
            &request_hash
        );
        let request_hash_sig = pbc::sign_hash(&request_hash, &self.skey);
        let body = ConsensusMessageBody::Precommit { request_hash_sig };
        let msg = ConsensusMessage::new(
            self.height,
            self.round,
            request_hash,
            &self.skey,
            &self.pkey,
            body,
        );
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Feed incoming message into the state machine.
    ///
    /// # Arguments
    ///
    /// * `msg` - a message to process.
    ///
    pub fn feed_message(
        &mut self,
        msg: ConsensusMessage<Request, Proof>,
    ) -> Result<(), ConsensusError> {
        trace!(
            "{}({}:{}): process message: msg={:?}",
            self.state.name(),
            self.height,
            self.round,
            &msg
        );

        // Check sender.
        if !self.validators.contains_key(&msg.pkey) {
            debug!(
                "{}({}:{}): peer is not a validator: msg={:?}",
                self.state.name(),
                self.height,
                self.round,
                &msg
            );
            return Err(ConsensusError::UnknownMessagePeer(msg.pkey));
        }

        if msg.height != self.height {
            debug!(
                "{}({}:{}): message from different height: msg={:?}",
                self.state.name(),
                self.height,
                self.round,
                &msg
            );
        }

        // Check round.
        if msg.round < self.round {
            debug!(
                "{}({}:{}): message from the past: msg={:?}",
                self.state.name(),
                self.height,
                self.round,
                &msg
            );
            // Discard this message.
            return Ok(());
        } else if msg.round > self.round {
            debug!(
                "{}({}:{}): message from the future: msg={:?}",
                self.state.name(),
                self.height,
                self.round,
                &msg
            );
            // Queue the message for future processing.
            self.inbox.push(msg);
            return Ok(());
        }
        assert_eq!(msg.round, self.round);

        // Check request_hash.
        if self.state != ConsensusState::Propose {
            let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
            if expected_request_hash != msg.request_hash {
                warn!(
                    "{}({}:{}): invalid request_hash: expected_request_hash={:?}, got_request_hash={:?}, msg={:?}",
                    self.state.name(),
                    self.height, self.round,
                    &expected_request_hash,
                    &msg.request_hash,
                    &msg
                );
                return Err(ConsensusError::InvalidRequestHash(
                    expected_request_hash,
                    msg.request_hash,
                    msg.pkey,
                ));
            }
        }

        if self.state == ConsensusState::Commit {
            debug!(
                "{}({}:{}): a late message: msg={:?}",
                self.state.name(),
                self.height,
                self.round,
                &msg
            );
            // Silently discard this message.
            return Ok(());
        }

        // Check valid transitions.
        match (&msg.body, &self.state) {
            // Obvious cases.
            (ConsensusMessageBody::Proposal { .. }, ConsensusState::Propose) => {}
            (ConsensusMessageBody::Prevote { .. }, ConsensusState::Prevote) => {}
            (ConsensusMessageBody::Precommit { .. }, ConsensusState::Precommit) => {}

            // Early pre-commits received in Prevote state.
            (ConsensusMessageBody::Precommit { .. }, ConsensusState::Prevote) => {}

            // Late pre-votes received in Precommit state.
            (ConsensusMessageBody::Prevote { .. }, ConsensusState::Precommit) => {}

            // Late pre-commits received in Commit state.
            (ConsensusMessageBody::Precommit { .. }, ConsensusState::Commit) => {}

            // Early Prevotes and Precommits in Propose state
            (_, ConsensusState::Propose) => {
                debug!(
                    "{}({}:{}): an early message: msg={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    &msg
                );
                self.inbox.push(msg);
                return Ok(());
            }

            // Unexpected message or message in unexpected state.
            (_, _) => {
                error!(
                    "{}({}:{}): unexpected message: msg={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    &msg
                );
                return Err(ConsensusError::InvalidMessage(
                    self.state.name(),
                    msg.name(),
                ));
            }
        }

        // Process received message.
        match msg.body {
            ConsensusMessageBody::Proposal { request, proof } => {
                assert_eq!(self.state, ConsensusState::Propose);

                // Check that message has been sent by leader.
                if msg.pkey != self.leader() {
                    error!(
                        "{}({}:{}): a proposal from a non-leader: leader={:?}, from={:?}",
                        self.state.name(),
                        self.height,
                        self.round,
                        &self.leader(),
                        &msg.pkey
                    );
                    return Err(ConsensusError::ProposalFromNonLeader(
                        msg.request_hash,
                        self.leader().clone(),
                        msg.pkey,
                    ));
                }

                // Check request hash.
                let expected_request_hash = Hash::digest(&request);
                if expected_request_hash != msg.request_hash {
                    return Err(ConsensusError::InvalidRequestHash(
                        expected_request_hash,
                        msg.request_hash,
                        msg.pkey,
                    ));
                }

                // Move to Prevote
                assert!(self.prevotes.is_empty());
                assert!(self.request.is_none());
                assert!(self.proof.is_none());
                debug!(
                    "{}({}:{}) => {}({}:{}): received a new proposal hash={:?}, from={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    ConsensusState::Prevote.name(),
                    self.height,
                    self.round,
                    &msg.request_hash,
                    &msg.pkey
                );
                self.state = ConsensusState::Prevote;
                metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Prevote as i64);
                self.request = Some(request);
                self.proof = Some(proof);
                if let Some(locked_round) = &self.locked_round {
                    if locked_round.request == *self.request.as_ref().unwrap() {
                        // Someone proposed a request that looks like our locked.
                        let locked = self.locked_round.take().unwrap();
                        self.precommits = locked.precommits;
                        // repeat prevote
                        self.prevote(Hash::digest(&self.request));
                    } // don't vote for request that is different from our locked.
                } else {
                    self.prevote(Hash::digest(&self.request));
                }
                self.process_inbox();
            }
            ConsensusMessageBody::Prevote {} => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Collect the vote.
                debug!(
                    "{}({}:{}): collected a pre-vote: from={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    &msg.pkey
                );
                self.prevotes.insert(msg.pkey, msg.sig);
            }
            ConsensusMessageBody::Precommit { request_hash_sig } => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Check signature.
                let request_hash = Hash::digest(self.request.as_ref().unwrap());
                if let Err(_e) = pbc::check_hash(&request_hash, &request_hash_sig, &msg.pkey) {
                    error!(
                        "{}({}:{}): a pre-commit signature is not valid: from={:?}",
                        self.state.name(),
                        self.height,
                        self.round,
                        &msg.pkey
                    );
                    return Err(ConsensusError::InvalidRequestSignature(request_hash));
                }

                // Collect the vote.
                debug!(
                    "{}({}:{}): collected a pre-commit: from={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    &msg.pkey
                );
                self.precommits.insert(msg.pkey, request_hash_sig);
            }
        }

        // Check if supermajority of votes is reached.
        if self.state == ConsensusState::Prevote {
            if !self.check_supermajority(&self.prevotes) {
                // No supermajority, skip transition.
                return Ok(());
            }
            // Move to Precommit.
            debug!(
                "{}({}:{}) => {}({}:{})",
                self.state.name(),
                self.height,
                self.round,
                ConsensusState::Precommit.name(),
                self.height,
                self.round,
            );
            self.state = ConsensusState::Precommit;
            metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Precommit as i64);
            if self.prevotes.contains_key(&self.pkey) {
                // Send a pre-commit vote.
                self.precommit(Hash::digest(&self.request));
            } else {
                // Don't vote in this case and stay silent.
                warn!(
                    "{}({}:{}): request accepted by supermajority, but rejected this node",
                    self.state.name(),
                    self.height,
                    self.round,
                );
            }
        } else if self.state == ConsensusState::Precommit {
            if self.check_supermajority(&self.precommits) {
                // Move to Commit.
                debug!(
                    "{}({}:{}) => {}({}:{})",
                    self.state.name(),
                    self.height,
                    self.round,
                    ConsensusState::Commit.name(),
                    self.height,
                    self.round,
                );
                self.state = ConsensusState::Commit;
                metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Commit as i64);
            }
        }

        Ok(())
    }

    /// Process pending messages received out-of-order.
    fn process_inbox(&mut self) {
        let inbox = std::mem::replace(&mut self.inbox, Vec::new());
        for msg in inbox {
            if let Err(e) = self.feed_message(msg) {
                warn!(
                    "{}({}:{}): failed to process message: error={:?}",
                    self.state.name(),
                    self.height,
                    self.round,
                    e
                );
            }
        }
    }

    ///
    /// Returns true if current node is leader.
    ///
    pub fn is_leader(&self) -> bool {
        self.pkey == self.leader()
    }

    ///
    /// Returns public key of the current leader.
    ///
    pub fn leader(&self) -> pbc::PublicKey {
        self.election_result.select_leader(self.round)
    }

    ///
    /// Returns number of current consensus epoch.
    ///
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    ///
    /// Returns number of current consensus round.
    ///
    pub fn round(&self) -> u32 {
        self.round
    }

    ///
    /// Returns snapshot of the consensus group.
    ///
    pub fn validators(&self) -> &BTreeMap<pbc::PublicKey, i64> {
        &self.validators
    }

    ///
    /// Returns true if current node should propose a new request.
    ///
    pub fn should_propose(&self) -> bool {
        self.state == ConsensusState::Propose && self.is_leader()
    }

    ///
    /// Returns true if current node should commit the request.
    ///
    pub fn should_commit(&self) -> bool {
        self.state == ConsensusState::Commit
    }

    ///
    /// Return a proposal to validate.
    ///
    pub fn get_proposal(&self) -> (&Request, &Proof) {
        (self.request.as_ref().unwrap(), self.proof.as_ref().unwrap())
    }

    ///
    /// Sign and commit the request and move to the next round.
    ///
    /// Returns negotiated request with proof and created multisignature.
    ///
    pub fn sign_and_commit(&mut self) -> (Request, Proof, pbc::Signature, BitVector) {
        assert!(self.should_commit());

        // TODO: Use id instead of PublicKey.
        let validators = self.validators.iter().map(|(k, v)| (*k, *v)).collect();
        // Create multi-signature.
        let (multisig, multisigmap) = create_multi_signature(&validators, &self.precommits);
        let r = (
            self.request.take().unwrap(),
            self.proof.take().unwrap(),
            multisig,
            multisigmap,
        );
        self.reset();
        r
    }

    ///
    /// Checks that supermajority of votes has been collected.
    ///
    fn check_supermajority(&self, accepts: &BTreeMap<pbc::PublicKey, pbc::Signature>) -> bool {
        trace!(
            "{}({}:{}): check for supermajority: accepts={:?}, total={:?}",
            self.state.name(),
            self.height,
            self.round,
            accepts.len(),
            self.validators.len()
        );
        let mut stake = 0;
        for (pk, _sign) in accepts {
            stake += self.validators.get(pk).expect("vote from validator");
        }
        check_supermajority(stake, self.total_slots)
    }
}

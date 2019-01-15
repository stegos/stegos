//! pBFT Consensus - States and Transitions.

//
// Copyright (c) 2018 Stegos
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
use crate::multisignature::*;
use bitvector::BitVector;
use log::*;
use std::collections::BTreeMap;
use std::fmt::Debug;
use stegos_crypto::hash::{Hash, Hashable};
use stegos_crypto::pbc::secure::check_hash as secure_check_hash;
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::SecretKey as SecureSecretKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

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
    /// Public key of current node.
    skey: SecureSecretKey,
    /// Public key of current node.
    pkey: SecurePublicKey,
    /// Public key of leader.
    leader: SecurePublicKey,
    /// Public keys and stakes of participating nodes.
    validators: BTreeMap<SecurePublicKey, i64>,
    /// Consensus State.
    state: ConsensusState,
    /// Identifier of current session.
    height: u64,
    /// Current epoch number.
    epoch: u64,
    /// Proposed request.
    request: Option<Request>,
    /// A proof need to validate request.
    proof: Option<Proof>,
    /// Collected Prevotes.
    prevotes: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Collected Precommits.
    precommits: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Pending messages.
    inbox: Vec<ConsensusMessage<Request, Proof>>,
    /// Outgoing messages.
    pub outbox: Vec<ConsensusMessage<Request, Proof>>,
}

impl<Request: Hashable + Clone + Debug, Proof: Hashable + Clone + Debug> Consensus<Request, Proof> {
    ///
    /// Start a new consensus protocol.
    ///
    /// # Arguments
    ///
    /// * `height` - identifier of session.
    /// * `skey` - BLS Secret Key of this node.
    /// * `pkey` - BLS Public Key of this node.
    /// * `leader` - group's leader - a node which creates and sends proposal.
    /// * `validators` - voting members of consensus.
    ///
    pub fn new(
        height: u64,
        epoch: u64,
        skey: SecureSecretKey,
        pkey: SecurePublicKey,
        leader: SecurePublicKey,
        validators: BTreeMap<SecurePublicKey, i64>,
    ) -> Self {
        assert!(validators.contains_key(&pkey));
        let state = ConsensusState::Propose;
        debug!("New => {}({})", state.name(), height);
        let prevote_accepts: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let precommit_accepts: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let request = None;
        let proof = None;
        let inbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        let outbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        Consensus {
            skey,
            pkey,
            leader,
            validators,
            state,
            height,
            epoch,
            request,
            proof,
            prevotes: prevote_accepts,
            precommits: precommit_accepts,
            inbox,
            outbox,
        }
    }

    ///
    /// Reset the current state and start a new session of consensus.
    ///
    /// # Arguments
    ///
    /// * `height` - a new identifier of session.
    ///
    pub fn reset(&mut self, height: u64) {
        self.height = height;
        self.state = ConsensusState::Propose;
        debug!("New => {}({})", self.state.name(), height);
        self.prevotes.clear();
        self.precommits.clear();
        self.request = None;
        self.proof = None;
        self.outbox.clear();
        self.process_inbox();
    }

    ///
    /// Propose a new request with a proof.
    ///
    /// # Arguments
    ///
    /// * `request` - a request to validate and sign.
    /// * `proof` - some extra information needed to validate request.
    ///
    pub fn propose(&mut self, request: Request, proof: Proof) {
        assert!(self.is_leader(), "only leader can propose");
        assert_eq!(self.state, ConsensusState::Propose, "valid state");
        let request_hash = Hash::digest(&request);
        debug!(
            "{}({}): propose request={:?}",
            self.state.name(),
            self.height,
            &request_hash
        );
        let body = ConsensusMessageBody::Proposal { request, proof };
        let msg = ConsensusMessage::new(
            self.height,
            self.epoch,
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
    pub fn prevote(&mut self, request_hash: Hash) {
        assert_eq!(self.state, ConsensusState::Prevote);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.prevotes.contains_key(&self.pkey));
        assert!(!self.precommits.contains_key(&self.pkey));
        debug!(
            "{}({}): pre-vote request={:?}",
            self.state.name(),
            self.height,
            &request_hash
        );
        let body = ConsensusMessageBody::Prevote {};
        let msg = ConsensusMessage::new(
            self.height,
            self.epoch,
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
        assert!(!self.precommits.contains_key(&self.pkey));
        debug!(
            "{}({}): pre-commit request={}",
            self.state.name(),
            self.height,
            &request_hash
        );
        let request_hash_sig = secure_sign_hash(&request_hash, &self.skey);
        let body = ConsensusMessageBody::Precommit { request_hash_sig };
        let msg = ConsensusMessage::new(
            self.height,
            self.epoch,
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
            "{}({}): process message: msg={:?}",
            self.state.name(),
            self.height,
            &msg
        );

        // Check sender.
        if !self.validators.contains_key(&msg.pkey) {
            debug!(
                "{}({}): peer is not a validator: msg={:?}",
                self.state.name(),
                self.height,
                &msg
            );
            return Err(ConsensusError::UnknownMessagePeer(msg.pkey));
        }

        // Validate signature and content.
        msg.validate()?;

        // Check round.
        if msg.height < self.height {
            debug!(
                "{}({}): message from the past: msg={:?}",
                self.state.name(),
                self.height,
                &msg
            );
            // Discard this message.
            return Ok(());
        } else if msg.height == self.height + 1 {
            debug!(
                "{}({}): message from the next round: msg={:?}",
                self.state.name(),
                self.height,
                &msg
            );
            // Queue the message for future processing.
            self.inbox.push(msg);
            return Ok(());
        } else if msg.height > self.height + 1 {
            warn!(
                "{}({}): message from the future: msg={:?}",
                self.state.name(),
                self.height,
                &msg
            );
            // Discard this message.
            return Ok(());
        }
        assert_eq!(msg.height, self.height);

        // Check request_hash.
        if self.state != ConsensusState::Propose {
            let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
            if expected_request_hash != msg.request_hash {
                warn!(
                    "{}({}): invalid request_hash: expected_request_hash={:?}, got_request_hash={:?}, msg={:?}",
                    self.state.name(),
                    self.height,
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
                "{}({}): a late message: msg={:?}",
                self.state.name(),
                self.height,
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
                    "{}({}): an early message: msg={:?}",
                    self.state.name(),
                    self.height,
                    &msg
                );
                self.inbox.push(msg);
                return Ok(());
            }

            // Unexpected message or message in unexpected state.
            (_, _) => {
                error!(
                    "{}({}): unexpected message: msg={:?}",
                    self.state.name(),
                    self.height,
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
                if msg.pkey != self.leader {
                    error!(
                        "{}({}): a proposal from a non-leader: leader={:?}, from={:?}",
                        self.state.name(),
                        self.height,
                        &self.leader,
                        &msg.pkey
                    );
                    return Err(ConsensusError::ProposalFromNonLeader(
                        msg.request_hash,
                        self.leader.clone(),
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
                assert!(self.precommits.is_empty());
                assert!(self.request.is_none());
                assert!(self.proof.is_none());
                debug!(
                    "{}({}) => {}({}): received a new proposal hash={}, from={}",
                    self.state.name(),
                    self.height,
                    ConsensusState::Prevote.name(),
                    self.height,
                    &msg.request_hash,
                    &msg.pkey
                );
                self.state = ConsensusState::Prevote;
                self.request = Some(request);
                self.proof = Some(proof);
                self.process_inbox();
            }
            ConsensusMessageBody::Prevote {} => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Collect the vote.
                debug!(
                    "{}({}): collected a pre-vote: from={:?}",
                    self.state.name(),
                    self.height,
                    &msg.pkey
                );
                self.prevotes.insert(msg.pkey, msg.sig);
            }
            ConsensusMessageBody::Precommit { request_hash_sig } => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Check signature.
                let request_hash = Hash::digest(self.request.as_ref().unwrap());
                if !secure_check_hash(&request_hash, &request_hash_sig, &msg.pkey) {
                    error!(
                        "{}({}): a pre-commit signature is not valid: from={:?}",
                        self.state.name(),
                        self.height,
                        &msg.pkey
                    );
                    return Err(ConsensusError::InvalidRequestSignature(request_hash));
                }

                // Collect the vote.
                debug!(
                    "{}({}): collected a pre-commit: from={:?}",
                    self.state.name(),
                    self.height,
                    &msg.pkey
                );
                self.precommits.insert(msg.pkey, request_hash_sig);
            }
        }

        // Check if supermajority of votes is reached.
        if self.state == ConsensusState::Prevote {
            if self.check_supermajority(&self.prevotes) {
                // Move to Precommit.
                debug!(
                    "{}({}) => {}({})",
                    self.state.name(),
                    self.height,
                    ConsensusState::Precommit.name(),
                    self.height
                );
                self.state = ConsensusState::Precommit;
                if self.prevotes.contains_key(&self.pkey) {
                    // Send a pre-commit vote.
                    self.precommit(Hash::digest(&self.request));
                } else {
                    // Don't vote in this case and stay silent.
                    warn!(
                        "{}({}): request accepted by supermajority, but rejected this node",
                        self.state.name(),
                        self.height,
                    );
                }
            }
        } else if self.state == ConsensusState::Precommit {
            if self.check_supermajority(&self.precommits) {
                // Move to Commit.
                debug!(
                    "{}({}) => {}({})",
                    self.state.name(),
                    self.height,
                    ConsensusState::Commit.name(),
                    self.height
                );
                self.state = ConsensusState::Commit;
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
                    "{}({}): failed to process message: error={:?}",
                    self.state.name(),
                    self.height,
                    e
                );
            }
        }
    }

    ///
    /// Returns true if current node is leader.
    ///
    pub fn is_leader(&self) -> bool {
        self.pkey == self.leader
    }

    ///
    /// Returns public key of the current leader.
    ///
    pub fn leader(&self) -> SecurePublicKey {
        self.leader
    }

    ///
    /// Returns number of current consensus epoch.
    ///
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    ///
    /// Returns snapshot of the consensus group.
    ///
    pub fn validators(&self) -> &BTreeMap<SecurePublicKey, i64> {
        &self.validators
    }

    ///
    /// Returns true if current node should propose a new request.
    ///
    pub fn should_propose(&self) -> bool {
        self.state == ConsensusState::Propose && self.is_leader()
    }

    ///
    /// Returns true if current node should pre-vote for the request.
    ///
    pub fn should_prevote(&self) -> bool {
        self.state == ConsensusState::Prevote
            && self.request.is_some()
            && !self.prevotes.contains_key(&self.pkey)
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
    pub fn sign_and_commit(&mut self) -> (Request, Proof, SecureSignature, BitVector) {
        assert!(self.should_commit());

        // Create multi-signature.
        let (multisig, multisigmap) = create_multi_signature(&self.validators, &self.precommits);
        let r = (
            self.request.take().unwrap(),
            self.proof.take().unwrap(),
            multisig,
            multisigmap,
        );
        self.reset(self.height + 1);
        r
    }

    ///
    /// Checks that supermajority of votes has been collected.
    ///
    fn check_supermajority(&self, accepts: &BTreeMap<SecurePublicKey, SecureSignature>) -> bool {
        trace!(
            "{}({}): check for supermajority: accepts={:?}, total={:?}",
            self.state.name(),
            self.height,
            accepts.len(),
            self.validators.len()
        );
        check_supermajority(accepts.len(), self.validators.len())
    }
}

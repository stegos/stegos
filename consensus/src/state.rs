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
use log::*;
use std::collections::BTreeMap;
use std::mem;
use stegos_blockchain::{
    check_supermajority, create_multi_signature, ElectionResult, MacroBlock, Timestamp,
};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

#[derive(Debug)]
struct LockedRound {
    precommits: BTreeMap<pbc::PublicKey, pbc::Signature>,
    block: MacroBlock,
    block_proposal: MacroBlockProposal,
}

#[derive(Debug, Eq, Copy, PartialEq, Clone)]
pub struct ConsensusInfo {
    pub epoch: u64,
    pub round: u32,
    pub state: ConsensusState,
    pub prevotes_len: usize,
    pub precommits_len: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum ConsensusState {
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

#[derive(Debug)]
/// Consensus State.
pub struct Consensus {
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
    /// The block.
    block: Option<MacroBlock>,
    /// The Hash of block.
    block_hash: Option<Hash>,
    /// Information needed to re-create the block.
    block_proposal: Option<MacroBlockProposal>,
    /// This state is used when some validator collect majority of prevotes.
    /// At this phase node is
    /// locked to some round, and didn't produce any new proposes.
    locked_round: Option<LockedRound>,
    /// Collected Prevotes.
    prevotes: BTreeMap<pbc::PublicKey, pbc::Signature>,
    /// Collected Precommits.
    precommits: BTreeMap<pbc::PublicKey, pbc::Signature>,

    /// Consensus start time (used for metrics).
    start_time: Timestamp,

    //
    // External events
    //
    /// Pending messages.
    inbox: Vec<ConsensusMessage>,
    /// Outgoing messages.
    pub outbox: Vec<ConsensusMessage>,
}

impl Consensus {
    ///
    /// Start a new consensus protocol.
    ///
    /// # Arguments
    ///
    /// * `epoch` - current consensus epoch.
    /// * `skey` - BLS Secret Key of this node.
    /// * `pkey` - BLS Public Key of this node.
    /// * `starting_view_change` - blockchain view_change number.
    /// * `election_result` - result of the previous election.
    /// * `validators` - voting members of consensus.
    pub fn new(
        epoch: u64,
        skey: pbc::SecretKey,
        pkey: pbc::PublicKey,
        election_result: ElectionResult,
        validators: BTreeMap<pbc::PublicKey, i64>,
    ) -> Self {
        assert!(validators.contains_key(&pkey));
        let state = ConsensusState::Propose;
        metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Propose as i64);
        debug!("New => {}({}:{})", state.name(), epoch, 0);
        let prevotes: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let precommits: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let total_slots = validators.iter().map(|v| v.1).sum();
        let block = None;
        let block_hash = None;
        let block_proposal = None;
        let locked_round = None;
        let round = 0;
        let inbox: Vec<ConsensusMessage> = Vec::new();
        let outbox: Vec<ConsensusMessage> = Vec::new();
        let start_time = Timestamp::now();
        metrics::PRECOMMITS_AMOUNT.set(0);
        metrics::PREVOTES_AMOUNT.set(0);
        Consensus {
            skey,
            pkey,
            validators,
            total_slots,
            state,
            election_result,
            epoch,
            round,
            block,
            block_hash,
            block_proposal,
            locked_round,
            prevotes,
            precommits,
            inbox,
            outbox,
            start_time,
        }
    }

    pub fn to_info(&self) -> ConsensusInfo {
        ConsensusInfo {
            epoch: self.epoch,
            round: self.round,
            state: self.state,
            prevotes_len: self.prevotes.len(),
            precommits_len: self.precommits.len(),
        }
    }

    fn lock(&mut self) {
        assert_eq!(self.state, ConsensusState::Precommit);
        let block = self.block.take().expect("expected some block");
        let block_proposal = self
            .block_proposal
            .take()
            .expect("expected some block_proposal");
        let locked_round = LockedRound {
            precommits: mem::replace(&mut self.precommits, BTreeMap::new()),
            block,
            block_proposal,
        };
        self.locked_round = Some(locked_round);
        self.reset();
    }

    pub fn reset(&mut self) {
        self.state = ConsensusState::Propose;
        self.prevotes.clear();
        self.precommits.clear();
        self.block = None;
        self.block_hash = None;
        self.block_proposal = None;
        self.outbox.clear();
        if self.is_leader() {
            // Automatically re-propose locked block.
            if let Some(locked_round) = &self.locked_round {
                let block_hash = Hash::digest(&locked_round.block);
                let block_proposal = locked_round.block_proposal.clone();
                self.propose_unchecked(block_hash, block_proposal);
            }
        }
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
            self.epoch,
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
            self.epoch,
            self.round
        );
    }

    ///
    /// Returns true if current node should propose a new request.
    ///
    pub fn should_propose(&self) -> bool {
        self.state == ConsensusState::Propose && self.is_leader() && self.locked_round.is_none()
    }

    ///
    /// Propose a new block.
    ///
    pub fn propose(&mut self, block_hash: Hash, block_proposal: MacroBlockProposal) {
        assert!(self.should_propose(), "invalid state");
        self.propose_unchecked(block_hash, block_proposal);
    }

    fn propose_unchecked(&mut self, block_hash: Hash, block_proposal: MacroBlockProposal) {
        debug!(
            "{}({}:{}): propose block={:?}",
            self.state.name(),
            self.epoch,
            self.round,
            &block_hash
        );
        let body = ConsensusMessageBody::Proposal(block_proposal);
        let msg = ConsensusMessage::new(
            self.epoch, self.round, block_hash, &self.skey, &self.pkey, body,
        );
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Returns true if current node should validate a new request.
    ///
    pub fn should_prevote(&self) -> bool {
        return self.state >= ConsensusState::Prevote && !self.prevotes.contains_key(&self.pkey);
    }

    ///
    /// Pre-vote the request.
    ///
    pub fn prevote(&mut self, block: MacroBlock) {
        assert!(self.should_prevote());
        let block_hash = Hash::digest(&block);
        assert_eq!(&block_hash, self.block_hash.as_ref().unwrap());

        // PREVOTE SHOULD ALWAYS SAVE BLOCK, EVEN IF WE LOCKED ON OTHER
        self.block = Some(block);
        // If propose was different from our locked, don't send it
        if let Some(locked_round) = &self.locked_round {
            let locked_block_hash = Hash::digest(&locked_round.block);
            if block_hash != locked_block_hash
                || Hash::digest(&locked_round.block_proposal)
                    != Hash::digest(self.block_proposal.as_ref().unwrap())
            {
                info!("{}({}:{}): Found valid propose, but we already locked at other propose, locked_block={}, current_block={}",
                      self.state.name(),
                      self.epoch,
                      self.round,
                      locked_block_hash,
                      block_hash,
                );
                return;
            }
        }

        debug!(
            "{}({}:{}): pre-vote block={:?}",
            self.state.name(),
            self.epoch,
            self.round,
            block_hash,
        );
        let body = ConsensusMessageBody::Prevote;
        let msg = ConsensusMessage::new(
            self.epoch, self.round, block_hash, &self.skey, &self.pkey, body,
        );
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Pre-commit the request.
    ///
    fn precommit(&mut self) {
        assert_eq!(self.state, ConsensusState::Precommit);
        assert!(self.block.is_some());
        let block_hash = self.block_hash.as_ref().unwrap().clone();
        debug!(
            "{}({}:{}): pre-commit block={:?}",
            self.state.name(),
            self.epoch,
            self.round,
            block_hash
        );
        let block_hash_sig = pbc::sign_hash(&block_hash, &self.skey);
        let body = ConsensusMessageBody::Precommit(block_hash_sig);
        let msg = ConsensusMessage::new(
            self.epoch, self.round, block_hash, &self.skey, &self.pkey, body,
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
    pub fn feed_message(&mut self, msg: ConsensusMessage) -> Result<(), ConsensusError> {
        trace!(
            "{}({}:{}): process message: msg={:?}",
            self.state.name(),
            self.epoch,
            self.round,
            &msg
        );

        msg.validate()?;

        // Check sender.
        if !self.validators.contains_key(&msg.pkey) {
            debug!(
                "{}({}:{}): peer is not a validator: msg={:?}",
                self.state.name(),
                self.epoch,
                self.round,
                &msg
            );
            return Err(ConsensusError::UnknownMessagePeer(msg.pkey));
        }

        if msg.epoch != self.epoch {
            debug!(
                "{}({}:{}): message from different epoch: msg={:?}",
                self.state.name(),
                self.epoch,
                self.round,
                &msg
            );
            // Discard this message.
            return Ok(());
        }

        // Check round.
        if msg.round < self.round {
            debug!(
                "{}({}:{}): message from the past: msg={:?}",
                self.state.name(),
                self.epoch,
                self.round,
                &msg
            );
            // Discard this message.
            return Ok(());
        } else if msg.round > self.round {
            debug!(
                "{}({}:{}): message from the future: msg={:?}",
                self.state.name(),
                self.epoch,
                self.round,
                &msg
            );
            // Queue the message for future processing.
            self.inbox.push(msg);
            return Ok(());
        }
        assert_eq!(msg.round, self.round);

        // Check block_hash.
        if self.state != ConsensusState::Propose {
            let expected_block_hash = self.block_hash.as_ref().unwrap();
            if expected_block_hash != &msg.block_hash {
                warn!(
                    "{}({}:{}): invalid block_hash: expected_block_hash={:?}, got_block_hash={:?}, msg={:?}",
                    self.state.name(),
                    self.epoch, self.round,
                    &expected_block_hash,
                    &msg.block_hash,
                    &msg
                );
                return Err(ConsensusError::InvalidRequestHash(
                    expected_block_hash.clone(),
                    msg.block_hash,
                    msg.pkey,
                ));
            }
        }

        if self.state == ConsensusState::Commit {
            debug!(
                "{}({}:{}): a late message: msg={:?}",
                self.state.name(),
                self.epoch,
                self.round,
                &msg
            );
            // Silently discard this message.
            return Ok(());
        }

        // Check valid transitions.
        match (&msg.body, &self.state) {
            // Obvious cases.
            (ConsensusMessageBody::Proposal(_), ConsensusState::Propose) => {}
            (ConsensusMessageBody::Prevote, ConsensusState::Prevote) => {}
            (ConsensusMessageBody::Precommit(_), ConsensusState::Precommit) => {}

            // Early pre-commits received in Prevote state.
            (ConsensusMessageBody::Precommit(_), ConsensusState::Prevote) => {}

            // Late pre-votes received in Precommit state.
            (ConsensusMessageBody::Prevote, ConsensusState::Precommit) => {}

            // Late pre-commits received in Commit state.
            (ConsensusMessageBody::Precommit(_), ConsensusState::Commit) => {}

            // Early Prevotes and Precommits in Propose state
            (_, ConsensusState::Propose) => {
                debug!(
                    "{}({}:{}): an early message: msg={:?}",
                    self.state.name(),
                    self.epoch,
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
                    self.epoch,
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
            ConsensusMessageBody::Proposal(block_proposal) => {
                assert_eq!(self.state, ConsensusState::Propose);

                // Check that message has been sent by leader.
                if msg.pkey != self.leader() {
                    error!(
                        "{}({}:{}): a proposal from a non-leader: leader={:?}, from={:?}",
                        self.state.name(),
                        self.epoch,
                        self.round,
                        &self.leader(),
                        &msg.pkey
                    );
                    return Err(ConsensusError::ProposalFromNonLeader(
                        msg.block_hash,
                        self.leader().clone(),
                        msg.pkey,
                    ));
                }

                // Move to Prevote
                let block_hash = msg.block_hash;
                assert!(self.prevotes.is_empty());
                assert!(self.block_hash.is_none());
                assert!(self.block_proposal.is_none());
                debug!(
                    "{}({}:{}) => {}({}:{}): received a new proposal hash={:?}, from={:?}",
                    self.state.name(),
                    self.epoch,
                    self.round,
                    ConsensusState::Prevote.name(),
                    self.epoch,
                    self.round,
                    &msg.block_hash,
                    &msg.pkey
                );
                self.state = ConsensusState::Prevote;
                metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Prevote as i64);
                self.block = None;
                self.block_hash = Some(block_hash);
                self.block_proposal = Some(block_proposal);
                if let Some(locked_round) = &self.locked_round {
                    if block_hash == Hash::digest(&locked_round.block)
                        && Hash::digest(&locked_round.block_proposal)
                            == Hash::digest(self.block_proposal.as_ref().unwrap())
                    {
                        // Someone proposed a request that looks like our locked.
                        let locked = self.locked_round.take().unwrap();
                        self.precommits = locked.precommits;
                        // repeat prevote
                        self.prevote(locked.block);
                    } // don't vote for request that is different from our locked.
                }
                self.process_inbox();
            }
            ConsensusMessageBody::Prevote => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Collect the vote.
                debug!(
                    "{}({}:{}): collected a pre-vote: from={:?}",
                    self.state.name(),
                    self.epoch,
                    self.round,
                    &msg.pkey
                );
                self.prevotes.insert(msg.pkey, msg.sig);
            }
            ConsensusMessageBody::Precommit(block_hash_sig) => {
                assert_ne!(self.state, ConsensusState::Propose);

                // Check signature.
                let block_hash = self.block_hash.as_ref().unwrap();
                if let Err(_e) = pbc::check_hash(&block_hash, &block_hash_sig, &msg.pkey) {
                    error!(
                        "{}({}:{}): a pre-commit signature is not valid: from={:?}",
                        self.state.name(),
                        self.epoch,
                        self.round,
                        &msg.pkey
                    );
                    return Err(ConsensusError::InvalidRequestSignature(block_hash.clone()));
                }

                // Collect the vote.
                debug!(
                    "{}({}:{}): collected a pre-commit: from={:?}",
                    self.state.name(),
                    self.epoch,
                    self.round,
                    &msg.pkey
                );
                self.precommits.insert(msg.pkey, block_hash_sig);
            }
        }

        // Check if supermajority of votes is reached.
        if self.state == ConsensusState::Prevote {
            let (super_majority, stake) = self.check_supermajority(&self.prevotes);
            metrics::PRECOMMITS_AMOUNT.set(stake);
            metrics::PREVOTES_AMOUNT.set(0);
            if !super_majority {
                // No supermajority, skip transition.
                return Ok(());
            }
            // Move to Precommit.
            debug!(
                "{}({}:{}) => {}({}:{})",
                self.state.name(),
                self.epoch,
                self.round,
                ConsensusState::Precommit.name(),
                self.epoch,
                self.round,
            );
            self.state = ConsensusState::Precommit;
            metrics::CONSENSUS_STATE.set(metrics::ConsensusState::Precommit as i64);
            if self.prevotes.contains_key(&self.pkey) {
                // Send a pre-commit vote.
                self.precommit();
            } else {
                // Don't vote in this case and stay silent.
                warn!(
                    "{}({}:{}): request accepted by supermajority, but rejected this node",
                    self.state.name(),
                    self.epoch,
                    self.round,
                );
            }
        } else if self.state == ConsensusState::Precommit {
            let (super_majority, stake) = self.check_supermajority(&self.precommits);
            metrics::PRECOMMITS_AMOUNT.set(stake);
            if super_majority {
                // Move to Commit.
                debug!(
                    "{}({}:{}) => {}({}:{})",
                    self.state.name(),
                    self.epoch,
                    self.round,
                    ConsensusState::Commit.name(),
                    self.epoch,
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
                    self.epoch,
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
    /// Returns true if current node should commit the request.
    ///
    pub fn should_commit(&self) -> bool {
        self.state == ConsensusState::Commit
    }

    ///
    /// Return a proposal to validate.
    ///
    pub fn get_proposal(&self) -> (&Hash, &MacroBlockProposal, u32) {
        assert_ne!(self.state, ConsensusState::Propose, "Have no proposal");
        (
            self.block_hash.as_ref().unwrap(),
            self.block_proposal.as_ref().unwrap(),
            self.round,
        )
    }

    ///
    /// Sign and commit the request and move to the next round.
    ///
    /// Returns negotiated MacroBlock.
    ///
    pub fn commit(mut self) -> MacroBlock {
        assert!(self.should_commit());

        // TODO: Use id instead of PublicKey.
        let validators = self.validators.iter().map(|(k, v)| (*k, *v)).collect();
        let mut block = self.block.take().unwrap();
        // Create multi-signature.
        let (multisig, multisigmap) = create_multi_signature(&validators, &self.precommits);
        block.multisig = multisig;
        block.multisigmap = multisigmap;
        block
    }

    ///
    /// Checks that supermajority of votes has been collected.
    ///
    fn check_supermajority(
        &self,
        accepts: &BTreeMap<pbc::PublicKey, pbc::Signature>,
    ) -> (bool, i64) {
        trace!(
            "{}({}:{}): check for supermajority: accepts={:?}, total={:?}",
            self.state.name(),
            self.epoch,
            self.round,
            accepts.len(),
            self.validators.len()
        );
        let mut stake = 0;
        for (pk, _sign) in accepts {
            stake += self.validators.get(pk).expect("vote from validator");
        }
        (check_supermajority(stake, self.total_slots), stake)
    }
}

impl Drop for Consensus {
    fn drop(&mut self) {
        let work_time = Timestamp::now()
            .duration_since(self.start_time)
            .as_secs_f64();
        metrics::CONSENSUS_WORK_TIME.set(work_time);
        metrics::CONSENSUS_STATE.set(metrics::ConsensusState::NotInConsensus as i64);
    }
}

//! message.rs - ValueShuffle Messages.

//
// Copyright (c) 2019 Stegos
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

use std::collections::HashMap;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SchnorrSig;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::dicemix::DcMatrix;
use stegos_crypto::dicemix::ParticipantID;
use stegos_crypto::hash::Hash;

#[derive(Clone)]
pub struct TXINPacket {
    // One of these sent to all participants at start of session
    // we send a list of TXIN's, identified by their UTXO Hash,
    // and a corresponding ownership signature
    pub txins: Vec<(Hash, SchnorrSig)>,
}

#[derive(Clone)]
pub struct KeyingPacket {
    // At start of every session round, we randomly re-key for
    // cloaked sharing. The public side of this information
    // is shared with every participant.
    pub sess_pkeys: HashMap<ParticipantID, PublicKey>,
}

#[derive(Clone)]
pub struct CommitmentPacket {
    // After constructing our cloaked sharing values we send
    // a commitment to them to all participants. That way they
    // can check that when we send the actual cloaked values
    // they are seen to be the same.
    pub commit: Hash,
}

#[derive(Clone)]
pub struct CloakedPacket {
    // After validating commitmemnts to this information,
    // we send the cloaked gamma_adj and matrix of UTXOs
    // to every participant. We also send a list of cloaking
    // hash values used between us and all the excluded participants.
    //
    // NOTE: unless there remain at least 3 participants (including us)
    // in any round, the disclosure of the shared cloaking hashes
    // could allow an attacker to reveal our cloaked values early,
    // thereby obviating anonymous sharing.
    pub gamma_adj: Fr,
    pub matrix: DcMatrix,
    pub k_excl: HashMap<ParticipantID, Hash>,
}

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

use lazy_static::lazy_static;
use prometheus::*;

#[repr(i64)]
pub enum ConsensusRole {
    Regular = 0,
    Validator = 1,
    Leader = 2,
}

#[repr(i64)]
pub enum ConsensusState {
    NotInConsensus = 0,
    Propose = 1,
    Prevote = 2,
    Precommit = 3,
    Commit = 4,
}

lazy_static! {

    pub static ref CONSENSUS_ROLE: IntGauge = register_int_gauge!(
        "stegos_consensus_role",
        "Current node consensus role (0 = regular, 1 = validator, 2 = leader)."
    )
    .unwrap();

    pub static ref PREVOTES_AMOUNT: IntGauge = register_int_gauge!(
        "stegos_consensus_prevotes",
        "Amount of prevotes collected by node."
    )
    .unwrap();

    pub static ref PRECOMMITS_AMOUNT: IntGauge = register_int_gauge!(
        "stegos_consensus_precommits",
        "Amount of precommits collected by node."
    )
    .unwrap();

    pub static ref CONSENSUS_WORK_TIME: Gauge = register_gauge!(
        "stegos_consensus_work_time",
        "Time in seconds when consensus was active."
    )
    .unwrap();

    pub static ref CONSENSUS_STATE: IntGauge = register_int_gauge!(
        "stegos_consensus_state",
        "Current node consensus state (0 = Not in consensus, 1 = Proposing, 2 = Prevote, 3 = Propose, 4 = Commit)."
    )
    .unwrap();
}

//! Blockchain definition.

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

lazy_static! {
    pub static ref VALIDATOR_SLOTS_GAUGEVEC: IntGaugeVec = register_int_gauge_vec!(
        "stegos_slots_vector",
        "slots per validator in current epoch",
        &["validator"]
    )
    .unwrap();
    pub static ref STAKERS_COUNT: IntGauge =
        register_int_gauge!("stegos_stakers_count", "Count of stakers").unwrap();
    pub static ref STAKERS_MAJORITY_COUNT: IntGauge = register_int_gauge!(
        "stegos_stakers_majority_count",
        "Count of stakers above min_stake_amount"
    )
    .unwrap();
    pub static ref TOTAL_STAKE_AMOUNT: IntGauge = register_int_gauge!(
        "stegos_total_stake_amount",
        "Amount of money staked totally on blockchain."
    )
    .unwrap();
    pub static ref AWARD_VALIDATORS_COUNT: IntGauge = register_int_gauge!(
        "stegos_award_validators_count",
        "Count of validators in service award."
    )
    .unwrap();
    pub static ref AWARD_FAILED_COUNT: IntGauge = register_int_gauge!(
        "stegos_award_failed_count",
        "Count of failed validators in service award."
    )
    .unwrap();
    pub static ref EPOCH: IntGauge =
        register_int_gauge!("stegos_blockchain_epoch", "Current blockchain epoch").unwrap();
    pub static ref OFFSET: IntGauge =
        register_int_gauge!("stegos_blockchain_offset", "Current microblock number").unwrap();
    pub static ref UTXO_LEN: IntGauge =
        register_int_gauge!("stegos_blockchain_utxo", "Size of UTXO map").unwrap();
    pub static ref DIFFICULTY: IntGauge =
        register_int_gauge!("stegos_blockchain_difficulty", "Current difficulty").unwrap();
    pub static ref EMISSION: IntGauge =
        register_int_gauge!("stegos_blockchain_emission", "Monetary emission").unwrap();
    pub static ref MACRO_BLOCK_INPUTS: IntGauge = register_int_gauge!(
        "stegos_macro_blocks_inputs",
        "The number of inputs in a macro block."
    )
    .unwrap();
    pub static ref MACRO_BLOCK_INPUTS_HG: Histogram = register_histogram!(
        "stegos_macro_blocks_inputs_hg",
        "Histogram of the number of inputs in a macro block.",
        vec![1., 5., 10., 20., 30., 40., 50., 100., 1000.0]
    )
    .unwrap();
    pub static ref MACRO_BLOCK_OUTPUTS: IntGauge = register_int_gauge!(
        "stegos_macro_blocks_outputs",
        "The number of outputs in a macro block."
    )
    .unwrap();
    pub static ref MACRO_BLOCK_OUTPUTS_HG: Histogram = register_histogram!(
        "stegos_macro_blocks_outputs_hg",
        "Histogram of the number of outputs in a macro block.",
        vec![1., 5., 10., 20., 30., 40., 50., 100.]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_INPUTS: IntGauge = register_int_gauge!(
        "stegos_micro_blocks_inputs",
        "The number of inputs in a micro block."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_INPUTS_HG: Histogram = register_histogram!(
        "stegos_micro_blocks_inputs_hg",
        "Histogram of the number of inputs in a micro block.",
        vec![1., 5., 10., 20., 30., 40., 50., 100., 1000.0]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_OUTPUTS: IntGauge = register_int_gauge!(
        "stegos_micro_blocks_outputs",
        "The number of outputs in a micro block."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_OUTPUTS_HG: Histogram = register_histogram!(
        "stegos_micro_blocks_outputs_hg",
        "Histogram of the number of outputs in a micro block.",
        vec![1., 5., 10., 20., 30., 40., 50., 100.]
    )
    .unwrap();
    pub static ref MICRO_BLOCK_TRANSACTIONS: IntGauge = register_int_gauge!(
        "stegos_micro_blocks_transactions",
        "The number of transactions in a micro block."
    )
    .unwrap();
    pub static ref MICRO_BLOCK_TRANSACTIONS_HG: Histogram = register_histogram!(
        "stegos_micro_blocks_transactions_hg",
        "Histogram of the number of transactions in a micro block.",
        vec![1., 5., 10., 20., 30., 40., 50., 100.]
    )
    .unwrap();
}

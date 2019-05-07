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

//!
//! Wallet api tests.
//!

#![allow(warnings)]

use crate::{TransactionCommitted, WalletNotification, WalletRequest, WalletResponse};
use pretty_assertions::assert_eq;
use serde::Serialize;
use serde_json::{json, Value};
use stegos_crypto::hash::Hash;

fn compare<T: Serialize>(val: T, expected: Value) {
    let actual = serde_json::to_value(val).expect("Cannot serialize value");
    assert_eq!(actual, expected, "different serialization form found");
}

#[test]
fn response_create_tx() {
    let response = WalletResponse::ValueShuffleStarted {
        session_id: Hash::zero(),
    };
    compare(
        response,
        json!({
            "response": "value_shuffle_started",
            "session_id": "0000000000000000000000000000000000000000000000000000000000000000",
        }),
    );
    let response = WalletResponse::TransactionCreated {
        tx_hash: Hash::zero(),
        fee: 0,
    };
    compare(
        response,
        json!({
            "response": "transaction_created",
            "tx_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "fee": 0,

        }),
    );
}

#[test]
fn response_committed_tx() {
    let t1 = TransactionCommitted::Committed {};

    compare(
        t1,
        json!( {
            "result":"committed",
        }),
    );
    let t2 = TransactionCommitted::ConflictTransactionCommitted {
        conflicted_output: Hash::zero(),
    };
    compare(
        t2,
        json!({
            "result":"conflict_transaction_committed",
            "conflicted_output":"0000000000000000000000000000000000000000000000000000000000000000"
        }),
    );
}

/*
BalanceInfo {
    balance: i64,
},
KeysInfo {
    wallet_pkey: PublicKey,
    network_pkey: secure::PublicKey,
},
UnspentInfo {
    payments: Vec<PaymentInfo>,
    stakes: Vec<StakeInfo>,
},
Recovery {
    recovery: String,
},
Error {
    error: String,
},
*/

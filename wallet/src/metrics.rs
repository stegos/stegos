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
    pub static ref WALLET_BALANCES: IntGaugeVec = register_int_gauge_vec!(
        "stegos_wallet_balances",
        "Balance per wallet public key",
        &["wallet"]
    )
    .unwrap();
    pub static ref WALLET_CREATEAD_PAYMENTS: IntGaugeVec = register_int_gauge_vec!(
        "stegos_wallet_pay_count",
        "Count of payment txs created per wallet",
        &["wallet"]
    )
    .unwrap();
    pub static ref WALLET_CREATEAD_SECURE_PAYMENTS: IntCounterVec = register_int_counter_vec!(
        "stegos_wallet_spay_count",
        "Count of secure payment txs created per wallet",
        &["wallet"]
    )
    .unwrap();
    pub static ref WALLET_COMMITTED_PAYMENTS: IntGaugeVec = register_int_gauge_vec!(
        "stegos_wallet_pay_committed",
        "Count of payment txs committed per wallet",
        &["wallet"]
    )
    .unwrap();
    pub static ref WALLET_PUBLISHED_PAYMENTS: IntCounterVec = register_int_counter_vec!(
        "stegos_wallet_spay_committed",
        "Count of secure payment txs committed per wallet",
        &["wallet"]
    )
    .unwrap();
}

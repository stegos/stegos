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
    pub static ref ACCOUNT_CURRENT_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_current_balance",
        "Account's balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_CURRENT_PAYMENT_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_current_payment_balance",
        "Account's current payment balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_CURRENT_STAKE_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_current_stake_balance",
        "Account's current stake balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_CURRENT_PUBLIC_PAYMENT_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_current_public_payment_balance",
        "Account's current public_payment balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_AVAILABLE_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_available_balance",
        "Account's available balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_AVAILABLE_PAYMENT_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_available_payment_balance",
        "Account's available payment balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_AVAILABLE_STAKE_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_available_stake_balance",
        "Account's available stake balance",
        &["account"]
    )
    .unwrap();
    pub static ref ACCOUNT_AVAILABLE_PUBLIC_PAYMENT_BALANCE: IntGaugeVec = register_int_gauge_vec!(
        "stegos_account_available_public_payment_balance",
        "Account's available public_payment balance",
        &["account"]
    )
    .unwrap();
    pub static ref WALLET_CREATEAD_PAYMENTS: IntGaugeVec = register_int_gauge_vec!(
        "stegos_wallet_pay_count",
        "Count of payment txs created per wallet",
        &["account"]
    )
    .unwrap();
    pub static ref WALLET_CREATEAD_SECURE_PAYMENTS: IntCounterVec = register_int_counter_vec!(
        "stegos_wallet_spay_count",
        "Count of secure payment txs created per wallet",
        &["account"]
    )
    .unwrap();
    pub static ref WALLET_COMMITTED_PAYMENTS: IntGaugeVec = register_int_gauge_vec!(
        "stegos_wallet_pay_committed",
        "Count of payment txs committed per wallet",
        &["account"]
    )
    .unwrap();
    pub static ref WALLET_PUBLISHED_PAYMENTS: IntCounterVec = register_int_counter_vec!(
        "stegos_wallet_spay_committed",
        "Count of secure payment txs committed per wallet",
        &["account"]
    )
    .unwrap();
}

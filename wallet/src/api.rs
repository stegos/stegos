//! Wallet - API.

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

use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_node::OutputsNotification;

//
// Outgoing messages.
//

#[derive(Debug, Clone)]
pub enum WalletNotification {
    BalanceChanged {
        balance: i64,
    },
    PaymentReceived {
        amount: i64,
        comment: String,
    },
    BalanceInfo {
        balance: i64,
    },
    KeysInfo {
        wallet_pkey: PublicKey,
        cosi_pkey: secure::PublicKey,
    },
    UnspentInfo {
        unspent: Vec<(Hash, i64)>,
        unspent_stakes: Vec<(Hash, i64)>,
    },
    Error {
        error: String,
    },
}

//
// Events.
//
#[derive(Debug)]
pub(crate) enum WalletEvent {
    //
    // Public API.
    //
    Subscribe {
        tx: UnboundedSender<WalletNotification>,
    },
    Payment {
        recipient: PublicKey,
        amount: i64,
        comment: String,
    },
    SecurePayment {
        recipient: PublicKey,
        amount: i64,
        comment: String,
    },
    Stake {
        amount: i64,
    },
    Unstake {
        amount: i64,
    },
    UnstakeAll {},

    KeysInfo,
    BalanceInfo,
    UnspentInfo,

    //
    // Internal events.
    //
    NodeOutputsChanged(OutputsNotification),
}

#[derive(Debug, Clone)]
pub struct Wallet {
    pub(crate) outbox: UnboundedSender<WalletEvent>,
}

impl Wallet {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> UnboundedReceiver<WalletNotification> {
        let (tx, rx) = unbounded();
        let msg = WalletEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    pub fn payment(&self, recipient: PublicKey, amount: i64, comment: String) {
        let msg = WalletEvent::Payment {
            recipient,
            amount,
            comment,
        };
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn secure_payment(&self, recipient: PublicKey, amount: i64, comment: String) {
        let msg = WalletEvent::SecurePayment {
            recipient,
            amount,
            comment,
        };
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn stake(&self, amount: i64) {
        let msg = WalletEvent::Stake { amount };
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn unstake(&self, amount: i64) {
        let msg = WalletEvent::Unstake { amount };
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn unstake_all(&self) {
        let msg = WalletEvent::UnstakeAll {};
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn balance_info(&self) {
        let msg = WalletEvent::BalanceInfo;
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn keys_info(&self) {
        let msg = WalletEvent::KeysInfo;
        self.outbox.unbounded_send(msg).expect("connected")
    }

    pub fn unspent_info(&self) {
        let msg = WalletEvent::UnspentInfo;
        self.outbox.unbounded_send(msg).expect("connected")
    }
}

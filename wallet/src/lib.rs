//! Wallet.

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

#![deny(warnings)]

mod change;
mod error;
mod transaction;

pub use crate::transaction::*;
use failure::Error;
use log::*;
use std::collections::HashMap;
use stegos_blockchain::EscrowOutput;
use stegos_blockchain::MonetaryOutput;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::hash::Hash;

pub enum WalletNotification {
    BalanceChanged { balance: i64 },
    MessageReceived { msg: Vec<u8>, prune_tx: Transaction },
}

pub struct Wallet {
    /// Secret Key.
    skey: SecretKey,
    /// Public Key.
    pkey: PublicKey,
    /// Unspent Monetary UXTO.
    unspent: HashMap<Hash, (MonetaryOutput, i64)>,
    /// Unspent Escrow UTXO.
    unspent_stakes: HashMap<Hash, EscrowOutput>,
    /// Calculated Node's balance.
    balance: i64,
}

impl Wallet {
    /// Create a new wallet.
    pub fn new(skey: SecretKey, pkey: PublicKey) -> Self {
        let unspent: HashMap<Hash, (MonetaryOutput, i64)> = HashMap::new();
        let unspent_stakes: HashMap<Hash, EscrowOutput> = HashMap::new();
        let balance: i64 = 0;
        Wallet {
            skey,
            pkey,
            unspent,
            unspent_stakes,
            balance,
        }
    }

    /// Send money.
    pub fn payment(&self, recipient: &PublicKey, amount: i64) -> Result<Transaction, Error> {
        let tx =
            create_monetary_transaction(&self.skey, &self.pkey, recipient, &self.unspent, amount)?;
        Ok(tx)
    }

    /// Send message.
    pub fn message(
        &self,
        recipient: &PublicKey,
        ttl: u64,
        data: Vec<u8>,
    ) -> Result<Transaction, Error> {
        let tx =
            create_data_transaction(&self.skey, &self.pkey, recipient, &self.unspent, ttl, data)?;
        Ok(tx)
    }

    /// Called when outputs registered and/or pruned.
    pub fn on_outputs_changed(
        &mut self,
        inputs: Vec<Output>,
        outputs: Vec<Output>,
    ) -> Vec<WalletNotification> {
        let mut notifications: Vec<WalletNotification> = Vec::new();

        let saved_balance = self.balance;

        for input in inputs {
            self.on_output_pruned(input);
        }

        for output in outputs {
            if let Some(notification) = self.on_output_created(output) {
                notifications.push(notification);
            }
        }

        if saved_balance != self.balance {
            let balance = self.balance;
            let notification = WalletNotification::BalanceChanged { balance };
            notifications.push(notification);
        }

        notifications
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, output: Output) -> Option<WalletNotification> {
        let hash = Hash::digest(&output);
        match output {
            Output::MonetaryOutput(o) => {
                if let Ok((_delta, _gamma, amount)) = o.decrypt_payload(&self.skey) {
                    info!("Received monetary UTXO: hash={}, amount={}", hash, amount);
                    let missing = self.unspent.insert(hash, (o, amount));
                    assert!(missing.is_none());
                    assert!(amount >= 0);
                    self.balance += amount
                }
            }
            Output::DataOutput(o) => {
                if let Ok((_delta, _gamma, msg)) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Received data UTXO: hash={}, msg={}",
                        hash,
                        String::from_utf8_lossy(&msg)
                    );

                    // Send a prune transaction.
                    debug!("Pruning data");
                    let prune_tx =
                        create_data_pruning_transaction(&self.skey, o).expect("cannot fail");
                    debug!("Created transaction: hash={}", Hash::digest(&prune_tx.body));

                    // Notify subscribers.
                    let notification = WalletNotification::MessageReceived { msg, prune_tx };
                    return Some(notification);
                }
            }
            Output::EscrowOutput(o) => {
                if let Ok(_delta) = o.decrypt_payload(&self.skey) {
                    info!("Staked money to escrow: hash={}, amount={}", hash, o.amount);
                    let missing = self.unspent_stakes.insert(hash, o);
                    assert!(missing.is_none());
                }
            }
        };
        None
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, output: Output) {
        let hash = Hash::digest(&output);
        match output {
            Output::MonetaryOutput(o) => {
                if let Ok((_delta, _gamma, amount)) = o.decrypt_payload(&self.skey) {
                    info!("Spent monetary UTXO: hash={}, amount={}", hash, amount);
                    let exists = self.unspent.remove(&hash);
                    assert!(exists.is_some());
                    self.balance -= amount;
                    assert!(self.balance >= 0);
                }
            }
            Output::DataOutput(o) => {
                if let Ok((_delta, _gamma, data)) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Pruned data UTXO: hash={}, msg={}",
                        hash,
                        String::from_utf8_lossy(&data)
                    );
                }
            }
            Output::EscrowOutput(o) => {
                if let Ok(_delta) = o.decrypt_payload(&self.skey) {
                    info!(
                        "Unstaked money from escrow: hash={}, amount={}",
                        hash, o.amount
                    );
                }
            }
        }
    }
}

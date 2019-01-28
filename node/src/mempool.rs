//! Memory Pool of Transactions.

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

use chrono::Utc;
use linked_hash_map::LinkedHashMap;
use log::*;
use std::collections::HashMap;
use stegos_blockchain::*;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;

/// Memory Pool of Transactions.
pub struct Mempool {
    pool: LinkedHashMap<Hash, Transaction>,
    inputs: HashMap<Hash, Hash>,
    outputs: HashMap<Hash, Hash>,
}

impl Mempool {
    ///
    /// Creates a new mempool instance.
    ///
    pub fn new() -> Self {
        let pool: LinkedHashMap<Hash, Transaction> = LinkedHashMap::new();
        let inputs: HashMap<Hash, Hash> = HashMap::new();
        let outputs: HashMap<Hash, Hash> = HashMap::new();
        return Self {
            pool,
            inputs,
            outputs,
        };
    }

    ///
    /// Checks if the mempool contains a transaction with claims `input_hash`.
    ///
    pub fn contains_input(&self, input_hash: &Hash) -> bool {
        self.inputs.contains_key(input_hash)
    }

    ///
    /// Checks if the mempool contains a transaction with claims `output_hash`.
    ///
    pub fn contains_output(&self, output_hash: &Hash) -> bool {
        self.outputs.contains_key(output_hash)
    }

    ///
    /// Checks if the mempool contains the given transaction.
    ///
    pub fn contains_tx(&self, tx_hash: &Hash) -> bool {
        self.pool.contains_key(tx_hash)
    }

    ///
    /// Returns a transaction from the mempool.
    ///
    pub fn get_tx(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.pool.get(tx_hash)
    }

    ///
    /// Queues a transaction to the mempool.
    ///
    pub fn push_tx(&mut self, tx_hash: Hash, tx: Transaction) {
        assert_eq!(&tx_hash, &Hash::digest(&tx.body));
        for input_hash in &tx.body.txins {
            self.inputs.insert(input_hash.clone(), tx_hash.clone());
        }
        for output in &tx.body.txouts {
            let output_hash = Hash::digest(output);
            self.outputs.insert(output_hash, tx_hash.clone());
        }
        self.pool.insert(tx_hash, tx);
    }

    /// Prune old transactions contains tx_hash from the mempool.
    pub fn prune(&mut self, _input_hashes: &[Hash], _output_hashes: &[Hash]) {
        // TODO: prune all transactions contains tx_hash.
        self.pool.clear();
        self.inputs.clear();
        self.outputs.clear();
    }

    ///
    /// Returns the number of transactions in this mempool.
    ///
    #[allow(dead_code)] // TODO: false-positive
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    ///
    /// Process transactions in mempool and create a new MonetaryBlockProposal.
    ///
    pub fn create_block(
        &mut self,
        previous: Hash,
        version: u64,
        epoch: u64,
        skey: &SecretKey,
        pkey: &PublicKey,
    ) -> (MonetaryBlock, Option<Output>, Vec<Hash>) {
        // TODO: limit the block size.
        let tx_count = self.pool.len();
        debug!(
            "Processing {}/{} transactions from mempool",
            tx_count,
            self.pool.len()
        );

        let timestamp = Utc::now().timestamp() as u64;
        let mut gamma = Fr::zero();
        let mut fee = 0i64;
        let mut inputs: Vec<Hash> = Vec::new();
        let mut outputs: Vec<Output> = Vec::new();
        let mut tx_hashes: Vec<Hash> = Vec::with_capacity(tx_count);
        for entry in self.pool.entries() {
            let tx_hash = entry.key();
            let tx = entry.get();
            assert_eq!(tx_hash, &Hash::digest(&tx.body));

            debug!("Processing transaction: hash={}", &tx_hash);
            tx_hashes.push(tx_hash.clone());
            inputs.extend(tx.body.txins.iter().cloned());
            outputs.extend(tx.body.txouts.iter().cloned());
            gamma += tx.body.gamma;
            fee += tx.body.fee;
        }

        // Create an output for fee.
        let output_fee = if fee > 0 {
            trace!("Creating fee UTXO...");
            let (output_fee, gamma_fee) =
                Output::new_payment(timestamp, skey, pkey, fee).expect("invalid keys");
            gamma -= gamma_fee;
            info!(
                "Created fee UTXO: hash={}, amount={}",
                Hash::digest(&output_fee),
                fee
            );
            outputs.push(output_fee.clone());
            Some(output_fee)
        } else {
            None
        };

        // Create a new monetary block.
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let block = MonetaryBlock::new(base, gamma, &inputs, &outputs);

        (block, output_fee, tx_hashes)
    }
}

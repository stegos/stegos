//! Memory Pool of Transactions.

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

use chrono::Utc;
use linked_hash_map::LinkedHashMap;
use log::*;
use std::collections::HashMap;
use std::collections::HashSet;
use stegos_blockchain::view_changes::ViewChangeProof;
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
    /// Queues a transaction to the mempool.
    ///
    pub fn push_tx(&mut self, tx_hash: Hash, tx: Transaction) {
        debug_assert_eq!(&tx_hash, &Hash::digest(&tx));
        for input_hash in &tx.body.txins {
            let exists = self.inputs.insert(input_hash.clone(), tx_hash.clone());
            assert!(exists.is_none());
        }
        for output in &tx.body.txouts {
            let output_hash = Hash::digest(output);
            let exists = self.outputs.insert(output_hash, tx_hash.clone());
            assert!(exists.is_none());
        }
        let exists = self.pool.insert(tx_hash, tx);
        assert!(exists.is_none());
    }

    /// Prune old transactions contains tx_hash from the mempool.
    pub fn prune(&mut self, input_hashes: &[Hash], output_hashes: &[Hash]) {
        let mut tx_hashes: HashSet<Hash> = HashSet::new();

        // Collect transactions affected by inputs.
        for input_hash in input_hashes {
            if let Some(tx_hash) = self.inputs.remove(&input_hash) {
                tx_hashes.insert(tx_hash);
            }
        }

        // Collect transactions affected by outputs.
        for output_hash in output_hashes {
            if let Some(tx_hash) = self.outputs.remove(&output_hash) {
                tx_hashes.insert(tx_hash);
            }
        }

        // Prune transactions.
        for tx_hash in tx_hashes {
            let tx = self.pool.remove(&tx_hash).expect("transaction exists");

            for input_hash in tx.body.txins {
                if self.inputs.contains_key(&input_hash) {
                    panic!("Inconsistent mempool pruning");
                }
            }

            for output in tx.body.txouts {
                let output_hash = Hash::digest(&output);
                if self.outputs.contains_key(&output_hash) {
                    panic!("Inconsistent mempool pruning");
                }
            }
        }
    }

    ///
    /// Returns the number of transactions in this mempool.
    ///
    #[allow(dead_code)] // TODO: false-positive
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    ///
    /// Process transactions in mempool and create a new monetary block.
    ///
    pub fn create_block(
        &mut self,
        previous: Hash,
        version: u64,
        height: u64,
        reward: i64,
        skey: &SecretKey,
        pkey: &PublicKey,
        view_change: u32,
        proof: Option<ViewChangeProof>,
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
            debug_assert_eq!(tx_hash, &Hash::digest(&tx));

            debug!("Processing transaction: hash={}", &tx_hash);
            tx_hashes.push(tx_hash.clone());
            inputs.extend(tx.body.txins.iter().cloned());
            outputs.extend(tx.body.txouts.iter().cloned());
            gamma += tx.body.gamma;
            fee += tx.body.fee;
        }

        let monetary_adjustment: i64 = reward;

        // Create an output for fee.
        let output_fee = if fee + reward > 0 {
            trace!("Creating reward UTXO...");
            let data = PaymentPayloadData::Comment("Block reward".to_string());
            let (output_fee, gamma_fee) =
                PaymentOutput::with_payload(timestamp, skey, pkey, fee + reward, data.clone())
                    .expect("invalid keys");
            gamma -= gamma_fee;
            info!(
                "Created reward UTXO: hash={}, fee={}, reward={}, data={:?}",
                Hash::digest(&output_fee),
                fee,
                reward,
                data
            );
            outputs.push(Output::PaymentOutput(output_fee.clone()));
            Some(Output::PaymentOutput(output_fee))
        } else {
            None
        };

        // Create a new monetary block.
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
        let block = MonetaryBlock::new(base, gamma, monetary_adjustment, &inputs, &outputs, proof);

        (block, output_fee, tx_hashes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::BTreeMap;
    use stegos_crypto::curve1174::cpt::make_random_keys;

    #[test]
    fn basic() {
        let (skey, pkey, _sig) = make_random_keys();
        let mut mempool = Mempool::new();

        let (tx1, inputs1, outputs1) =
            Transaction::new_test(&skey, &pkey, 100, 2, 200, 1, 0).expect("transaction valid");
        let (tx2, inputs2, outputs2) =
            Transaction::new_test(&skey, &pkey, 300, 1, 100, 3, 0).expect("transaction valid");
        let tx_hash1 = Hash::digest(&tx1);
        let tx_hash2 = Hash::digest(&tx2);

        mempool.push_tx(tx_hash1.clone(), tx1.clone());
        mempool.push_tx(tx_hash2.clone(), tx2.clone());
        assert!(mempool.contains_tx(&tx_hash1));
        assert!(mempool.contains_tx(&tx_hash2));
        assert_eq!(mempool.len(), 2);

        for input in inputs1.iter().chain(inputs2.iter()) {
            let input_hash = Hash::digest(input);
            assert!(mempool.contains_input(&input_hash));
        }

        for output in outputs1.iter().chain(outputs2.iter()) {
            let output_hash = Hash::digest(output);
            assert!(mempool.contains_output(&output_hash));
        }

        //
        // Pruning.
        //
        let input1_hashes: Vec<Hash> = inputs1.iter().map(|o| Hash::digest(o)).collect();
        let output1_hashes: Vec<Hash> = outputs1.iter().map(|o| Hash::digest(o)).collect();
        mempool.prune(&input1_hashes, &output1_hashes);
        assert!(!mempool.contains_tx(&tx_hash1));
        for input in &inputs1 {
            let input_hash = Hash::digest(input);
            assert!(!mempool.contains_input(&input_hash));
        }
        for output in &outputs1 {
            let output_hash = Hash::digest(output);
            assert!(!mempool.contains_output(&output_hash));
        }
        assert!(mempool.contains_tx(&tx_hash2));
        for input in &inputs2 {
            let input_hash = Hash::digest(input);
            assert!(mempool.contains_input(&input_hash));
        }
        for output in &outputs2 {
            let output_hash = Hash::digest(output);
            assert!(mempool.contains_output(&output_hash));
        }
        assert_eq!(mempool.len(), 1);

        mempool.push_tx(tx_hash1.clone(), tx1.clone());
        assert!(mempool.contains_tx(&tx_hash1));
        assert_eq!(mempool.len(), 2);

        // Prune nothing.
        mempool.prune(&vec![Hash::digest(&1u64)], &vec![Hash::digest(&1u64)]);
        assert!(mempool.contains_tx(&tx_hash1));
        assert!(mempool.contains_tx(&tx_hash2));
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    #[should_panic]
    pub fn inconsistent_pruning1() {
        let (skey, pkey, _sig) = make_random_keys();
        let mut mempool = Mempool::new();

        let (tx, inputs, _outputs) =
            Transaction::new_test(&skey, &pkey, 100, 1, 100, 1, 0).expect("transaction valid");
        let tx_hash = Hash::digest(&tx);
        mempool.push_tx(tx_hash.clone(), tx.clone());
        mempool.prune(&vec![Hash::digest(&inputs[0])], &vec![]);
    }

    #[test]
    #[should_panic]
    pub fn inconsistent_pruning2() {
        let (skey, pkey, _sig) = make_random_keys();
        let mut mempool = Mempool::new();

        let (tx, _inputs, outputs) =
            Transaction::new_test(&skey, &pkey, 100, 1, 100, 1, 0).expect("transaction valid");
        let tx_hash = Hash::digest(&tx);
        mempool.push_tx(tx_hash.clone(), tx.clone());
        mempool.prune(&vec![], &vec![Hash::digest(&outputs[0])]);
    }

    #[test]
    fn create_block() {
        let (skey, pkey, _sig) = make_random_keys();
        let mut mempool = Mempool::new();

        let (tx1, inputs1, _outputs1) =
            Transaction::new_test(&skey, &pkey, 3, 2, 2, 1, 4).expect("transaction valid");
        let (tx2, inputs2, _outputs2) =
            Transaction::new_test(&skey, &pkey, 6, 1, 2, 2, 2).expect("transaction valid");

        let tx_hash1 = Hash::digest(&tx1);
        let tx_hash2 = Hash::digest(&tx2);
        mempool.push_tx(tx_hash1.clone(), tx1.clone());
        mempool.push_tx(tx_hash2.clone(), tx2.clone());

        let previous = Hash::digest(&1u64);
        let version = 1;
        let height = 0;
        let view_change = 0;
        let (block, output_fee, tx_hashes) = mempool.create_block(
            previous,
            version,
            height,
            0,
            &skey,
            &pkey,
            view_change,
            None,
        );

        // Used transactions.
        assert_eq!(tx_hashes, vec![tx_hash1, tx_hash2]);

        // Monetary balance.
        let mut inputs: BTreeMap<Hash, Output> = BTreeMap::new();
        for input in inputs1.iter().chain(inputs2.iter()) {
            let input_hash = Hash::digest(input);
            inputs.insert(input_hash, input.clone());
        }

        let inputs: Vec<Output> = inputs.values().cloned().collect();
        block.validate_balance(&inputs).expect("block is valid");

        // Fee.
        if let Some(Output::PaymentOutput(o)) = output_fee {
            let PaymentPayload { amount, .. } = o.decrypt_payload(&skey).expect("keys are valid");
            assert_eq!(amount, 6);
        } else {
            unreachable!();
        }
    }
}

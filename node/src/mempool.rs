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

use log::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::SystemTime;
use stegos_blockchain::view_changes::ViewChangeProof;
use stegos_blockchain::*;
use stegos_crypto::curve1174::{self, Fr};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

/// Memory Pool of Transactions.
pub struct Mempool {
    pool: HashMap<Hash, Transaction>,
    inputs: HashMap<Hash, Hash>,
    outputs: HashMap<Hash, Hash>,
}

impl Mempool {
    ///
    /// Creates a new mempool instance.
    ///
    pub fn new() -> Self {
        let pool: HashMap<Hash, Transaction> = HashMap::new();
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
        for input_hash in tx.txins() {
            let exists = self.inputs.insert(input_hash.clone(), tx_hash.clone());
            assert!(exists.is_none());
        }
        for output in tx.txouts() {
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
            for input_hash in tx.txins() {
                if let Some(tx_hash2) = self.inputs.remove(input_hash) {
                    assert_eq!(tx_hash2, tx_hash);
                }
            }
            for output in tx.txouts() {
                let output_hash = Hash::digest(output);
                if let Some(tx_hash2) = self.outputs.remove(&output_hash) {
                    assert_eq!(tx_hash2, tx_hash);
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
    /// Returns the number of inputs in this mempool.
    ///
    pub fn inputs_len(&self) -> usize {
        self.inputs.len()
    }

    ///
    /// Returns the number of outputs in this mempool.
    ///
    pub fn outputs_len(&self) -> usize {
        self.outputs.len()
    }

    ///
    /// Process transactions in mempool and create a new monetary block.
    ///
    pub fn create_block(
        &mut self,
        previous: Hash,
        epoch: u64,
        offset: u32,
        view_change: u32,
        view_change_proof: Option<ViewChangeProof>,
        last_random: Hash,
        block_reward: i64,
        recipient_pkey: &curve1174::PublicKey,
        network_skey: &pbc::SecretKey,
        network_pkey: &pbc::PublicKey,
        max_utxo_in_block: usize,
    ) -> MicroBlock {
        let timestamp = SystemTime::now();
        let seed = mix(last_random, view_change);
        let random = pbc::make_VRF(network_skey, &seed);

        // Sort transactions by fee.
        // RestakeTransactions have high priority.
        let mut pool: Vec<(&Hash, &Transaction, i64)> = self
            .pool
            .iter()
            .map(|(hash, tx)| {
                let prio = match tx {
                    Transaction::RestakeTransaction(_) => i64::max_value(),
                    _ => tx.fee(),
                };
                (hash, tx, prio)
            })
            .collect();
        pool.sort_by_key(|(_h, _tx, prio)| -*prio);

        //
        // Mempool Transactions.
        //
        let mut utxo_in_block: usize = 1; // Coinbase has one output
        let mut block_fee: i64 = 0;
        let mut transactions: Vec<Transaction> = Vec::new();
        // Reserve a place for coinbase.
        transactions.push(Transaction::CoinbaseTransaction(Default::default()));
        for (tx_hash, tx, _prio) in pool {
            // Ensure that transaction has proper type.
            match tx {
                Transaction::PaymentTransaction(_tx) => {}
                Transaction::RestakeTransaction(_tx) => {}
                Transaction::SlashingTransaction(_tx) => {}
                Transaction::CoinbaseTransaction(_) | Transaction::ServiceAwardTransaction(_) => {
                    panic!("Invalid transaction type in mempool: tx={:?}", tx_hash)
                }
            };

            // Check the maximum number of UTXO in block.
            if utxo_in_block + tx.txins().len() + tx.txouts().len() >= max_utxo_in_block {
                break;
            }

            debug!("Processing transaction: hash={}", &tx_hash);
            transactions.push(tx.clone());
            block_fee += tx.fee();
            utxo_in_block += tx.txins().len();
            utxo_in_block += tx.txouts().len();
        }

        debug!(
            "Processed {}/{} transactions from mempool",
            transactions.len() - 1, // exclude coinbase
            self.pool.len()
        );

        //
        // Coinbase Transaction.
        //
        {
            let mut txouts: Vec<Output> = Vec::new();
            let mut gamma = Fr::zero();

            // Create outputs for fee and rewards.
            for (amount, comment) in vec![(block_reward + block_fee, "reward+fee")] {
                if amount <= 0 {
                    continue;
                }

                let data = PaymentPayloadData::Comment(format!("Block {}", comment));
                let (output_fee, gamma_fee, _rvalue) =
                    PaymentOutput::with_payload(None, recipient_pkey, amount, data.clone(), None)
                        .expect("invalid keys");
                gamma -= gamma_fee;

                info!(
                    "Created {} UTXO: hash={}, amount={}, data={:?}",
                    comment,
                    Hash::digest(&output_fee),
                    amount,
                    data
                );
                txouts.push(Output::PaymentOutput(output_fee));
            }

            let coinbase = CoinbaseTransaction {
                block_reward,
                block_fee,
                gamma,
                txouts,
            };

            match std::mem::replace(&mut transactions[0], coinbase.into()) {
                Transaction::CoinbaseTransaction(_tx) => {}
                _ => panic!("CoinbaseTransaction must be first in the block"),
            };
        }

        // Create a new micro block.
        MicroBlock::new(
            previous,
            epoch,
            offset,
            view_change,
            view_change_proof,
            network_pkey.clone(),
            random,
            timestamp,
            transactions,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let (skey, pkey) = curve1174::make_random_keys();
        let mut mempool = Mempool::new();

        let (tx1, inputs1, outputs1) =
            PaymentTransaction::new_test(&skey, &pkey, 100, 2, 200, 1, 0)
                .expect("transaction valid");
        let (tx2, inputs2, outputs2) =
            PaymentTransaction::new_test(&skey, &pkey, 300, 1, 100, 3, 0)
                .expect("transaction valid");
        let tx_hash1 = Hash::digest(&tx1);
        let tx_hash2 = Hash::digest(&tx2);

        mempool.push_tx(tx_hash1.clone(), tx1.clone().into());
        mempool.push_tx(tx_hash2.clone(), tx2.clone().into());
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

        mempool.push_tx(tx_hash1.clone(), tx1.clone().into());
        assert!(mempool.contains_tx(&tx_hash1));
        assert_eq!(mempool.len(), 2);

        // Prune nothing.
        mempool.prune(&vec![Hash::digest(&1u64)], &vec![Hash::digest(&1u64)]);
        assert!(mempool.contains_tx(&tx_hash1));
        assert!(mempool.contains_tx(&tx_hash2));
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    pub fn partial_pruning1() {
        let (skey, pkey) = curve1174::make_random_keys();
        let mut mempool = Mempool::new();

        let (tx, inputs, outputs) = PaymentTransaction::new_test(&skey, &pkey, 100, 2, 100, 2, 0)
            .expect("transaction valid");
        let tx_hash = Hash::digest(&tx);
        mempool.push_tx(tx_hash.clone(), tx.clone().into());
        mempool.prune(&vec![Hash::digest(&inputs[0])], &vec![]);
        assert!(!mempool.contains_tx(&tx_hash));
        for input in inputs {
            let input_hash = Hash::digest(&input);
            assert!(!mempool.contains_input(&input_hash));
        }
        for output in outputs {
            let output_hash = Hash::digest(&output);
            assert!(!mempool.contains_output(&output_hash));
        }
    }

    #[test]
    pub fn partial_pruning2() {
        let (skey, pkey) = curve1174::make_random_keys();
        let mut mempool = Mempool::new();

        let (tx, inputs, outputs) = PaymentTransaction::new_test(&skey, &pkey, 100, 2, 100, 2, 0)
            .expect("transaction valid");
        let tx_hash = Hash::digest(&tx);
        mempool.push_tx(tx_hash.clone(), tx.clone().into());
        mempool.prune(&vec![], &vec![Hash::digest(&outputs[0])]);
        assert!(!mempool.contains_tx(&tx_hash));
        for input in inputs {
            let input_hash = Hash::digest(&input);
            assert!(!mempool.contains_input(&input_hash));
        }
        for output in outputs {
            let output_hash = Hash::digest(&output);
            assert!(!mempool.contains_output(&output_hash));
        }
    }

    #[test]
    fn create_block() {
        let (recipient_skey, recipient_pkey) = curve1174::make_random_keys();
        let (network_skey, network_pkey) = pbc::make_random_keys();

        let max_utxo_in_block: usize = 9;
        let mut mempool = Mempool::new();

        let (tx1, _inputs1, _outputs1) =
            PaymentTransaction::new_test(&recipient_skey, &recipient_pkey, 6, 1, 2, 3, 2)
                .expect("transaction valid");
        let (tx2, _inputs2, _outputs2) =
            PaymentTransaction::new_test(&recipient_skey, &recipient_pkey, 6, 1, 2, 3, 0)
                .expect("transaction valid");
        let (tx3, _inputs3, _outputs3) =
            PaymentTransaction::new_test(&recipient_skey, &recipient_pkey, 3, 2, 2, 1, 4)
                .expect("transaction valid");

        let tx_hash1 = Hash::digest(&tx1);
        let tx_hash2 = Hash::digest(&tx2);
        let tx_hash3 = Hash::digest(&tx3);
        mempool.push_tx(tx_hash1.clone(), tx1.clone().into());
        mempool.push_tx(tx_hash2.clone(), tx2.clone().into());
        mempool.push_tx(tx_hash3.clone(), tx3.clone().into());

        let previous = Hash::digest(&1u64);
        let epoch = 1;
        let offset = 5;
        let view_change = 0;
        let reward = 10;
        let block = mempool.create_block(
            previous,
            epoch,
            offset,
            view_change,
            None,
            Hash::digest("test"),
            reward,
            &recipient_pkey,
            &network_skey,
            &network_pkey,
            max_utxo_in_block,
        );

        assert_eq!(block.transactions.len(), 3);
        if let Transaction::CoinbaseTransaction(tx) = &block.transactions[0] {
            // Reward + Fee.
            if let Some(Output::PaymentOutput(o)) = tx.txouts.get(0) {
                let PaymentPayload { amount, .. } =
                    o.decrypt_payload(&recipient_skey).expect("keys are valid");
                assert_eq!(amount, reward + 6);
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
        //
        // Used transactions. Order is important:
        //   - tx_hash3 has fee = 4
        //   - tx_hash1 has fee = 2
        //   - tx_hash2 is not included because of max_utxo_in_block.
        //
        assert_eq!(Hash::digest(&block.transactions[1]), tx_hash3);
        assert_eq!(Hash::digest(&block.transactions[2]), tx_hash1);
    }
}

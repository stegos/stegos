//
// MIT License
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

use crate::config::ChainConfig;
use crate::error::*;
use crate::mempool::Mempool;
use failure::Error;
use log::*;
use std::time::SystemTime;
use stegos_blockchain::MacroBlock;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
use stegos_blockchain::{Blockchain, TransactionError};
use stegos_crypto::hash::Hash;

///
/// Validate transaction.
///
pub(crate) fn validate_transaction(
    tx: &Transaction,
    mempool: &Mempool,
    chain: &Blockchain,
    _timestamp: SystemTime,
    payment_fee: i64,
    stake_fee: i64,
) -> Result<(), Error> {
    let tx_hash = Hash::digest(tx);

    // Check that transaction exists in the mempool.
    if mempool.contains_tx(&tx_hash) {
        return Err(NodeTransactionError::AlreadyExists(tx_hash).into());
    }

    // Check fee.
    let mut min_fee: i64 = 0;
    for txout in &tx.body.txouts {
        min_fee += match txout {
            Output::PaymentOutput(_o) => payment_fee,
            Output::PublicPaymentOutput(_o) => payment_fee,
            Output::StakeOutput(_o) => stake_fee,
        };
    }
    if tx.body.fee < min_fee {
        return Err(NodeTransactionError::TooLowFee(tx_hash, min_fee, tx.body.fee).into());
    }

    let mut inputs: Vec<Output> = Vec::new();

    // TODO: allow transaction with overlapping inputs/outputs in mempool.
    // See https://github.com/stegos/stegos/issues/826.

    // Check for overlapping inputs in mempool.
    for input_hash in &tx.body.txins {
        // Check that the input can be resolved.
        let input = match chain.output_by_hash(input_hash)? {
            Some(input) => input,
            None => {
                return Err(TransactionError::MissingInput(tx_hash, input_hash.clone()).into());
            }
        };

        // Check that the input is not claimed by other transactions.
        if mempool.contains_input(input_hash) {
            return Err(TransactionError::MissingInput(tx_hash, input_hash.clone()).into());
        }

        inputs.push(input);
    }

    // Check for overlapping outputs in mempool.
    for output in &tx.body.txouts {
        let output_hash = Hash::digest(output);
        // Check that the output is unique and don't overlap with other transactions.
        if mempool.contains_output(&output_hash) || chain.contains_output(&output_hash) {
            return Err(TransactionError::OutputHashCollision(tx_hash, output_hash).into());
        }
    }

    // Check the monetary balance, Bulletpoofs/amounts and signature.
    let staking_balance = tx.validate(&inputs)?;

    // Checks staking balance.
    chain.validate_staking_balance(staking_balance.iter())?;

    Ok(())
}

fn vetted_timestamp(
    block: &MacroBlock,
    cfg: &ChainConfig,
    last_block_time: SystemTime,
) -> Result<(), Error> {
    let timestamp = SystemTime::now();

    if block.header.base.timestamp <= last_block_time {
        return Err(
            NodeBlockError::OutdatedBlock(block.header.base.timestamp, last_block_time).into(),
        );
    }

    if block.header.base.timestamp >= timestamp {
        let duration = block
            .header
            .base
            .timestamp
            .duration_since(timestamp)
            .unwrap();

        if duration > cfg.macro_block_timeout {
            return Err(NodeBlockError::OutOfSyncTimestamp(
                block.header.base.height,
                Hash::digest(block),
                block.header.base.timestamp,
                timestamp,
            )
            .into());
        }
    }

    Ok(())
}

///
/// Validate proposed macro block.
///
pub(crate) fn validate_proposed_macro_block(
    cfg: &ChainConfig,
    chain: &Blockchain,
    view_change: u32,
    block_hash: Hash,
    block: &MacroBlock,
) -> Result<(), Error> {
    debug_assert_eq!(&Hash::digest(block), &block_hash);

    // Ensure that block was produced at round lower than current.
    if block.header.base.view_change > view_change {
        return Err(NodeBlockError::OutOfSyncViewChange(
            block.header.base.height,
            block_hash,
            block.header.base.view_change,
            view_change,
        )
        .into());
    }
    vetted_timestamp(block, cfg, chain.last_macro_block_timestamp())?;
    chain.validate_macro_block(block, block.header.base.timestamp, true)?;

    debug!("Key block proposal is valid: block={:?}", block_hash);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, SystemTime};
    use stegos_blockchain::*;
    use stegos_crypto::curve1174::fields::Fr;
    use stegos_keychain::KeyChain;

    #[test]
    fn test_validate_transaction() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let payment_fee: i64 = 1;
        let stake_fee: i64 = 0;
        let amount: i64 = 10000;
        let mut timestamp = SystemTime::now();
        let keychain = KeyChain::new_mem();
        let mut mempool = Mempool::new();
        let mut cfg: BlockchainConfig = Default::default();
        let stake_epochs = 1;
        cfg.stake_epochs = stake_epochs;
        let stake: i64 = cfg.min_stake_amount;
        let genesis = genesis(&[keychain.clone()], stake, amount + stake, timestamp);
        let chain =
            Blockchain::testing(cfg, genesis, timestamp).expect("Failed to create blockchain");
        let mut inputs: Vec<Output> = Vec::new();
        let mut stakes: Vec<Output> = Vec::new();
        for output_hash in chain.unspent() {
            let output = chain
                .output_by_hash(&output_hash)
                .expect("no disk errors")
                .expect("exists");
            match output {
                Output::PaymentOutput(ref _o) => inputs.push(output),
                Output::PublicPaymentOutput(ref _o) => inputs.push(output),
                Output::StakeOutput(ref _o) => stakes.push(output),
            }
        }

        let skey = &keychain.wallet_skey;
        let pkey = &keychain.wallet_pkey;
        let validator_skey = &keychain.network_skey;
        let validator_pkey = &keychain.network_pkey;

        //
        // Valid transaction.
        //
        {
            let fee = 2 * payment_fee;
            let (output1, gamma1) = Output::new_payment(&pkey, 1).unwrap();
            let (output2, gamma2) = Output::new_payment(&pkey, amount - fee - 1).unwrap();
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1 + gamma2;
            let tx = Transaction::new(&skey, &inputs, &outputs, &outputs_gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Fee > expected.
        //
        {
            let fee = payment_fee + 1;
            let (output, gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], &gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Fee < expected.
        //
        {
            let fee = payment_fee - 1;
            let (output, gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
            let tx = Transaction::unchecked(&skey, &inputs, &[output], &gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().unwrap() {
                NodeTransactionError::TooLowFee(tx_hash, min, got) => {
                    assert_eq!(tx_hash, Hash::digest(&tx));
                    assert_eq!(min, payment_fee);
                    assert_eq!(got, fee);
                }
                _ => panic!(),
            }
        }

        //
        // Missing or spent input in blockchain.
        //
        {
            let fee = payment_fee;
            let (input, _inputs_gamma) = Output::new_payment(&pkey, amount).unwrap();
            let (output, outputs_gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
            let missing = Hash::digest(&input);
            let tx = Transaction::new(&skey, &[input], &[output], &outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<TransactionError>().unwrap() {
                TransactionError::MissingInput(_tx_hash, hash) => {
                    assert_eq!(hash, missing);
                }
                _ => panic!(),
            }
        }

        //
        // TX hash is unique.
        // Claimed input in mempool.
        //
        {
            let fee = payment_fee;
            let (output, outputs_gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            let tx = Transaction::new(&skey, &inputs, &outputs, &outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&tx), tx.clone());

            // TX hash is unique.
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().expect("proper error") {
                NodeTransactionError::AlreadyExists(tx_hash) => {
                    assert_eq!(tx_hash, Hash::digest(&tx));
                }
                _ => panic!(),
            }

            // Claimed input in mempool.
            let tx2 = {
                let (output2, outputs2_gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
                Transaction::new(&skey, &inputs, &[output2], &outputs2_gamma, fee).unwrap()
            };
            let e = validate_transaction(&tx2, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<TransactionError>().expect("proper error") {
                TransactionError::MissingInput(_tx_hash, hash) => {
                    assert_eq!(hash, input_hashes[0]);
                }
                _ => panic!(),
            }

            mempool.prune(&input_hashes, &output_hashes);
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
            validate_transaction(&tx2, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Valid stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = stake_fee;
            let output =
                Output::new_stake(&pkey, &validator_pkey, &validator_skey, amount - fee).unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], &Fr::zero(), fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Zero or negative stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = payment_fee + stake_fee;
            let stake = 0;
            let (output1, gamma1) = Output::new_payment(&pkey, amount - stake - fee).unwrap();
            let mut output2 = StakeOutput::new(&pkey, &validator_pkey, &validator_skey, 1).unwrap();
            output2.amount = stake; // StakeOutput::new() doesn't allow zero amount.
            let output2 = Output::StakeOutput(output2);
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1;
            let tx = Transaction::unchecked(&skey, &inputs, &outputs, &outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<OutputError>().expect("proper error") {
                OutputError::InvalidStake(_output_hash) => {}
                _ => panic!(),
            }
        }

        //
        // Locked stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = payment_fee;
            let (output, outputs_gamma) = Output::new_payment(&pkey, stake - fee).unwrap();
            let tx =
                Transaction::unchecked(&skey, &stakes, &[output], &outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::StakeIsLocked(
                    validator_pkey2,
                    expected_balance,
                    active_balance,
                ) => {
                    assert_eq!(validator_pkey, &validator_pkey2);
                    assert_eq!(expected_balance, 0);
                    assert_eq!(active_balance, stake);
                }
                _ => panic!(),
            }
        }

        //
        // Re-stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let output =
                Output::new_stake(&pkey, &keychain.network_pkey, &keychain.network_skey, stake)
                    .unwrap();
            let tx = Transaction::unchecked(&skey, &stakes, &[output], &Fr::zero(), 0).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, 0)
                .expect("transaction is valid");
        }

        //
        // Output hash collision in mempool.
        //
        {
            let fee = payment_fee;
            let (output, outputs_gamma) = Output::new_payment(&pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            // Claim output in mempool.
            let claim_tx =
                Transaction::unchecked(&skey, &[], &outputs, &outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&claim_tx), claim_tx);

            let tx = Transaction::unchecked(&skey, &inputs, &outputs, &outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<TransactionError>().expect("proper error") {
                TransactionError::OutputHashCollision(_tx_hash, hash) => {
                    assert_eq!(hash, output_hashes[0]);
                }
                _ => panic!(),
            }

            mempool.prune(&[], &output_hashes);
        }
    }
}

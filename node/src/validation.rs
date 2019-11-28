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

use crate::error::*;
use crate::mempool::Mempool;
use failure::Error;
use stegos_blockchain::Timestamp;
use stegos_blockchain::{Blockchain, Output, Transaction, TransactionError};
use stegos_crypto::hash::Hash;

///
/// Validate transaction.
///
pub(crate) fn validate_external_transaction(
    tx: &Transaction,
    mempool: &Mempool,
    chain: &Blockchain,
    _timestamp: Timestamp,
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
    for txout in tx.txouts() {
        min_fee += match txout {
            Output::PaymentOutput(_o) => payment_fee,
            Output::PublicPaymentOutput(_o) => payment_fee,
            Output::StakeOutput(_o) => stake_fee,
        };
    }
    if tx.fee() < min_fee {
        return Err(NodeTransactionError::TooLowFee(tx_hash, min_fee, tx.fee()).into());
    }

    let mut inputs: Vec<Output> = Vec::new();

    // TODO: allow transaction with overlapping inputs/outputs in mempool.
    // See https://github.com/stegos/stegos/issues/826.

    // Check for overlapping inputs in mempool.
    for input_hash in tx.txins() {
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
    for output in tx.txouts() {
        let output_hash = Hash::digest(output);
        // Check that the output is unique and don't overlap with other transactions.
        if mempool.contains_output(&output_hash) || chain.contains_output(&output_hash) {
            return Err(TransactionError::OutputHashCollision(tx_hash, output_hash).into());
        }
        output.validate()?;
    }

    match tx {
        // Staking balance of cheater was already validated in tx.validate()
        Transaction::SlashingTransaction(_) => {}
        _ => chain.validate_stakes(inputs.iter(), tx.txouts().iter())?,
    }

    // Check the monetary balance, Bulletpoofs/amounts and signature.
    match tx {
        Transaction::RestakeTransaction(tx) => tx.validate(&inputs)?,
        Transaction::PaymentTransaction(tx) => tx.validate(&inputs)?,
        Transaction::SlashingTransaction(..)
        | Transaction::CoinbaseTransaction(..)
        | Transaction::ServiceAwardTransaction(..) => {
            return Err(TransactionError::ReceivedInvalidTransaction(tx.to_type_str()).into())
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;
    use stegos_blockchain::test::*;
    use stegos_blockchain::Timestamp;
    use stegos_blockchain::*;
    use stegos_crypto::scc::Fr;
    use tempdir::TempDir;

    #[test]
    fn test_validate_transaction() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let mut cfg: ChainConfig = Default::default();
        let payment_fee: i64 = 1;
        let stake_fee: i64 = 0;
        let amount: i64 = 10000;
        let stake: i64 = cfg.min_stake_amount;
        let stake_epochs = 1;
        cfg.stake_epochs = stake_epochs;
        let mut timestamp = Timestamp::now();
        let (mut keychains, genesis) = fake_genesis(
            stake,
            amount + stake,
            cfg.max_slot_count,
            1,
            timestamp,
            None,
        );
        let keychain = keychains.pop().unwrap();
        let (account_skey, account_pkey) = (keychain.account_skey, keychain.account_pkey);
        let (network_skey, network_pkey) = (keychain.network_skey, keychain.network_pkey);
        let mut mempool = Mempool::new();
        let chain_dir = TempDir::new("test").unwrap();
        let consistency_check = ConsistencyCheck::Full;
        let chain = Blockchain::new(cfg, chain_dir.path(), consistency_check, genesis, timestamp)
            .expect("Failed to create blockchain");
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

        //
        // Valid transaction.
        //
        {
            let fee = 2 * payment_fee;
            let (output1, gamma1) = Output::new_payment(&account_pkey, 1).unwrap();
            let (output2, gamma2) = Output::new_payment(&account_pkey, amount - fee - 1).unwrap();
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1 + gamma2;
            let tx = PaymentTransaction::new(&account_skey, &inputs, &outputs, &outputs_gamma, fee)
                .unwrap();
            validate_external_transaction(
                &tx.into(),
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect("transaction is valid");
        }

        //
        // Fee > expected.
        //
        {
            let fee = payment_fee + 1;
            let (output, gamma) = Output::new_payment(&account_pkey, amount - fee).unwrap();
            let tx = PaymentTransaction::new(&account_skey, &inputs, &[output], &gamma, fee)
                .unwrap()
                .into();
            validate_external_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Fee < expected.
        //
        {
            let fee = payment_fee - 1;
            let (output, gamma) = Output::new_payment(&account_pkey, amount - fee).unwrap();
            let tx = PaymentTransaction::unchecked(&account_skey, &inputs, &[output], &gamma, fee)
                .unwrap()
                .into();
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
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
            let (input, _inputs_gamma) = Output::new_payment(&account_pkey, amount).unwrap();
            let (output, outputs_gamma) = Output::new_payment(&account_pkey, amount - fee).unwrap();
            let missing = Hash::digest(&input);
            let tx =
                PaymentTransaction::new(&account_skey, &[input], &[output], &outputs_gamma, fee)
                    .unwrap()
                    .into();
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
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
            let (output, outputs_gamma) = Output::new_payment(&account_pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
            let tx: Transaction =
                PaymentTransaction::new(&account_skey, &inputs, &outputs, &outputs_gamma, fee)
                    .unwrap()
                    .into();
            mempool.push_tx(Hash::digest(&tx), tx.clone());

            // TX hash is unique.
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().expect("proper error") {
                NodeTransactionError::AlreadyExists(tx_hash) => {
                    assert_eq!(tx_hash, Hash::digest(&tx));
                }
                _ => panic!(),
            }

            // Claimed input in mempool.
            let tx2 = {
                let (output2, outputs2_gamma) =
                    Output::new_payment(&account_pkey, amount - fee).unwrap();
                PaymentTransaction::new(&account_skey, &inputs, &[output2], &outputs2_gamma, fee)
                    .unwrap()
                    .into()
            };
            let e = validate_external_transaction(
                &tx2,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect_err("transaction is not valid");
            match e.downcast::<TransactionError>().expect("proper error") {
                TransactionError::MissingInput(_tx_hash, hash) => {
                    assert_eq!(hash, input_hashes[0]);
                }
                _ => panic!(),
            }

            let input_hashes: Vec<Hash> = inputs.iter().map(Hash::digest).collect();
            let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
            mempool.prune(input_hashes.iter(), output_hashes.iter());
            validate_external_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
            validate_external_transaction(
                &tx2,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect("transaction is valid");
        }

        //
        // Valid stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = stake_fee;
            let output =
                Output::new_stake(&account_pkey, &network_skey, &network_pkey, amount - fee)
                    .unwrap();
            let tx = PaymentTransaction::new(&account_skey, &inputs, &[output], &Fr::zero(), fee)
                .unwrap()
                .into();
            validate_external_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Zero or negative stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = payment_fee + stake_fee;
            let stake = 0;
            let (output1, gamma1) =
                Output::new_payment(&account_pkey, amount - stake - fee).unwrap();
            let mut output2 =
                StakeOutput::new(&account_pkey, &network_skey, &network_pkey, 1).unwrap();
            output2.amount = stake; // StakeOutput::new() doesn't allow zero amount.
            let output2 = Output::StakeOutput(output2);
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1;
            let tx = PaymentTransaction::unchecked(
                &account_skey,
                &inputs,
                &outputs,
                &outputs_gamma,
                fee,
            )
            .unwrap()
            .into();
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::OutputError(OutputError::InvalidAmount(_output_hash, _)) => {}
                _ => panic!(),
            }
        }

        //
        // Locked stake.
        //
        {
            timestamp += Duration::from_millis(1);
            let fee = payment_fee;
            let (output, outputs_gamma) = Output::new_payment(&account_pkey, stake - fee).unwrap();
            let tx = PaymentTransaction::unchecked(
                &account_skey,
                &stakes,
                &[output],
                &outputs_gamma,
                fee,
            )
            .unwrap()
            .into();
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::StakeIsLocked(
                    validator_pkey2,
                    expected_balance,
                    active_balance,
                ) => {
                    assert_eq!(network_pkey, validator_pkey2);
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
                Output::new_stake(&account_pkey, &network_skey, &network_pkey, stake).unwrap();
            let tx =
                PaymentTransaction::unchecked(&account_skey, &stakes, &[output], &Fr::zero(), 0)
                    .unwrap()
                    .into();
            validate_external_transaction(&tx, &mempool, &chain, timestamp, payment_fee, 0)
                .expect("transaction is valid");
        }

        //
        // Output hash collision in mempool.
        //
        {
            let fee = payment_fee;
            let (output, outputs_gamma) = Output::new_payment(&account_pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            // Claim output in mempool.
            let claim_tx =
                PaymentTransaction::unchecked(&account_skey, &[], &outputs, &outputs_gamma, fee)
                    .unwrap()
                    .into();
            mempool.push_tx(Hash::digest(&claim_tx), claim_tx);
            let tx = PaymentTransaction::unchecked(
                &account_skey,
                &inputs,
                &outputs,
                &outputs_gamma,
                fee,
            )
            .unwrap()
            .into();
            let e = validate_external_transaction(
                &tx,
                &mempool,
                &chain,
                timestamp,
                payment_fee,
                stake_fee,
            )
            .expect_err("transaction is not valid");
            match e.downcast::<TransactionError>().expect("proper error") {
                TransactionError::OutputHashCollision(_tx_hash, hash) => {
                    assert_eq!(hash, output_hashes[0]);
                }
                _ => panic!(),
            }

            let input_hashes: Vec<Hash> = vec![];
            let output_hashes: Vec<Hash> = outputs.iter().map(Hash::digest).collect();
            mempool.prune(input_hashes.iter(), output_hashes.iter());
        }
    }
}

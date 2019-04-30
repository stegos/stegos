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
use stegos_blockchain::Blockchain;
use stegos_blockchain::KeyBlock;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
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
    //
    // Validation checklist:
    //
    // - TX hash is unique
    // - Fee is acceptable.
    // - At least one input or output is present.
    // - Inputs can be resolved.
    // - Inputs have not been spent by blocks.
    // - Inputs are not claimed by other transactions in mempool.
    // - Inputs are unique.
    // - Outputs are unique.
    // - Outputs don't overlap with other transactions in mempool.
    // - Bulletpoofs/amounts are valid.
    // - UTXO-specific checks.
    // - Monetary balance is valid.
    // - Signature is valid.
    //

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
            Output::StakeOutput(_o) => stake_fee,
        };
    }
    if tx.body.fee < min_fee {
        return Err(NodeTransactionError::TooLowFee(tx_hash, min_fee, tx.body.fee).into());
    }

    // Validate inputs.
    let mut inputs: Vec<Output> = Vec::new();
    for input_hash in &tx.body.txins {
        // Check that the input can be resolved.
        // TODO: check outputs created by mempool transactions.
        let input = match chain.output_by_hash(input_hash)? {
            Some(input) => input,
            None => {
                return Err(NodeTransactionError::MissingInput(tx_hash, input_hash.clone()).into());
            }
        };

        // Check that the input is not claimed by other transactions.
        if mempool.contains_input(input_hash) {
            return Err(NodeTransactionError::MissingInput(tx_hash, input_hash.clone()).into());
        }

        // Check escrow.
        if let Output::StakeOutput(ref input) = input {
            chain.validate_unstake(&input.validator, input_hash)?;
        }

        inputs.push(input);
    }

    // Check outputs.
    for output in &tx.body.txouts {
        let output_hash = Hash::digest(output);

        // Check that the output is unique and don't overlap with other transactions.
        if mempool.contains_output(&output_hash) || chain.contains_output(&output_hash) {
            return Err(NodeTransactionError::OutputHashCollision(tx_hash, output_hash).into());
        }
    }

    // Check the monetary balance, Bulletpoofs/amounts and signature.
    tx.validate(&inputs)?;

    Ok(())
}

fn vetted_timestamp(
    block: &KeyBlock,
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

        if duration > cfg.key_block_timeout {
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
/// Validate proposed key block.
///
pub(crate) fn validate_proposed_key_block(
    cfg: &ChainConfig,
    chain: &Blockchain,
    view_change: u32,
    block_hash: Hash,
    block: &KeyBlock,
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
    vetted_timestamp(block, cfg, chain.last_key_block_timestamp())?;
    chain.validate_key_block(block, true)?;

    debug!("Key block proposal is valid: block={:?}", block_hash);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VERSION;
    use std::time::SystemTime;
    use stegos_blockchain::*;
    use stegos_crypto::pbc::secure;
    use stegos_crypto::CryptoError;
    use stegos_keychain::KeyChain;

    #[test]
    fn test_validate_transaction() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let payment_fee: i64 = 1;
        let stake_fee: i64 = 1;
        let amount: i64 = 10000;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let keychain = KeyChain::new_mem();
        let mut mempool = Mempool::new();
        let cfg: BlockchainConfig = Default::default();
        let stake_epochs = cfg.stake_epochs;
        let stake: i64 = cfg.min_stake_amount;
        let genesis = genesis(&[keychain.clone()], stake, amount + stake, timestamp);
        let mut chain =
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
            let (output1, gamma1) = Output::new_payment(timestamp, &skey, &pkey, 1).unwrap();
            let (output2, gamma2) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee - 1).unwrap();
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1 + gamma2;
            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Fee > expected.
        //
        {
            let fee = payment_fee + 1;
            let (output, gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Fee < expected.
        //
        {
            let fee = payment_fee - 1;
            let (output, gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
            let tx = Transaction::unchecked(&skey, &inputs, &[output], gamma, fee).unwrap();
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
            let (input, _inputs_gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount).unwrap();
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
            let missing = Hash::digest(&input);
            let tx = Transaction::new(&skey, &[input], &[output], outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().unwrap() {
                NodeTransactionError::MissingInput(_tx_hash, hash) => {
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
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
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
                let (output2, outputs2_gamma) =
                    Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
                Transaction::new(&skey, &inputs, &[output2], outputs2_gamma, fee).unwrap()
            };
            let e = validate_transaction(&tx2, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().expect("proper error") {
                NodeTransactionError::MissingInput(_tx_hash, hash) => {
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
            let fee = stake_fee;
            let (output, gamma) = Output::new_stake(
                timestamp,
                &skey,
                &pkey,
                &validator_pkey,
                &validator_skey,
                amount - fee,
            )
            .unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Zero or negative stake.
        //
        {
            let fee = payment_fee + stake_fee;
            let stake = 0;
            let (output1, gamma1) =
                Output::new_payment(timestamp, &skey, &pkey, amount - stake - fee).unwrap();
            let (mut output2, _gamma) =
                StakeOutput::new(timestamp, &skey, &pkey, &validator_pkey, &validator_skey, 1)
                    .unwrap();
            output2.amount = stake; // StakeOutput::new() doesn't allow zero amount.
            let output2 = Output::StakeOutput(output2);
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1;
            let tx = Transaction::unchecked(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<CryptoError>().expect("proper error") {
                CryptoError::BadKeyingSignature => {}
                _ => panic!(),
            }
        }

        //
        // Locked stake.
        //
        {
            let fee = payment_fee;
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey, &pkey, stake - fee).unwrap();
            let tx = Transaction::unchecked(&skey, &stakes, &[output], outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<OutputError>().expect("proper error") {
                OutputError::StakeIsActive(
                    input_hash,
                    validator_pkey2,
                    valid_until_epoch,
                    epoch2,
                ) => {
                    assert_eq!(input_hash, Hash::digest(&stakes[0]));
                    assert_eq!(validator_pkey, &validator_pkey2);
                    assert_eq!(valid_until_epoch, stake_epochs);
                    assert_eq!(epoch2, chain.epoch());
                }
                _ => panic!(),
            }
            // Create a new epoch to unlock stakes.
            let key_block = create_fake_key_block(&chain, &[keychain.clone()], timestamp);
            chain.push_key_block(key_block).expect("Invalid key block");
            validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect("transaction is valid");
        }

        //
        // Output hash collision in mempool.
        //
        {
            let fee = payment_fee;
            let (output, outputs_gamma) =
                Output::new_payment(timestamp, &skey, &pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            // Claim output in mempool.
            let claim_tx =
                Transaction::unchecked(&skey, &[], &outputs, outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&claim_tx), claim_tx);

            let tx = Transaction::unchecked(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().expect("proper error") {
                NodeTransactionError::OutputHashCollision(_tx_hash, hash) => {
                    assert_eq!(hash, output_hashes[0]);
                }
                _ => panic!(),
            }

            mempool.prune(&[], &output_hashes);
        }

        //
        // Output hash collision in blockchain.
        //
        {
            // Register one more UTXO.
            let fee = payment_fee;
            let previous = chain.last_block_hash();
            let height = chain.height();
            let version = VERSION;
            let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
            let (output, outputs_gamma) = Output::new_payment(timestamp, skey, pkey, amount - fee)
                .expect("genesis has valid public keys");
            let outputs = vec![output.clone()];
            let gamma = -outputs_gamma;
            let mut block = MicroBlock::new(base, gamma, amount - fee, &[], &outputs, None);
            let block_hash = Hash::digest(&block);
            block.body.sig = secure::sign_hash(&block_hash, &validator_skey);

            chain
                .push_micro_block(block, timestamp)
                .expect("block is valid");

            let tx = Transaction::unchecked(&skey, &inputs, &[output.clone()], outputs_gamma, fee)
                .unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, timestamp, payment_fee, stake_fee)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeTransactionError>().expect("proper error") {
                NodeTransactionError::OutputHashCollision(_tx_hash, hash) => {
                    assert_eq!(hash, Hash::digest(&output));
                }
                _ => panic!(),
            }
        }
    }
}

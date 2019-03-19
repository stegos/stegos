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
use crate::PAYMENT_FEE;
use crate::STAKE_FEE;
use chrono::Utc;
use failure::ensure;
use failure::Error;
use log::*;
use stegos_blockchain::Blockchain;
use stegos_blockchain::BlockchainError;
use stegos_blockchain::KeyBlock;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
use stegos_consensus::BlockConsensus;
use stegos_crypto::hash::Hash;

///
/// Validate transaction.
///
pub(crate) fn validate_transaction(
    tx: &Transaction,
    mempool: &Mempool,
    chain: &Blockchain,
    current_timestamp: u64,
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
        return Err(NodeError::TransactionAlreadyExists(tx_hash).into());
    }

    // Check fee.
    let mut min_fee: i64 = 0;
    for txout in &tx.body.txouts {
        min_fee += match txout {
            Output::PaymentOutput(_o) => PAYMENT_FEE,
            Output::StakeOutput(_o) => STAKE_FEE,
        };
    }
    if tx.body.fee < min_fee {
        return Err(NodeError::TooLowFee(min_fee, tx.body.fee).into());
    }

    // Validate inputs.
    let mut inputs: Vec<Output> = Vec::new();
    for input_hash in &tx.body.txins {
        // Check that the input can be resolved.
        // TODO: check outputs created by mempool transactions.
        let input = chain.output_by_hash(input_hash)?;

        // Check that the input is not claimed by other transactions.
        if mempool.contains_input(input_hash) {
            return Err(BlockchainError::MissingUTXO(input_hash.clone()).into());
        }

        // Check escrow.
        if let Output::StakeOutput(ref input) = input {
            chain
                .escrow()
                .validate_unstake(&input.validator, input_hash, current_timestamp)?;
        }

        inputs.push(input);
    }

    // Check outputs.
    for output in &tx.body.txouts {
        let output_hash = Hash::digest(output);

        // Check that the output is unique and don't overlap with other transactions.
        if mempool.contains_output(&output_hash) || chain.contains_output(&output_hash) {
            return Err(BlockchainError::OutputHashCollision(output_hash).into());
        }
    }

    // Check the monetary balance, Bulletpoofs/amounts and signature.
    tx.validate(&inputs)?;

    Ok(())
}

///
/// Validate proposed key block.
///
pub(crate) fn validate_proposed_key_block(
    chain: &Blockchain,
    consensus: &BlockConsensus,
    block_hash: Hash,
    block: &KeyBlock,
) -> Result<(), Error> {
    debug_assert_eq!(&Hash::digest(block), &block_hash);

    let timestamp = Utc::now().timestamp() as u64;
    if block.header.base.timestamp.saturating_sub(timestamp) > crate::TIME_TO_RECEIVE_BLOCK
        || timestamp.saturating_sub(block.header.base.timestamp) > crate::TIME_TO_RECEIVE_BLOCK
    {
        return Err(NodeError::UnsynchronizedBlock(block.header.base.timestamp, timestamp).into());
    }

    ensure!(
        block.header.leader == consensus.leader(),
        "Consensus leader different from our consensus group."
    );
    ensure!(
        block.header.validators.len() == consensus.validators().len(),
        "Received key block proposal with wrong consensus group"
    );

    for validator in &block.header.validators {
        ensure!(
            consensus.validators().contains_key(validator),
            "Received Key block proposal with wrong consensus group."
        );
    }

    chain.validate_key_block(block, true)?;

    debug!("Key block proposal is valid: block={:?}", block_hash);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VERSION;
    use chrono::Utc;
    use stegos_blockchain::*;
    use stegos_crypto::curve1174::fields::Fr;
    use stegos_keychain::KeyChain;

    #[test]
    fn test_validate_transaction() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let stake: i64 = MIN_STAKE_AMOUNT;
        let amount: i64 = 10000;
        let current_timestamp = Utc::now().timestamp() as u64;
        let keychain = KeyChain::new_mem();
        let mut mempool = Mempool::new();
        let genesis = genesis(
            &[keychain.clone()],
            stake,
            amount + stake,
            current_timestamp,
        );
        let mut chain = Blockchain::testing(genesis, current_timestamp);
        let mut inputs: Vec<Output> = Vec::new();
        let mut stakes: Vec<Output> = Vec::new();
        for output_hash in chain.unspent() {
            let output = chain
                .output_by_hash(&output_hash)
                .expect("exists and no disk errors");
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
            let fee = 2 * PAYMENT_FEE;
            let (output1, gamma1) =
                Output::new_payment(current_timestamp, &skey, &pkey, 1).unwrap();
            let (output2, gamma2) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee - 1).unwrap();
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1 + gamma2;
            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect("transaction is valid");
        }

        //
        // Fee > expected.
        //
        {
            let fee = PAYMENT_FEE + 1;
            let (output, gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], gamma, fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect("transaction is valid");
        }

        //
        // Fee < expected.
        //
        {
            let fee = PAYMENT_FEE - 1;
            let (output, gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
            let tx = Transaction::unchecked(&skey, &inputs, &[output], gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeError>().unwrap() {
                NodeError::TooLowFee(min, got) => {
                    assert_eq!(min, PAYMENT_FEE);
                    assert_eq!(got, fee);
                }
                _ => panic!(),
            }
        }

        //
        // Missing or spent input in blockchain.
        //
        {
            let fee = PAYMENT_FEE;
            let (input, _inputs_gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount).unwrap();
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
            let missing = Hash::digest(&input);
            let tx = Transaction::new(&skey, &[input], &[output], outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().unwrap() {
                BlockchainError::MissingUTXO(hash) => {
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
            let fee = PAYMENT_FEE;
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let input_hashes: Vec<Hash> = inputs.iter().map(|o| Hash::digest(o)).collect();
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&tx), tx.clone());

            // TX hash is unique.
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<NodeError>().expect("proper error") {
                NodeError::TransactionAlreadyExists(tx_hash) => {
                    assert_eq!(tx_hash, Hash::digest(&tx));
                }
                _ => panic!(),
            }

            // Claimed input in mempool.
            let tx2 = {
                let (output2, outputs2_gamma) =
                    Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
                Transaction::new(&skey, &inputs, &[output2], outputs2_gamma, fee).unwrap()
            };
            let e = validate_transaction(&tx2, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::MissingUTXO(hash) => {
                    assert_eq!(hash, input_hashes[0]);
                }
                _ => panic!(),
            }

            mempool.prune(&input_hashes, &output_hashes);
            validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect("transaction is valid");
            validate_transaction(&tx2, &mempool, &chain, current_timestamp)
                .expect("transaction is valid");
        }

        //
        // Valid stake.
        //
        {
            let fee = STAKE_FEE;
            let output = Output::new_stake(
                current_timestamp,
                &skey,
                &pkey,
                &validator_pkey,
                amount - fee,
            )
            .unwrap();
            let tx = Transaction::new(&skey, &inputs, &[output], Fr::zero(), fee).unwrap();
            validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect("transaction is valid");
        }

        //
        // Zero or negative stake.
        //
        {
            let fee = PAYMENT_FEE + STAKE_FEE;
            let stake = 0;
            let (output1, gamma1) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - stake - fee).unwrap();
            let mut output2 =
                StakeOutput::new(current_timestamp, &skey, &pkey, &validator_pkey, 1).unwrap();
            output2.amount = stake; // StakeOutput::new() doesn't allow zero amount.
            let output2 = Output::StakeOutput(output2);
            let outputs: Vec<Output> = vec![output1, output2];
            let outputs_gamma = gamma1;
            let tx = Transaction::unchecked(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<OutputError>().expect("proper error") {
                OutputError::InvalidStake => {}
                _ => panic!(),
            }
        }

        //
        // Locked stake.
        //
        {
            let fee = PAYMENT_FEE;
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, stake - fee).unwrap();
            let tx = Transaction::unchecked(&skey, &stakes, &[output], outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<EscrowError>().expect("proper error") {
                EscrowError::StakeIsLocked(
                    validator_pkey2,
                    input_hash,
                    bonding_timestamp,
                    current_timestamp2,
                ) => {
                    assert_eq!(input_hash, Hash::digest(&stakes[0]));
                    assert_eq!(validator_pkey, &validator_pkey2);
                    assert_eq!(bonding_timestamp, current_timestamp + BONDING_TIME);
                    assert_eq!(current_timestamp2, current_timestamp);
                }
            }
            validate_transaction(&tx, &mempool, &chain, current_timestamp + BONDING_TIME + 1)
                .expect("transaction is valid");
        }

        //
        // Output hash collision in mempool.
        //
        {
            let fee = PAYMENT_FEE;
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, &skey, &pkey, amount - fee).unwrap();
            let outputs: Vec<Output> = vec![output];
            let output_hashes: Vec<Hash> = outputs.iter().map(|o| Hash::digest(o)).collect();
            // Claim output in mempool.
            let claim_tx =
                Transaction::unchecked(&skey, &[], &outputs, outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&claim_tx), claim_tx);

            let tx = Transaction::unchecked(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::OutputHashCollision(hash) => {
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
            let fee = PAYMENT_FEE;
            let previous = chain.last_block_hash();
            let epoch = chain.epoch();
            let version = VERSION;
            let base = BaseBlockHeader::new(version, previous, epoch, current_timestamp);
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, skey, pkey, amount - fee)
                    .expect("genesis has valid public keys");
            let outputs = vec![output.clone()];
            let gamma = -outputs_gamma;
            let mut block = MonetaryBlock::new(base, gamma, amount - fee, &[], &outputs);
            let block_hash = Hash::digest(&block);
            let (multisig, multisigmap) = create_proposal_signature(
                &block_hash,
                &validator_skey,
                &validator_pkey,
                &chain.validators(),
            );
            block.header.base.multisig = multisig;
            block.header.base.multisigmap = multisigmap;

            chain
                .push_monetary_block(block, current_timestamp)
                .expect("block is valid");

            let tx = Transaction::unchecked(&skey, &inputs, &[output.clone()], outputs_gamma, fee)
                .unwrap();
            let e = validate_transaction(&tx, &mempool, &chain, current_timestamp)
                .expect_err("transaction is not valid");
            match e.downcast::<BlockchainError>().expect("proper error") {
                BlockchainError::OutputHashCollision(hash) => {
                    assert_eq!(hash, Hash::digest(&output));
                }
                _ => panic!(),
            }
        }
    }
}

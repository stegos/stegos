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
use crate::BLOCK_REWARD;
use crate::PAYMENT_FEE;
use crate::STAKE_FEE;
use failure::ensure;
use failure::Error;
use log::*;
use std::collections::BTreeSet;
use stegos_blockchain::Blockchain;
use stegos_blockchain::BlockchainError;
use stegos_blockchain::KeyBlock;
use stegos_blockchain::MonetaryBlock;
use stegos_blockchain::Output;
use stegos_blockchain::OutputError;
use stegos_blockchain::Transaction;
use stegos_blockchain::TransactionError;
use stegos_consensus::check_multi_signature;
use stegos_consensus::BlockConsensus;
use stegos_crypto::bulletproofs::validate_range_proof;
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
        let input = match chain.output_by_hash(input_hash) {
            Some(tx_input) => tx_input,
            None => return Err(BlockchainError::MissingUTXO(input_hash.clone()).into()),
        };

        // Check that the input is not claimed by other transactions.
        if mempool.contains_input(input_hash) {
            return Err(BlockchainError::MissingUTXO(input_hash.clone()).into());
        }

        // Check escrow.
        if let Output::StakeOutput(input) = input {
            chain
                .escrow
                .validate_unstake(&input.validator, input_hash, current_timestamp)?;
        }

        inputs.push(input.clone());
    }

    // Check outputs.
    for output in &tx.body.txouts {
        let output_hash = Hash::digest(output);

        // Check that the output is unique and don't overlap with other transactions.
        if mempool.contains_output(&output_hash) || chain.output_by_hash(&output_hash).is_some() {
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
    consensus: &BlockConsensus,
    block_hash: Hash,
    block: &KeyBlock,
) -> Result<(), Error> {
    block.validate()?;
    ensure!(
        block.header.leader == consensus.leader(),
        "Consensus leader different from our consensus group."
    );
    ensure!(
        block.header.witnesses.len() == consensus.validators().len(),
        "Received key block proposal with wrong consensus group"
    );

    for validator in &block.header.witnesses {
        ensure!(
            consensus.validators().contains_key(validator),
            "Received Key block proposal with wrong consensus group."
        );
    }
    debug!("Key block proposal is valid: block={}", block_hash);
    Ok(())
}

///
/// Validate sealed key block.
///
pub(crate) fn validate_sealed_key_block(
    key_block: &KeyBlock,
    chain: &Blockchain,
) -> Result<(), Error> {
    let block_hash = Hash::digest(&key_block);

    // Check epoch.
    if key_block.header.base.epoch != chain.epoch + 1 {
        return Err(NodeError::OutOfOrderBlockEpoch(
            block_hash,
            chain.epoch + 1,
            key_block.header.base.epoch,
        )
        .into());
    }

    let leader = key_block.header.leader.clone();
    let validators = chain.escrow.multiget(&key_block.header.witnesses);
    // We didn't allows fork, this is done by forcing group to be the same as stakers count.
    let stakers = chain.escrow.get_stakers_majority();
    if stakers != validators {
        return Err(NodeError::ValidatorsNotEqualToOurStakers.into());
    }
    // Check BLS multi-signature.
    if !check_multi_signature(
        &block_hash,
        &key_block.header.base.multisig,
        &key_block.header.base.multisigmap,
        &validators,
        &leader,
    ) {
        return Err(NodeError::InvalidBlockSignature(block_hash).into());
    }

    key_block.validate()?;

    Ok(())
}

///
/// Validate proposed monetary block.
///
pub(crate) fn validate_proposed_monetary_block(
    mempool: &Mempool,
    chain: &Blockchain,
    block_hash: Hash,
    block: &MonetaryBlock,
    fee_output: &Option<Output>,
    tx_hashes: &Vec<Hash>,
) -> Result<(), Error> {
    if block.header.monetary_adjustment != BLOCK_REWARD {
        // TODO: support slashing.
        return Err(NodeError::InvalidBlockReward(
            block_hash,
            block.header.monetary_adjustment,
            BLOCK_REWARD,
        )
        .into());
    }

    // Check transactions.
    let mut inputs = Vec::<Output>::new();
    let mut inputs_hashes = BTreeSet::<Hash>::new();
    let mut outputs = Vec::<Output>::new();
    let mut outputs_hashes = BTreeSet::<Hash>::new();
    for tx_hash in tx_hashes {
        debug!("Processing transaction: hash={}", &tx_hash);

        // Check that transaction is present in mempool.
        let tx = mempool.get_tx(&tx_hash);
        if tx.is_none() {
            return Err(NodeError::TransactionMissingInMempool(*tx_hash).into());
        }

        let tx = tx.unwrap();

        // Check that transaction's inputs are exists.
        let tx_inputs = chain
            .outputs_by_hashes(&tx.body.txins)
            .expect("mempool transaction is valid");

        // Check transaction's signature, monetary balance, fee and others.
        tx.validate(&tx_inputs)
            .expect("mempool transaction is valid");

        // Check that transaction's inputs are not used yet.
        for tx_input_hash in &tx.body.txins {
            if !inputs_hashes.insert(tx_input_hash.clone()) {
                return Err(TransactionError::DuplicateInput(
                    tx_hash.clone(),
                    tx_input_hash.clone(),
                )
                .into());
            }
        }

        // Check transaction's outputs.
        for tx_output in &tx.body.txouts {
            let tx_output_hash = Hash::digest(tx_output);
            if let Some(_) = chain.output_by_hash(&tx_output_hash) {
                return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
            }
            if !outputs_hashes.insert(tx_output_hash.clone()) {
                return Err(
                    TransactionError::DuplicateOutput(tx_hash.clone(), tx_output_hash).into(),
                );
            }
        }

        inputs.extend(tx_inputs.iter().cloned());
        outputs.extend(tx.body.txouts.iter().cloned());
    }

    if let Some(output_fee) = fee_output {
        let tx_output_hash = Hash::digest(output_fee);
        if let Some(_) = chain.output_by_hash(&tx_output_hash) {
            return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
        }
        if !outputs_hashes.insert(tx_output_hash.clone()) {
            return Err(BlockchainError::OutputHashCollision(tx_output_hash).into());
        }
        match &output_fee {
            Output::PaymentOutput(o) => {
                // Check bulletproofs of created outputs
                if !validate_range_proof(&o.proof) {
                    return Err(OutputError::InvalidBulletProof.into());
                }
            }
            _ => {
                return Err(NodeError::InvalidFeeUTXO(tx_output_hash).into());
            }
        };
        outputs.push(output_fee.clone());
    }

    drop(outputs_hashes);

    debug!("Validating monetary block");

    let inputs_hashes: Vec<Hash> = inputs_hashes.into_iter().collect();

    let base_header = block.header.base.clone();
    let block = MonetaryBlock::new(
        base_header,
        block.header.gamma.clone(),
        block.header.monetary_adjustment,
        &inputs_hashes,
        &outputs,
    );
    let inputs = chain
        .outputs_by_hashes(&block.body.inputs)
        .expect("check above");
    block.validate(&inputs)?;

    // TODO: block hash doesn't cover inputs and outputs
    let block_hash2 = Hash::digest(&block);

    if block_hash != block_hash2 {
        return Err(NodeError::InvalidBlockHash(block_hash, block_hash2).into());
    }

    debug!("Block proposal is valid: block={}", block_hash);

    Ok(())
}

/// Handle incomingelf.escrow.get(&key).expect MonetaryBlock
pub(crate) fn validate_sealed_monetary_block(
    monetary_block: &MonetaryBlock,
    chain: &Blockchain,
    current_timestamp: u64,
) -> Result<(), Error> {
    let block_hash = Hash::digest(&monetary_block);

    // Check epoch.
    if monetary_block.header.base.epoch != chain.epoch {
        return Err(NodeError::OutOfOrderBlockEpoch(
            block_hash,
            chain.epoch,
            monetary_block.header.base.epoch,
        )
        .into());
    }

    // Check BLS multi-signature.
    if !check_multi_signature(
        &block_hash,
        &monetary_block.header.base.multisig,
        &monetary_block.header.base.multisigmap,
        &chain.validators,
        &chain.leader,
    ) {
        return Err(NodeError::InvalidBlockSignature(block_hash).into());
    }

    trace!("Validating block monetary balance: hash={}..", &block_hash);

    // Resolve inputs.
    let inputs = chain.outputs_by_hashes(&monetary_block.body.inputs)?;

    // Validate inputs.
    for input in inputs.iter() {
        // Check unstaking.
        if let Output::StakeOutput(input) = input {
            let input_hash = Hash::digest(input);
            chain
                .escrow
                .validate_unstake(&input.validator, &input_hash, current_timestamp)?;
        }
    }

    // Validate monetary balance.
    monetary_block.validate(&inputs)?;

    info!("Monetary block is valid: hash={}", &block_hash);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Utc;
    use stegos_blockchain::*;
    use stegos_crypto::curve1174::fields::Fr;
    use stegos_keychain::KeyChain;

    #[test]
    fn test_validate_transaction() {
        let stake: i64 = 100;
        let amount: i64 = 1000;
        let current_timestamp = Utc::now().timestamp() as u64;
        let keychain = KeyChain::new_mem();
        let mut mempool = Mempool::new();
        let mut chain = Blockchain::testing();
        for block in genesis(
            &[keychain.clone()],
            stake,
            amount + stake,
            current_timestamp,
        ) {
            match block {
                Block::KeyBlock(key_block) => {
                    chain.register_key_block(key_block).unwrap();
                }
                Block::MonetaryBlock(monetary_block) => {
                    chain
                        .register_monetary_block(monetary_block, current_timestamp)
                        .unwrap();
                }
            }
        }
        let mut inputs: Vec<Output> = Vec::new();
        let mut stakes: Vec<Output> = Vec::new();
        for output in chain.outputs_by_hashes(&chain.unspent()).unwrap() {
            match output {
                Output::PaymentOutput(ref _o) => inputs.push(output),
                Output::StakeOutput(ref _o) => stakes.push(output),
            }
        }

        let skey = &keychain.wallet_skey;
        let pkey = &keychain.wallet_pkey;
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
            let tx = Transaction::new(&skey, &inputs, &[output], gamma, fee).unwrap();
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
            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
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
            let tx = Transaction::new(&skey, &stakes, &[output], outputs_gamma, fee).unwrap();
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
            let claim_tx = Transaction::new(&skey, &[], &outputs, outputs_gamma, fee).unwrap();
            mempool.push_tx(Hash::digest(&claim_tx), claim_tx);

            let tx = Transaction::new(&skey, &inputs, &outputs, outputs_gamma, fee).unwrap();
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
            let last_block = chain.last_block();
            let previous = Hash::digest(last_block);
            let epoch = last_block.base_header().epoch;
            let version = last_block.base_header().version;
            let base = BaseBlockHeader::new(version, previous, epoch, current_timestamp);
            let (output, outputs_gamma) =
                Output::new_payment(current_timestamp, skey, pkey, amount - fee)
                    .expect("genesis has valid public keys");
            let outputs = vec![output.clone()];
            let gamma = -outputs_gamma;
            let block = MonetaryBlock::new(base, gamma, amount - fee, &[], &outputs);
            chain
                .register_monetary_block(block, current_timestamp)
                .expect("block is valid");

            let tx =
                Transaction::new(&skey, &inputs, &[output.clone()], outputs_gamma, fee).unwrap();
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

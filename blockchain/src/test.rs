//! Tests.

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

#![allow(dead_code)]

use crate::block::{MacroBlock, MicroBlock};
use crate::blockchain::Blockchain;
use crate::election::mix;
use crate::multisignature::create_multi_signature;
use crate::output::{Output, PaymentOutput, PaymentPayloadData, StakeOutput};
use crate::timestamp::Timestamp;
use crate::transaction::{
    CoinbaseTransaction, PaymentTransaction, RestakeTransaction, Transaction,
};
use bitvector::BitVector;
use log::*;
use std::collections::btree_map::BTreeMap;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::{self, Fr};

#[derive(Clone, Debug)]
pub struct KeyChain {
    /// Wallet Secret Key.
    pub wallet_skey: scc::SecretKey,
    /// Wallet Public Key.
    pub wallet_pkey: scc::PublicKey,
    /// Network Secret Key.
    pub network_skey: pbc::SecretKey,
    /// Network Public Key.
    pub network_pkey: pbc::PublicKey,
}

impl KeyChain {
    pub fn new() -> Self {
        let (wallet_skey, wallet_pkey) = scc::make_random_keys();
        let (network_skey, network_pkey) = pbc::make_random_keys();
        Self {
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
        }
    }
}

pub fn fake_genesis(
    stake: i64,
    coins: i64,
    num_nodes: usize,
    timestamp: Timestamp,
) -> (Vec<KeyChain>, MacroBlock) {
    let mut keychains = Vec::with_capacity(num_nodes);
    let mut outputs: Vec<Output> = Vec::with_capacity(1 + keychains.len());
    let mut payout = coins;
    for _i in 0..num_nodes {
        // Generate keys.
        let keychain = KeyChain::new();

        // Create a stake.
        let output = StakeOutput::new(
            &keychain.wallet_pkey,
            &keychain.network_skey,
            &keychain.network_pkey,
            stake,
        )
        .expect("invalid keys");
        assert!(payout >= stake);
        payout -= stake;
        outputs.push(output.into());

        keychains.push(keychain);
    }

    // Create an initial payment.
    assert!(payout > 0);
    let (output, outputs_gamma) =
        PaymentOutput::new(&keychains[0].wallet_pkey, payout).expect("invalid keys");
    outputs.push(output.into());

    // Calculate initial values.
    let epoch: u64 = 0;
    let view_change: u32 = 0;
    let previous = Hash::digest("genesis");
    let seed = Hash::digest("genesis");
    let random = pbc::make_VRF(&keychains[0].network_skey, &seed);
    let activity_map = BitVector::ones(keychains.len());

    // Create a block.
    let genesis = MacroBlock::new(
        previous,
        epoch,
        view_change,
        keychains[0].network_pkey.clone(),
        random,
        timestamp,
        coins,
        activity_map,
        -outputs_gamma,
        &[],
        &outputs,
    );

    (keychains, genesis)
}

pub fn sign_fake_macro_block(block: &mut MacroBlock, chain: &Blockchain, keychains: &[KeyChain]) {
    let block_hash = Hash::digest(block);
    let validators = chain.validators();
    let mut signatures: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
    for keychain in keychains {
        let sig = pbc::sign_hash(&block_hash, &keychain.network_skey);
        signatures.insert(keychain.network_pkey.clone(), sig);
    }
    let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
    block.multisig = multisig;
    block.multisigmap = multisigmap;
}

pub fn create_fake_macro_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: Timestamp,
) -> (MacroBlock, Vec<Transaction>) {
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let keys = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let (mut block, extra_transactions) = chain.create_macro_block(
        view_change,
        &keys.wallet_pkey,
        &keys.network_skey,
        keys.network_pkey,
        timestamp,
    );
    sign_fake_macro_block(&mut block, chain, keychains);
    (block, extra_transactions)
}

pub fn create_fake_micro_block(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: Timestamp,
) -> (MicroBlock, Vec<Hash>, Vec<Hash>) {
    let epoch = chain.epoch();
    let offset = chain.offset();
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let leader = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let previous = chain.last_block_hash().clone();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&leader.network_skey, &seed);
    let block_reward = chain.cfg().block_reward;
    let block_fee: i64 = 0;
    let mut transactions: Vec<Transaction> = Vec::new();

    //
    // Create coinbase transaction.
    //
    let coinbase_tx = {
        let data = PaymentPayloadData::Comment(format!("Block reward"));
        let (output, gamma, _rvalue) =
            PaymentOutput::with_payload(None, &leader.wallet_pkey, block_reward, data, None)
                .expect("invalid keys");
        CoinbaseTransaction {
            block_reward,
            block_fee,
            gamma: -gamma,
            txouts: vec![Output::PaymentOutput(output)],
        }
    };
    coinbase_tx.validate().expect("Invalid transaction");
    transactions.push(coinbase_tx.into());

    //
    // Create random transactions.
    //
    let wallet_keys: Vec<(&scc::SecretKey, &scc::PublicKey)> = keychains
        .iter()
        .map(|keychain| (&keychain.wallet_skey, &keychain.wallet_pkey))
        .collect();
    let wallets_recovery = chain.recover_wallets(&wallet_keys).unwrap();
    for (keychain, unspent) in keychains.iter().zip(wallets_recovery) {
        // Calculate actual balance.
        let mut payments: Vec<Output> = Vec::new();
        let mut stakes: Vec<Output> = Vec::new();
        let mut payment_balance: i64 = 0;
        let mut staking_balance: i64 = 0;
        for (input, epoch) in unspent {
            match input {
                Output::PaymentOutput(ref o) => {
                    let payload = o.decrypt_payload(&keychain.wallet_skey).unwrap();
                    payment_balance += payload.amount;
                    payments.push(input);
                }
                Output::PublicPaymentOutput(ref o) => {
                    payment_balance += o.amount;
                    payments.push(input);
                }
                Output::StakeOutput(ref o) => {
                    let active_until_epoch = epoch + chain.cfg().stake_epochs;
                    if active_until_epoch > chain.epoch() {
                        continue;
                    }
                    staking_balance += o.amount;
                    stakes.push(input);
                }
            }
        }

        // Payments.
        if payment_balance > 0 {
            let inputs = payments;
            let mut outputs: Vec<Output> = Vec::new();
            let mut outputs_gamma = Fr::zero();

            let (output, output_gamma) =
                PaymentOutput::new(&keychain.wallet_pkey, payment_balance).expect("keys are valid");
            outputs.push(output.into());
            outputs_gamma += output_gamma;
            let tx = PaymentTransaction::new(
                &keychain.wallet_skey,
                &inputs,
                &outputs,
                &outputs_gamma,
                block_fee,
            )
            .expect("Invalid keys");
            tx.validate(&inputs).expect("Invalid transaction");
            transactions.push(tx.into());
        }

        // Stakes.
        if staking_balance > 0 {
            let inputs = stakes;
            let mut outputs: Vec<Output> = Vec::new();
            let output = StakeOutput::new(
                &keychain.wallet_pkey,
                &keychain.network_skey,
                &keychain.network_pkey,
                staking_balance,
            )
            .expect("keys are valid");
            outputs.push(output.into());
            let tx = RestakeTransaction::new(
                &keychain.network_skey,
                &keychain.network_pkey,
                &inputs,
                &outputs,
            )
            .expect("Keys are valid");
            transactions.push(tx.into());
        }
    }

    //
    // Create a block.
    //
    let mut input_hashes: Vec<Hash> = Vec::new();
    let mut output_hashes: Vec<Hash> = Vec::new();
    for tx in &transactions {
        input_hashes.extend(tx.txins());
        output_hashes.extend(tx.txouts().iter().map(Hash::digest));
    }
    let mut block = MicroBlock::new(
        previous,
        epoch,
        offset,
        view_change,
        None,
        leader.network_pkey,
        random,
        timestamp,
        transactions,
    );
    block.sign(&leader.network_skey, &leader.network_pkey);
    (block, input_hashes, output_hashes)
}

pub fn create_micro_block_with_coinbase(
    chain: &Blockchain,
    keychains: &[KeyChain],
    timestamp: Timestamp,
) -> MicroBlock {
    let previous = chain.last_block_hash().clone();
    let epoch = chain.epoch();
    let offset = chain.offset();
    let view_change = chain.view_change();
    let key = chain.select_leader(view_change);
    let keys = keychains.iter().find(|p| p.network_pkey == key).unwrap();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&keys.network_skey, &seed);
    let mut txouts: Vec<Output> = Vec::new();
    let mut gamma = Fr::zero();

    let block_fee = 0;
    let block_reward = chain.cfg().block_reward;
    // Create outputs for fee and rewards.
    for (amount, comment) in vec![(block_fee, "fee"), (block_reward, "reward")] {
        if amount <= 0 {
            continue;
        }

        let data = PaymentPayloadData::Comment(format!("Block {}", comment));
        let (output_fee, gamma_fee, _rvalue) =
            PaymentOutput::with_payload(None, &keys.wallet_pkey, amount, data.clone(), None)
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
    let txs = vec![coinbase.into()];
    let mut block = MicroBlock::new(
        previous,
        epoch,
        offset,
        view_change,
        None,
        keys.network_pkey,
        random,
        timestamp,
        txs,
    );
    block.sign(&keys.network_skey, &keys.network_pkey);
    block
}

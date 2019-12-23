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

use super::block::{Block, MacroBlock, MicroBlock};
use super::blockchain::{Blockchain, OutputRecovery};
use super::election::mix;
use super::error::BlockchainError;
use super::multisignature::create_multi_signature;
use super::output::{Output, PaymentOutput, PaymentPayloadData, StakeOutput};
use super::timestamp::Timestamp;
use super::transaction::{
    CoinbaseTransaction, PaymentTransaction, RestakeTransaction, Transaction,
};
use crate::election;
use bit_vec::BitVec;
use log::*;
use rand::{thread_rng, Rng};
use rand_core::RngCore;
use std::collections::{BTreeMap, HashMap};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc;

#[derive(Clone, Debug)]
pub struct KeyChain {
    /// Account Secret Key.
    pub account_skey: scc::SecretKey,
    /// Account Public Key.
    pub account_pkey: scc::PublicKey,
    /// Network Secret Key.
    pub network_skey: pbc::SecretKey,
    /// Network Public Key.
    pub network_pkey: pbc::PublicKey,
}

impl KeyChain {
    pub fn new(rng: &mut dyn RngCore) -> Self {
        let (account_skey, account_pkey) = scc::make_deterministic_keys(&rng.gen::<[u8; 32]>());
        let (network_skey, network_pkey) = pbc::make_deterministic_keys(&rng.gen::<[u8; 32]>());
        Self {
            account_skey,
            account_pkey,
            network_skey,
            network_pkey,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Default, Clone)]
pub struct AccountRecoveryState {
    pub removed: HashMap<Hash, OutputRecovery>,
    pub commited: HashMap<Hash, OutputRecovery>,
    pub prepared: HashMap<Hash, OutputRecovery>,
}

///
/// Recovery account state from the blockchain.
///
fn recover_account(
    chain: &Blockchain,
    account_skey: &scc::SecretKey,
    account_pkey: &scc::PublicKey,
    mut epoch: u64,
    mut unspent: HashMap<Hash, Output>,
) -> Result<AccountRecoveryState, BlockchainError> {
    let mut account_state: AccountRecoveryState = Default::default();

    let process_output = |account_state: &mut AccountRecoveryState,
                          output: &Output,
                          epoch: u64,
                          block_hash: &Hash,
                          is_final: bool,
                          timestamp: Timestamp| {
        let output_hash = Hash::digest(&output);
        if !chain.contains_output(&output_hash) {
            return; // Spent.
        }

        let is_my_utxo = match output {
            Output::PaymentOutput(o) => o.decrypt_payload(&account_pkey, &account_skey).is_ok(),
            Output::PublicPaymentOutput(o) => &o.recipient == account_pkey,
            Output::StakeOutput(o) => &o.recipient == account_pkey,
            Output::ChatMessageOutput(_o) => false,
        };
        if is_my_utxo {
            let output = OutputRecovery {
                output: output.clone(),
                epoch,
                block_hash: block_hash.clone(),
                timestamp,
                is_final,
            };

            if is_final {
                account_state.commited.insert(output_hash, output);
            } else {
                account_state.prepared.insert(output_hash, output);
            }
        }
    };

    let mut process_input = |account_state: &mut AccountRecoveryState,
                             input: &Hash,
                             epoch: u64,
                             block_hash: &Hash,
                             is_final: bool,
                             timestamp: Timestamp| {
        if let Some(output) = unspent.remove(input) {
            let output = OutputRecovery {
                output,
                epoch,
                block_hash: block_hash.clone(),
                timestamp,
                is_final,
            };

            account_state.removed.insert(*input, output);
        }
    };

    for block in chain.blocks_starting(epoch, 0) {
        let block_hash = Hash::digest(&block);
        match block {
            Block::MacroBlock(block) => {
                for output in &block.outputs {
                    process_output(
                        &mut account_state,
                        output,
                        epoch,
                        &block_hash,
                        true,
                        block.header.timestamp,
                    );
                }
                for input in &block.inputs {
                    process_input(
                        &mut account_state,
                        input,
                        epoch,
                        &block_hash,
                        false,
                        block.header.timestamp,
                    )
                }
                epoch += 1;
            }
            Block::MicroBlock(block) => {
                for tx in block.transactions {
                    for output in tx.txouts() {
                        process_output(
                            &mut account_state,
                            output,
                            epoch,
                            &block_hash,
                            false,
                            block.header.timestamp,
                        );
                    }
                    for input in tx.txins() {
                        process_input(
                            &mut account_state,
                            input,
                            epoch,
                            &block_hash,
                            false,
                            block.header.timestamp,
                        )
                    }
                }
            }
        }
    }
    assert_eq!(epoch, chain.epoch());
    Ok(account_state)
}

pub fn fake_genesis(
    stake: i64,
    coins: i64,
    max_slot_count: i64,
    num_nodes: usize,
    timestamp: Timestamp,
    prng: Option<&mut dyn RngCore>,
) -> (Vec<KeyChain>, MacroBlock) {
    let mut stakers = Vec::with_capacity(num_nodes);
    let mut keychains = Vec::with_capacity(num_nodes);
    let mut outputs: Vec<Output> = Vec::with_capacity(1 + keychains.len());
    let mut payout = coins;
    let mut thread_rng = thread_rng();
    let rng = prng.unwrap_or(&mut thread_rng);
    for _i in 0..num_nodes {
        // Generate keys.
        let keychain = KeyChain::new(rng);

        // Create a stake.
        let output = StakeOutput::new(
            &keychain.account_pkey,
            &keychain.network_skey,
            &keychain.network_pkey,
            stake,
        )
        .expect("invalid keys");
        assert!(payout >= stake);
        payout -= stake;
        outputs.push(output.into());

        stakers.push((keychain.network_pkey, stake));
        keychains.push(keychain);
    }

    // Create an initial payment.
    assert!(payout > 0);
    //TODO: Should we also create outputs in predictable way?
    let (output, outputs_gamma) =
        PaymentOutput::new(&keychains[0].account_pkey, payout).expect("invalid keys");
    outputs.push(output.into());

    // Calculate initial values.
    let epoch: u64 = 0;
    let view_change: u32 = 0;
    let last_macro_block_random = Hash::digest("genesis");
    let previous = Hash::digest("genesis");
    let seed = mix(last_macro_block_random, view_change);
    let random = pbc::make_VRF(&keychains[0].network_skey, &seed);
    let difficulty = 1;
    let activity_map = BitVec::from_elem(keychains.len(), true);

    let validators = election::select_validators_slots(stakers, random, max_slot_count).validators;

    // Create a block.
    let genesis = MacroBlock::new(
        previous,
        epoch,
        view_change,
        keychains[0].network_pkey.clone(),
        random,
        difficulty,
        timestamp,
        coins,
        -outputs_gamma,
        activity_map,
        validators,
        Vec::new(),
        outputs,
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
        &keys.account_pkey,
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
    let last_random = chain.last_random();
    let seed = mix(last_random, view_change);
    let random = pbc::make_VRF(&leader.network_skey, &seed);
    let solution = chain.vdf_solver()();
    let block_reward = chain.cfg().block_reward;
    let block_fee: i64 = 0;
    let mut transactions: Vec<Transaction> = Vec::new();

    //
    // Create coinbase transaction.
    //
    let coinbase_tx = {
        let data = PaymentPayloadData::Comment(format!("Block reward"));
        let (output, gamma, _rvalue) =
            PaymentOutput::with_payload(None, &leader.account_pkey, block_reward, data)
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

    for keychain in keychains.iter() {
        let accounts_recovery = recover_account(
            chain,
            &keychain.account_skey,
            &keychain.account_pkey,
            0,
            HashMap::new(),
        )
        .unwrap();
        let unspent = accounts_recovery
            .commited
            .into_iter()
            .chain(accounts_recovery.prepared);
        // Calculate actual balance.
        let mut payments: Vec<Output> = Vec::new();
        let mut stakes: Vec<Output> = Vec::new();
        let mut payment_balance: i64 = 0;
        let mut staking_balance: i64 = 0;
        for (_, OutputRecovery { output, epoch, .. }) in unspent {
            match output {
                Output::PaymentOutput(ref o) => {
                    let payload = o
                        .decrypt_payload(&keychain.account_pkey, &keychain.account_skey)
                        .unwrap();
                    payment_balance += payload.amount;
                    payments.push(output);
                }
                Output::PublicPaymentOutput(ref o) => {
                    payment_balance += o.amount;
                    payments.push(output);
                }
                Output::StakeOutput(ref o) => {
                    let active_until_epoch = epoch + chain.cfg().stake_epochs;
                    if active_until_epoch > chain.epoch() {
                        continue;
                    }
                    staking_balance += o.amount;
                    stakes.push(output);
                }
                Output::ChatMessageOutput(ref o) => {
                    // failure in this unwrap indicates a program error
                    let good_until = o.get_expiration_date().unwrap();
                    if Timestamp::now() > good_until {
                        continue;
                    }
                }
            }
        }

        // Payments.
        if payment_balance > 0 {
            let inputs = payments;
            let mut outputs: Vec<Output> = Vec::new();
            let mut outputs_gamma = scc::Fr::zero();

            let (output, output_gamma) =
                PaymentOutput::new(&keychain.account_pkey, payment_balance)
                    .expect("keys are valid");
            outputs.push(output.into());
            outputs_gamma += output_gamma;
            let tx = PaymentTransaction::new(
                &keychain.account_skey,
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
                &keychain.account_pkey,
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
        solution,
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
    let last_random = chain.last_random();
    let seed = mix(last_random, view_change);
    let random = pbc::make_VRF(&keys.network_skey, &seed);
    let solution = chain.vdf_solver()();
    let mut txouts: Vec<Output> = Vec::new();
    let mut gamma = scc::Fr::zero();

    let block_fee = 0;
    let block_reward = chain.cfg().block_reward;
    // Create outputs for fee and rewards.
    for (amount, comment) in vec![(block_fee, "fee"), (block_reward, "reward")] {
        if amount <= 0 {
            continue;
        }

        let data = PaymentPayloadData::Comment(format!("Block {}", comment));
        let (output_fee, gamma_fee, _rvalue) =
            PaymentOutput::with_payload(None, &keys.account_pkey, amount, data.clone())
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
        solution,
        timestamp,
        txs,
    );
    block.sign(&keys.network_skey, &keys.network_pkey);
    block
}

#[test]
fn roundtrip_bitvec() {
    use bit_vec::BitVec;
    use serde_derive::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct RT {
        #[serde(deserialize_with = "stegos_crypto::utils::deserialize_bitvec")]
        #[serde(serialize_with = "stegos_crypto::utils::serialize_bitvec")]
        v: BitVec,
    }
    let data = vec![
        0, 1, 2, 10, 15, 18, 25, 31, 40, 42, 60, 64, 7, 102, 132, 314, 231, 23, 24, 26, 27, 70, 71,
        77, 72, 73, 74, 75, 76, 81, 82, 83, 84, 85, 86, 87, 91, 92, 93, 94,
    ];

    let mut v = BitVec::from_elem(315, false);
    for i in data {
        v.set(i, true);
    }

    let rt = RT { v };

    let json = serde_json::to_string(&rt).unwrap();
    let mut rt_recovered: RT = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, rt_recovered);
    stegos_crypto::utils::trim_bitvec(&mut rt_recovered.v);
    assert_eq!(rt, rt_recovered)
}

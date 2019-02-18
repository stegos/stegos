//
// Copyright (c) 2019 Stegos
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

use super::Loopback;
use crate::*;
use chrono::Utc;
use std::collections::HashMap;
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_wallet::create_payment_transaction;

#[test]
pub fn init() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let keys = KeyChain::new_mem();
    let (_outbox, inbox) = unbounded();
    let (_loopback, network) = Loopback::new();

    let mut node = NodeService::testing(keys.clone(), network, inbox).unwrap();

    assert_eq!(node.chain.blocks().len(), 0);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.epoch, 0);
    assert_ne!(node.chain.leader, keys.cosi_pkey);
    assert!(node.chain.validators.is_empty());

    let current_timestamp = Utc::now().timestamp() as u64;
    let genesis = genesis(&[keys.clone()], 100, 3_000_000, current_timestamp);
    let genesis_count = genesis.len();
    node.handle_init(genesis).unwrap();
    assert_eq!(node.chain.blocks().len(), genesis_count);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.epoch, 1);
    assert_eq!(node.chain.leader, keys.cosi_pkey);
    assert_eq!(node.chain.validators.len(), 1);
    assert_eq!(
        node.chain.validators.keys().next().unwrap(),
        &node.chain.leader
    );
}

fn simulate_consensus(node: &mut NodeService) {
    let previous = Hash::digest(node.chain.last_block());
    let (block, _fee_output, _tx_hashes) = node.mempool.create_block(
        previous,
        VERSION,
        node.chain.epoch,
        0,
        &node.keys.wallet_skey,
        &node.keys.wallet_pkey,
    );

    let block = Block::MonetaryBlock(block);
    let block_hash = Hash::digest(&block);
    let multisig = secure_sign_hash(&block_hash, &node.keys.cosi_skey);
    let mut multisigmap = BitVector::new(1);
    multisigmap.insert(0);
    node.commit_proposed_block(block, multisig, multisigmap);
}

fn unspent(node: &NodeService) -> HashMap<Hash, (PaymentOutput, i64)> {
    let mut unspent: HashMap<Hash, (PaymentOutput, i64)> = HashMap::new();
    for hash in node.chain.unspent() {
        let output = node.chain.output_by_hash(&hash).unwrap();
        if let Output::PaymentOutput(o) = output {
            let PaymentPayload { amount, .. } = o.decrypt_payload(&node.keys.wallet_skey).unwrap();
            unspent.insert(hash, (o.clone(), amount));
        }
    }
    unspent
}

fn simulate_payment(node: &mut NodeService, amount: i64) -> Result<(), Error> {
    let (inputs, outputs, gamma, fee) = create_payment_transaction(
        &node.keys.wallet_skey,
        &node.keys.wallet_pkey,
        &node.keys.wallet_pkey,
        &unspent(node),
        amount,
        PaymentPayloadData::Comment("Test".to_string()),
    )?;
    let tx = Transaction::new(&node.keys.wallet_skey, &inputs, &outputs, gamma, fee)?;
    node.handle_transaction(tx)?;
    Ok(())
}

#[test]
pub fn monetary_requests() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let keys = KeyChain::new_mem();
    let (_outbox, inbox) = unbounded();
    let (_loopback, network) = Loopback::new();

    let mut node = NodeService::testing(keys.clone(), network, inbox).unwrap();

    let total: i64 = 3_000_000;
    let stake: i64 = 100;
    let current_timestamp = Utc::now().timestamp() as u64;
    let genesis = genesis(&[keys.clone()], stake, total, current_timestamp);
    node.handle_init(genesis).unwrap();
    let mut block_count = node.chain.blocks().len();

    // Payment without a change.
    simulate_payment(&mut node, total - stake - PAYMENT_FEE).unwrap();
    assert_eq!(node.mempool.len(), 1);
    simulate_consensus(&mut node);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.blocks().len(), block_count + 1);
    let mut amounts = Vec::new();
    for unspent in node.chain.unspent() {
        match node.chain.output_by_hash(&unspent) {
            Some(Output::PaymentOutput(o)) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&keys.wallet_skey).unwrap();
                amounts.push(amount);
            }
            Some(Output::StakeOutput(o)) => {
                assert_eq!(o.amount, stake);
            }
            _ => panic!(),
        }
    }
    amounts.sort();
    assert_eq!(amounts, vec![PAYMENT_FEE, total - stake - PAYMENT_FEE]);
    block_count += 1;

    // Payment with a change.
    simulate_payment(&mut node, 100).unwrap();
    assert_eq!(node.mempool.len(), 1);
    simulate_consensus(&mut node);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.blocks().len(), block_count + 1);
    let mut amounts = Vec::new();
    for unspent in node.chain.unspent() {
        match node.chain.output_by_hash(&unspent) {
            Some(Output::PaymentOutput(o)) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&keys.wallet_skey).unwrap();
                amounts.push(amount);
            }
            Some(Output::StakeOutput(o)) => {
                assert_eq!(o.amount, stake);
            }
            _ => panic!(),
        }
    }
    amounts.sort();
    let expected = vec![2 * PAYMENT_FEE, 100, total - stake - 100 - 2 * PAYMENT_FEE];
    assert_eq!(amounts, expected);

    assert_eq!(block_count, 3);
}

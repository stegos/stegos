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

use super::Loopback;
use crate::*;
use chrono::Utc;
use stegos_blockchain::*;

#[test]
pub fn init() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let keys = KeyChain::new_mem();
    let (_outbox, inbox) = unbounded();
    let (_loopback, network) = Loopback::new();

    let mut node = NodeService::testing(keys.clone(), network, inbox).unwrap();

    assert_eq!(node.chain.height(), 0);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.epoch, 0);
    assert_ne!(node.chain.leader, keys.network_pkey);
    assert!(node.chain.validators.is_empty());

    let current_timestamp = Utc::now().timestamp() as u64;
    let genesis = genesis(&[keys.clone()], 1000, 3_000_000, current_timestamp);
    let genesis_count = genesis.len() as u64;
    node.handle_init(genesis).unwrap();
    assert_eq!(node.chain.height(), genesis_count);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.epoch, 1);
    assert_eq!(node.chain.leader, keys.network_pkey);
    assert_eq!(node.chain.validators.len(), 1);
    assert_eq!(
        node.chain.validators.keys().next().unwrap(),
        &node.chain.leader
    );
}

fn simulate_consensus(node: &mut NodeService) {
    node.create_monetary_block().unwrap();
}

fn simulate_payment(node: &mut NodeService, amount: i64) -> Result<(), Error> {
    let sender_skey = &node.keys.wallet_skey;
    let sender_pkey = &node.keys.wallet_pkey;
    let mut inputs: Vec<Output> = Vec::new();
    let mut inputs_amount: i64 = 0;
    for hash in node.chain.unspent() {
        let output = node
            .chain
            .output_by_hash(&hash)
            .expect("no disk errors")
            .expect("utxo exists");
        if let Output::PaymentOutput(ref o) = output {
            let PaymentPayload { amount, .. } = o.decrypt_payload(sender_skey).unwrap();
            inputs.push(output);
            inputs_amount += amount;
        }
    }

    let fee: i64 = PAYMENT_FEE * inputs.len() as i64;
    assert!(inputs_amount >= amount + fee);
    let change = inputs_amount - amount - fee;
    let timestamp = Utc::now().timestamp() as u64;
    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);
    let (output1, gamma1) = PaymentOutput::new(timestamp, sender_skey, sender_pkey, amount)?;
    outputs.push(Output::PaymentOutput(output1));
    let mut outputs_gamma = gamma1;
    if change > 0 {
        let (output2, gamma2) = PaymentOutput::new(timestamp, sender_skey, sender_pkey, change)?;
        outputs.push(Output::PaymentOutput(output2));
        outputs_gamma += gamma2;
    }

    let tx = Transaction::new(sender_skey, &inputs, &outputs, outputs_gamma, fee)?;
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
    let stake: i64 = 1000;
    let current_timestamp = Utc::now().timestamp() as u64;
    let genesis = genesis(&[keys.clone()], stake, total, current_timestamp);
    node.handle_init(genesis).unwrap();
    let mut block_count = node.chain.height();

    // Payment without a change.
    simulate_payment(&mut node, total - stake - PAYMENT_FEE).unwrap();
    assert_eq!(node.mempool.len(), 1);
    simulate_consensus(&mut node);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.height(), block_count + 1);
    let mut amounts = Vec::new();
    for unspent in node.chain.unspent() {
        match node.chain.output_by_hash(&unspent).expect("no disk errors") {
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
    assert_eq!(
        amounts,
        vec![PAYMENT_FEE + BLOCK_REWARD, total - stake - PAYMENT_FEE]
    );
    block_count += 1;

    // Payment with a change.
    simulate_payment(&mut node, 100).unwrap();
    assert_eq!(node.mempool.len(), 1);
    simulate_consensus(&mut node);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.height(), block_count + 1);
    let mut amounts = Vec::new();
    for unspent in node.chain.unspent() {
        match node.chain.output_by_hash(&unspent).expect("no disk errors") {
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
    let expected = vec![
        BLOCK_REWARD + 2 * PAYMENT_FEE,
        100,
        BLOCK_REWARD + total - stake - 100 - 2 * PAYMENT_FEE,
    ];
    assert_eq!(amounts, expected);

    assert_eq!(block_count, 3);
}

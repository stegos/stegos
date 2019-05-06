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
use std::time::SystemTime;
use stegos_blockchain::*;

#[test]
pub fn init() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let keys = KeyChain::new_mem();
    let (_loopback, network) = Loopback::new();

    let cfg: ChainConfig = Default::default();
    let timestamp = SystemTime::now();
    let genesis = genesis(
        &[keys.clone()],
        cfg.min_stake_amount,
        1000 * cfg.min_stake_amount,
        timestamp,
    );
    let genesis_count = genesis.len() as u64;
    let chain = Blockchain::testing(cfg.clone().into(), genesis, timestamp)
        .expect("Failed to create blockchain");
    let (node, _node_api) = NodeService::new(cfg, chain, keys.clone(), network).unwrap();
    assert_eq!(node.chain.height(), genesis_count);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.epoch(), 1);
    assert_eq!(node.chain.leader(), keys.network_pkey);
    assert_eq!(node.chain.validators().len(), 1);
    assert_eq!(
        node.chain.validators().iter().next().unwrap().0,
        node.chain.leader()
    );
}

fn simulate_consensus(node: &mut NodeService) {
    node.create_micro_block(None).unwrap();
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

    let fee: i64 = node.cfg.payment_fee * inputs.len() as i64;
    assert!(inputs_amount >= amount + fee);
    let change = inputs_amount - amount - fee;
    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);
    let (output1, gamma1) = PaymentOutput::new(sender_pkey, amount)?;
    outputs.push(Output::PaymentOutput(output1));
    let mut outputs_gamma = gamma1;
    if change > 0 {
        let (output2, gamma2) = PaymentOutput::new(sender_pkey, change)?;
        outputs.push(Output::PaymentOutput(output2));
        outputs_gamma += &gamma2;
    }

    let tx = Transaction::new(sender_skey, &inputs, &outputs, &outputs_gamma, fee)?;
    node.handle_transaction(tx)?;
    Ok(())
}

#[test]
pub fn payments() {
    simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
    let keys = KeyChain::new_mem();
    let (_loopback, network) = Loopback::new();

    let cfg: ChainConfig = Default::default();
    let total: i64 = 1000 * cfg.min_stake_amount;
    let stake: i64 = cfg.min_stake_amount;
    let timestamp = SystemTime::now();
    let genesis = genesis(&[keys.clone()], stake, total, timestamp);
    let chain = Blockchain::testing(cfg.clone().into(), genesis, timestamp)
        .expect("Failed to create blockchain");
    let (mut node, _node_api) =
        NodeService::new(cfg.clone(), chain, keys.clone(), network).unwrap();
    let mut block_count = node.chain.height();

    // Payment without a change.
    simulate_payment(&mut node, total - stake - cfg.payment_fee).unwrap();
    assert_eq!(node.mempool.len(), 1);
    simulate_consensus(&mut node);
    assert_eq!(node.mempool.len(), 0);
    assert_eq!(node.chain.height(), block_count + 1);
    let mut amounts = Vec::new();
    for unspent in node.chain.unspent() {
        match node
            .chain
            .output_by_hash(&unspent)
            .expect("no disk errors")
            .expect("utxo exists")
        {
            Output::PaymentOutput(o) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&keys.wallet_skey).unwrap();
                amounts.push(amount);
            }
            Output::PublicPaymentOutput(_o) => {
                panic!("Not Implemented");
            }
            Output::StakeOutput(o) => {
                assert_eq!(o.amount, stake);
            }
        }
    }
    amounts.sort();
    assert_eq!(
        amounts,
        vec![
            cfg.payment_fee,
            cfg.block_reward,
            total - stake - cfg.payment_fee
        ]
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
        match node
            .chain
            .output_by_hash(&unspent)
            .expect("no disk errors")
            .expect("exists and no disk errors")
        {
            Output::PaymentOutput(o) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&keys.wallet_skey).unwrap();
                amounts.push(amount);
            }
            Output::PublicPaymentOutput(_o) => {
                panic!("NOT IMPLEMENTED");
            }
            Output::StakeOutput(o) => {
                assert_eq!(o.amount, stake);
            }
        }
    }
    amounts.sort();
    let expected = vec![
        100,
        3 * cfg.payment_fee,
        cfg.block_reward,
        cfg.block_reward + total - stake - 100 - 3 * cfg.payment_fee,
    ];
    assert_eq!(amounts, expected);

    assert_eq!(block_count, 2);
}

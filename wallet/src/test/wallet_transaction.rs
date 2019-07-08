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

use super::*;
use crate::valueshuffle::message::{Message, VsPayload};
use crate::*;
use assert_matches::assert_matches;
use futures::sync::oneshot::Receiver;
use futures::{Async, Future};
use std::time::Duration;
use stegos_crypto::scc::PublicKey;

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

#[test]
fn empty_log_at_start() {
    Sandbox::start(Default::default(), |mut s| {
        let mut wallets = genesis_wallets(&mut s);
        s.poll();
        let rx = wallets[0].wallet.request(WalletRequest::HistoryInfo {
            starting_from: Timestamp::now() - Duration::from_secs(1000),
            limit: 1,
        });
        wallets[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        assert_eq!(response, WalletResponse::HistoryInfo { log: vec![] });
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC])
    });
}

#[test]
fn create_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut wallets = genesis_wallets(&mut s);

        s.poll();
        //        s.add_money(wallet.wallet_service.wallet_pkey, 100);
        let recipient = wallets[1].wallet_service.wallet_pkey;

        let rx = wallets[0].wallet.request(WalletRequest::Payment {
            password: PASSWORD.to_string(),
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        wallets[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let tx_hash = match response {
            WalletResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        let mut commited_status = wallets[0]
            .wallet
            .request(WalletRequest::WaitForCommit { tx_hash });

        wallets[0].poll();
        assert_eq!(commited_status.poll(), Ok(Async::NotReady));
        s.wait(s.config.node.tx_wait_timeout);
        s.skip_micro_block();

        wallets[0].poll();

        assert_matches!(
            get_request(commited_status),
            WalletResponse::TransactionCommitted(_)
        );
        let commited_status_post = wallets[0]
            .wallet
            .request(WalletRequest::WaitForCommit { tx_hash });
        wallets[0].poll();
        assert_matches!(
            get_request(commited_status_post),
            WalletResponse::TransactionCommitted(_)
        );
    });
}

// genesis wallet should has atleast N* amount of wallets
fn precondition_each_wallet_has_tokens(
    s: &mut Sandbox,
    amount: i64,
    genesis_wallet: &mut WalletSandbox,
    wallets: &mut [WalletSandbox],
) {
    for new_wallet in wallets.iter() {
        let rx = genesis_wallet.wallet.request(WalletRequest::Payment {
            password: PASSWORD.to_string(),
            recipient: new_wallet.wallet_service.wallet_pkey,
            amount,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });
        genesis_wallet.poll();
        assert_matches!(get_request(rx), WalletResponse::TransactionCreated(_));

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        s.wait(s.config.node.tx_wait_timeout);
        s.skip_micro_block();
        genesis_wallet.poll();
    }

    for new_wallet in wallets {
        new_wallet.poll();
        let rx = new_wallet.wallet.request(WalletRequest::BalanceInfo {});
        new_wallet.poll();

        match get_request(rx) {
            WalletResponse::BalanceInfo { balance } => {
                dbg!((balance, amount));
                assert!(balance >= amount);
            }
            _ => panic!("Wrong respnse to payment request"),
        };
    }
}

fn vs_start(
    recipient: PublicKey,
    amount: i64,
    wallet: &mut WalletSandbox,
) -> Receiver<WalletResponse> {
    let rx = wallet.wallet.request(WalletRequest::SecurePayment {
        password: PASSWORD.to_string(),
        recipient,
        amount,
        payment_fee: PAYMENT_FEE,
        comment: "Test".to_string(),
        locked_timestamp: None,
    });

    wallet.poll();

    let response = get_request(rx);
    info!("{:?}", response);
    let tx_hash = match response {
        WalletResponse::ValueShuffleStarted { session_id } => session_id,
        _ => panic!("Wrong respnse to payment request"),
    };

    let mut commited_status = wallet
        .wallet
        .request(WalletRequest::WaitForCommit { tx_hash });

    wallet.poll();
    assert_eq!(commited_status.poll(), Ok(Async::NotReady));

    commited_status
}

/// 3 nodes send monet to 1 recipient, using vs
#[ignore]
#[test]
fn create_vs_tx() {
    const SEND_TOKENS: i64 = 10;
    // send MINIMAL_TOKEN + FEE
    const MIN_AMOUNT: i64 = SEND_TOKENS + PAYMENT_FEE;
    // set micro_blocks to some big value.
    let config = SandboxConfig {
        chain: ChainConfig {
            micro_blocks_in_epoch: 2000,
            ..Default::default()
        },
        ..Default::default()
    };
    Sandbox::start(config, |mut s| {
        let mut wallets = genesis_wallets(&mut s);

        s.poll();
        let (genesis, rest) = wallets.split_at_mut(1);
        precondition_each_wallet_has_tokens(&mut s, MIN_AMOUNT, &mut genesis[0], rest);

        let num_nodes = wallets.len() - 1;
        let sleep_since_epoch = s.config.node.tx_wait_timeout * num_nodes as u32;

        let recipient = wallets[3].wallet_service.wallet_pkey;

        let mut committed_statuses = Vec::new();
        for i in 0..num_nodes {
            let status = vs_start(recipient, SEND_TOKENS, &mut wallets[i]);
            committed_statuses.push(status);
            wallets[i].poll();
        }
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== JOINING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_JOIN_TOPIC);
        s.poll();

        // this code are done just to work with different timeout configuration.
        {
            // we already sleep for 3 microblocks,
            let sleep_time = if stegos_node::txpool::MESSAGE_TIMEOUT > sleep_since_epoch {
                stegos_node::txpool::MESSAGE_TIMEOUT - sleep_since_epoch
            } else {
                Duration::from_millis(0)
            };

            s.wait(sleep_time);
            // if we sleep enought for microblock, then broadcast microblock.
            if sleep_time >= s.config.node.tx_wait_timeout {
                s.skip_micro_block();
                // if we sleep enought for view_change, then filter_view_change.
                if sleep_time >= s.config.node.micro_block_timeout {
                    s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
                }
            } else {
                // if not, just poll to triger txpoll_anouncment
                s.poll();
            }
        }
        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== VS STARTED NEW POOL: Send::SharedKeying =====");
        wallets.iter_mut().for_each(WalletSandbox::poll);

        let mut shared_keying = HashMap::new();
        for wallet in wallets.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = wallet
                    .network
                    .get_unicast::<valueshuffle::message::DirectMessage>(
                        crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg.message,
                    Message::VsMessage{
                        payload: VsPayload::SharedKeying {
                            ..
                        },
                        ..
                });

                debug!("Adding msg to peer = {}", peer);
                let entry = shared_keying.entry(peer).or_insert(Vec::new());
                entry.push(msg); // msg directed to peer
            }
        }

        for wallet in wallets.iter_mut().take(num_nodes) {
            debug!(
                "Receiving msg to peer = {}",
                wallet.wallet_service.network_pkey
            );
            for msg in shared_keying
                .get(&wallet.wallet_service.network_pkey)
                .unwrap()
            {
                wallet.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive shared keying: Send::Commitment =====");
        wallets.iter_mut().for_each(WalletSandbox::poll);

        let mut commitments = HashMap::new();
        for wallet in wallets.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = wallet
                    .network
                    .get_unicast::<valueshuffle::message::DirectMessage>(
                        crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg.message,
                    Message::VsMessage{
                        payload: VsPayload::Commitment {
                            ..
                        },
                        ..
                });

                let entry = commitments.entry(peer).or_insert(Vec::new());
                entry.push(msg); // msg directed to peer
            }
        }

        for wallet in wallets.iter_mut().take(num_nodes) {
            for msg in commitments
                .get(&wallet.wallet_service.network_pkey)
                .unwrap()
            {
                wallet.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        wallets.iter_mut().for_each(WalletSandbox::poll);

        let mut cloaked_vals = HashMap::new();
        for wallet in wallets.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = wallet
                    .network
                    .get_unicast::<valueshuffle::message::DirectMessage>(
                        crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg.message,
                    Message::VsMessage{
                        payload: VsPayload::CloakedVals {
                            ..
                        },
                        ..
                });

                let entry = cloaked_vals.entry(peer).or_insert(Vec::new());
                entry.push(msg); // msg directed to peer
            }
        }

        for wallet in wallets.iter_mut().take(num_nodes) {
            for msg in cloaked_vals
                .get(&wallet.wallet_service.network_pkey)
                .unwrap()
            {
                wallet.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        wallets.iter_mut().for_each(WalletSandbox::poll);

        let mut signatures = HashMap::new();
        for wallet in wallets.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = wallet
                    .network
                    .get_unicast::<valueshuffle::message::DirectMessage>(
                        crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg.message,
                    Message::VsMessage{
                        payload: VsPayload::Signature {
                            ..
                        },
                        ..
                });

                let entry = signatures.entry(peer).or_insert(Vec::new());
                entry.push(msg); // msg directed to peer
            }
        }

        for wallet in wallets.iter_mut().take(num_nodes) {
            for msg in signatures.get(&wallet.wallet_service.network_pkey).unwrap() {
                wallet.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }
        debug!("===== VS Receive Signatures: produce tx =====");
        wallets.iter_mut().for_each(WalletSandbox::poll);
        // rebroadcast transaction to each node
        debug!("===== BROADCAST VS TRANSACTION =====");
        s.broadcast(stegos_node::TX_TOPIC);

        s.wait(s.config.node.tx_wait_timeout);
        s.skip_micro_block();

        for (wallet, committed_status) in wallets.iter_mut().zip(committed_statuses) {
            wallet.poll();
            assert_matches!(
                get_request(committed_status),
                WalletResponse::TransactionCommitted(_)
            );
        }
    });
}

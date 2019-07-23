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
use futures::Async;
use std::time::Duration;
use stegos_crypto::scc::PublicKey;

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

#[test]
fn empty_log_at_start() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);
        s.poll();
        let log = account_history(&mut accounts[0]);
        assert_eq!(log.len(), 0);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
    });
}

#[test]
fn create_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
    });
}

#[test]
fn create_tx_with_certificate() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: true,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert_eq!(tx.certificates.len(), 1);
                assert_eq!(tx.certificates[0].recipient, recipient);
                assert_eq!(tx.certificates[0].amount, 10);

                // TODO: Get transaction from the node using api.
                {
                    let timestamp = accounts[0]
                        .account_service
                        .account_log
                        .tx_entry(tx.tx_hash)
                        .unwrap();
                    let tx_entry = accounts[0]
                        .account_service
                        .account_log
                        .iter_range(timestamp, 1)
                        .next()
                        .unwrap();
                    let output = match tx_entry.1 {
                        LogEntry::Outgoing { ref tx } => {
                            &tx.tx.txouts[tx.certificates[0].id as usize]
                        }
                        _ => panic!("Expected outgoing entry."),
                    };
                    let output = match output {
                        Output::PaymentOutput(o) => o,
                        _ => panic!("Expected payment output."),
                    };
                    // check that we cant decrypt payment using our secretkeys

                    assert!(output
                        .decrypt_payload(&accounts[0].account_service.account_skey)
                        .is_err());
                    let actual_amount = output
                        .verify_proof_of_payment(
                            &accounts[0].account_service.account_pkey,
                            &tx.certificates[0].rvalue,
                            &recipient,
                        )
                        .unwrap();
                    assert_eq!(actual_amount, 10);
                }

                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
    });
}

#[test]
fn full_transfer() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        let rx = accounts[0].account.request(AccountRequest::BalanceInfo {});

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let balance = match response {
            AccountResponse::BalanceInfo { balance } => balance,
            _ => panic!("Wrong response to payment request"),
        };

        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: balance - PAYMENT_FEE,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
    });
}

#[test]
fn create_tx_invalid() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        let rx = accounts[0].account.request(AccountRequest::BalanceInfo {});

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let balance = match response {
            AccountResponse::BalanceInfo { balance } => balance,
            _ => panic!("Wrong response to payment request"),
        };

        let recipient = accounts[1].account_service.account_pkey;

        // invalid amount
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: -10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        match response {
            AccountResponse::Error { error } => {}
            _ => panic!("Wrong response to payment request"),
        };

        // money more than exist
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: balance - PAYMENT_FEE + 1, // 1 token more than real balance
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        match response {
            AccountResponse::Error { error } => {}
            _ => panic!("Wrong response to payment request"),
        };
        // comment too long

        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: std::iter::repeat('a').take(PAYMENT_DATA_LEN - 1).collect(),
            locked_timestamp: None,
            with_certificate: false,
        });

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        match response {
            AccountResponse::Error { error } => {}
            _ => panic!("Wrong response to payment request"),
        };
    });
}

#[test]
fn get_recovery_key() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::GetRecovery {});

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();

        let response = get_request(rx);
        info!("{:?}", response);
        let recovery = match response {
            AccountResponse::Recovery { recovery } => recovery,
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
    });
}

#[test]
fn wait_for_epoch_end_with_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }

        let offset = s.first().chain().offset();

        for offset in offset..s.config.chain.micro_blocks_in_epoch {
            s.poll();
            s.skip_micro_block()
        }
        s.skip_macro_block();
        accounts[0].poll();

        // ignore multiple notification, and assert that notification not equal to our.
        while let AccountNotification::TransactionStatus {
            tx_hash,
            status: TransactionStatus::Committed { .. },
        } = get_notification(&mut notification)
        {
            if tx_hash != my_tx {
                unreachable!()
            }
        }
    });
}

#[test]
fn create_public_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::PublicPayment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            locked_timestamp: None,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        let epoch = s.first().chain().epoch();
        let offset = s.first().chain().offset();
        let microblock = s.first().chain().micro_block(epoch, offset - 1).unwrap();
        let our_tx = microblock.transactions.last();
        let our_tx = match our_tx {
            Some(Transaction::PaymentTransaction(tx)) => tx,
            _ => panic!(" not expeceted tx"),
        };

        let our_output = match our_tx.txouts.first() {
            Some(Output::PublicPaymentOutput(p)) => p,
            _ => panic!(" not expeceted output"),
        };

        assert_eq!(our_output.amount, 10);
        assert_eq!(our_output.recipient, recipient);

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
    });
}

#[test]
fn recovery_acount_after_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: 10,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });

        assert_eq!(notification.poll(), Ok(Async::NotReady));
        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let my_tx = match response {
            AccountResponse::TransactionCreated(tx) => {
                assert!(tx.certificates.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        accounts[0].poll();
        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Accepted {},
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
        s.skip_micro_block();

        accounts[0].poll();

        match get_notification(&mut notification) {
            AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }

        let log = account_history(&mut accounts[0]);

        assert_eq!(log.len(), 1);

        // save account dirs, and destroy accounts.
        let dirs: Vec<_> = accounts.into_iter().map(|acc| acc._tmp_dir).collect();

        let mut accounts = Vec::new();
        for (i, path) in (0..s.nodes.len()).zip(dirs) {
            let account = AccountSandbox::new_genesis(&mut s, i, path.into());
            accounts.push(account);
        }

        let log_after_recovery = account_history(&mut accounts[0]);

        assert_eq!(log_after_recovery.len(), 1);
        assert_eq!(log, log_after_recovery);
    });
}

fn account_history(account: &mut AccountSandbox) -> Vec<LogEntryInfo> {
    let rx = account.account.request(AccountRequest::HistoryInfo {
        starting_from: Timestamp::now() - Duration::from_secs(1000),
        limit: 1,
    });
    account.poll();

    let response = get_request(rx);
    info!("{:?}", response);

    let log = match response {
        AccountResponse::HistoryInfo { log } => log,
        _ => panic!("Wrong responses was found"),
    };
    log
}

// genesis account should has atleast N* amount of accounts
fn precondition_each_account_has_tokens(
    s: &mut Sandbox,
    amount: i64,
    genesis_account: &mut AccountSandbox,
    accounts: &mut [AccountSandbox],
) {
    for new_account in accounts.iter() {
        let rx = genesis_account.account.request(AccountRequest::Payment {
            recipient: new_account.account_service.account_pkey,
            amount,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });
        genesis_account.poll();
        assert_matches!(get_request(rx), AccountResponse::TransactionCreated(_));

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        // poll sandbox, to process transaction.
        s.poll();
        // rebroadcast transaction to each node
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();
        genesis_account.poll();
    }

    for new_account in accounts {
        new_account.poll();
        let rx = new_account.account.request(AccountRequest::BalanceInfo {});
        new_account.poll();

        match get_request(rx) {
            AccountResponse::BalanceInfo { balance } => {
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
    account: &mut AccountSandbox,
    notification: &mut mpsc::UnboundedReceiver<AccountNotification>,
) -> (Hash, oneshot::Receiver<AccountResponse>) {
    let rx = account.account.request(AccountRequest::SecurePayment {
        recipient,
        amount,
        payment_fee: PAYMENT_FEE,
        comment: "Test".to_string(),
        locked_timestamp: None,
    });

    account.poll();

    match get_notification(notification) {
        AccountNotification::SnowballStarted { session_id } => (session_id, rx),
        e => panic!("{:?}", e),
    }
}

/// 3 nodes send monet to 1 recipient, using vs
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
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let (genesis, rest) = accounts.split_at_mut(1);
        precondition_each_account_has_tokens(&mut s, MIN_AMOUNT, &mut genesis[0], rest);
        let num_nodes = accounts.len() - 1;
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let (id, response) =
                vs_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, id, response));
            accounts[i].poll();
        }
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== JOINING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_JOIN_TOPIC);
        s.poll();

        // this code are done just to work with different timeout configuration.
        {
            let sleep_time = stegos_node::txpool::MESSAGE_TIMEOUT;

            s.wait(sleep_time);
            // if not, just poll to triger txpoll_anouncment
            s.poll();
        }

        for (account, status) in accounts.iter_mut().zip(&mut notifications) {
            let (notification, _, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== VS STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut shared_keying = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
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

        for account in accounts.iter_mut().take(num_nodes) {
            debug!(
                "Receiving msg to peer = {}",
                account.account_service.network_pkey
            );
            for msg in shared_keying
                .get(&account.account_service.network_pkey)
                .unwrap()
            {
                account.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut commitments = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
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

        for account in accounts.iter_mut().take(num_nodes) {
            for msg in commitments
                .get(&account.account_service.network_pkey)
                .unwrap()
            {
                account.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut cloaked_vals = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
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

        for account in accounts.iter_mut().take(num_nodes) {
            for msg in cloaked_vals
                .get(&account.account_service.network_pkey)
                .unwrap()
            {
                account.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut signatures = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
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

        for account in accounts.iter_mut().take(num_nodes) {
            for msg in signatures
                .get(&account.account_service.network_pkey)
                .unwrap()
            {
                account.network.receive_unicast(
                    msg.source.pkey,
                    crate::valueshuffle::VALUE_SHUFFLE_TOPIC,
                    msg.clone(),
                )
            }
        }
        debug!("===== VS Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, hash, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push((notification, hash))
        }

        debug!("===== BROADCAST VS TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let (notification, _hash) = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepare { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }
    });
}

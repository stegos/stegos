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
use crate::snowball::message::{SnowballMessage, SnowballPayload};
use crate::*;
use assert_matches::assert_matches;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::oneshot::Receiver;
use futures::Async;
use std::string::ToString;
use std::time::Duration;
use stegos_crypto::scc::PublicKey;
use stegos_node::txpool;

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

#[test]
fn empty_log_at_start() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);
        s.poll();
        let log = account_history(&mut accounts[0]);
        assert_eq!(log.len(), 1);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
    });
}

fn last_outgoing(log: &Vec<LogEntryInfo>) -> &LogEntryInfo {
    for e in log.iter().rev() {
        if let LogEntryInfo::Outgoing { .. } = e {
            return e;
        }
    }
    unreachable!()
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
            AccountResponse::TransactionCreated(tx) => tx.tx_hash,
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
                status: TransactionStatus::Prepared { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }

        let log = account_history(&mut accounts[0]);

        let entry = last_outgoing(&log);

        if let LogEntryInfo::Outgoing { timestamp, tx } = entry {
            let outputs = &tx.outputs;

            assert_eq!(outputs.len(), 2);
            let output = unwrap_payment(outputs[0].clone());
            assert_eq!(output.amount, 10);
            assert!(!output.is_change);
            assert!(output.rvalue.is_none());
            assert_eq!(output.recipient, recipient);

            let output = unwrap_payment(outputs[1].clone());
            assert!(output.is_change);
            assert!(output.rvalue.is_none());
            assert_eq!(output.recipient, accounts[0].account_service.account_pkey);
        } else {
            unreachable!();
        }
    });
}

fn unwrap_payment(output: OutputInfo) -> PaymentInfo {
    match output {
        OutputInfo::Payment(p) => p,
        _ => unreachable!(),
    }
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
                assert_eq!(tx.outputs.len(), 2);
                let output_info = unwrap_payment(tx.outputs[0].clone());

                assert_eq!(output_info.recipient, recipient);
                assert_eq!(output_info.amount, 10);

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
                        LogEntry::Outgoing { ref tx } => &tx.tx.txouts[0],
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
                    let amount = output
                        .validate_certificate(
                            &accounts[0].account_service.account_pkey,
                            &recipient,
                            &output_info.rvalue.unwrap(),
                        )
                        .unwrap();
                    assert_eq!(amount, 10);
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
                status: TransactionStatus::Prepared { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }
    });
}

fn balance_request(account: &mut AccountSandbox) -> AccountBalance {
    let rx = account.account.request(AccountRequest::BalanceInfo {});

    account.poll();
    let response = get_request(rx);
    info!("{:?}", response);
    match response {
        AccountResponse::BalanceInfo(account_balance) => account_balance,
        _ => panic!("Wrong response to balance request"),
    }
}

#[test]
fn full_transfer() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        let balance = balance_request(&mut accounts[0]);

        let recipient = accounts[1].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let rx = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: balance.payment.current - PAYMENT_FEE,
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
            AccountResponse::TransactionCreated(tx) => tx.tx_hash,
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
                status: TransactionStatus::Prepared { .. },
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
        let balance = balance_request(&mut accounts[0]);
        info!("{:?}", balance);

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
            amount: balance.payment.current - PAYMENT_FEE + 1, // 1 token more than real balance
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
            AccountResponse::TransactionCreated(tx) => tx.tx_hash,
            e => panic!("Wrong respnse to payment request: e={:?}", e),
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
                status: TransactionStatus::Prepared { .. },
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
            AccountResponse::TransactionCreated(tx) => tx.tx_hash,
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
                status: TransactionStatus::Prepared { .. },
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

        accounts[0].poll();

        let log = account_history(&mut accounts[0]);

        assert_eq!(log.len(), 1);
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
            AccountResponse::TransactionCreated(tx) => tx.tx_hash,
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
                status: TransactionStatus::Prepared { .. },
            } => assert_eq!(tx_hash, my_tx),
            _ => unreachable!(),
        }

        let log = account_history(&mut accounts[0]);

        let len = log.len();
        assert!(len >= 3); // genesis utxo + tx + change utxo + Optional<Reward>

        // save account dirs, and destroy accounts.
        let dirs: Vec<_> = accounts.into_iter().map(|acc| acc._tmp_dir).collect();

        let mut accounts = Vec::new();
        for (i, path) in (0..s.nodes.len()).zip(dirs) {
            let account = AccountSandbox::new_genesis(&mut s, i, path.into());
            accounts.push(account);
        }
        s.poll();

        let log_after_recovery = account_history(&mut accounts[0]);

        assert_eq!(log_after_recovery.len(), len);
        assert_eq!(log, log_after_recovery);
    });
}

#[test]
fn send_node_duplicate_tx() {
    Sandbox::start(Default::default(), |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let recipient = accounts[1].account_service.account_pkey;

        accounts[0].poll();

        let log = account_history(&mut accounts[0]);

        assert_eq!(log.len(), 1);
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
                assert!(!tx.outputs.is_empty());
                tx.tx_hash
            }
            _ => panic!("Wrong respnse to payment request"),
        };

        s.nodes[0].poll(); // give node time to process tx

        accounts[0].poll(); // process update status

        let log = account_history(&mut accounts[0]);

        let len = log.len();
        assert_eq!(len, 2);

        match log.last().unwrap() {
            LogEntryInfo::Outgoing {
                tx:
                    TransactionInfo {
                        status: TransactionStatus::Accepted {},
                        ..
                    },
                ..
            } => {}
            e => panic!("Incorrect entry = {:?}.", e),
        }

        // save account dirs, and destroy accounts.
        let dirs: Vec<_> = accounts.into_iter().map(|acc| acc._tmp_dir).collect();

        let mut accounts = Vec::new();
        for (i, path) in (0..s.nodes.len()).zip(dirs) {
            let account = AccountSandbox::new_genesis(&mut s, i, path.into());
            accounts.push(account);
        }
        s.poll();

        accounts[0].poll();

        s.nodes[0].poll(); // give node time to process tx

        accounts[0].poll();

        let log_after_recovery = account_history(&mut accounts[0]);

        assert_eq!(len, 2);

        match log_after_recovery.last().unwrap() {
            LogEntryInfo::Outgoing {
                tx:
                    TransactionInfo {
                        status: TransactionStatus::Accepted {},
                        ..
                    },
                ..
            } => {}
            e => panic!("Incorrect entry = {:?}.", e),
        }

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        s.filter_broadcast(&[stegos_node::TX_TOPIC]);
    });
}

fn account_history(account: &mut AccountSandbox) -> Vec<LogEntryInfo> {
    let rx = account.account.request(AccountRequest::HistoryInfo {
        starting_from: Timestamp::now() - Duration::from_secs(1000),
        limit: 100,
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
            AccountResponse::BalanceInfo(AccountBalance {
                payment:
                    Balance {
                        current: balance,
                        available: _,
                    },
                ..
            }) => {
                dbg!((balance, amount));
                assert!(balance >= amount);
            }
            _ => panic!("Wrong respnse to payment request"),
        };
    }
}

fn snowball_start(
    recipient: PublicKey,
    amount: i64,
    account: &mut AccountSandbox,
    notification: &mut mpsc::UnboundedReceiver<AccountNotification>,
) -> (oneshot::Receiver<AccountResponse>) {
    let rx = account.account.request(AccountRequest::SecurePayment {
        recipient,
        amount,
        payment_fee: PAYMENT_FEE,
        comment: "Test".to_string(),
        locked_timestamp: None,
    });

    account.poll();

    match get_notification(notification) {
        AccountNotification::SnowballStatus(status) => {
            assert_eq!(status, SnowballStatus::PoolWait);
        }
        e => panic!("{:?}", e),
    }

    rx
}

/// 3 nodes send monet to 1 recipient, using Snowball
#[test]
fn create_snowball_tx() {
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
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== ANONCING TXPOOL =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut shared_keying = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
                    .network
                    .get_unicast::<snowball::message::SnowballMessage>(
                        crate::snowball::SNOWBALL_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg,
                    SnowballMessage {
                        payload: SnowballPayload::SharedKeying {
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
                    crate::snowball::SNOWBALL_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== SB Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut commitments = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
                    .network
                    .get_unicast::<snowball::message::SnowballMessage>(
                        crate::snowball::SNOWBALL_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg,
                    SnowballMessage {
                        payload: SnowballPayload::Commitment {
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
                    crate::snowball::SNOWBALL_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut cloaked_vals = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
                    .network
                    .get_unicast::<snowball::message::SnowballMessage>(
                        crate::snowball::SNOWBALL_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg,
                    SnowballMessage {
                        payload: SnowballPayload::CloakedVals {
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
                    crate::snowball::SNOWBALL_TOPIC,
                    msg.clone(),
                )
            }
        }

        debug!("===== SB Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);

        let mut signatures = HashMap::new();
        for account in accounts.iter_mut().take(num_nodes) {
            for _ in 0..num_nodes - 1 {
                // each node send message to rest
                let (msg, peer) = account
                    .network
                    .get_unicast::<snowball::message::SnowballMessage>(
                        crate::snowball::SNOWBALL_TOPIC,
                    );

                // TODO: extend assertion.
                assert_matches!(msg,
                    SnowballMessage {
                        payload: SnowballPayload::Signature {
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
                    crate::snowball::SNOWBALL_TOPIC,
                    msg.clone(),
                )
            }
        }
        debug!("===== SB Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push(notification)
        }

        debug!("===== BROADCAST SB TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let notification = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepared { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }

        let log = account_history(&mut accounts[1]);
        let entry = last_outgoing(&log);

        if let LogEntryInfo::Outgoing { timestamp, tx } = entry {
            let outputs = &tx.outputs;

            let output = unwrap_payment(outputs[0].clone());

            assert_eq!(outputs.len(), 1);
            assert_eq!(output.amount, SEND_TOKENS);
            assert!(!output.is_change);
            assert!(output.rvalue.is_none());
            assert_eq!(output.recipient, recipient);
        } else {
            unreachable!();
        }
    });
}

/// 3 nodes send monet to 1 recipient, using Snowball
#[test]
fn snowball_lock_utxo() {
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

        let balance = balance_request(&mut accounts[0]);
        assert!(balance.payment.available > 0);

        let mut notification = accounts[0].account.subscribe();
        let mut response =
            snowball_start(recipient, SEND_TOKENS, &mut accounts[0], &mut notification);
        accounts[0].poll();

        s.filter_unicast(&[stegos_node::txpool::POOL_JOIN_TOPIC]);
        let balance = balance_request(&mut accounts[0]);
        assert_eq!(balance.payment.available, 0);
        let mut response2 = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: SEND_TOKENS,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });
        accounts[0].poll();

        assert_eq!(response.poll(), Ok(Async::NotReady));

        // second request failed, because of locked utxos.
        let response2 = get_request(response2);

        match response2 {
            AccountResponse::Error { error } => {
                assert!(error.starts_with("No enough payment utxo available"))
            }
            _ => unreachable!(),
        };

        s.wait(crate::PENDING_UTXO_TIME);
        let balance = balance_request(&mut accounts[0]);
        assert!(balance.payment.available > 0);
        accounts[0].poll();
        let response = get_request(response);
        match response {
            AccountResponse::Error { error } => assert_eq!(error, "Snowball timed out"),
            _ => unreachable!(),
        };

        let mut response3 = accounts[0].account.request(AccountRequest::Payment {
            recipient,
            amount: SEND_TOKENS,
            payment_fee: PAYMENT_FEE,
            comment: "Test".to_string(),
            locked_timestamp: None,
            with_certificate: false,
        });
        accounts[0].poll();

        // after timeout request should be accepted.
        let response3 = get_request(response3);
        match response3 {
            AccountResponse::TransactionCreated(_) => {}
            _ => unreachable!(),
        };
        let balance = balance_request(&mut accounts[0]);
        assert_eq!(balance.payment.available, 0);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
    });
}

/// !! This tests asserts internal state, so it could not be ported to API directly. !!
/// 1 node failed to join pool, and reset snowball on timeout
#[test]
fn snowball_failed_join() {
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
        let num_nodes = accounts.len() - 1;
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let response = snowball_start(recipient, SEND_TOKENS, &mut accounts[0], &mut notification);
        accounts[0].poll();
        assert!(accounts[0].account_service.snowball.is_some());
        assert!(!accounts[0].account_service.pending_payments.is_empty());

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);

        debug!("===== JOINING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_JOIN_TOPIC);
        s.poll();

        s.wait(crate::PENDING_UTXO_TIME);
        s.poll();

        accounts[0].poll();
        assert!(accounts[0].account_service.pending_payments.is_empty());
        assert!(accounts[0].account_service.snowball.is_none());

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
    });
}

/// Tests that annihilated inputs/outputs doesn't crash on_outputs_changed().
#[test]
fn annihilation() {
    let cfg = ChainConfig {
        micro_blocks_in_epoch: 3,
        ..Default::default()
    };
    let config = SandboxConfig {
        chain: cfg,
        num_nodes: 3,
        ..Default::default()
    };
    Sandbox::start(config, |mut s| {
        let mut accounts = genesis_accounts(&mut s);
        for _offset in 0..s.config.chain.micro_blocks_in_epoch - 1 {
            let recipient = accounts[0].account_service.account_pkey;
            let rx = accounts[0].account.request(AccountRequest::Payment {
                recipient,
                amount: 1,
                payment_fee: PAYMENT_FEE,
                comment: "Test".to_string(),
                locked_timestamp: None,
                with_certificate: false,
            });
            accounts[0].poll();
            assert_matches!(get_request(rx), AccountResponse::TransactionCreated(_));
            s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
            // poll sandbox, to process transaction.
            s.poll();
            // rebroadcast transaction to each node
            s.broadcast(stegos_node::TX_TOPIC);
            s.skip_micro_block();
            accounts[0].poll();
        }
        s.poll();
        s.skip_micro_block();
        s.skip_macro_block();
    });
}

// check that after message from wrong facilitator, snowball will not break it's session.
// For more detail, see: #1177
#[test]
fn snowball_with_wrong_facilitator_pool() {
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
        let num_nodes = accounts.len() - 1;
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notification = accounts[0].account.subscribe();
        let response = snowball_start(recipient, SEND_TOKENS, &mut accounts[0], &mut notification);
        accounts[0].poll();
        assert!(accounts[0].account_service.snowball.is_some());

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);

        let (_, key) = pbc::make_random_keys();

        let msg = txpool::messages::PoolInfo {
            participants: vec![],
            session_id: Hash::digest("test"),
        };

        accounts[0]
            .network
            .receive_unicast(key, txpool::POOL_ANNOUNCE_TOPIC, msg);
        accounts[0].poll();
        assert!(accounts[0].account_service.snowball.is_some());

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        s.filter_unicast(&[txpool::POOL_JOIN_TOPIC]);
        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
    });
}

/// create_snowball but with simplifed broadcast, and 4 participants
#[test]
fn create_snowball_simple() {
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
        let num_nodes = accounts.len();
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push(notification)
        }

        debug!("===== BROADCAST SB TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let notification = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepared { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }
    });
}

//
// Check errors in Snowball.
//

#[test]
fn create_snowball_fail_share_key() {
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
        let num_nodes = accounts.len();
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");

        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::snowball::SNOWBALL_TIMER);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== SB Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push(notification)
        }

        debug!("===== BROADCAST SB TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let notification = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepared { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }
    });
}

#[test]
fn create_snowball_fail_commitment() {
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
        let num_nodes = accounts.len();
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");

        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);
        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== SB Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::snowball::SNOWBALL_TIMER);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive CloakedVals: Check invalid supertransaction, restart=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push(notification)
        }

        debug!("===== BROADCAST SB TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let (notification) = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepared { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }
    });
}

#[test]
fn create_snowball_fail_cloacked_vals() {
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
        let num_nodes = accounts.len();
        assert!(num_nodes >= 3);

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");

        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);
        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::snowball::SNOWBALL_TIMER);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== SB Receive CloakedVals: Check invalid supertransaction, restart=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive Signatures: produce tx =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        // rebroadcast transaction to each node
        let mut my_tx_hash = None;
        let mut notifications_new = Vec::new();
        for (account, status) in accounts.iter_mut().zip(notifications) {
            let (mut notification, response) = status;
            account.poll();
            my_tx_hash = Some(match get_request(response) {
                AccountResponse::TransactionCreated(tx) => tx.tx_hash,

                e => panic!("{:?}", e),
            });
            notifications_new.push(notification)
        }

        debug!("===== BROADCAST SB TRANSACTION =====");
        s.poll();
        s.broadcast(stegos_node::TX_TOPIC);
        s.skip_micro_block();

        for (account, status) in accounts.iter_mut().zip(&mut notifications_new) {
            let notification = status;

            account.poll();

            // ignore multiple notification, and assert that notification not equal to our.
            while let AccountNotification::TransactionStatus {
                tx_hash,
                status: TransactionStatus::Prepared { .. },
            } = get_notification(notification)
            {
                if tx_hash != my_tx_hash.unwrap() {
                    unreachable!()
                }
            }
        }
    });
}

#[derive(Clone, Copy)]
struct DropoutCfg {
    num_nodes: usize,
    num_drops: usize,
}
// perform random dropouts
fn random_drops(s: &mut Sandbox, accounts: &mut Vec<AccountSandbox>, dropout_cfg: DropoutCfg) {
    use rand::Rng;

    let num_nodes = dropout_cfg.num_nodes;
    let num_drops = 1 + s.prng.gen::<usize>() % dropout_cfg.num_drops;

    let random_ids: Vec<_> = (0..num_drops)
        .map(|_| {
            (
                s.prng.gen::<usize>() % num_nodes,
                s.prng.gen::<usize>() % (num_nodes - 1),
            )
        })
        .collect();
    let mut messages = HashMap::new();
    for (node_id, account) in accounts.iter_mut().take(num_nodes).enumerate() {
        'msg: for msg_id in 0..num_nodes - 1 {
            // each node send message to rest
            let (msg, peer) = account
                .network
                .get_unicast::<snowball::message::SnowballMessage>(crate::snowball::SNOWBALL_TOPIC);

            for (random_node_id, random_msg_id) in &random_ids {
                // perform random message dropout.
                if *random_node_id == node_id && *random_msg_id == msg_id {
                    trace!(
                        "Perform random dropouts of msg from={}, to={}",
                        account.account_service.network_pkey,
                        peer
                    );
                    continue 'msg;
                }
            }
            let entry = messages.entry(peer).or_insert(Vec::new());
            entry.push(msg); // msg directed to peer
        }
    }

    // see deliver_with_restart method
    s.wait(crate::snowball::SNOWBALL_TIMER / 2);
    for account in accounts.iter_mut().take(num_nodes) {
        for msg in messages.get(&account.account_service.network_pkey).unwrap() {
            account.network.receive_unicast(
                msg.source.pkey,
                crate::snowball::SNOWBALL_TOPIC,
                msg.clone(),
            )
        }
    }

    accounts.iter_mut().for_each(AccountSandbox::poll);

    s.wait(crate::snowball::SNOWBALL_TIMER / 2);
}

fn deliver_with_restart(
    s: &mut Sandbox,
    accounts: &mut Vec<AccountSandbox>,
    dropout_cfg: DropoutCfg,
) {
    // we know that not all good, so we should wait for timeout, after delivering message.

    // sandbox work synchronised in time.
    // And after random dropouts, some nodes can go to the next stage,
    // so split wait into two phases (before and after message receiving).
    // So if node receive enough messages it will reset timer.
    trace!("Delivering messages, with wait timeout");
    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);
    accounts.iter_mut().for_each(AccountSandbox::poll);

    trace!("WAIT HALF");
    s.wait(crate::snowball::SNOWBALL_TIMER / 2);
    s.poll();
    s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
    s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
    trace!("WAIT NEXT HALF");
    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);
    accounts.iter_mut().for_each(AccountSandbox::poll);

    s.wait(crate::snowball::SNOWBALL_TIMER / 2);
}

//
// Assymetric dropouts.
//

#[test]
#[ignore]
fn create_snowball_asymetric_dropouts_sharing() {
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
    let drop_cfg = DropoutCfg {
        num_nodes: 4,
        num_drops: 1,
    };
    Sandbox::start(config, |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let (genesis, rest) = accounts.split_at_mut(1);
        precondition_each_account_has_tokens(&mut s, MIN_AMOUNT, &mut genesis[0], rest);
        let num_nodes = drop_cfg.num_nodes;
        assert!(num_nodes >= 3);
        assert!(num_nodes <= accounts.len());

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        random_drops(&mut s, &mut accounts, drop_cfg);

        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== SB Receive SharedKeying: Check dropout?, restart=====");

        perform_restart_asymetric(s, accounts, drop_cfg, notifications);
    });
}

#[test]
fn create_snowball_asymetric_dropouts_cloackedvals() {
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
    let drop_cfg = DropoutCfg {
        num_nodes: 4,
        num_drops: 1,
    };
    Sandbox::start(config, |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let (genesis, rest) = accounts.split_at_mut(1);
        precondition_each_account_has_tokens(&mut s, MIN_AMOUNT, &mut genesis[0], rest);
        let num_nodes = drop_cfg.num_nodes;
        assert!(num_nodes >= 3);
        assert!(num_nodes <= accounts.len());

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive SharedKeying: produce commitment with dropouts=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        random_drops(&mut s, &mut accounts, drop_cfg);

        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== SB Receive commitment: Check invalid??, restart=====");
        perform_restart_asymetric(s, accounts, drop_cfg, notifications);
    });
}

#[test]
fn create_snowball_asymetric_dropouts_commitment() {
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
    let drop_cfg = DropoutCfg {
        num_nodes: 4,
        num_drops: 1,
    };
    Sandbox::start(config, |mut s| {
        let mut accounts = genesis_accounts(&mut s);

        s.poll();
        let (genesis, rest) = accounts.split_at_mut(1);
        precondition_each_account_has_tokens(&mut s, MIN_AMOUNT, &mut genesis[0], rest);
        let num_nodes = drop_cfg.num_nodes;
        assert!(num_nodes >= 3);
        assert!(num_nodes <= accounts.len());

        let recipient = accounts[3].account_service.account_pkey;

        let mut notifications = Vec::new();
        for i in 0..num_nodes {
            let mut notification = accounts[i].account.subscribe();
            let response =
                snowball_start(recipient, SEND_TOKENS, &mut accounts[i], &mut notification);
            notifications.push((notification, response));
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
            let (notification, _) = status;
            account.poll();
            clear_notification(notification)
        }

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== ANONCING TXPOOL =====");
        s.deliver_unicast(stegos_node::txpool::POOL_ANNOUNCE_TOPIC);

        debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive SharedKeying: produce сommitment=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

        debug!("===== SB Receive сommitment: produce cloackedvals with dropout=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        random_drops(&mut s, &mut accounts, drop_cfg);

        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        debug!("===== SB Receive Commitment: Check invalid supertransaction, restart=====");
        perform_restart_asymetric(s, accounts, drop_cfg, notifications);
    });
}

fn perform_restart_asymetric(
    mut s: Sandbox,
    mut accounts: Vec<AccountSandbox>,
    drop_cfg: DropoutCfg,
    mut notifications: Vec<(
        UnboundedReceiver<AccountNotification>,
        Receiver<AccountResponse>,
    )>,
) {
    accounts.iter_mut().for_each(AccountSandbox::poll);
    deliver_with_restart(&mut s, &mut accounts, drop_cfg);

    s.poll();
    s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
    s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

    debug!("===== SB STARTED NEW POOL: Send::SharedKeying =====");
    accounts.iter_mut().for_each(AccountSandbox::poll);
    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

    debug!("===== SB Receive commitment: produce CloakedVals =====");
    accounts.iter_mut().for_each(AccountSandbox::poll);
    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

    debug!("===== SB Receive CloakedVals: produce signatures =====");
    accounts.iter_mut().for_each(AccountSandbox::poll);
    s.deliver_unicast(crate::snowball::SNOWBALL_TOPIC);

    debug!("===== SB Receive Signatures: produce tx =====");
    accounts.iter_mut().for_each(AccountSandbox::poll);
    // rebroadcast transaction to each node
    let mut my_tx_hash = None;
    let mut dropouts = None;
    let mut notifications_new = Vec::new();
    for (id, (account, status)) in accounts.iter_mut().zip(notifications).enumerate() {
        let (mut notification, mut response) = status;
        account.poll();
        my_tx_hash = Some(match response.poll() {
            Ok(Async::Ready(AccountResponse::TransactionCreated(tx))) => tx.tx_hash,

            _ => {
                assert_eq!(dropouts, None);
                dropouts = Some(id);
                continue;
            }
        });
        notifications_new.push(notification)
    }

    assert!(dropouts.is_some());
    debug!("===== BROADCAST SB TRANSACTION =====");
    s.poll();
    s.broadcast(stegos_node::TX_TOPIC);
    s.skip_micro_block();

    for (id, (account, status)) in accounts.iter_mut().zip(&mut notifications_new).enumerate() {
        let notification = status;

        account.poll();

        if id == dropouts.unwrap() {
            continue;
        }
        // ignore multiple notification, and assert that notification not equal to our.
        while let AccountNotification::TransactionStatus {
            tx_hash,
            status: TransactionStatus::Prepared { .. },
        } = get_notification(notification)
        {
            if tx_hash != my_tx_hash.unwrap() {
                unreachable!()
            }
        }
    }
}

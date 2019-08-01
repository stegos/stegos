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
                assert_eq!(tx.outputs.len(), 2);
                assert_eq!(tx.outputs[0].info.recipient, recipient);
                assert_eq!(tx.outputs[0].info.amount, 10);

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
                            &tx.outputs[0].info.rvalue.unwrap(),
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
            AccountResponse::BalanceInfo { balance, .. } => balance,
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
        let rx = accounts[0].account.request(AccountRequest::BalanceInfo {});

        accounts[0].poll();
        let response = get_request(rx);
        info!("{:?}", response);
        let balance = match response {
            AccountResponse::BalanceInfo { balance, .. } => balance,
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
            AccountResponse::BalanceInfo { balance, .. } => {
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

/// !! This tests asserts internal state, so it could not be ported to API directly. !!
/// 1 node failed to join pool, and reset snowball on timeout
#[test]
fn vs_failed_join() {
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
        let (id, response) = vs_start(recipient, SEND_TOKENS, &mut accounts[0], &mut notification);
        accounts[0].poll();
        assert!(accounts[0].account_service.vs_session.is_some());
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
        assert!(accounts[0].account_service.vs_session.is_none());

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
fn vs_with_wrong_facilitator_pool() {
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
        let (id, response) = vs_start(recipient, SEND_TOKENS, &mut accounts[0], &mut notification);
        accounts[0].poll();
        assert!(accounts[0].account_service.vs_session.is_some());

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
        assert!(accounts[0].account_service.vs_session.is_some());

        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);

        s.filter_unicast(&[txpool::POOL_JOIN_TOPIC]);
        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
    });
}

/// create_vs but with simplifed broadcast, and 4 participants
#[test]
fn create_vs_simple() {
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
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

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
// Check errors in vs.
//

#[test]
fn create_vs_fail_share_key() {
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

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== VS STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::valueshuffle::VS_TIMER * crate::valueshuffle::VS_TIMEOUT as u32);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== VS Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

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
fn create_vs_fail_commitment() {
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
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== VS Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::valueshuffle::VS_TIMER * crate::valueshuffle::VS_TIMEOUT as u32);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive CloakedVals: Check invalid supertransaction, restart=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

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
fn create_vs_fail_cloacked_vals() {
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
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive shared keying: Send::Commitment =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        let last_account = accounts.pop();
        drop(last_account);
        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.wait(crate::valueshuffle::VS_TIMER * crate::valueshuffle::VS_TIMEOUT as u32);
        s.poll();

        s.filter_broadcast(&[stegos_node::VIEW_CHANGE_TOPIC]);
        s.filter_unicast(&[stegos_node::CHAIN_LOADER_TOPIC]);
        debug!("===== VS Receive CloakedVals: Check invalid supertransaction, restart=====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS STARTED NEW POOL: Send::SharedKeying =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive commitment: produce CloakedVals =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

        debug!("===== VS Receive CloakedVals: produce signatures =====");
        accounts.iter_mut().for_each(AccountSandbox::poll);
        s.deliver_unicast(crate::valueshuffle::VALUE_SHUFFLE_TOPIC);

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

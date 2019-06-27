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
use crate::*;
use assert_matches::assert_matches;
use futures::{Async, Future};
use std::collections::HashSet;
use std::time::Duration;
use stegos_blockchain::Block;

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

#[test]
fn empty_log_at_start() {
    Sandbox::start(Default::default(), |mut s| {
        let mut wallets = genesis_wallets(&mut s);
        s.poll();
        let mut rx = wallets[0].wallet.request(WalletRequest::HistoryInfo {
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

        let mut rx = wallets[0].wallet.request(WalletRequest::Payment {
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
        //        let mut commited_status_post = wallets[0].wallet.request(WalletRequest::WaitForCommit {tx_hash});
        //        assert_matches!(get_request(commited_status_post), WalletResponse::TransactionCommitted(_));
    });
}

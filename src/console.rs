///! Console - command-line interface.
//
// Copyright (c) 2018 Stegos
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
use crate::consts;
use dirs;
use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::{Async, Future, Poll, Sink, Stream};
use lazy_static::*;
use log::*;
use regex::Regex;
use rustyline as rl;
use std::path::PathBuf;
use std::thread;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;
use stegos_network::Network;
use stegos_node::*;
use stegos_txpool::TransactionPool;
use stegos_wallet::{Wallet, WalletNotification};

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Console - command-line interface.
pub struct Console {}

impl Console {
    /// Create a new Console Service.
    pub fn new(
        keys: &KeyChain,
        network: Network,
        node: Node,
        txpool: TransactionPool,
    ) -> Result<impl Future<Item = (), Error = ()>, Error> {
        ConsoleService::new(keys, network, node, txpool)
    }
}

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

lazy_static! {
    /// Regex to parse "pay" command.
    static ref PAY_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<amount>[0-9]{1,19})(\s+(?P<comment>.+))?\s*$").unwrap();
    /// Regex to parse "msg" command.
    static ref MSG_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "stake/unstake" command.
    static ref STAKE_COMMAND_RE: Regex = Regex::new(r"\s*(?P<amount>[0-9]{1,19})\s*$").unwrap();
    /// Regex to parse "publish" command.
    static ref PUBLISH_COMMAND_RE: Regex = Regex::new(r"\s*(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.*)$").unwrap();
    /// Regex to parse "send" command.
    static ref SEND_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "txpool" command.
    static ref TXPOOL_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)$").unwrap();
}

/// Console (stdin) service.
struct ConsoleService {
    /// Wallet.
    wallet: Wallet,
    /// Transaction pool
    txpool: TransactionPool,
    /// Network message broker.
    network: Network,
    /// Blockchain Node.
    node: Node,
    /// Validator's public key
    validator_pkey: secure::PublicKey,
    /// A channel to receive message from stdin thread.
    stdin: Receiver<String>,
    /// A thread used for readline.
    stdin_th: thread::JoinHandle<()>,
    /// A channel to receive notification about UTXO changes.
    outputs_rx: UnboundedReceiver<OutputsNotification>,
    /// A channel to receive notification about Epoch changes.
    epoch_rx: UnboundedReceiver<EpochNotification>,
}

impl ConsoleService {
    /// Constructor.
    fn new(
        keys: &KeyChain,
        network: Network,
        node: Node,
        txpool: TransactionPool,
    ) -> Result<ConsoleService, Error> {
        let wallet = Wallet::new(keys.wallet_skey.clone(), keys.wallet_pkey.clone());
        let validator_pkey = keys.cosi_pkey.clone();
        let (tx, rx) = channel::<String>(1);
        let stdin_th = thread::spawn(move || ConsoleService::readline_thread_f(tx));
        let stdin = rx;
        let outputs_rx = node.subscribe_outputs()?;
        let epoch_rx = node.subscribe_epoch()?;

        let service = ConsoleService {
            wallet,
            txpool,
            network,
            node,
            validator_pkey,
            stdin,
            stdin_th,
            outputs_rx,
            epoch_rx,
        };
        Ok(service)
    }

    /// Background thread to read stdin.
    fn readline_thread_f(mut tx: Sender<String>) {
        // Use ~/.share/stegos.history for command line history.
        let history_path = dirs::data_dir()
            .unwrap_or(PathBuf::from(r"."))
            .join(PathBuf::from(consts::HISTORY_FILE_NAME));

        let config = rl::Config::builder()
            .history_ignore_space(true)
            .history_ignore_dups(true)
            .completion_type(rl::CompletionType::List)
            .auto_add_history(true)
            .edit_mode(rl::EditMode::Emacs)
            .build();

        let mut rl = rl::Editor::<()>::with_config(config);
        rl.load_history(&history_path).ok(); // just ignore errors

        loop {
            match rl.readline(consts::PROMPT) {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }
                    if tx.try_send(line).is_err() {
                        assert!(tx.is_closed()); // this channel is never full
                        break;
                    }
                    // Block until line is processed by ConsoleService.
                    thread::park();
                }
                Err(rl::error::ReadlineError::Interrupted) | Err(rl::error::ReadlineError::Eof) => {
                    break;
                }
                Err(e) => {
                    error!("CLI I/O Error: {}", e);
                    break;
                }
            }
        }
        tx.close().ok(); // ignore errors
        if let Err(e) = rl.save_history(&history_path) {
            error!("Failed to save CLI history: {}", e);
        };
    }

    fn help() {
        println!("Usage:");
        println!("pay PUBLICKEY AMOUNT - send money");
        println!("msg PUBLICKEY MESSAGE - send data");
        println!("stake AMOUNT - stake money");
        println!("unstake AMOUNT - unstake money");
        // println!("send PUBLICKEY MESSAGE - send unicast message");
        // println!("connect MULTIADDR - connect to a node");
        // println!("publish TOPIC MESSAGE - publish a message");
        println!("");
    }

    fn help_publish() {
        println!("Usage: publish TOPIC MESSAGE");
        println!(" - TOPIC - floodsub topic");
        println!(" - MESSAGE - arbitrary message");
        println!("");
    }

    fn help_pay() {
        println!("Usage: pay PUBLICKEY AMOUNT [COMMENT]");
        println!(" - PUBLICKEY recipient's public key in HEX format");
        println!(" - AMOUNT amount in tokens");
        println!(" - COMMENT purpose of payment");
        println!("");
    }

    fn help_stake() {
        println!("Usage: stake AMOUNT");
        println!(" - AMOUNT amount to stake into escrow, in tokens");
        println!("");
    }

    fn help_unstake() {
        println!("Usage: unstake [AMOUNT]");
        println!(" - AMOUNT amount to unstake from escrow, in tokens");
        println!("   if not specified, unstakes all of the money.");
        println!("");
    }

    fn help_msg() {
        println!("Usage: msg PUBLICKEY MESSAGE [TTL]");
        println!(" - PUBLICKEY recipient's public key in HEX format");
        println!(" - MESSAGE some message");
        println!(" - TTL the number of blocks for which this message should be kept");
        println!("");
    }

    fn help_send() {
        println!("Usage: send PUBLICKEY MESSAGE");
        println!(" - PUBLICKEY recipient's public key in HEX format");
        println!(" - MESSAGE some message");
        println!("");
    }

    fn help_txpool() {
        println!("Adds public key into pool, just for tests.");
        println!("Usage: txpool PUBLICKEY");
        println!(" - PUBLICKEY recipient's public key in HEX format");
        println!("");
    }

    /// Called when line is typed on standard input.
    fn on_input(&mut self, msg: &str) {
        if msg.starts_with("publish ") {
            let caps = match PUBLISH_COMMAND_RE.captures(&msg[8..]) {
                Some(c) => c,
                None => return ConsoleService::help_publish(),
            };

            let topic = caps.name("topic").unwrap().as_str();
            let msg = caps.name("msg").unwrap().as_str();
            info!("Publish: topic='{}', msg='{}'", topic, msg);
            self.network
                .publish(&topic, msg.as_bytes().to_vec())
                .unwrap();
        } else if msg.starts_with("txpool ") {
            let caps = match TXPOOL_COMMAND_RE.captures(&msg[7..]) {
                Some(c) => c,
                None => return ConsoleService::help_txpool(),
            };

            let node = caps.name("recipient").unwrap().as_str();
            let node = match secure::PublicKey::try_from_hex(node) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid public key '{}': {}", node, e);
                    return ConsoleService::help_txpool();
                }
            };
            info!("Trying add into pool: pk='{}'", node);
            self.txpool.add_message(node).unwrap();
        } else if msg.starts_with("send ") {
            let caps = match SEND_COMMAND_RE.captures(&msg[5..]) {
                Some(c) => c,
                None => return ConsoleService::help_publish(),
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match secure::PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid public key '{}': {}", recipient, e);
                    return ConsoleService::help_send();
                }
            };
            let msg = caps.name("msg").unwrap().as_str();
            info!("Send: to='{}', msg='{}'", recipient.into_hex(), msg);
            self.network
                .send(recipient, "console", msg.as_bytes().to_vec())
                .unwrap();
        } else if msg.starts_with("pay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => return ConsoleService::help_pay(),
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid public key '{}': {}", recipient, e);
                    return ConsoleService::help_pay();
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = amount.parse::<i64>().unwrap(); // check by regex
            let comment = if let Some(m) = caps.name("comment") {
                m.as_str().to_string()
            } else {
                String::new()
            };

            info!("Sending {} STG to {}", amount, recipient.into_hex());
            if let Err(e) = self
                .wallet
                .payment(&recipient, amount, comment)
                .and_then(move |tx| self.node.send_transaction(tx))
            {
                error!("Request failed: {}", e);
            }
        } else if msg.starts_with("msg ") {
            let caps = match MSG_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => return ConsoleService::help_msg(),
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid public key '{}': {}", recipient, e);
                    return ConsoleService::help_msg();
                }
            };
            let amount: i64 = 0;
            let comment = caps.name("msg").unwrap().as_str().to_string();
            assert!(comment.len() > 0);

            info!("Sending message to {}", recipient.into_hex());

            if let Err(e) = self
                .wallet
                .payment(&recipient, amount, comment)
                .and_then(move |tx| self.node.send_transaction(tx))
            {
                error!("Request failed: {}", e);
            }
        } else if msg.starts_with("stake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[6..]) {
                Some(c) => c,
                None => return ConsoleService::help_stake(),
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = amount.parse::<i64>().unwrap(); // check by regex

            info!("Staking {} STG into escrow", amount);
            if let Err(e) = self
                .wallet
                .stake(&self.validator_pkey, amount)
                .and_then(move |tx| self.node.send_transaction(tx))
            {
                error!("Request failed: {}", e);
            }
        } else if msg == "unstake" {
            info!("Unstaking all of the money from escrow");
            if let Err(e) = self
                .wallet
                .unstake_all(&self.validator_pkey)
                .and_then(move |tx| self.node.send_transaction(tx))
            {
                error!("Request failed: {}", e);
            }
        } else if msg.starts_with("unstake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[8..]) {
                Some(c) => c,
                None => return ConsoleService::help_unstake(),
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = amount.parse::<i64>().unwrap(); // check by regex

            info!("Unstaking {} STG from escrow", amount);
            if let Err(e) = self
                .wallet
                .unstake(&self.validator_pkey, amount)
                .and_then(move |tx| self.node.send_transaction(tx))
            {
                error!("Request failed: {}", e);
            }
        } else {
            return ConsoleService::help();
        }
    }

    fn on_exit(&self) {
        std::process::exit(0);
    }

    fn on_notification(&mut self, notifications: Vec<WalletNotification>) {
        for notification in notifications {
            match notification {
                WalletNotification::BalanceChanged { balance } => {
                    info!("Balance is {} STG", balance);
                }
                WalletNotification::PaymentReceived { amount, comment } => {
                    if amount == 0 && !comment.is_empty() {
                        info!("Incoming message: {}", comment);
                    }
                }
            }
        }
    }
}

// Event loop.
impl Future for ConsoleService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.stdin.poll() {
                Ok(Async::Ready(Some(line))) => {
                    self.on_input(&line);
                    // Wake up readline thread after processing input.
                    self.stdin_th.thread().unpark();
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!(),
            }
        }

        loop {
            match self.outputs_rx.poll() {
                Ok(Async::Ready(Some(msg))) => {
                    let notifications = self.wallet.on_outputs_changed(msg.inputs, msg.outputs);
                    self.on_notification(notifications)
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Wallet failure"),
            }
        }

        loop {
            // Transfer epoch notification into txpool
            match self.epoch_rx.poll() {
                Ok(Async::Ready(Some(msg))) => {
                    let facilitator = msg.facilitator;
                    if let Err(e) = self.txpool.change_facilitator(facilitator) {
                        error!("Error in sending message to txpool: {}", e);
                    }
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Wallet failure"),
            }
        }

        loop {
            match self.txpool.feedback_receiver.poll() {
                Ok(Async::Ready(Some(msg))) => debug!("Received message from txpool {:?}", msg),
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Wallet failure"),
            }
        }

        return Ok(Async::NotReady);
    }
}

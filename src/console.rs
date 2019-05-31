///! Console - command-line interface.
//
// Copyright (c) 2018 Stegos AG
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
use crate::config::GeneralConfig;
use crate::consts;
use crate::generator::{Generator, GeneratorMode};
use crate::money::{format_money, parse_money};
use dirs;
use failure::Error;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use futures::{Async, Future, Poll, Sink, Stream};
use lazy_static::*;
use log::*;
use regex::Regex;
use rustyline as rl;
use std::fmt;
use std::path::PathBuf;
use std::thread;
use stegos_crypto::curve1174::PublicKey;
use stegos_crypto::pbc;
use stegos_network::Network;
use stegos_network::UnicastMessage;
use stegos_node::{Node, NodeRequest, NodeResponse};
use stegos_wallet::{
    PaymentInfo, PaymentPayloadData, Wallet, WalletNotification, WalletRequest, WalletResponse,
};

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

// No public API provided.

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

lazy_static! {
    /// Regex to parse "pay" command.
    static ref PAY_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<amount>[0-9\.]{1,19})(\s+(?P<comment>.+))?\s*$").unwrap();
    /// Regex to parse "msg" command.
    static ref MSG_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "stake/unstake" command.
    static ref STAKE_COMMAND_RE: Regex = Regex::new(r"\s*(?P<amount>[0-9\.]{1,19})\s*$").unwrap();
    /// Regex to parse "publish" command.
    static ref PUBLISH_COMMAND_RE: Regex = Regex::new(r"\s*(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.*)$").unwrap();
    /// Regex to parse "send" command.
    static ref SEND_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
}

const CONSOLE_PROTOCOL_ID: &'static str = "console";

/// Console (stdin) service.
pub struct ConsoleService {
    /// Network API.
    network: Network,
    /// Wallet API.
    wallet: Wallet,
    /// Node API.
    node: Node,
    /// Generator.
    generator: Option<Generator>,
    /// Wallet events.
    wallet_notifications: UnboundedReceiver<WalletNotification>,
    /// Wallet RPC responses.
    wallet_response: Option<oneshot::Receiver<WalletResponse>>,
    /// Node RPC responses.
    node_response: Option<oneshot::Receiver<NodeResponse>>,
    /// A channel to receive message from stdin thread.
    stdin: Receiver<String>,
    /// A thread used for readline.
    stdin_th: thread::JoinHandle<()>,
    /// A channel to receive unicast messages
    unicast_rx: UnboundedReceiver<UnicastMessage>,
}

impl ConsoleService {
    /// Constructor.
    pub fn new(
        cfg: &GeneralConfig,
        network: Network,
        wallet: Wallet,
        node: Node,
    ) -> Result<ConsoleService, Error> {
        let (tx, rx) = channel::<String>(1);
        let wallet_notifications = wallet.subscribe();
        let wallet_response = None;
        let node_response = None;
        let stdin_th = thread::spawn(move || Self::readline_thread_f(tx));
        let stdin = rx;
        let unicast_rx = network.subscribe_unicast(CONSOLE_PROTOCOL_ID)?;
        let generator = if !cfg.generate_txs.is_empty() {
            Some(Generator::new(
                wallet.clone(),
                cfg.generate_txs.clone(),
                GeneratorMode::Regular,
                true,
            ))
        } else {
            None
        };
        let service = ConsoleService {
            network,
            wallet,
            generator,
            wallet_notifications,
            wallet_response,
            node_response,
            stdin,
            stdin_th,
            unicast_rx,
            node,
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
        println!("pay WALLET_PUBKEY AMOUNT [/public] [COMMENT] - send money");
        println!("spay WALLET_PUBKEY AMOUNT [COMMENT] - send money using ValueShuffle");
        println!("msg WALLET_PUBKEY MESSAGE - send a message via blockchain");
        println!("stake AMOUNT - stake money");
        println!("unstake [AMOUNT] - unstake money");
        println!("restake - restake all available stakes");
        println!("cloak - exchange all available public outputs");
        println!("show version - print version information");
        println!("show keys - print keys");
        println!("show balance - print balance");
        println!("show utxo - print unspent outputs");
        println!("show election - print leader election state");
        println!("show escrow - print escrow");
        println!("show recovery - print recovery information");
        println!("net publish TOPIC MESSAGE - publish a network message via floodsub");
        println!("net send NETWORK_PUBKEY MESSAGE - send a network message via unicast");
        println!("db pop block - revert the latest block");
        println!("generator start LIST_OF_WALLETS_ADDRESSES - start transaction generator");
        println!("generator stop - stop transaction generator");
        println!();
    }

    fn help_publish() {
        println!("Usage: net publish TOPIC MESSAGE");
        println!(" - TOPIC - floodsub topic");
        println!(" - MESSAGE - arbitrary message");
        println!();
    }

    fn help_send() {
        println!("Usage: net send NETWORK_PUBKEY MESSAGE");
        println!(" - NETWORK_PUBKEY recipient's network public key in HEX format");
        println!(" - MESSAGE some message");
        println!();
    }

    fn help_pay() {
        println!("Usage: pay WALLET_PUBKEY AMOUNT [COMMENT]");
        println!(" - WALLET_PUBKEY recipient's wallet public key in HEX format");
        println!(" - AMOUNT amount in tokens");
        println!(" - /public if present, send money as PublicUTXO, with uncloaked recipient and amaount.");
        println!(" - COMMENT purpose of payment");
        println!();
    }

    fn help_spay() {
        println!("Usage: spay WALLET_PUBKEY AMOUNT [COMMENT]");
        println!(" - WALLET_PUBKEY recipient's wallet public key in HEX format");
        println!(" - AMOUNT amount in tokens");
        println!(" - COMMENT purpose of payment");
        println!();
    }

    fn help_stake() {
        println!("Usage: stake AMOUNT");
        println!(" - AMOUNT amount to stake into escrow, in tokens");
        println!();
    }

    fn help_unstake() {
        println!("Usage: unstake [AMOUNT]");
        println!(" - AMOUNT amount to unstake from escrow, in tokens");
        println!("   if not specified, unstakes all of the money.");
        println!();
    }

    fn help_msg() {
        println!("Usage: msg WALLET_PUBKEY MESSAGE");
        println!(" - WALLET_PUBKEY recipient's public key in HEX format");
        println!(" - MESSAGE some message");
        println!();
    }

    fn help_generator() {
        println!("Usage: generator SUBCOMMAND");
        println!(" - start or stop transaction generator");
        println!(" - SUBCOMMAND can be one of [start, stop]");
        println!(
            " - generator start LIST_OF_WALLETS_ADDRESSES - will start generator, \
             or add new wallet keys to generator list."
        );
        println!(" - generator stop will stop generator");
        println!();
    }

    /// Called when line is typed on standard input.
    fn on_input(&mut self, msg: &str) -> bool {
        if msg.starts_with("net publish ") {
            let caps = match PUBLISH_COMMAND_RE.captures(&msg[12..]) {
                Some(c) => c,
                None => {
                    Self::help_publish();
                    return true;
                }
            };

            let topic = caps.name("topic").unwrap().as_str();
            let msg = caps.name("msg").unwrap().as_str();
            info!("Publish: topic='{}', msg='{}'", topic, msg);
            self.network
                .publish(&topic, msg.as_bytes().to_vec())
                .unwrap();
            return true;
        } else if msg.starts_with("net send ") {
            let caps = match SEND_COMMAND_RE.captures(&msg[9..]) {
                Some(c) => c,
                None => {
                    Self::help_publish();
                    return true;
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match pbc::PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid network public key '{}': {}", recipient, e);
                    Self::help_send();
                    return true;
                }
            };
            let msg = caps.name("msg").unwrap().as_str();
            info!("Send: to='{}', msg='{}'", recipient.to_hex(), msg);
            self.network
                .send(recipient, "console", msg.as_bytes().to_vec())
                .unwrap();
            return true;
        } else if msg.starts_with("pay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_pay();
                    return true;
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_pay();
                    return true;
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    println!("{}", e);
                    Self::help_pay();
                    return true;
                }
            };

            // return none if /public transaciton
            let comment_or_public = match caps.name("comment") {
                Some(m) if m.as_str() == "/public" => None,
                Some(m) => m.as_str().to_string().into(),
                None => String::new().into(),
            };

            let request = if let Some(comment) = comment_or_public {
                info!(
                    "Sending {} STG to {}",
                    format_money(amount),
                    recipient.to_hex()
                );
                WalletRequest::Payment {
                    recipient,
                    amount,
                    comment,
                }
            } else {
                info!(
                    "Sending {} STG to {}, with uncloaked recipient and amount.",
                    format_money(amount),
                    recipient.to_hex()
                );
                WalletRequest::PublicPayment { recipient, amount }
            };
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg.starts_with("spay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[5..]) {
                Some(c) => c,
                None => {
                    Self::help_spay();
                    return true;
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_spay();
                    return true;
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    println!("{}", e);
                    Self::help_spay();
                    return true;
                }
            };
            let comment = if let Some(m) = caps.name("comment") {
                m.as_str().to_string()
            } else {
                String::new()
            };

            info!(
                "Sending {} to {} via ValueShuffle",
                format_money(amount),
                recipient.to_hex()
            );
            let request = WalletRequest::SecurePayment {
                recipient,
                amount,
                comment,
            };
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg.starts_with("msg ") {
            let caps = match MSG_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_msg();
                    return true;
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    println!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_msg();
                    return true;
                }
            };
            let amount: i64 = 0;
            let comment = caps.name("msg").unwrap().as_str().to_string();
            assert!(comment.len() > 0);

            info!("Sending message to {}", recipient.to_hex());
            let request = WalletRequest::Payment {
                recipient,
                amount,
                comment,
            };
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg.starts_with("stake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[6..]) {
                Some(c) => c,
                None => {
                    Self::help_stake();
                    return true;
                }
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    println!("{}", e);
                    Self::help_stake();
                    return true;
                }
            };

            info!("Staking {} STG into escrow", format_money(amount));
            let request = WalletRequest::Stake { amount };
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "unstake" {
            info!("Unstaking all of the money from escrow");
            let request = WalletRequest::UnstakeAll {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg.starts_with("unstake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[8..]) {
                Some(c) => c,
                None => {
                    Self::help_unstake();
                    return true;
                }
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    println!("{}", e);
                    Self::help_unstake();
                    return true;
                }
            };

            info!("Unstaking {} STG from escrow", format_money(amount));
            let request = WalletRequest::Unstake { amount };
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "restake" {
            let request = WalletRequest::RestakeAll {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "cloak" {
            let request = WalletRequest::CloakAll {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg.starts_with("generator ") {
            let subcommand = &msg[10..];
            if subcommand.starts_with("stop") {
                println!("Stoping generator.");
                self.generator = None;
            } else if subcommand.starts_with("start ") {
                let mut keys = Vec::new();
                let keys_str = &subcommand[6..];
                for key in keys_str.split(',') {
                    let recipient = match PublicKey::try_from_hex(key.trim()) {
                        Ok(r) => r,
                        Err(e) => {
                            println!("Invalid wallet public key '{}': {}", key, e);
                            Self::help_generator();
                            return true;
                        }
                    };

                    keys.push(recipient)
                }
                if let Some(ref mut generator) = self.generator {
                    generator.add_destinations(keys)
                } else {
                    self.generator = Some(Generator::new(
                        self.wallet.clone(),
                        keys.clone(),
                        GeneratorMode::Regular,
                        false,
                    ));
                }
            } else {
                Self::help_generator()
            }
            return true;
        } else if msg == "show version" {
            println!(
                "Stegos {}.{}.{} ({} {})",
                env!("VERSION_MAJOR"),
                env!("VERSION_MINOR"),
                env!("VERSION_PATCH"),
                env!("VERSION_COMMIT"),
                env!("VERSION_DATE")
            );
            return true;
        } else if msg == "show keys" {
            let request = WalletRequest::KeysInfo {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "show balance" {
            let request = WalletRequest::BalanceInfo {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "show election" {
            let request = NodeRequest::ElectionInfo {};
            self.node_response = Some(self.node.request(request));
        } else if msg == "show escrow" {
            let request = NodeRequest::EscrowInfo {};
            self.node_response = Some(self.node.request(request));
        } else if msg == "show utxo" {
            let request = WalletRequest::UnspentInfo {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "show recovery" {
            let request = WalletRequest::GetRecovery {};
            self.wallet_response = Some(self.wallet.request(request));
        } else if msg == "db pop block" {
            self.node.pop_block();
            return true;
        } else {
            Self::help();
            return true;
        }
        return false; // keep stdin parked until result is received.
    }

    fn on_exit(&self) {
        std::process::exit(0);
    }

    fn on_node_response(&mut self, info: NodeResponse) {
        let output = match info {
            NodeResponse::EscrowInfo(info) => serde_yaml::to_string(&[info]),
            NodeResponse::ElectionInfo(info) => serde_yaml::to_string(&[info]),
        }
        .map_err(|_| fmt::Error)
        .unwrap();
        println!("{}\n...\n", output);
        self.stdin_th.thread().unpark();
    }

    fn on_wallet_notification(&mut self, notification: WalletNotification) {
        match notification {
            WalletNotification::Received(PaymentInfo { data, amount, .. }) => {
                if let PaymentPayloadData::Comment(comment) = data {
                    if amount == 0 && !comment.is_empty() {
                        info!("Incoming message: {}", comment);
                    }
                }
            }
            WalletNotification::ReceivedPublic(_) => {}
            WalletNotification::Spent(_) => {}
            WalletNotification::SpentPublic(_) => {}
            WalletNotification::Staked(_) => {}
            WalletNotification::Unstaked(_) => {}
            WalletNotification::BalanceChanged { balance } => {
                info!("Balance is {} STG", format_money(balance));
            }
        }
    }

    fn on_wallet_response(&mut self, response: WalletResponse) {
        let output = serde_yaml::to_string(&[response])
            .map_err(|_| fmt::Error)
            .unwrap();
        println!("{}\n...\n", output);
        self.stdin_th.thread().unpark();
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
                    if self.on_input(&line) {
                        self.stdin_th.thread().unpark();
                    }
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!(),
            }
        }

        loop {
            match self.wallet_notifications.poll() {
                Ok(Async::Ready(Some(notification))) => {
                    self.on_wallet_notification(notification);
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Wallet failure"),
            }
        }

        if self.wallet_response.is_some() {
            let mut rx = self.wallet_response.take().unwrap();
            match rx.poll() {
                Ok(Async::Ready(response)) => {
                    self.on_wallet_response(response);
                }
                Ok(Async::NotReady) => self.wallet_response = Some(rx),
                Err(_) => panic!("Wallet failure"),
            }
        }

        if let Some(mut rx) = self.node_response.take() {
            match rx.poll() {
                Ok(Async::Ready(response)) => {
                    self.on_node_response(response);
                }
                Ok(Async::NotReady) => self.node_response = Some(rx),
                Err(_) => panic!("Wallet failure"),
            }
        }

        loop {
            // Process unicast messages
            match self.unicast_rx.poll() {
                Ok(Async::Ready(Some(msg))) => {
                    info!(
                        "Received unicast message: from: {}, data: {}",
                        msg.from,
                        String::from_utf8_lossy(&msg.data)
                    );
                }
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => panic!("Unicast failure"),
            }
        }

        if let Some(ref mut generator) = self.generator {
            match generator.poll() {
                Ok(Async::NotReady) => {}
                _ => panic!("Generator finished."),
            }
        }

        return Ok(Async::NotReady);
    }
}

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
use crate::consts;
use crate::money::{format_money, parse_money};
use dirs;
use failure::Error;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::{Async, Future, Poll, Sink, Stream};
use lazy_static::*;
use log::trace;
use regex::Regex;
use rustyline as rl;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
pub use stegos_api::url;
use stegos_api::*;
use stegos_blockchain::Timestamp;
use stegos_crypto::curve1174::PublicKey;
use stegos_crypto::pbc;
use stegos_keychain::input;

const CONSOLE_HISTORY_LIMIT: u64 = 50;

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

// No public API provided.

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

lazy_static! {
    /// Regex to parse "pay" command.
    static ref PAY_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9A-Za-z]+)\s+(?P<amount>[0-9\.]{1,19})(?P<arguments>.+)?\s*$").unwrap();
    /// Regex to parse argument of "pay" command.
    static ref PAY_ARGUMENTS_RE: Regex = Regex::new(r"^(\s+(?P<public>(/public)))?(\s+(?P<comment>[^/]+?))?(\s+(?P<lock>(/lock\s*.*)))?(\s+(?P<fee>(/fee\s[0-9\.]{1,19})))?\s*$").unwrap();
    /// Regex to parse argument of "pay" command.
    static ref SPAY_ARGUMENTS_RE: Regex = Regex::new(r"^(\s+(?P<comment>[^/]+?))?(\s+(?P<lock>(/lock\s*.*)))?\s*$").unwrap();
    /// Regex to parse "msg" command.
    static ref MSG_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "stake/unstake" command.
    static ref STAKE_COMMAND_RE: Regex = Regex::new(r"\s*(?P<amount>[0-9\.]{1,19})\s*$").unwrap();
    /// Regex to parse "publish" command.
    static ref PUBLISH_COMMAND_RE: Regex = Regex::new(r"\s*(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.*)$").unwrap();
    /// Regex to parse "send" command.
    static ref SEND_COMMAND_RE: Regex = Regex::new(r"\s*(?P<recipient>[0-9a-f]+)\s+(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.+)$").unwrap();
}

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

/// Console (stdin) service.
pub struct ConsoleService {
    /// API client.
    client: WebSocketClient,
    /// A channel to receive message from stdin thread.
    stdin: Receiver<String>,
    /// A thread used for readline.
    stdin_th: thread::JoinHandle<()>,
}

impl ConsoleService {
    /// Constructor.
    pub fn new(uri: String, api_token: ApiToken) -> ConsoleService {
        let (tx, rx) = channel::<String>(1);
        let client = WebSocketClient::new(uri, api_token);
        let stdin_th = thread::spawn(move || Self::readline_thread_f(tx));
        let stdin = rx;
        ConsoleService {
            client,
            stdin,
            stdin_th,
        }
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
                    eprintln!("CLI I/O Error: {}", e);
                    break;
                }
            }
        }
        tx.close().ok(); // ignore errors
        if let Err(e) = rl.save_history(&history_path) {
            eprintln!("Failed to save CLI history: {}", e);
        };
    }

    fn help() {
        eprintln!("Usage:");
        eprintln!("pay WALLET_PUBKEY AMOUNT [COMMENT] [/public]  [/lock duration] [/fee fee] - send money");
        eprintln!(
            "spay WALLET_PUBKEY AMOUNT [COMMENT] [/lock duration] - send money using ValueShuffle"
        );
        eprintln!("msg WALLET_PUBKEY MESSAGE - send a message via blockchain");
        eprintln!("stake AMOUNT - stake money");
        eprintln!("unstake [AMOUNT] - unstake money");
        eprintln!("restake - restake all available stakes");
        eprintln!("cloak - exchange all available public outputs");
        eprintln!("show version - print version information");
        eprintln!("show keys - print keys");
        eprintln!("show balance - print balance");
        eprintln!("show utxo - print unspent outputs");
        eprintln!("show history [STARTING DATE] - print history since date");
        eprintln!("show election - print leader election state");
        eprintln!("show escrow - print escrow");
        eprintln!("show recovery - print recovery information");
        eprintln!("passwd - change wallet's password");
        eprintln!("net publish TOPIC MESSAGE - publish a network message via floodsub");
        eprintln!("net send NETWORK_PUBKEY TOPIC MESSAGE - send a network message via unicast");
        eprintln!("db pop block - revert the latest block");
        eprintln!();
    }

    fn help_publish() {
        eprintln!("Usage: net publish TOPIC MESSAGE");
        eprintln!(" - TOPIC topic");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn help_send() {
        eprintln!("Usage: net send NETWORK_PUBKEY TOPIC MESSAGE");
        eprintln!(" - NETWORK_PUBKEY recipient's network public key in HEX format");
        eprintln!(" - TOPIC topic");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn help_pay() {
        eprintln!("Usage: pay WALLET_PUBKEY AMOUNT [COMMENT] [/public] [/lock duration]");
        eprintln!(" - WALLET_PUBKEY recipient's wallet public key in HEX format");
        eprintln!(" - AMOUNT amount in tokens");
        eprintln!(" - COMMENT purpose of payment, no comments are allowed in public utxo.");
        eprintln!(" - /public if present, send money as PublicUTXO, with uncloaked recipient and amaount.");
        eprintln!(" - /lock if present, set the duration from which the output can be spent.");
        eprintln!(" - /fee FEE set desired fee per each created UTXO.");
        eprintln!();
    }

    fn help_spay() {
        eprintln!("Usage: spay WALLET_PUBKEY AMOUNT [COMMENT] [/lock duration]");
        eprintln!(" - WALLET_PUBKEY recipient's wallet public key in HEX format");
        eprintln!(" - AMOUNT amount in tokens");
        eprintln!(" - COMMENT purpose of payment");
        eprintln!(" - COMMENT purpose of payment, no comments are allowed in public utxo.");
        eprintln!(" - /lock if present, set the duration from which the output can be spent.");
        eprintln!();
    }

    fn help_stake() {
        eprintln!("Usage: stake AMOUNT");
        eprintln!(" - AMOUNT amount to stake into escrow, in tokens");
        eprintln!();
    }

    fn help_unstake() {
        eprintln!("Usage: unstake [AMOUNT]");
        eprintln!(" - AMOUNT amount to unstake from escrow, in tokens");
        eprintln!("   if not specified, unstakes all of the money.");
        eprintln!();
    }

    fn help_msg() {
        eprintln!("Usage: msg WALLET_PUBKEY MESSAGE");
        eprintln!(" - WALLET_PUBKEY recipient's public key in HEX format");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn send_network_request(&mut self, request: NetworkRequest) -> Result<(), WebSocketError> {
        let request = Request {
            kind: RequestKind::NetworkRequest(request),
            id: 0,
        };
        self.client.send(request)?;
        Ok(())
    }

    fn send_wallet_request(&mut self, request: WalletRequest) -> Result<(), WebSocketError> {
        let request = Request {
            kind: RequestKind::WalletRequest(request),
            id: 0,
        };
        self.client.send(request)?;
        Ok(())
    }

    fn send_node_request(&mut self, request: NodeRequest) -> Result<(), WebSocketError> {
        let request = Request {
            kind: RequestKind::NodeRequest(request),
            id: 0,
        };
        self.client.send(request)?;
        Ok(())
    }

    /// Called when line is typed on standard input.
    fn on_input(&mut self, msg: &str) -> Result<bool, Error> {
        if msg.starts_with("net publish ") {
            let caps = match PUBLISH_COMMAND_RE.captures(&msg[12..]) {
                Some(c) => c,
                None => {
                    Self::help_publish();
                    return Ok(true);
                }
            };

            let topic = caps.name("topic").unwrap().as_str().to_string();
            let msg = caps.name("msg").unwrap().as_str();
            println!("Publish: topic='{}', msg='{}'", topic, msg);
            let data = msg.as_bytes().to_vec();
            self.send_network_request(NetworkRequest::PublishBroadcast { topic, data })?;
            return Ok(true);
        } else if msg.starts_with("net send ") {
            let caps = match SEND_COMMAND_RE.captures(&msg[9..]) {
                Some(c) => c,
                None => {
                    Self::help_send();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match pbc::PublicKey::try_from_hex(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid network public key '{}': {}", recipient, e);
                    Self::help_send();
                    return Ok(true);
                }
            };
            let topic = caps.name("topic").unwrap().as_str().to_string();
            let msg = caps.name("msg").unwrap().as_str();
            println!(
                "Send: to='{}', topic='{}', msg='{}'",
                recipient.to_hex(),
                topic,
                msg
            );
            let data = msg.as_bytes().to_vec();
            self.send_network_request(NetworkRequest::SendUnicast {
                topic,
                to: recipient,
                data,
            })?;
            return Ok(true);
        } else if msg.starts_with("pay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_pay();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_pay();
                    return Ok(true);
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    eprintln!("{}", e);
                    Self::help_pay();
                    return Ok(true);
                }
            };

            let (public, comment, locked_timestamp, payment_fee) = match caps.name("arguments") {
                None => (false, String::new(), None, PAYMENT_FEE),

                Some(m) => {
                    let caps = match PAY_ARGUMENTS_RE.captures(m.as_str()) {
                        Some(c) => c,
                        None => {
                            Self::help_pay();
                            return Ok(true);
                        }
                    };

                    let public = caps.name("public").is_some();
                    let comment = caps
                        .name("comment")
                        .map(|s| String::from(s.as_str()))
                        .unwrap_or(String::new());

                    // if parse_lock_format return None, print help, and stop execute.
                    let locked_timestamp = caps.name("lock").map(|s| parse_lock_format(s.as_str()));
                    let locked_timestamp = match locked_timestamp {
                        Some(Some(locked_timestamp)) => Some(Timestamp::now() + locked_timestamp),
                        None => None,
                        Some(None) => {
                            Self::help_pay();
                            return Ok(true);
                        }
                    };

                    // Parse /fee.
                    let fee_arg = caps.name("fee").map(|s| {
                        assert!(s.as_str().starts_with("/fee "));
                        parse_money(&s.as_str()[5..])
                    });
                    let payment_fee = match fee_arg {
                        Some(Ok(fee)) => fee,
                        Some(Err(e)) => {
                            eprintln!("{}", e);
                            Self::help_pay();
                            return Ok(true);
                        }
                        None => PAYMENT_FEE, // use the default value.
                    };
                    (public, comment, locked_timestamp, payment_fee)
                }
            };

            if public && !comment.is_empty() {
                eprintln!("Comment in public utxo will be omitted.");
            }

            let request = if public {
                println!(
                    "Sending {} STG to {}, with uncloaked recipient and amount.",
                    format_money(amount),
                    String::from(&recipient)
                );
                let password = input::read_password_from_stdin(false)?;
                WalletRequest::PublicPayment {
                    password,
                    recipient,
                    amount,
                    payment_fee,
                    locked_timestamp,
                }
            } else {
                println!(
                    "Sending {} STG to {}",
                    format_money(amount),
                    String::from(&recipient)
                );
                let password = input::read_password_from_stdin(false)?;
                WalletRequest::Payment {
                    password,
                    recipient,
                    amount,
                    payment_fee,
                    comment,
                    locked_timestamp,
                }
            };
            self.send_wallet_request(request)?
        } else if msg.starts_with("spay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[5..]) {
                Some(c) => c,
                None => {
                    Self::help_spay();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_spay();
                    return Ok(true);
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    eprintln!("{}", e);
                    Self::help_spay();
                    return Ok(true);
                }
            };
            let (comment, locked_timestamp) = match caps.name("arguments") {
                None => (String::new(), None),

                Some(m) => {
                    let caps = match SPAY_ARGUMENTS_RE.captures(m.as_str()) {
                        Some(c) => c,
                        None => {
                            Self::help_spay();
                            return Ok(true);
                        }
                    };
                    let comment = caps
                        .name("comment")
                        .map(|s| String::from(s.as_str()))
                        .unwrap_or(String::new());

                    // if parse_lock_format return None, print help, and stop execute.
                    let locked_timestamp = caps.name("lock").map(|s| parse_lock_format(s.as_str()));
                    let locked_timestamp = match locked_timestamp {
                        Some(Some(locked_timestamp)) => Some(Timestamp::now() + locked_timestamp),
                        None => None,
                        Some(None) => {
                            Self::help_spay();
                            return Ok(true);
                        }
                    };

                    (comment, locked_timestamp)
                }
            };
            let payment_fee = PAYMENT_FEE;
            println!(
                "Sending {} to {} via ValueShuffle",
                format_money(amount),
                String::from(&recipient)
            );
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::SecurePayment {
                password,
                recipient,
                amount,
                payment_fee,
                comment,
                locked_timestamp,
            };
            self.send_wallet_request(request)?
        } else if msg.starts_with("msg ") {
            let caps = match MSG_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_msg();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid wallet public key '{}': {}", recipient, e);
                    Self::help_msg();
                    return Ok(true);
                }
            };
            let amount: i64 = 0;
            let payment_fee = PAYMENT_FEE;
            let comment = caps.name("msg").unwrap().as_str().to_string();
            assert!(comment.len() > 0);

            println!("Sending message to {}", String::from(&recipient));
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::Payment {
                password,
                recipient,
                amount,
                payment_fee,
                comment,
                locked_timestamp: None,
            };
            self.send_wallet_request(request)?
        } else if msg.starts_with("stake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[6..]) {
                Some(c) => c,
                None => {
                    Self::help_stake();
                    return Ok(true);
                }
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    eprintln!("{}", e);
                    Self::help_stake();
                    return Ok(true);
                }
            };
            let payment_fee = PAYMENT_FEE;

            println!("Staking {} STG into escrow", format_money(amount));
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::Stake {
                password,
                amount,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg == "unstake" {
            println!("Unstaking all of the money from escrow");
            let payment_fee = PAYMENT_FEE;
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::UnstakeAll {
                password,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg.starts_with("unstake ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[8..]) {
                Some(c) => c,
                None => {
                    Self::help_unstake();
                    return Ok(true);
                }
            };

            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    eprintln!("{}", e);
                    Self::help_unstake();
                    return Ok(true);
                }
            };
            let payment_fee = PAYMENT_FEE;

            println!("Unstaking {} STG from escrow", format_money(amount));
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::Unstake {
                password,
                amount,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg == "restake" {
            println!("Restaking all stakes");
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::RestakeAll { password };
            self.send_wallet_request(request)?
        } else if msg == "cloak" {
            println!("Cloaking all public inputs");
            let password = input::read_password_from_stdin(false)?;
            let payment_fee = PAYMENT_FEE;
            let request = WalletRequest::CloakAll {
                password,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg == "show version" {
            eprintln!(
                "Stegos {}.{}.{} ({} {})",
                env!("VERSION_MAJOR"),
                env!("VERSION_MINOR"),
                env!("VERSION_PATCH"),
                env!("VERSION_COMMIT"),
                env!("VERSION_DATE")
            );
            return Ok(true);
        } else if msg == "show keys" {
            let request = WalletRequest::KeysInfo {};
            self.send_wallet_request(request)?
        } else if msg == "show balance" {
            let request = WalletRequest::BalanceInfo {};
            self.send_wallet_request(request)?
        } else if msg == "show election" {
            let request = NodeRequest::ElectionInfo {};
            self.send_node_request(request)?
        } else if msg == "show escrow" {
            let request = NodeRequest::EscrowInfo {};
            self.send_node_request(request)?
        } else if msg == "show utxo" {
            let request = WalletRequest::UnspentInfo {};
            self.send_wallet_request(request)?
        } else if msg.starts_with("show history") {
            let arg = &msg[12..];

            let starting_from = humantime::parse_rfc3339(arg)?.into();
            let request = WalletRequest::HistoryInfo {
                starting_from,
                limit: CONSOLE_HISTORY_LIMIT,
            };
            self.send_wallet_request(request)?
        } else if msg == "show recovery" {
            let password = input::read_password_from_stdin(false)?;
            let request = WalletRequest::GetRecovery { password };
            self.send_wallet_request(request)?
        } else if msg == "passwd" {
            let old_password = input::read_password_from_stdin(false)?;
            let new_password = input::read_password_from_stdin(true)?;
            let request = WalletRequest::ChangePassword {
                old_password,
                new_password,
            };
            self.send_wallet_request(request)?
        } else if msg == "db pop block" {
            let request = NodeRequest::PopBlock {};
            self.send_node_request(request)?
        } else {
            Self::help();
            return Ok(true);
        }
        return Ok(false); // keep stdin parked until result is received.
    }

    fn on_exit(&self) {
        std::process::exit(0);
    }

    fn on_response(&mut self, response: Response) {
        let output = serde_yaml::to_string(&[&response])
            .map_err(|_| fmt::Error)
            .unwrap();
        eprintln!("{}\n...\n", output);
        match &response.kind {
            ResponseKind::NodeResponse(_) | ResponseKind::WalletResponse(_) => {
                self.stdin_th.thread().unpark();
            }
            _ => {}
        }
    }
}

// Event loop.
impl Future for ConsoleService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.client.poll() {
                Ok(Async::Ready(response)) => {
                    self.on_response(response);
                }
                Ok(Async::NotReady) => {
                    break;
                }
                Err(()) => unreachable!(),
            }
        }

        loop {
            match self.stdin.poll() {
                Ok(Async::Ready(Some(line))) => match self.on_input(&line) {
                    Ok(true) => {
                        self.stdin_th.thread().unpark();
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("{}", e);
                        self.stdin_th.thread().unpark();
                    }
                },
                Ok(Async::Ready(None)) => self.on_exit(),
                Ok(Async::NotReady) => break, // fall through
                Err(()) => unreachable!(),
            }
        }

        return Ok(Async::NotReady);
    }
}

fn parse_lock_format(lock_str: &str) -> Option<Duration> {
    trace!("Trying to parse duration from argument={}", lock_str);
    if !lock_str.starts_with("/lock ") {
        eprintln!("Can't find /lock command.");
        return None;
    };

    let lock_argument = &lock_str[6..];
    let duration = lock_argument.parse::<humantime::Duration>();
    trace!("Parsed duration = {:?}", duration);
    duration.map(Into::into).ok()
}

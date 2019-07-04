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
use crate::money::parse_money;
use dirs;
use failure::{format_err, Error};
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::{Async, Future, Poll, Sink, Stream};
use lazy_static::*;
use regex::Regex;
use rustyline as rl;
use serde::ser::Serialize;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
pub use stegos_api::url;
use stegos_api::*;
use stegos_blockchain::Timestamp;
use stegos_crypto::pbc;
use stegos_crypto::scc::PublicKey;
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
    static ref PAY_ARGUMENTS_RE: Regex = Regex::new(r"^(\s+(?P<public>(/public)))?(\s+(?P<snowball>(/snowball)))?(\s+(?P<comment>[^/]+?))?(\s+(?P<lock>(/lock\s*[^/]*)))?(\s+(?P<fee>(/fee\s[0-9\.]{1,19})))?(\s+(?P<certificate>(/certificate)))?\s*$").unwrap();
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
        // Use ~/.share/stegos/console.history for command line history.
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
        eprintln!(
            "pay ADDRESS AMOUNT [COMMENT] [/public] [/snowball] [/lock duration] [/fee fee] - send money"
        );
        eprintln!("msg ADDRESS MESSAGE - send a message via blockchain");
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
        eprintln!("net send NETWORK_ADDRESS TOPIC MESSAGE - send a network message via unicast");
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
        eprintln!("Usage: net send NETWORK_ADDRESS TOPIC MESSAGE");
        eprintln!(" - NETWORK_ADDRESS network address");
        eprintln!(" - TOPIC topic");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn help_pay() {
        eprintln!(
            "Usage: pay ADDRESS AMOUNT [COMMENT] [/snowball] [/public] [/lock DATETIME] [/fee FEE]"
        );
        eprintln!(" - ADDRESS recipient's address");
        eprintln!(" - AMOUNT amount in STG");
        eprintln!(" - COMMENT purpose of payment");
        eprintln!(" - /snowball use Snowball mixing protocol");
        eprintln!(" - /public don't encrypt recipient and amount (not recommended)");
        eprintln!(" - /lock DATETIME lock money until the specified time:");
        eprintln!("       '2019-07-01 12:52:11', '2019-07-01T12:52:11Z', '15days 2min 2s'");
        eprintln!(" - /fee FEE set fee per each created UTXO");
        eprintln!();
    }

    fn help_stake() {
        eprintln!("Usage: stake AMOUNT");
        eprintln!(" - AMOUNT amount to stake into escrow, in STG");
        eprintln!();
    }

    fn help_unstake() {
        eprintln!("Usage: unstake [AMOUNT]");
        eprintln!(" - AMOUNT amount to unstake from escrow, in STG");
        eprintln!("   if not specified, unstakes all of the money");
        eprintln!();
    }

    fn help_msg() {
        eprintln!("Usage: msg ADDRESS MESSAGE");
        eprintln!(" - ADDRESS recipient's address");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn send_network_request(&mut self, request: NetworkRequest) -> Result<(), WebSocketError> {
        Self::print(&request);
        let request = Request {
            kind: RequestKind::NetworkRequest(request),
            id: 0,
        };
        self.client.send(request)?;
        Ok(())
    }

    fn send_wallet_request(&mut self, request: WalletRequest) -> Result<(), Error> {
        match &request {
            WalletRequest::ChangePassword { .. } => {} // Don't print this request.
            _ => {
                Self::print(&request);
            }
        }

        let request = Request {
            kind: RequestKind::WalletRequest(request),
            id: 0,
        };
        self.client.send(request)?;
        Ok(())
    }

    fn send_node_request(&mut self, request: NodeRequest) -> Result<(), WebSocketError> {
        Self::print(&request);
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
            let data = msg.as_bytes().to_vec();
            self.send_network_request(NetworkRequest::PublishBroadcast { topic, data })?;
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
            let data = msg.as_bytes().to_vec();
            self.send_network_request(NetworkRequest::SendUnicast {
                topic,
                to: recipient,
                data,
            })?;
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

            let (public, snowball, comment, locked_timestamp, payment_fee, with_certificate) =
                match caps.name("arguments") {
                    None => (false, false, String::new(), None, PAYMENT_FEE, false),

                    Some(m) => {
                        let caps = match PAY_ARGUMENTS_RE.captures(m.as_str()) {
                            Some(c) => c,
                            None => {
                                Self::help_pay();
                                return Ok(true);
                            }
                        };

                        let public = caps.name("public").is_some();
                        let certificate = caps.name("certificate").is_some();
                        let snowball = caps.name("snowball").is_some();
                        let comment = caps
                            .name("comment")
                            .map(|s| String::from(s.as_str()))
                            .unwrap_or(String::new());

                        let locked_timestamp = match caps.name("lock") {
                            Some(s) => Some(parse_future_datetime(&s.as_str()[6..])?),
                            None => None,
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
                        (
                            public,
                            snowball,
                            comment,
                            locked_timestamp,
                            payment_fee,
                            certificate,
                        )
                    }
                };

            if public && snowball {
                return Err(format_err!("Snowball is not supported for public payments"));
            }

            if public && with_certificate {
                return Err(format_err!(
                    "Certificate is not supported for public payments"
                ));
            }

            if snowball && with_certificate {
                return Err(format_err!(
                    "Currently snowball with certificate is not supported"
                ));
            }

            if public && !comment.is_empty() {
                return Err(format_err!("Public payments doesn't support comments"));
            }

            let request = if snowball {
                WalletRequest::SecurePayment {
                    recipient,
                    amount,
                    payment_fee,
                    comment,
                    locked_timestamp,
                }
            } else if public {
                WalletRequest::PublicPayment {
                    recipient,
                    amount,
                    payment_fee,
                    locked_timestamp,
                }
            } else {
                WalletRequest::Payment {
                    recipient,
                    amount,
                    payment_fee,
                    comment,
                    locked_timestamp,
                    with_certificate,
                }
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

            let request = WalletRequest::Payment {
                recipient,
                amount,
                payment_fee,
                comment,
                locked_timestamp: None,
                with_certificate: false,
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
            let request = WalletRequest::Stake {
                amount,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg == "unstake" {
            let payment_fee = PAYMENT_FEE;
            let request = WalletRequest::UnstakeAll { payment_fee };
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
            let request = WalletRequest::Unstake {
                amount,
                payment_fee,
            };
            self.send_wallet_request(request)?
        } else if msg == "restake" {
            let request = WalletRequest::RestakeAll {};
            self.send_wallet_request(request)?
        } else if msg == "cloak" {
            let payment_fee = PAYMENT_FEE;
            let request = WalletRequest::CloakAll { payment_fee };
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
            let starting_from = if arg.is_empty() {
                Timestamp::now() - Duration::from_secs(86400)
            } else {
                parse_past_datetime(arg)?
            };
            let request = WalletRequest::HistoryInfo {
                starting_from,
                limit: CONSOLE_HISTORY_LIMIT,
            };
            self.send_wallet_request(request)?
        } else if msg == "show recovery" {
            let request = WalletRequest::GetRecovery {};
            self.send_wallet_request(request)?
        } else if msg == "passwd" {
            let new_password = input::read_password_from_stdin(true)?;
            let request = WalletRequest::ChangePassword { new_password };
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

    fn print<S: Serialize>(s: &S) {
        let output = serde_yaml::to_string(&[s]).map_err(|_| fmt::Error).unwrap();
        println!("{}\n...\n", output);
    }

    fn on_response(&mut self, response: Response) {
        Self::print(&response);
        match &response.kind {
            ResponseKind::NodeResponse(_)
            | ResponseKind::WalletResponse(_)
            | ResponseKind::NetworkResponse(_) => {
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

/// Parses durations in free form like 15days 2min 2s
/// Parses timestamp in RFC 3339/ ISO 8601 format: 2018-01-01T12:53:00Z
/// Parses timestamps in a weaker format: 2018-01-01 12:53:00
fn parse_future_datetime(s: &str) -> Result<Timestamp, Error> {
    match humantime::parse_duration(s) {
        Ok(duration) => Ok(Timestamp::now() + duration),
        Err(_e) => match humantime::parse_rfc3339(s) {
            Ok(timestamp) => Ok(timestamp.into()),
            Err(e) => return Err(e.into()),
        },
    }
}

/// See parse_future_datetime().
fn parse_past_datetime(s: &str) -> Result<Timestamp, Error> {
    match humantime::parse_duration(s) {
        Ok(duration) => Ok(Timestamp::now() - duration),
        Err(_e) => match humantime::parse_rfc3339(s) {
            Ok(timestamp) => Ok(timestamp.into()),
            Err(e) => return Err(e.into()),
        },
    }
}

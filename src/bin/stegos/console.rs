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
use failure::{format_err, Error};
use futures::future::Fuse;
use futures::prelude::*;
use futures::select;
use lazy_static::*;
use log::{debug, trace};
use regex::Regex;
use rpassword::prompt_password_stdout;
use rustyline as rl;
use serde::ser::Serialize;
use std::fmt;
use std::io::stdin;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stegos_api::*;
use stegos_blockchain::{chain_to_prefix, Timestamp};
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

// No public API provided.

// ----------------------------------------------------------------
// Internal Implementation.
// ----------------------------------------------------------------

lazy_static! {
    /// Regex to parse "pay" command.
    static ref PAY_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<recipient>[0-9A-Za-z]+)\s+(?P<amount>[0-9_]{1,25})(?P<arguments>.+)?$").unwrap();
    /// Regex to parse argument of "pay" command.
    static ref PAY_ARGUMENTS_RE: Regex = Regex::new(r"^(\s+(?P<public>(/public)))?(\s+(?P<snowball>(/snowball)))?(\s+(?P<comment>[^/]+?))?(\s+(?P<fee>(/fee\s[0-9_]{1,25})))?(\s+(?P<certificate>(/certificate)))?$").unwrap();
    /// Regex to parse "msg" command.
    static ref MSG_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<recipient>[0-9a-f]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "stake/unstake" command.
    static ref STAKE_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<amount>[0-9_]{1,25})$").unwrap();
    /// Regex to parse "publish" command.
    static ref PUBLISH_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.*)$").unwrap();
    /// Regex to parse "send" command.
    static ref SEND_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<recipient>[0-9a-f]+)\s+(?P<topic>[0-9A-Za-z]+)\s+(?P<msg>.+)$").unwrap();
    /// Regex to parse "validate certificate" command.
    static ref VALIDATE_CERTIFICATE_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<utxo>[0-9a-f]+)\s+(?P<spender>[0-9A-Za-z]+)\s+(?P<recipient>[0-9A-Za-z]+)\s+(?P<rvalue>[0-9a-f]+)$").unwrap();
    /// Regex to parse "show block" command.
    static ref SHOW_BLOCK_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<epoch>[0-9]+)(\s+(?P<offset>[0-9]+))?$").unwrap();
    /// Regex to parse "use" command.
    static ref USE_COMMAND_RE: Regex = Regex::new(r"^\s*(?P<account_id>[0-9A-Za-z]+)$").unwrap();
}

const RECOVERY_PROMPT: &'static str = "Enter 24-word recovery phrase: ";
const PASSWORD_PROMPT: &'static str = "Enter password: ";
const PASSWORD_PROMPT1: &'static str = "Enter new password: ";
const PASSWORD_PROMPT2: &'static str = "Enter same password again: ";
// The number of records in `show history`.
const CONSOLE_HISTORY_LIMIT: u64 = 50;

fn read_line() -> Result<Option<String>, std::io::Error> {
    let mut line = String::new();
    if stdin().read_line(&mut line)? == 0 {
        return Ok(None); // EOF
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }

    Ok(Some(line))
}

fn read_password() -> Result<String, std::io::Error> {
    if !atty::is(atty::Stream::Stdin) {
        return Ok(read_line()?.unwrap_or_default());
    }
    prompt_password_stdout(PASSWORD_PROMPT)
}

fn read_password_with_confirmation() -> Result<String, std::io::Error> {
    if !atty::is(atty::Stream::Stdin) {
        return Ok(read_line()?.unwrap_or_default());
    }
    loop {
        let password = prompt_password_stdout(PASSWORD_PROMPT1)?;
        if password.is_empty() {
            eprintln!("Password is empty. Try again.");
            continue;
        }
        let password2 = prompt_password_stdout(PASSWORD_PROMPT2)?;
        if password == password2 {
            return Ok(password);
        } else {
            eprintln!("Passwords do not match. Try again.");
            continue;
        }
    }
}

fn parse_money(amount: &str) -> Result<i64, Error> {
    amount
        .replace("_", "")
        .parse::<i64>()
        .map_err(|e| format_err!("{}", e))
}

const PAYMENT_FEE: i64 = 1_000; // 0.001 STG

pub enum Formatter {
    YAML,
    JSON,
}

impl FromStr for Formatter {
    type Err = Error;

    fn from_str(formatter: &str) -> Result<Self, Error> {
        match formatter {
            "yaml" => Ok(Formatter::YAML),
            "json" => Ok(Formatter::JSON),
            _ => Err(format_err!("Unknown formatter '{}'", formatter)),
        }
    }
}

/// Console (stdin) service.
pub struct ConsoleService {
    /// API client.
    client: WebSocketClient,
    /// Current Account Id.
    account_id: Arc<Mutex<AccountId>>,
    /// A channel to receive message from stdin thread.
    reader: Box<dyn Stream<Item = Result<String, Error>> + Unpin>,
    /// Display formatter.
    formatter: Formatter,
    /// Parse stdin line as JSON request.
    raw: bool,
    subscribed: bool,
}

impl ConsoleService {
    /// Constructor.
    pub async fn spawn(
        chain: Option<String>,
        name: String,
        version: String,
        uri: String,
        api_token: ApiToken,
        history_file: PathBuf,
        formatter: Formatter,
        raw: bool,
        subscribed: bool,
    ) -> Result<(), Error> {
        let mut client = WebSocketClient::new(uri, api_token).await?;
        let account_id = Arc::new(Mutex::new("1".to_string()));

        if let Some(chain) = &chain {
            debug!("Initialising cli for chain = {}", chain);
            stegos_crypto::set_network_prefix(chain_to_prefix(&chain))
                .expect("Network prefix not initialised.");
        } else {
            Self::try_chain_name_resolve(&mut client).await;
        }
        let (reader, raw) = if atty::is(atty::Stream::Stdin) {
            println!("{} {}", name, version);
            println!("Type 'help' to get help");
            println!();
            let th_account_id = account_id.clone();
            (
                Self::interactive_thread_f(history_file, th_account_id),
                false,
            )
        } else {
            (Self::noninteractive_thread_f(), raw)
        };
        let service = ConsoleService {
            client,
            account_id,
            reader,
            formatter,
            raw,
            subscribed,
        };
        service.run().await
    }

    async fn run(mut self) -> Result<(), Error> {
        let mut first_time = true;
        loop {
            let mut notification_orig = self.client.notification();

            let notification = unsafe { Pin::new_unchecked(&mut notification_orig) };
            let mut notification = notification.fuse();
            let mut reader = self.reader.next().fuse();
            if !first_time {
                reader = Fuse::terminated();
            }
            select! {
                item = notification => {
                    drop(notification_orig);
                    self.on_notification(item.unwrap());
                },
                input = reader => {
                    drop(notification_orig);
                    match input {
                        Some(Ok(line)) => {
                            self.on_input(&line).await?;
                        },
                        Some(Err(e)) => {
                            eprintln!("Error during processing stdin = {}", e);
                            break;
                        }
                        None => {
                            if !self.subscribed {
                                self.on_exit()
                            }
                            else {
                                println!("Keeping console for notifications.");
                                first_time = false;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // TODO: FIx pormt in async/await
    /// Background thread to read stdin with TTY.
    fn interactive_thread_f(
        history_file: PathBuf,
        account_id: Arc<Mutex<AccountId>>,
    ) -> Box<dyn Stream<Item = Result<String, Error>> + Unpin> {
        use futures::stream::try_unfold;
        use tokio::task;

        let config = rl::Config::builder()
            .history_ignore_space(true)
            .history_ignore_dups(true)
            .completion_type(rl::CompletionType::List)
            .auto_add_history(true)
            .edit_mode(rl::EditMode::Emacs)
            .build();

        let mut rl = rl::Editor::<()>::with_config(config);
        rl.load_history(&history_file).ok(); // just ignore errors

        let stream = try_unfold(rl, move |mut rl| {
            let account_id_ref = account_id.clone();
            let history_file_ref = history_file.clone();
            async {
                let handle = task::spawn_blocking(move || -> Result<_, Error> {
                    let prompt = format!("account#{}> ", account_id_ref.lock().unwrap().clone());
                    loop {
                        match rl.readline(&prompt) {
                            Ok(line) => {
                                if line.is_empty() {
                                    continue;
                                }
                                // Skip history for commands starting with whitespace.
                                if !line.starts_with(" ") {
                                    rl.add_history_entry(line.clone());
                                }

                                if let Err(e) = rl.save_history(&history_file_ref) {
                                    eprintln!(
                                        "Failed to save CLI history to {:?}: {}",
                                        history_file_ref, e
                                    );
                                };

                                return Ok(Some((line, rl)));
                            }
                            Err(rl::error::ReadlineError::Interrupted) => {
                                return Err(rl::error::ReadlineError::Interrupted.into())
                            }
                            Err(rl::error::ReadlineError::Eof) => {
                                return Err(rl::error::ReadlineError::Eof.into())
                            }
                            Err(err) => {
                                eprintln!("CLI I/O Error: {}", err);
                                return Err(err.into());
                            }
                        }
                    }
                });
                handle.await?
            }
        })
        .map_err(From::from);
        let stream = Box::pin(stream);
        Box::new(stream)
    }

    /// Background thread to read stdin without TTY.
    fn noninteractive_thread_f() -> Box<dyn Stream<Item = Result<String, Error>> + Unpin> {
        use tokio::io::{stdin, AsyncBufReadExt, BufReader};
        Box::new(BufReader::new(stdin()).lines().map_err(From::from))
    }

    fn help() {
        eprintln!("Usage:");

        eprintln!("show accounts - show available accounts");
        eprintln!("use ACCOUNT_ID - switch to a account");
        eprintln!("create account - add a new account");
        eprintln!("recover account - recover account from 24-word recovery phrase");
        eprintln!("delete account - delete active account");
        eprintln!("passwd - change account's password");
        eprintln!("lock - lock the account");
        eprintln!("unlock - unlock the account");
        eprintln!();
        eprintln!(
            "pay ADDRESS AMOUNT [COMMENT] [/snowball] [/public] [/fee FEE] [/certificate] - send money"
        );
        eprintln!("validate certificate UTXO SENDER_ADDRESS RECIPIENT_ADDRESS RVALUE - check that payment certificate is valid");
        eprintln!("msg ADDRESS MESSAGE - send a message via blockchain");
        eprintln!("stake remote - stake money to remote node, network key should be located near account key.");
        eprintln!("stake AMOUNT - stake money");
        eprintln!("stake all - stake all available money");
        eprintln!("unstake [AMOUNT] - unstake money");
        eprintln!("enable restaking - enable automatic re-staking (default)");
        eprintln!("disable restaking - disable automatic re-staking");
        eprintln!("cloak - exchange all available public outputs");
        eprintln!("show version - print version information");
        eprintln!("show validators - print active epoch validators list.");
        eprintln!("show keys - print keys");
        eprintln!("show balance - print balance");
        eprintln!("show utxo - print unspent outputs");
        eprintln!("show history [STARTING DATE] - print history since date");
        eprintln!("show election - show consensus state");
        eprintln!("show escrow - print escrow");
        eprintln!("show replication - show replication status");
        eprintln!("change upstream - change the current replication upstream");
        eprintln!("show recovery - print recovery information");
        eprintln!("show block EPOCH [OFFSET] - show a block");
        eprintln!("pop block - revert the latest micro block");
        eprintln!("subscribe chain EPOCH [OFFSET] - subscribe for blockchain changes");
        eprintln!("show status - show general information about node status");
        eprintln!("subscribe status - subscribe for status changes");
        eprintln!("subscribe wallet - subscribe for wallet updates");
        eprintln!("net publish TOPIC MESSAGE - publish a network message via floodsub");
        eprintln!("net send NETWORK_ADDRESS TOPIC MESSAGE - send a network message via unicast");
        eprintln!("net peers - show connected peers");
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
            "Usage: pay ADDRESS AMOUNT [COMMENT] [/snowball] [/public] [/fee FEE] [/certificate]"
        );
        eprintln!(" - ADDRESS recipient's address");
        eprintln!(" - AMOUNT amount in μSTG");
        eprintln!(" - COMMENT purpose of payment");
        eprintln!(" - /snowball use Snowball mixing protocol");
        eprintln!(" - /public don't encrypt recipient and amount (not recommended)");
        eprintln!("       '2019-07-01 12:52:11', '2019-07-01T12:52:11Z', '15days 2min 2s'");
        eprintln!(" - /fee FEE set fee in μSTG per each created UTXO");
        eprintln!(" - /certificate create payment certificate");
        eprintln!();
    }

    fn help_stake_remote() {
        eprintln!("Usage: stake_remote AMOUNT");
        eprintln!(" - AMOUNT amount to stake into escrow, in μSTG");
        eprintln!();
    }
    fn help_stake() {
        eprintln!("Usage: stake AMOUNT");
        eprintln!(" - AMOUNT amount to stake into escrow, in μSTG");
        eprintln!();
    }

    fn help_validate_certificate() {
        eprintln!("Usage: validate certificate UTXO SENDER_ADDRESS RECIPIENT_ADDRESS RVALUE");
        eprintln!(" - UTXO - UTXO ID");
        eprintln!(" - SENDER_ADDRESS - senders's address");
        eprintln!(" - RECIPIENT_ADDRESS - recipient's address");
        eprintln!(" - RVALUE - decryption key");
        eprintln!();
    }

    fn help_unstake() {
        eprintln!("Usage: unstake [AMOUNT]");
        eprintln!(" - AMOUNT amount to unstake from escrow, in μSTG");
        eprintln!("   if not specified, unstakes all of the money");
        eprintln!();
    }

    fn help_msg() {
        eprintln!("Usage: msg ADDRESS MESSAGE");
        eprintln!(" - ADDRESS recipient's address");
        eprintln!(" - MESSAGE some message");
        eprintln!();
    }

    fn help_use() {
        eprintln!("Usage: use ACCOUNT_ID");
        eprintln!();
    }

    fn help_show_block() {
        eprintln!("Usage: show block EPOCH [OFFSET]");
        eprintln!(" - EPOCH - epoch number");
        eprintln!(" - OFFSET - micro block offset");
        eprintln!();
    }

    fn help_subscribe_chain() {
        eprintln!("Usage: subscribe chain EPOCH [OFFSET]");
        eprintln!(" - EPOCH - epoch number");
        eprintln!(" - OFFSET - micro block offset");
        eprintln!();
    }

    async fn send_network_request(&mut self, request: NetworkRequest) -> Result<(), Error> {
        self.print(&request);
        let request = Request {
            kind: RequestKind::NetworkRequest(request),
            id: 0,
        };
        let response = self.client.request(request).await?;
        self.on_response(response);
        Ok(())
    }

    async fn send_wallet_control_request(
        &mut self,
        request: WalletControlRequest,
    ) -> Result<(), Error> {
        match &request {
            WalletControlRequest::CreateAccount { .. }
            | WalletControlRequest::RecoverAccount { .. } => {
                // Print passwords only if Trace level is enabled.
                if log::log_enabled!(log::Level::Trace) {
                    self.print(&request);
                }
            }
            _ => {
                self.print(&request);
            }
        }
        let request = WalletRequest::WalletControlRequest(request);
        let request = Request {
            kind: RequestKind::WalletsRequest(request),
            id: 0,
        };
        let response = self.client.request(request).await?;
        self.on_response(response);
        Ok(())
    }

    async fn send_account_request(&mut self, request: AccountRequest) -> Result<(), Error> {
        match &request {
            AccountRequest::ChangePassword { .. }
            | AccountRequest::Seal { .. }
            | AccountRequest::Unseal { .. } => {
                // Print passwords only if Trace level is enabled.
                if log::log_enabled!(log::Level::Trace) {
                    self.print(&request);
                }
            }
            _ => {
                self.print(&request);
            }
        }

        let account_id: String = self.account_id.lock().unwrap().clone();
        let request = WalletRequest::AccountRequest {
            account_id,
            request,
        };

        let request = Request {
            kind: RequestKind::WalletsRequest(request),
            id: 0,
        };
        let response = self.client.request(request).await?;
        self.on_response(response);
        Ok(())
    }

    async fn send_raw_request(&mut self, request: serde_json::Value) -> Result<(), Error> {
        trace!("Received raw request ={:?}", request);
        self.print(&request);
        let request = Request {
            kind: RequestKind::Raw(request),
            id: 0,
        };
        let response = self.client.request(request).await?;
        self.on_response(response);
        Ok(())
    }

    async fn send_node_request(&mut self, request: NodeRequest) -> Result<(), Error> {
        self.print(&request);
        let request = Request {
            kind: RequestKind::NodeRequest(request),
            id: 0,
        };
        let response = self.client.request(request).await?;
        self.on_response(response);
        Ok(())
    }

    /// Called when line is typed on standard input.
    async fn on_input(&mut self, msg: &str) -> Result<bool, Error> {
        if self.raw {
            let request: Request = serde_json::from_str(msg)?;
            match request.kind {
                RequestKind::NetworkRequest(request) => self.send_network_request(request).await?,
                RequestKind::WalletsRequest(WalletRequest::AccountRequest {
                    account_id,
                    request,
                }) => {
                    {
                        let mut locked = self.account_id.lock().unwrap();
                        *locked = account_id;
                    }
                    self.send_account_request(request).await?
                }
                RequestKind::WalletsRequest(WalletRequest::WalletControlRequest(request)) => {
                    self.send_wallet_control_request(request).await?
                }
                RequestKind::NodeRequest(request) => self.send_node_request(request).await?,
                RequestKind::Raw(request) => self.send_raw_request(request).await?,
            }
            return Ok(false); // keep stdin parked until response received.
        }

        let msg = msg.trim();
        if msg == "lock" || msg == "seal" {
            self.send_account_request(AccountRequest::Seal {}).await?;
        } else if msg == "unlock" || msg == "unseal" {
            let password = read_password()?;
            self.send_account_request(AccountRequest::Unseal { password })
                .await?;
        } else if msg.starts_with("net publish ") {
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
            self.send_network_request(NetworkRequest::PublishBroadcast { topic, data })
                .await?;
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
            })
            .await?;
        } else if msg.starts_with("net peers") {
            self.send_network_request(NetworkRequest::ConnectedNodesRequest {})
                .await?
        } else if msg.starts_with("pay ") {
            let caps = match PAY_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_pay();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match scc::PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid account public key '{}': {}", recipient, e);
                    Self::help_pay();
                    return Ok(true);
                }
            };
            let amount = caps.name("amount").unwrap().as_str();
            let amount = match parse_money(amount) {
                Ok(amount) => amount,
                Err(e) => {
                    eprintln!("Invalid amount '{}': {}", amount, e);
                    Self::help_pay();
                    return Ok(true);
                }
            };

            let (public, snowball, comment, payment_fee, with_certificate) =
                match caps.name("arguments") {
                    None => (false, false, String::new(), PAYMENT_FEE, false),

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

                        // Parse /fee.
                        let payment_fee = match caps.name("fee") {
                            Some(s) => {
                                assert!(s.as_str().starts_with("/fee "));
                                let fee = &s.as_str()[5..];
                                match parse_money(fee) {
                                    Ok(fee) => fee,
                                    Err(e) => {
                                        eprintln!("Invalid fee '{}': {}", fee, e);
                                        Self::help_pay();
                                        return Ok(true);
                                    }
                                }
                            }
                            None => PAYMENT_FEE, // use the default value.
                        };
                        (public, snowball, comment, payment_fee, certificate)
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
                AccountRequest::SecurePayment {
                    recipient,
                    amount,
                    payment_fee,
                    comment,
                }
            } else if public {
                AccountRequest::PublicPayment {
                    recipient,
                    amount,
                    payment_fee,
                    raw: false,
                }
            } else {
                AccountRequest::Payment {
                    recipient,
                    amount,
                    payment_fee,
                    comment,
                    with_certificate,
                    raw: false,
                }
            };
            self.send_account_request(request).await?
        } else if msg.starts_with("validate certificate ") {
            let caps = match VALIDATE_CERTIFICATE_COMMAND_RE.captures(&msg[20..]) {
                Some(c) => c,
                None => {
                    Self::help_validate_certificate();
                    return Ok(true);
                }
            };

            let utxo = caps.name("utxo").unwrap().as_str();
            let output_hash = match Hash::try_from_hex(utxo) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid UTXO hash '{}': {}", utxo, e);
                    Self::help_validate_certificate();
                    return Ok(true);
                }
            };

            let spender = caps.name("spender").unwrap().as_str();
            let spender = match scc::PublicKey::from_str(spender) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid spender address '{}': {}", spender, e);
                    Self::help_validate_certificate();
                    return Ok(true);
                }
            };
            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match scc::PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid recipient address '{}': {}", recipient, e);
                    Self::help_validate_certificate();
                    return Ok(true);
                }
            };
            let rvalue = caps.name("rvalue").unwrap().as_str();
            let rvalue = match scc::Fr::try_from_hex(rvalue) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid rvalue '{}': {}", rvalue, e);
                    Self::help_validate_certificate();
                    return Ok(true);
                }
            };

            let request = NodeRequest::ValidateCertificate {
                output_hash,
                spender,
                recipient,
                rvalue,
            };
            self.send_node_request(request).await?
        } else if msg.starts_with("msg ") {
            let caps = match MSG_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_msg();
                    return Ok(true);
                }
            };

            let recipient = caps.name("recipient").unwrap().as_str();
            let recipient = match scc::PublicKey::from_str(recipient) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid account public key '{}': {}", recipient, e);
                    Self::help_msg();
                    return Ok(true);
                }
            };
            let amount: i64 = 0;
            let payment_fee = PAYMENT_FEE;
            let comment = caps.name("msg").unwrap().as_str().to_string();
            assert!(comment.len() > 0);

            let request = AccountRequest::Payment {
                recipient,
                amount,
                payment_fee,
                comment,
                with_certificate: false,
                raw: false,
            };
            self.send_account_request(request).await?
        } else if msg.starts_with("stake all") {
            let payment_fee = PAYMENT_FEE;
            let request = AccountRequest::StakeAll { payment_fee };
            self.send_account_request(request).await?
        } else if msg.starts_with("stake remote ") {
            let caps = match STAKE_COMMAND_RE.captures(&msg[13..]) {
                Some(c) => c,
                None => {
                    Self::help_stake_remote();
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
            let payment_fee = PAYMENT_FEE;
            let request = AccountRequest::StakeRemote {
                amount,
                payment_fee,
            };
            self.send_account_request(request).await?
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
                    Self::help_pay();
                    return Ok(true);
                }
            };
            let payment_fee = PAYMENT_FEE;
            let request = AccountRequest::Stake {
                amount,
                payment_fee,
            };
            self.send_account_request(request).await?
        } else if msg == "unstake" {
            let payment_fee = PAYMENT_FEE;
            let request = AccountRequest::UnstakeAll { payment_fee };
            self.send_account_request(request).await?
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
            let request = AccountRequest::Unstake {
                amount,
                payment_fee,
            };
            self.send_account_request(request).await?
        } else if msg == "cloak" {
            let payment_fee = PAYMENT_FEE;
            let request = AccountRequest::CloakAll { payment_fee };
            self.send_account_request(request).await?
        } else if msg == "show version" {
            self.send_network_request(NetworkRequest::VersionInfo {})
                .await?;
            return Ok(true);
        } else if msg == "show validators" {
            self.send_node_request(NodeRequest::ValidatorsInfo {})
                .await?;
            return Ok(true);
        } else if msg == "show keys" {
            let request = AccountRequest::AccountInfo {};
            self.send_account_request(request).await?
        } else if msg == "show balance" {
            let request = AccountRequest::BalanceInfo {};
            self.send_account_request(request).await?
        } else if msg == "show election" {
            let request = NodeRequest::ElectionInfo {};
            self.send_node_request(request).await?
        } else if msg == "show escrow" {
            let request = NodeRequest::EscrowInfo {};
            self.send_node_request(request).await?
        } else if msg == "show replication" {
            let request = NodeRequest::ReplicationInfo {};
            self.send_node_request(request).await?
        } else if msg == "change upstream" {
            let request = NodeRequest::ChangeUpstream {};
            self.send_node_request(request).await?
        } else if msg == "show utxo" {
            let request = AccountRequest::UnspentInfo {};
            self.send_account_request(request).await?
        } else if msg == "show light replication" {
            let request = WalletControlRequest::LightReplicationInfo {};
            self.send_wallet_control_request(request).await?
        } else if msg.starts_with("show history") {
            let arg = &msg[12..];
            let starting_from = if arg.is_empty() {
                Timestamp::now() - Duration::from_secs(86400)
            } else {
                parse_past_datetime(arg)?
            };
            let request = AccountRequest::HistoryInfo {
                starting_from,
                limit: CONSOLE_HISTORY_LIMIT,
            };
            self.send_account_request(request).await?
        } else if msg == "show recovery" {
            let request = AccountRequest::GetRecovery {};
            self.send_account_request(request).await?
        } else if msg.starts_with("show block") {
            let caps = match SHOW_BLOCK_COMMAND_RE.captures(&msg[10..]) {
                Some(c) => c,
                None => {
                    Self::help_show_block();
                    return Ok(true);
                }
            };

            let request = if let Some(offset) = caps.name("offset") {
                let offset: u32 = offset.as_str().parse().unwrap();
                let epoch = caps.name("epoch").unwrap().as_str();
                let epoch: u64 = epoch.parse()?;
                NodeRequest::MicroBlockInfo { epoch, offset }
            } else {
                let epoch = caps.name("epoch").unwrap();
                let epoch: u64 = epoch.as_str().parse()?;
                NodeRequest::MacroBlockInfo { epoch }
            };
            self.send_node_request(request).await?
        } else if msg.starts_with("subscribe chain") {
            let caps = match SHOW_BLOCK_COMMAND_RE.captures(&msg[15..]) {
                Some(c) => c,
                None => {
                    Self::help_subscribe_chain();
                    return Ok(true);
                }
            };

            let epoch: u64 = caps.name("epoch").unwrap().as_str().parse()?;
            let offset: u32 = if let Some(offset) = caps.name("offset") {
                offset.as_str().parse()?
            } else {
                0u32
            };
            let request = NodeRequest::SubscribeChain { epoch, offset };
            self.send_node_request(request).await?
        } else if msg.starts_with("show status") {
            let request = NodeRequest::StatusInfo {};
            self.send_node_request(request).await?
        } else if msg.starts_with("subscribe status") {
            let request = NodeRequest::SubscribeStatus {};
            self.send_node_request(request).await?
        } else if msg.starts_with("subscribe wallet") {
            let request = WalletControlRequest::SubscribeWalletUpdates {};
            self.send_wallet_control_request(request).await?
        } else if msg == "show accounts" {
            let request = WalletControlRequest::AccountsInfo {};
            self.send_wallet_control_request(request).await?;
        } else if msg == "create account" {
            let password = read_password_with_confirmation()?;
            let request = WalletControlRequest::CreateAccount { password };
            self.send_wallet_control_request(request).await?;
        } else if msg == "recover account" {
            let recovery = {
                if !atty::is(atty::Stream::Stdin) {
                    read_line()?.unwrap_or_default()
                } else {
                    prompt_password_stdout(RECOVERY_PROMPT)?
                }
            };
            let password = read_password_with_confirmation()?;
            let request = WalletControlRequest::RecoverAccount {
                recovery: AccountRecovery { recovery },
                password,
            };
            self.send_wallet_control_request(request).await?;
        } else if msg == "passwd" {
            let new_password = read_password_with_confirmation()?;
            let request = AccountRequest::ChangePassword { new_password };
            self.send_account_request(request).await?
        } else if msg.starts_with("use ") {
            let caps = match USE_COMMAND_RE.captures(&msg[4..]) {
                Some(c) => c,
                None => {
                    Self::help_use();
                    return Ok(true);
                }
            };
            let account_id = caps.name("account_id").unwrap().as_str().to_string();
            let mut locked = self.account_id.lock().unwrap();
            *locked = account_id;
            return Ok(true);
        } else if msg.starts_with("delete account") {
            eprint!("Are you sure? Please type YES to continue: ");
            let mut yes = String::new();
            stdin().read_line(&mut yes).unwrap();
            if yes.trim_end() != "YES" {
                eprintln!("Cancelled");
                return Ok(true);
            }
            let account_id = {
                let mut locked = self.account_id.lock().unwrap();
                let account_id = locked.clone();
                *locked = String::new();
                account_id
            };
            let request = WalletControlRequest::DeleteAccount { account_id };
            self.send_wallet_control_request(request).await?;
        } else if msg == "pop block" {
            let request = NodeRequest::PopMicroBlock {};
            self.send_node_request(request).await?
        } else if msg == "enable restaking" {
            let request = NodeRequest::EnableRestaking {};
            self.send_node_request(request).await?
        } else if msg == "disable restaking" {
            let request = NodeRequest::DisableRestaking {};
            self.send_node_request(request).await?
        } else {
            Self::help();
            return Ok(true);
        }
        return Ok(false); // keep stdin parked until result is received.
    }

    fn on_exit(&self) {
        std::process::exit(0);
    }

    fn print<S: Serialize>(&self, s: &S) {
        match self.formatter {
            Formatter::YAML => {
                let output = serde_yaml::to_string(&[s]).map_err(|_| fmt::Error).unwrap();
                println!("{}\n...\n", output);
            }
            Formatter::JSON => {
                let output = serde_json::to_string_pretty(&s)
                    .map_err(|_| fmt::Error)
                    .unwrap();
                println!("{}\n", output);
            }
        }
    }
    fn on_notification(&mut self, notification: Response) {
        self.print(&notification);
    }

    fn on_response(&mut self, response: Response) {
        match &response.kind {
            ResponseKind::NodeResponse(_)
            | ResponseKind::WalletResponse(_)
            | ResponseKind::NetworkResponse(_) => {
                self.print(&response);
            }
            _ => {
                self.print(&response);
            }
        }
    }

    async fn try_chain_name_resolve(client: &mut WebSocketClient) {
        let request = Request {
            kind: RequestKind::NetworkRequest(NetworkRequest::ChainName {}),
            id: 0,
        };
        let response = client.request(request).await.unwrap();
        let chain = match response {
            Response {
                kind: ResponseKind::NetworkResponse(NetworkResponse::ChainName { name }),
                ..
            } => name,
            response => panic!("Wrong reponse to chain name request = {:?}", response),
        };
        debug!("Initialising cli for chain = {}", chain);
        stegos_crypto::set_network_prefix(chain_to_prefix(&chain))
            .expect("Network prefix not initialised.");
    }
}

/// Parses durations in free form like 15days 2min 2s
/// Parses timestamp in RFC 3339/ ISO 8601 format: 2018-01-01T12:53:00Z
/// Parses timestamps in a weaker format: 2018-01-01 12:53:00
fn parse_past_datetime(s: &str) -> Result<Timestamp, Error> {
    match humantime::parse_duration(s) {
        Ok(duration) => Ok(Timestamp::now() - duration),
        Err(_e) => match humantime::parse_rfc3339(s) {
            Ok(timestamp) => Ok(timestamp.into()),
            Err(e) => return Err(e.into()),
        },
    }
}

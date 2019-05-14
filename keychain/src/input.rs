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

use crate::error::KeyError;
use crate::recovery::recovery_to_wallet_skey;
use log::*;
use rpassword::prompt_password_stdout;
use std::fs;
use std::path::Path;
use stegos_crypto::curve1174;

/// PEM tag for encrypted wallet secret key.
const RECOVERY_PROMPT: &'static str = "Enter 24-word recovery phrase: ";
const PASSWORD_PROMPT1: &'static str = "Enter password: ";
const PASSWORD_PROMPT2: &'static str = "Enter same password again: ";

fn fix_newline(password: &mut String) {
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
}

fn read_recovery_from_stdin() -> Result<curve1174::SecretKey, KeyError> {
    loop {
        let recovery = prompt_password_stdout(RECOVERY_PROMPT)
            .map_err(|e| KeyError::InputOutputError("stdin".to_string(), e))?;
        match recovery_to_wallet_skey(&recovery) {
            Ok(skey) => return Ok(skey),
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        }
    }
}

fn read_recovery_from_file(recovery_file: &str) -> Result<curve1174::SecretKey, KeyError> {
    info!("Reading recovery phrase from file {}...", recovery_file);
    let recovery_file_path = Path::new(recovery_file);
    let mut recovery = fs::read_to_string(recovery_file_path)
        .map_err(|e| KeyError::InputOutputError(recovery_file.to_string(), e))?;
    fix_newline(&mut recovery);
    Ok(recovery_to_wallet_skey(&recovery)?)
}

pub(crate) fn read_recovery(recovery_file: &str) -> Result<curve1174::SecretKey, KeyError> {
    if recovery_file == "-" && atty::is(atty::Stream::Stdin) {
        read_recovery_from_stdin()
    } else {
        read_recovery_from_file(recovery_file)
    }
}

pub(crate) fn read_password_from_stdin(confirm: bool) -> Result<String, KeyError> {
    loop {
        let password = prompt_password_stdout(PASSWORD_PROMPT1)
            .map_err(|e| KeyError::InputOutputError("stdin".to_string(), e))?;
        if password.is_empty() {
            eprintln!("Password is empty. Try again.");
            continue;
        }
        if !confirm {
            return Ok(password);
        }
        let password2 = prompt_password_stdout(PASSWORD_PROMPT2)
            .map_err(|e| KeyError::InputOutputError("stdin".to_string(), e))?;
        if password == password2 {
            return Ok(password);
        } else {
            eprintln!("Passwords do not match. Try again.");
            continue;
        }
    }
}

fn read_password_from_file(password_file: &str) -> Result<String, KeyError> {
    info!("Reading password from file {}...", password_file);
    let password_file_path = Path::new(password_file);
    let mut password = fs::read_to_string(password_file_path)
        .map_err(|e| KeyError::InputOutputError(password_file.to_string(), e))?;
    fix_newline(&mut password);
    Ok(password)
}

pub(crate) fn read_password(password_file: &str, confirm: bool) -> Result<String, KeyError> {
    if password_file == "-" && atty::is(atty::Stream::Stdin) {
        read_password_from_stdin(confirm)
    } else {
        read_password_from_file(password_file)
    }
}

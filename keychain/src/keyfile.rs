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
use crate::pem;
use log::*;
use std::fs;
use std::path::Path;
use stegos_crypto::curve1174;
use stegos_crypto::pbc;
use stegos_serialization::traits::ProtoConvert;

/// PEM tag for encrypted wallet secret key.
const WALLET_ENCRYPTED_SKEY_TAG: &'static str = "STEGOS-CURVE1174 ENCRYPTED SECRET KEY";
/// PEM tag for wallet public key.
const WALLET_PKEY_TAG: &'static str = "STEGOS-CURVE1174 PUBLIC KEY";
/// PEM tag for encrypted network secret key.
const NETWORK_ENCRYPTED_SKEY_TAG: &'static str = "STEGOS-PBC ENCRYPTED SECRET KEY";
/// PEM tag for network public key.
const NETWORK_PKEY_TAG: &'static str = "STEGOS-PBC PUBLIC KEY";

fn load_key(path: &Path, tag: &str) -> Result<Vec<u8>, KeyError> {
    let pem = fs::read_to_string(path)
        .map_err(|e| KeyError::InputOutputError(path.to_string_lossy().to_string(), e))?;
    let pem =
        pem::parse(pem).map_err(|e| KeyError::ParseError(path.to_string_lossy().to_string(), e))?;
    if pem.tag != tag {
        return Err(KeyError::InvalidTag(
            path.to_string_lossy().to_string(),
            tag.to_string(),
            pem.tag,
        ));
    }
    Ok(pem.contents)
}

fn load_encrypted_key(path: &Path, tag: &str, password: &str) -> Result<Vec<u8>, KeyError> {
    let skey = load_key(path, tag)?;
    let skey = curve1174::EncryptedKey::from_buffer(&skey)
        .map_err(|e| KeyError::InvalidPayload(path.to_string_lossy().to_string(), e))?;
    let skey = curve1174::decrypt_key(&password, &skey)
        .map_err(|_e| KeyError::InvalidPasswordPhrase(path.to_string_lossy().to_string()))?;
    Ok(skey)
}

pub fn load_wallet_pkey(path: &Path) -> Result<curve1174::PublicKey, KeyError> {
    let pkey = load_key(path, WALLET_PKEY_TAG)?;
    curve1174::PublicKey::try_from_bytes(&pkey)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_network_pkey(path: &Path) -> Result<pbc::PublicKey, KeyError> {
    let pkey = load_key(path, NETWORK_PKEY_TAG)?;
    pbc::PublicKey::try_from_bytes(&pkey)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_wallet_skey(path: &Path, password: &str) -> Result<curve1174::SecretKey, KeyError> {
    let bytes = load_encrypted_key(path, WALLET_ENCRYPTED_SKEY_TAG, password)?;
    curve1174::SecretKey::try_from_bytes(&bytes)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_network_skey(path: &Path, password: &str) -> Result<pbc::SecretKey, KeyError> {
    let bytes = load_encrypted_key(path, NETWORK_ENCRYPTED_SKEY_TAG, password)?;
    pbc::SecretKey::try_from_bytes(&bytes)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

fn write_key(path: &Path, tag: &str, contents: Vec<u8>) -> Result<(), KeyError> {
    let pem = pem::Pem {
        tag: tag.to_string(),
        contents,
    };
    fs::write(path, pem::encode(&pem))
        .map_err(|e| KeyError::InputOutputError(path.to_string_lossy().to_string(), e))
}

fn write_encrypted_key(
    path: &Path,
    tag: &str,
    contents: Vec<u8>,
    password: &str,
) -> Result<(), KeyError> {
    let contents = curve1174::encrypt_key(&password, &contents)
        .into_buffer()
        .expect("Failed to encode encrypted payload");
    write_key(path, tag, contents)
}

pub fn write_wallet_pkey(path: &Path, pkey: &curve1174::PublicKey) -> Result<(), KeyError> {
    write_key(path, WALLET_PKEY_TAG, pkey.to_bytes().to_vec())
}

pub fn write_network_pkey(path: &Path, pkey: &pbc::PublicKey) -> Result<(), KeyError> {
    write_key(path, NETWORK_PKEY_TAG, pkey.to_bytes().to_vec())
}

pub fn write_wallet_skey(
    path: &Path,
    skey: &curve1174::SecretKey,
    password: &str,
) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_encrypted_key(path, WALLET_ENCRYPTED_SKEY_TAG, contents, password)
}

pub fn write_network_skey(
    path: &Path,
    skey: &pbc::SecretKey,
    password: &str,
) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_encrypted_key(path, NETWORK_ENCRYPTED_SKEY_TAG, contents, password)
}

pub fn load_wallet_keypair(
    wallet_skey_file: &str,
    wallet_pkey_file: &str,
    password: &str,
) -> Result<(curve1174::SecretKey, curve1174::PublicKey), KeyError> {
    debug!(
        "Loading wallet key pair: wallet_skey_file={}, wallet_pkey_file={}...",
        wallet_skey_file, wallet_pkey_file
    );
    let wallet_pkey = load_wallet_pkey(Path::new(wallet_pkey_file))?;
    let wallet_skey = load_wallet_skey(Path::new(wallet_skey_file), password)?;
    if let Err(_e) = curve1174::check_keying(&wallet_skey, &wallet_pkey) {
        return Err(KeyError::InvalidKeying(
            wallet_skey_file.to_string(),
            wallet_pkey_file.to_string(),
        ));
    }
    info!("Loaded wallet key pair: pkey={}", wallet_pkey);
    Ok((wallet_skey, wallet_pkey))
}

pub fn load_network_keypair(
    network_skey_file: &str,
    network_pkey_file: &str,
    password: &str,
) -> Result<(pbc::SecretKey, pbc::PublicKey), KeyError> {
    debug!(
        "Loading network key pair: network_skey_file={}, network_pkey_file={}...",
        network_skey_file, network_pkey_file
    );
    let network_pkey = load_network_pkey(Path::new(network_pkey_file))?;
    let network_skey = load_network_skey(Path::new(network_skey_file), password)?;

    if let Err(_e) = pbc::check_keying(&network_skey, &network_pkey) {
        return Err(KeyError::InvalidKeying(
            network_skey_file.to_string(),
            network_pkey_file.to_string(),
        ));
    }
    info!("Loaded network key pair: pkey={}", network_pkey);
    Ok((network_skey, network_pkey))
}

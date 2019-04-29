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
use std::fs;
use std::path::Path;
use stegos_crypto::curve1174::cpt;
use stegos_crypto::pbc::secure;
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
    let skey = cpt::EncryptedKey::from_buffer(&skey)
        .map_err(|e| KeyError::InvalidPayload(path.to_string_lossy().to_string(), e))?;
    let skey = cpt::decrypt_key(&password, &skey)
        .map_err(|_e| KeyError::InvalidPasswordPhrase(path.to_string_lossy().to_string()))?;
    Ok(skey)
}

pub(crate) fn load_wallet_pkey(path: &Path) -> Result<cpt::PublicKey, KeyError> {
    let pkey = load_key(path, WALLET_PKEY_TAG)?;
    cpt::PublicKey::try_from_bytes(&pkey)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub(crate) fn load_network_pkey(path: &Path) -> Result<secure::PublicKey, KeyError> {
    let pkey = load_key(path, NETWORK_PKEY_TAG)?;
    secure::PublicKey::try_from_bytes(&pkey)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub(crate) fn load_wallet_skey(path: &Path, password: &str) -> Result<cpt::SecretKey, KeyError> {
    let bytes = load_encrypted_key(path, WALLET_ENCRYPTED_SKEY_TAG, password)?;
    cpt::SecretKey::try_from_bytes(&bytes)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub(crate) fn load_network_skey(
    path: &Path,
    password: &str,
) -> Result<secure::SecretKey, KeyError> {
    let bytes = load_encrypted_key(path, NETWORK_ENCRYPTED_SKEY_TAG, password)?;
    secure::SecretKey::try_from_bytes(&bytes)
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
    let contents = cpt::encrypt_key(&password, &contents)
        .into_buffer()
        .expect("Failed to encode encrypted payload");
    write_key(path, tag, contents)
}

pub(crate) fn write_wallet_pkey(path: &Path, pkey: &cpt::PublicKey) -> Result<(), KeyError> {
    write_key(path, WALLET_PKEY_TAG, pkey.to_bytes().to_vec())
}

pub(crate) fn write_network_pkey(path: &Path, pkey: &secure::PublicKey) -> Result<(), KeyError> {
    write_key(path, NETWORK_PKEY_TAG, pkey.to_bytes().to_vec())
}

pub(crate) fn write_wallet_skey(
    path: &Path,
    skey: &cpt::SecretKey,
    password: &str,
) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_encrypted_key(path, WALLET_ENCRYPTED_SKEY_TAG, contents, password)
}

pub(crate) fn write_network_skey(
    path: &Path,
    skey: &secure::SecretKey,
    password: &str,
) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_encrypted_key(path, NETWORK_ENCRYPTED_SKEY_TAG, contents, password)
}

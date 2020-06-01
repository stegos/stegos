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
use std::str::FromStr;

use stegos_crypto::pbc;
use stegos_crypto::scc;
use stegos_serialization::traits::ProtoConvert;

/// PEM tag for encrypted account secret key.
const ACCOUNT_ENCRYPTED_SKEY_TAG: &'static str = "STEGOS-CURVE25519 ENCRYPTED SECRET KEY";
/// PEM tag for network secret key.
const NETWORK_SKEY_TAG: &'static str = "STEGOS-PBC SECRET KEY";

fn read(path: &Path) -> Result<Vec<u8>, KeyError> {
    match fs::read(path) {
        Ok(r) => Ok(r),
        Err(e) => {
            let path = path.to_string_lossy().to_string();
            error!("Failed to read file: path={}, error={}", path, e);
            Err(KeyError::InputOutputError(path, e))
        }
    }
}

fn write(path: &Path, contents: Vec<u8>) -> Result<(), KeyError> {
    let tmp_path = path.with_extension(".tmp");
    if let Err(e) = fs::write(&tmp_path, contents) {
        let path_str = path.to_string_lossy().to_string();
        error!("Failed to write to file: path={}, error={}", path_str, e);
        if let Err(e) = fs::remove_file(&tmp_path) {
            error!("Failed to remove file: path={}, error={}", path_str, e);
        }
        return Err(KeyError::InputOutputError(path_str, e));
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let path_str = path.to_string_lossy().to_string();
        error!(
            "Failed to rename file: from={}, to={}, error={}",
            tmp_path.to_string_lossy(),
            path_str,
            e
        );
        return Err(KeyError::InputOutputError(path_str, e));
    }
    Ok(())
}

fn load_key(path: &Path, tag: &str) -> Result<Vec<u8>, KeyError> {
    let pem = read(path)?;
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
    let skey = scc::EncryptedKey::from_buffer(&skey)
        .map_err(|e| KeyError::InvalidPayload(path.to_string_lossy().to_string(), e))?;
    let skey = scc::decrypt_key(&password, &skey)
        .map_err(|_e| KeyError::InvalidPasswordPhrase(path.to_string_lossy().to_string()))?;
    Ok(skey)
}

pub fn load_account_pkey(path: &Path) -> Result<scc::PublicKey, KeyError> {
    let pkey_encoded = read(path)?;
    scc::PublicKey::from_str(String::from_utf8_lossy(&pkey_encoded).trim())
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_network_pkey(path: &Path) -> Result<pbc::PublicKey, KeyError> {
    let pkey = read(path)?;
    pbc::PublicKey::try_from_hex(String::from_utf8_lossy(&pkey).trim())
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_account_skey(path: &Path, password: &str) -> Result<scc::SecretKey, KeyError> {
    let bytes = load_encrypted_key(path, ACCOUNT_ENCRYPTED_SKEY_TAG, password)?;
    scc::SecretKey::try_from_bytes(&bytes)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

pub fn load_network_skey(path: &Path) -> Result<pbc::SecretKey, KeyError> {
    let bytes = load_key(path, NETWORK_SKEY_TAG)?;
    pbc::SecretKey::try_from_bytes(&bytes)
        .map_err(|e| KeyError::InvalidKey(path.to_string_lossy().to_string(), e))
}

fn write_key(path: &Path, tag: &str, contents: Vec<u8>) -> Result<(), KeyError> {
    let pem = pem::Pem {
        tag: tag.to_string(),
        contents,
    };
    write(path, pem::encode(&pem).into_bytes())
}

fn write_encrypted_key(
    path: &Path,
    tag: &str,
    contents: Vec<u8>,
    password: &str,
) -> Result<(), KeyError> {
    let contents = scc::encrypt_key(&password, &contents)
        .into_buffer()
        .expect("Failed to encode encrypted payload");
    write_key(path, tag, contents)
}

pub fn write_account_pkey(path: &Path, pkey: &scc::PublicKey) -> Result<(), KeyError> {
    write(path, String::from(pkey).as_bytes().to_vec())
}

pub fn write_network_pkey(path: &Path, pkey: &pbc::PublicKey) -> Result<(), KeyError> {
    write(path, pkey.to_hex().as_bytes().to_vec())
}

pub fn write_account_skey(
    path: &Path,
    skey: &scc::SecretKey,
    password: &str,
) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_encrypted_key(path, ACCOUNT_ENCRYPTED_SKEY_TAG, contents, password)
}

pub fn write_network_skey(path: &Path, skey: &pbc::SecretKey) -> Result<(), KeyError> {
    let contents = skey.to_bytes().to_vec();
    write_key(path, NETWORK_SKEY_TAG, contents)
}

pub fn load_account_keypair(
    account_skey_file: &Path,
    account_pkey_file: &Path,
    password: &str,
) -> Result<(scc::SecretKey, scc::PublicKey), KeyError> {
    debug!(
        "Loading account key pair: account_skey_file={}, account_pkey_file={}...",
        account_skey_file.to_string_lossy(),
        account_pkey_file.to_string_lossy()
    );
    let account_pkey = load_account_pkey(account_pkey_file)?;
    let account_skey = load_account_skey(account_skey_file, password)?;
    if let Err(_e) = scc::check_keying(&account_skey, &account_pkey) {
        return Err(KeyError::InvalidKeying(
            account_skey_file.to_string_lossy().to_string(),
            account_pkey_file.to_string_lossy().to_string(),
        ));
    }
    info!("Loaded account key pair: pkey={}", account_pkey);
    Ok((account_skey, account_pkey))
}

pub fn load_network_keypair(
    network_skey_file: &Path,
    network_pkey_file: &Path,
) -> Result<(pbc::SecretKey, pbc::PublicKey), KeyError> {
    debug!(
        "Loading network key pair: network_skey_file={}, network_pkey_file={}...",
        network_skey_file.to_string_lossy(),
        network_pkey_file.to_string_lossy()
    );
    let network_pkey = load_network_pkey(network_pkey_file)?;
    let network_skey = load_network_skey(network_skey_file)?;

    if let Err(_e) = pbc::check_keying(&network_skey, &network_pkey) {
        return Err(KeyError::InvalidKeying(
            network_skey_file.to_string_lossy().to_string(),
            network_pkey_file.to_string_lossy().to_string(),
        ));
    }
    info!("Loaded network key pair: pkey={}", network_pkey);
    Ok((network_skey, network_pkey))
}

/// Load or create network keys.
pub fn load_network_keys(
    network_skey_file: &Path,
    network_pkey_file: &Path,
) -> Result<(pbc::SecretKey, pbc::PublicKey), KeyError> {
    if !network_skey_file.exists() && !network_pkey_file.exists() {
        debug!(
            "Can't find network keys on the disk: skey_file={}, pkey_file={}",
            network_skey_file.to_string_lossy(),
            network_pkey_file.to_string_lossy()
        );

        debug!("Generating a new network key pair...");
        let (network_skey, network_pkey) = pbc::make_random_keys();
        info!(
            "Generated a new network key pair: pkey={}",
            network_pkey.to_hex()
        );

        write_network_pkey(&network_pkey_file, &network_pkey)?;
        write_network_skey(&network_skey_file, &network_skey)?;
        info!(
            "Wrote network key pair to the disk: skey_file={}, pkey_file={}",
            network_skey_file.to_string_lossy(),
            network_pkey_file.to_string_lossy(),
        );

        Ok((network_skey, network_pkey))
    } else {
        debug!("Loading network keys from the disk...");
        let (network_skey, network_pkey) =
            load_network_keypair(&network_skey_file, &network_pkey_file)?;

        Ok((network_skey, network_pkey))
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use tempdir::TempDir;
    #[test]
    fn whitespace_tolerate_account_pkey() {
        stegos_crypto::init_test_network_prefix();

        let tmp_file = TempDir::new("whitespace_tolerate_account_pkey").unwrap();
        let source = " dev15q68emdmr3zyk3vqj644kpcpx7grqekdw0cge36fjlm4g0q284esvgy78c \n";
        let mut path = tmp_file.into_path();
        path.push("file");
        write(&path, source.as_bytes().to_vec()).unwrap();

        //test

        load_account_pkey(&path).unwrap();
    }

    #[test]
    fn whitespace_tolerate_network_pkey() {
        let tmp_file = TempDir::new("whitespace_tolerate_account_pkey").unwrap();
        let source =
            " 0757675e2547e04ee1f17ec1992a80d8da6f9a05aef55f76a66d5c32c068a32\
             81212970a44d3150934358f8414b2f60579858c67718fcd4b102eb45add61d069fdb4316fe0ca70f6777\
             bb0c9b35633469547c2dd1c0382418b88789af01e48ad \n";
        let mut path = tmp_file.into_path();
        path.push("file");
        write(&path, source.as_bytes().to_vec()).unwrap();

        //test

        load_network_pkey(&path).unwrap();
    }
}

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

#![deny(warnings)]

mod config;
pub mod pem;
pub use config::*;

use failure::{Error, Fail};
use log::*;
use std::fs;
use std::path::Path;
use stegos_crypto::curve1174::cpt;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;

use secp256k1::rand::{ChaChaRng, SeedableRng};

/// Create deterministic Network keys from Wallet keys.
///
/// # Arguments
///
/// * `wallet_skey` - Wallet Secret Key.
///
pub fn wallet_to_network_keys(
    wallet_skey: &cpt::SecretKey,
) -> (secure::SecretKey, secure::PublicKey, secure::Signature) {
    let wallet_skey_hash = Hash::digest(wallet_skey);
    let network_seed = wallet_skey_hash.base_vector();
    secure::make_deterministic_keys(network_seed)
}

/// PEM tag for secret key.
const SKEY_TAG: &'static str = "STEGOS-CURVE1174 SECRET KEY";
/// PEM tag for public key.
const PKEY_TAG: &'static str = "STEGOS-CURVE1174 PUBLIC KEY";

/// Wallet implementation.
#[derive(Clone, Debug)]
pub struct KeyChain {
    /// Wallet Secret Key.
    pub wallet_skey: cpt::SecretKey,
    /// Wallet Public Key.
    pub wallet_pkey: cpt::PublicKey,
    /// Network Secret Key.
    pub network_skey: secure::SecretKey,
    /// Network Public Key.
    pub network_pkey: secure::PublicKey,
}

#[derive(Debug, Fail)]
pub enum KeyChainError {
    #[fail(display = "Failed to parse key: {}.", _0)]
    KeyParseError(String),
    #[fail(display = "Failed to validate key.")]
    KeyValidateError,
}

impl KeyChain {
    pub fn new(cfg: &KeyChainConfig) -> Result<Self, Error> {
        let skey_path = Path::new(&cfg.private_key);
        let pkey_path = Path::new(&cfg.public_key);

        let (wallet_skey, wallet_pkey) = if !skey_path.exists() && !pkey_path.exists() {
            info!("Generating a new key pair...");
            let (skey, pkey, _sig) = cpt::make_random_keys();

            let skey_pem = pem::Pem {
                tag: SKEY_TAG.to_string(),
                contents: skey.to_bytes().to_vec(),
            };
            let pkey_bytes: [u8; 32] = pkey.to_bytes();
            let pkey_pem = pem::Pem {
                tag: PKEY_TAG.to_string(),
                contents: pkey_bytes.to_vec(),
            };

            fs::write(skey_path, pem::encode(&skey_pem))?;
            fs::write(pkey_path, pem::encode(&pkey_pem))?;

            debug!("Generated {}", pkey);
            (skey, pkey)
        } else {
            debug!(
                "Loading existing key pair from {} and {}...",
                cfg.private_key, cfg.public_key
            );

            let skey = fs::read_to_string(skey_path)?;
            let pkey = fs::read_to_string(pkey_path)?;

            let skey = pem::parse(skey)
                .map_err(|_| KeyChainError::KeyParseError(cfg.private_key.clone()))?;
            if skey.tag != SKEY_TAG {
                return Err(KeyChainError::KeyParseError(cfg.private_key.clone()).into());
            }

            let pkey = pem::parse(pkey)
                .map_err(|_| KeyChainError::KeyParseError(cfg.public_key.clone()))?;
            if pkey.tag != PKEY_TAG {
                return Err(KeyChainError::KeyParseError(cfg.public_key.clone()).into());
            }

            let skey = cpt::SecretKey::try_from_bytes(&skey.contents)?;
            let pkey = cpt::PublicKey::try_from_bytes(&pkey.contents[..])?;
            let pkey_check = skey.clone().into();

            if pkey != pkey_check {
                return Err(KeyChainError::KeyValidateError.into());
            }

            (skey, pkey)
        };

        let (network_skey, network_pkey, _network_sig) = wallet_to_network_keys(&wallet_skey);

        let keychain = KeyChain {
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
        };

        Ok(keychain)
    }

    /// Temporary KeyChain for tests.
    pub fn new_mem() -> Self {
        let (wallet_skey, wallet_pkey, _wallet_sig) = cpt::make_random_keys();
        let (network_skey, network_pkey, _network_sig) = wallet_to_network_keys(&wallet_skey);

        let keychain = KeyChain {
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
        };

        keychain
    }

    /// Generate new secp256k1 keypair using KeyChain as seed.
    pub fn generate_secp256k1_keypair(
        &self,
    ) -> Result<(secp256k1::key::SecretKey, secp256k1::key::PublicKey), Error> {
        // seed generator, with validator key.
        let seed: [u8; 32] = self.wallet_skey.to_bytes();
        // convert seed to old rand version format.
        let mut seed_converted = [0u32; 4];
        for i in 0..4 {
            seed_converted[i] = (seed[i * 4 + 0] as u32) << 24
                | (seed[i * 4 + 1] as u32) << 16
                | (seed[i * 4 + 2] as u32) << 8
                | (seed[i * 4 + 3] as u32);
        }

        let mut rng = ChaChaRng::from_seed(&seed_converted);

        let sec = secp256k1::Secp256k1::new();
        Ok(sec.generate_keypair(&mut rng))
    }
}

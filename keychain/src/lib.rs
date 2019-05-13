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

// #![deny(warnings)]

mod config;
mod error;
pub mod pem;
pub use config::*;
mod input;
mod keyfile;
mod recovery;

use crate::error::KeyError;
use crate::input::*;
use crate::keyfile::*;
use crate::recovery::wallet_skey_to_recovery;
use failure::Error;
use log::*;
use secp256k1::rand::{ChaChaRng, SeedableRng};
use std::path::Path;
use stegos_crypto::curve1174::cpt;
use stegos_crypto::pbc::secure;

/// Wallet implementation.
#[derive(Clone, Debug)]
pub struct KeyChain {
    /// Configuration.
    cfg: KeyChainConfig,
    /// Wallet Secret Key.
    pub wallet_skey: cpt::SecretKey,
    /// Wallet Public Key.
    pub wallet_pkey: cpt::PublicKey,
    /// Network Secret Key.
    pub network_skey: secure::SecretKey,
    /// Network Public Key.
    pub network_pkey: secure::PublicKey,
}

impl KeyChain {
    pub fn new(cfg: KeyChainConfig) -> Result<Self, KeyError> {
        let wallet_skey_path = Path::new(&cfg.wallet_skey_file);
        let wallet_pkey_path = Path::new(&cfg.wallet_pkey_file);
        let network_skey_path = Path::new(&cfg.network_skey_file);
        let network_pkey_path = Path::new(&cfg.network_pkey_file);

        let (wallet_skey, wallet_pkey, network_skey, network_pkey) = if !wallet_skey_path.exists()
            && !wallet_pkey_path.exists()
            && !network_skey_path.exists()
            && !network_pkey_path.exists()
        {
            debug!("Can't find keys on the disk: wallet_skey_file={}, wallet_pkey_file={}, network_skey_file={}, network_pkey_file={}",
                cfg.wallet_skey_file, cfg.wallet_pkey_file, cfg.network_skey_file, cfg.network_pkey_file);

            let (wallet_skey, wallet_pkey) = if !cfg.recovery_file.is_empty() {
                info!("Recovering keys...");
                let wallet_skey = read_recovery(&cfg.recovery_file)?;
                let wallet_pkey: cpt::PublicKey = (&wallet_skey).into();
                info!("Recovered a wallet key: pkey={}", wallet_pkey);
                (wallet_skey, wallet_pkey)
            } else {
                debug!("Generating a new wallet key pair...");
                let (wallet_skey, wallet_pkey) = cpt::make_random_keys();
                info!("Generated a new wallet key pair: pkey={}", wallet_pkey);
                (wallet_skey, wallet_pkey)
            };

            debug!("Generating a new network key pair...");
            let (network_skey, network_pkey) = secure::make_random_keys();
            info!("Generated a new network key pair: pkey={}", network_pkey);

            let password = read_password(&cfg.password_file, true)?;

            debug!(
                "Writing wallet key pair: wallet_skey_file={} wallet_pkey_file={}",
                cfg.wallet_skey_file, cfg.wallet_pkey_file
            );
            write_wallet_pkey(wallet_pkey_path, &wallet_pkey)?;
            write_wallet_skey(wallet_skey_path, &wallet_skey, &password)?;
            info!(
                "Wrote wallet key pair: wallet_skey_file={}, wallet_pkey_pkey={}",
                cfg.wallet_skey_file, cfg.wallet_pkey_file
            );

            debug!(
                "Writing network key pair: network_skey_file={}, network_pkey_file={}...",
                cfg.network_skey_file, cfg.network_pkey_file
            );
            write_network_pkey(network_pkey_path, &network_pkey)?;
            write_network_skey(network_skey_path, &network_skey, &password)?;
            info!(
                "Wrote network key pair: network_skey_file={}, network_pkey_file={}",
                cfg.network_skey_file, cfg.network_pkey_file
            );

            (wallet_skey, wallet_pkey, network_skey, network_pkey)
        } else {
            debug!("Loading keys from the disk...");
            let password = read_password(&cfg.password_file, false)?;

            debug!(
                "Loading wallet key pair: wallet_skey_file={}, wallet_pkey_file={}...",
                cfg.wallet_skey_file, cfg.wallet_pkey_file
            );
            let wallet_pkey = load_wallet_pkey(wallet_pkey_path)?;
            let wallet_skey = load_wallet_skey(wallet_skey_path, &password)?;
            if let Err(_e) = cpt::check_keying(&wallet_skey, &wallet_pkey) {
                return Err(KeyError::InvalidKeying(
                    cfg.wallet_skey_file,
                    cfg.wallet_pkey_file,
                ));
            }
            info!("Loaded wallet key pair: pkey={}", wallet_pkey);

            debug!(
                "Loading network key pair: network_skey_file={}, network_pkey_file={}...",
                cfg.network_skey_file, cfg.network_pkey_file
            );
            let network_pkey = load_network_pkey(network_pkey_path)?;
            let network_skey = load_network_skey(network_skey_path, &password)?;
            if let Err(_e) = secure::check_keying(&network_skey, &network_pkey) {
                return Err(KeyError::InvalidKeying(
                    cfg.network_skey_file,
                    cfg.network_pkey_file,
                ));
            }
            info!("Loaded network key pair: pkey={}", network_pkey);

            (wallet_skey, wallet_pkey, network_skey, network_pkey)
        };

        let keychain = KeyChain {
            cfg,
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
        };

        Ok(keychain)
    }

    /// Temporary KeyChain for tests.
    pub fn new_mem() -> Self {
        let (wallet_skey, wallet_pkey) = cpt::make_random_keys();
        let (network_skey, network_pkey) = secure::make_random_keys();

        let keychain = KeyChain {
            cfg: Default::default(),
            wallet_skey,
            wallet_pkey,
            network_skey,
            network_pkey,
        };

        keychain
    }

    /// Get recovery phrase.
    pub fn show_recovery(&self) -> Result<String, KeyError> {
        let password = read_password_from_stdin(false)?;
        let wallet_skey_path = Path::new(&self.cfg.wallet_skey_file);
        let wallet_skey = load_wallet_skey(wallet_skey_path, &password)?;
        Ok(wallet_skey_to_recovery(&wallet_skey))
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

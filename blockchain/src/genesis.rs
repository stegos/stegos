//! Genesis Block.

//
// Copyright (c) 2018 Stegos
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

use chrono::prelude::{TimeZone, Utc};
use crate::block::*;
use crate::output::*;
use stegos_crypto::curve1174::cpt as wallet_keys;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure as cosi_keys;
use stegos_keychain::wallet_to_cosi_keys;

const GENESIS_WITNESSES_COUNT: usize = 3;

/// Genesis blocks for tests and development purposes.
pub fn genesis_dev() -> (KeyBlock, MonetaryBlock) {
    //
    // Create initial keys.
    //
    #[allow(dead_code)]
    struct SeedKeys {
        wallet_skey: wallet_keys::SecretKey,
        wallet_pkey: wallet_keys::PublicKey,
        wallet_sig: wallet_keys::SchnorrSig,
        cosi_skey: cosi_keys::SecretKey,
        cosi_pkey: cosi_keys::PublicKey,
        cosi_sig: cosi_keys::Signature,
    }
    let mut keys = Vec::<SeedKeys>::with_capacity(GENESIS_WITNESSES_COUNT);
    for i in 0..GENESIS_WITNESSES_COUNT {
        let seed = format!("dev{}", i + 1);
        let (wallet_skey, wallet_pkey, wallet_sig) =
            wallet_keys::make_deterministic_keys(seed.as_bytes());

        let (cosi_skey, cosi_pkey, cosi_sig) = wallet_to_cosi_keys(&wallet_skey);

        keys.push(SeedKeys {
            wallet_skey,
            wallet_pkey,
            wallet_sig,
            cosi_skey,
            cosi_pkey,
            cosi_sig,
        });
    }

    // Both block are created at the same time in the same epoch.
    let version: u64 = 1;
    let epoch: u64 = 1;
    let timestamp = Utc.ymd(2018, 11, 01).and_hms(0, 0, 0).timestamp() as u64;

    //
    // Create initial Key Block.
    //
    let block1 = {
        let previous = Hash::digest(&"dev".to_string());
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

        let witnesses = keys
            .iter()
            .map(|p| p.cosi_pkey.clone())
            .collect::<Vec<cosi_keys::PublicKey>>();
        let leader = witnesses[0].clone();

        KeyBlock::new(base, leader, witnesses)
    };

    //
    // Create initial Monetary Block.
    //
    let block2 = {
        let previous = Hash::digest(&block1);
        let base = BaseBlockHeader::new(version, previous, epoch, timestamp);
        let amount: i64 = 1_000_000;

        // Genesis doesn't have inputs
        let inputs = Vec::<Hash>::new();

        // Genesis block have one hard-coded output.

        // Send money to yourself.
        let sender = &keys[0];
        let recipient = &keys[0];

        let (output, gamma) = Output::new(
            timestamp,
            &sender.wallet_skey,
            &recipient.wallet_pkey,
            amount,
        ).expect("genesis has valid public keys");
        let outputs = [output];

        // Adjustment is the sum of all gamma found in UTXOs.
        let adjustment = gamma;

        MonetaryBlock::new(base, adjustment, &inputs, &outputs)
    };

    (block1, block2)
}

/*
pub fn genesis_dev() -> (MonetaryBlock, Vec<(Hash, MerklePath)>) {
    let version: u64 = 1;
    let amount: i64 = 1_000_000;
    let epoch: u64 = 1;
    let previous = Hash::digest(&"dev".to_string());
    let timestamp = Utc.ymd(2018, 11, 01).and_hms(0, 0, 0).timestamp() as u64;


    // Fool-proof checks.
    static PREVIOUS_HEX: &str = "daeed6308874de11ec5ba896aff636aee60821b397f88164be3eae5cf6d276d8";
    static SKEY_HEX: &str = "0136fbf72a0a0c0ea44f850e26a55f0443622cd8ae00fd49e845ffba9d1ef0d2";
    static PKEY_HEX: &str = "86b452ac7d46311ccccf475e9716fb47086589e5720848986f2657f489fc1b05";
    // static SIG_HEX: &str = "f28cde3684e3176a72203c2231615eae825bd691c04ff1a44bb3f283414b3b1701";
    // static DELTA_HEX: &str = "3987487567fa7d862b5890ba4b288efc486298ba";
    // static HASH_HEX: &str = "3334d1466924068a65de9be925059ab9ee8866f62db9432d502edd7252b483ea";
    assert_eq!(previous, Hash::from_hex(PREVIOUS_HEX).expect("hex"));
    assert_eq!(skey, SecretKey::from_str(SKEY_HEX).expect("hex"));
    assert_eq!(pkey, PublicKey::from_str(PKEY_HEX).expect("hex"));
    // assert_eq!(sig, SchnorrSig::from_str(SIG_HEX).expect("hex"));
    // assert_eq!(delta, Zr::from_str(DELTA_HEX).expect("hex"));
    // assert_eq!(block.header.hash, Hash::from_hex(HASH_HEX).expect("hex"));

    (block, paths)
}
*/

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_genesis_dev() {
        let (block1, _block2) = genesis_dev();
        let header = block1.header;

        assert_eq!(header.base.epoch, 1);
        assert_eq!(header.base.version, 1);

        // TODO: add more tests
    }
}

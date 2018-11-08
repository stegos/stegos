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

use block::*;
use chrono::prelude::{TimeZone, Utc};
use input::*;
use merkle::MerklePath;
use output::*;
use payload::*;
use stegos_crypto::bulletproofs;
use stegos_crypto::curve1174::cpt::{make_deterministic_keys, PublicKey, SecretKey};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;

/// Genesis block for tests and development purposes.
pub fn genesis_dev() -> (MonetaryBlock, Vec<(Hash, MerklePath)>) {
    let version: u64 = 1;
    let amount: i64 = 1_000_000;
    let epoch: u64 = 1;
    let previous = Hash::digest(&"dev".to_string());
    let timestamp = Utc.ymd(2018, 11, 01).and_hms(0, 0, 0).timestamp() as u64;

    let base = BaseBlockHeader::new(version, previous, epoch, timestamp);

    let (skey, pkey, _sig) = make_deterministic_keys(b"dev");
    let delta: Fr = Fr::random();

    let leader = pkey;

    // Recipient is ourselves.
    let recipient = leader.clone();

    // Genesis block doesn't have inputs.
    let inputs: [Input; 0] = [];

    // Genesis block have one hard-coded output.
    let (proof, gamma) = bulletproofs::make_range_proof(amount);

    // Genesis block
    let payload = new_monetary(delta, gamma, amount, pkey).expect("genesis has valid keys");

    let output = Output::new(recipient, proof, payload);
    let outputs = [output];

    // Adjustment is the sum of all gamma found in UTXOs.
    let adjustment = delta;

    let (block, paths) = MonetaryBlock::new(base, adjustment, &inputs, &outputs);

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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_genesis_dev() {
        let (genesis, _) = genesis_dev();
        let header = genesis.header;

        assert_eq!(header.base.epoch, 1);
        assert_eq!(header.base.version, 1);

        // TODO: add more tests
    }
}

//! Genesis Block.

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

use crate::block::*;
use crate::mix;
use crate::multisignature::create_multi_signature;
use crate::output::*;
use std::collections::BTreeMap;
use std::time::SystemTime;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_keychain::KeyChain;

/// Genesis blocks.
pub fn genesis(
    keychains: &[KeyChain],
    stake: i64,
    coins: i64,
    timestamp: SystemTime,
) -> MacroBlock {
    // Both block are created at the same time in the same epoch.
    let version: u64 = 1;
    let view_change: u32 = 0;
    let height: u64 = 0;

    let init_random = Hash::digest("random");

    //
    // Create initial Macro Block.
    //
    let block1 = {
        let previous = Hash::digest(&"genesis".to_string());
        let seed = mix(init_random, view_change);
        let random = pbc::make_VRF(&keychains[0].network_skey, &seed);
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        //
        // Genesis has one PaymentOutput + N * StakeOutput, where N is the number of validators.
        //

        // Node #1 receives all moneys except stakes.
        // All nodes gets `stake` money staked.
        //
        let mut outputs: Vec<Output> = Vec::with_capacity(1 + keychains.len());

        // Create PaymentOutput for node #1.
        let recipient_pkey = &keychains[0].wallet_pkey;
        let mut coins1: i64 = coins - keychains.len() as i64 * stake;
        let (output, outputs_gamma) =
            Output::new_payment(recipient_pkey, coins1).expect("genesis has valid public keys");
        outputs.push(output);

        // Create StakeOutput for each node.
        for keys in keychains {
            let output = Output::new_stake(
                &keys.wallet_pkey,
                &keys.network_skey,
                &keys.network_pkey,
                stake,
            )
            .expect("genesis has valid public keys");
            coins1 += stake;
            outputs.push(output);
        }
        assert_eq!(coins, coins1);

        let gamma = -outputs_gamma;
        let mut block =
            MacroBlock::new(base, gamma, coins, &[], &outputs, keychains[0].network_pkey);

        let block_hash = Hash::digest(&block);
        let mut signatures: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
        let mut validators: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
        for keychain in keychains.iter() {
            let sig = pbc::sign_hash(&block_hash, &keychain.network_skey);
            signatures.insert(keychain.network_pkey.clone(), sig);
            validators.insert(keychain.network_pkey.clone(), stake);
        }
        let validators = validators.into_iter().collect();
        let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
        block.body.multisig = multisig;
        block.body.multisigmap = multisigmap;
        block
    };

    block1
}

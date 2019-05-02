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
use crate::multisignature::create_multi_signature;
use crate::output::*;
use std::collections::BTreeMap;
use std::time::SystemTime;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;

/// Genesis blocks.
pub fn genesis(
    keychains: &[KeyChain],
    stake: i64,
    coins: i64,
    timestamp: SystemTime,
) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(2);

    // Both block are created at the same time in the same epoch.
    let version: u64 = 1;
    let mut view_change: u32 = 0;
    let mut height: u64 = 0;

    //
    // Create initial Monetary Block.
    //
    let block1 = {
        let previous = Hash::digest(&"genesis".to_string());
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);
        //
        // Genesis has one PaymentOutput + N * StakeOutput, where N is the number of validators.
        //

        // Node #1 receives all moneys except stakes.
        // All nodes gets `stake` money staked.
        //
        let mut outputs: Vec<Output> = Vec::with_capacity(1 + keychains.len());

        // Create PaymentOutput for node #1.
        let sender_skey = &keychains[0].wallet_skey;
        let recipient_pkey = &keychains[0].wallet_pkey;
        let mut coins1: i64 = coins - keychains.len() as i64 * stake;
        let mut gamma = Fr::zero();
        let (output, outputs_gamma) =
            Output::new_payment(timestamp, sender_skey, recipient_pkey, coins1)
                .expect("genesis has valid public keys");
        outputs.push(output);
        gamma -= outputs_gamma;

        // Create StakeOutput for each node.
        for keys in keychains {
            let (output, stake_gamma) = Output::new_stake(
                timestamp,
                &keys.wallet_skey,
                &keys.wallet_pkey,
                &keys.network_pkey,
                &keys.network_skey,
                stake,
            )
            .expect("genesis has valid public keys");
            coins1 += stake;
            outputs.push(output);
            gamma -= stake_gamma;
        }
        assert_eq!(coins, coins1);

        MicroBlock::new(base, gamma, coins, &[], &outputs, None)
    };
    view_change += 1;
    height += 1;

    //
    // Create initial Key Block.
    //
    let block2 = {
        let init_random = Hash::digest("random");
        let previous = Hash::digest(&block1);
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp);

        let seed = crate::election::mix(init_random, view_change);
        let random = secure::make_VRF(&keychains[0].network_skey.clone(), &seed);
        let mut block = KeyBlock::new(base, random);
        let block_hash = Hash::digest(&block);

        let mut signatures: BTreeMap<secure::PublicKey, secure::Signature> = BTreeMap::new();
        let mut validators: BTreeMap<secure::PublicKey, i64> = BTreeMap::new();
        for keychain in keychains.iter() {
            let sig = secure::sign_hash(&block_hash, &keychain.network_skey);
            signatures.insert(keychain.network_pkey.clone(), sig);
            validators.insert(keychain.network_pkey.clone(), stake);
        }
        let validators = validators.into_iter().collect();
        let (multisig, multisigmap) = create_multi_signature(&validators, &signatures);
        block.body.multisig = multisig;
        block.body.multisigmap = multisigmap;
        block
    };

    blocks.push(Block::MicroBlock(block1));
    blocks.push(Block::KeyBlock(block2));

    blocks
}

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
use bitvector::BitVector;
use std::collections::BTreeMap;
use std::time::SystemTime;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

/// Genesis blocks.
pub fn genesis(stakes: &[StakeDef], coins: i64, timestamp: SystemTime) -> MacroBlock {
    // Both block are created at the same time in the same epoch.
    let view_change: u32 = 0;
    let epoch: u64 = 0;

    let init_random = Hash::digest("random");

    //
    // Create initial Macro Block.
    //
    let block1 = {
        let previous = Hash::digest(&"genesis".to_string());
        let seed = mix(init_random, view_change);
        let random = pbc::make_VRF(stakes[0].network_skey, &seed);
        //
        // Genesis has one PaymentOutput + N * StakeOutput, where N is the number of validators.
        //

        // Node #1 receives all moneys except stakes.
        // All nodes gets `stake` money staked.
        //
        let mut outputs: Vec<Output> = Vec::with_capacity(1 + stakes.len());

        // Create PaymentOutput for node #1.
        let beneficiary_pkey = stakes[0].beneficiary_pkey;
        let mut payout = coins;
        // Create StakeOutput for each node.
        for stake in stakes {
            let output = StakeOutput::from_def(stake).expect("genesis has valid public keys");
            payout -= stake.amount;
            outputs.push(output.into());
        }
        assert!(payout > 0);
        let (output, outputs_gamma) =
            Output::new_payment(beneficiary_pkey, payout).expect("genesis has valid public keys");
        outputs.push(output);

        let gamma = -outputs_gamma;
        let mut block = MacroBlock::new(
            previous,
            epoch,
            view_change,
            stakes[0].network_pkey.clone(),
            random,
            timestamp,
            coins,
            BitVector::ones(stakes.len()),
            gamma,
            &[],
            &outputs,
        );

        let block_hash = Hash::digest(&block);
        let (multisig, multisigmap) = {
            let mut signatures: BTreeMap<pbc::PublicKey, pbc::Signature> = BTreeMap::new();
            let mut validators: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
            for stake in stakes {
                let sig = pbc::sign_hash(&block_hash, &stake.network_skey);
                signatures.insert(stake.network_pkey.clone(), sig);
                validators.insert(stake.network_pkey.clone(), stake.amount);
            }
            let validators = validators.into_iter().collect();
            create_multi_signature(&validators, &signatures)
        };
        block.multisig = multisig;
        block.multisigmap = multisigmap;
        block
    };

    block1
}

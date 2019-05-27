//
// MIT License
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

use crate::config::ChainConfig;
use crate::error::*;
use failure::Error;
use log::*;
use std::time::SystemTime;
use stegos_blockchain::{mix, BaseBlockHeader, Blockchain, MacroBlock, VERSION};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

pub fn create_macro_block_proposal(
    chain: &Blockchain,
    view_change: u32,
    network_skey: &pbc::SecretKey,
    network_pkey: &pbc::PublicKey,
) -> MacroBlock {
    let timestamp = SystemTime::now();
    let seed = mix(chain.last_random(), view_change);
    let random = pbc::make_VRF(&network_skey, &seed);

    let previous = chain.last_block_hash();
    let height = chain.height();
    let epoch = chain.epoch() + 1;
    let base = BaseBlockHeader::new(VERSION, previous, height, view_change, timestamp, random);
    debug!(
        "Creating a new macro block proposal: height={}, view_change={}, epoch={}",
        height,
        view_change,
        chain.epoch() + 1,
    );

    let block = MacroBlock::empty(base, network_pkey.clone());
    let block_hash = Hash::digest(&block);

    // Validate the block via chain (just double-checking here).
    chain
        .validate_macro_block(&block, timestamp, true)
        .expect("proposed macro block is valid");

    info!(
        "Created a new macro block proposal: height={}, view_change={}, epoch={}, hash={}",
        height, view_change, epoch, block_hash
    );

    block
}

fn vetted_timestamp(
    block: &MacroBlock,
    cfg: &ChainConfig,
    last_block_time: SystemTime,
) -> Result<(), Error> {
    let timestamp = SystemTime::now();

    if block.header.base.timestamp <= last_block_time {
        return Err(
            NodeBlockError::OutdatedBlock(block.header.base.timestamp, last_block_time).into(),
        );
    }

    if block.header.base.timestamp >= timestamp {
        let duration = block
            .header
            .base
            .timestamp
            .duration_since(timestamp)
            .unwrap();

        if duration > cfg.macro_block_timeout {
            return Err(NodeBlockError::OutOfSyncTimestamp(
                block.header.base.height,
                Hash::digest(block),
                block.header.base.timestamp,
                timestamp,
            )
            .into());
        }
    }

    Ok(())
}

///
/// Validate proposed macro block.
///
pub fn validate_proposed_macro_block(
    cfg: &ChainConfig,
    chain: &Blockchain,
    view_change: u32,
    block_hash: Hash,
    block: &MacroBlock,
) -> Result<(), Error> {
    debug_assert_eq!(&Hash::digest(block), &block_hash);

    // Ensure that block was produced at round lower than current.
    if block.header.base.view_change > view_change {
        return Err(NodeBlockError::OutOfSyncViewChange(
            block.header.base.height,
            block_hash,
            block.header.base.view_change,
            view_change,
        )
        .into());
    }
    vetted_timestamp(block, cfg, chain.last_macro_block_timestamp())?;
    chain.validate_macro_block(block, block.header.base.timestamp, true)?;

    debug!("Key block proposal is valid: block={:?}", block_hash);
    Ok(())
}

//! Blockchain Implementation.

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

pub mod api;
mod awards;
mod block;
mod blockchain;
mod config;
pub mod election;
mod error;
mod escrow;
mod merkle;
mod metrics;
mod multisignature;
pub mod mvcc;
mod output;
pub mod protos;
mod slashing;
pub mod test;
mod timestamp;
mod transaction;
mod validation;
pub mod view_changes;

pub use crate::awards::ValidatorAwardState;
pub use crate::block::*;
pub use crate::blockchain::*;
pub use crate::config::*;
pub use crate::election::{mix, ElectionInfo, ElectionResult};
pub use crate::error::*;
pub use crate::escrow::*;
pub use crate::merkle::*;
pub use crate::multisignature::*;
pub use crate::output::*;
pub use crate::slashing::*;
pub use crate::timestamp::Timestamp;
pub use crate::transaction::*;

use failure::{format_err, Error};
use stegos_serialization::traits::ProtoConvert;

pub fn chain_to_prefix(network: &str) -> &'static str {
    match network {
        "mainnet" => "stg",
        "testnet" => "stt",
        "devnet" => "str",
        "dev" => "dev",
        e => panic!("Unexpected prefix name = {}", e),
    }
}

pub fn initialize_chain(chain: &str) -> Result<(MacroBlock, ChainConfig), Error> {
    let (genesis, chain_cfg): (&[u8], ChainConfig) = match chain {
        "dev" => (
            include_bytes!("../../chains/dev/genesis.bin"),
            ChainConfig {
                awards_difficulty: 3,
                stake_epochs: 1,
                ..Default::default()
            },
        ),
        "testnet" => (
            include_bytes!("../../chains/testnet/genesis.bin"),
            ChainConfig {
                ..Default::default()
            },
        ),
        "mainnet" => (
            include_bytes!("../../chains/mainnet/genesis.bin"),
            ChainConfig {
                ..Default::default()
            },
        ),
        chain @ _ => {
            return Err(format_err!("Unknown chain: {}", chain));
        }
    };
    let genesis = Block::from_buffer(genesis).expect("Invalid genesis");
    let genesis = genesis.unwrap_macro();
    Ok((genesis, chain_cfg))
}

pub trait BlockReader {
    fn iter_starting<'a>(
        &'a self,
        epoch: u64,
        offset: u32,
    ) -> Result<Box<dyn Iterator<Item = Block> + 'a>, Error>;

    fn light_iter_starting<'a>(
        &'a self,
        epoch: u64,
        offset: u32,
    ) -> Result<Box<dyn Iterator<Item = LightBlock> + 'a>, Error>;

    fn get_block<'a>(
        &'a self,
        epoch: u64,
        offset: u32,
    ) -> Result<std::borrow::Cow<'a, Block>, Error>;
}

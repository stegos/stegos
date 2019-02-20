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

use failure::Error;
use log::{debug, info, warn};
use rand::seq::IteratorRandom;
use std::mem;

use stegos_blockchain::Block;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_serialization::traits::ProtoConvert;

use crate::consensus::SealedBlockMessage;
use crate::NodeService;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RequestBlocks {
    pub start_block: Hash,
}

impl Hashable for RequestBlocks {
    fn hash(&self, state: &mut Hasher) {
        self.start_block.hash(state);
    }
}

impl RequestBlocks {
    pub fn new(start_block: Hash) -> RequestBlocks {
        Self { start_block }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseBlocks {
    pub blocks: Vec<Block>,
}

impl Hashable for ResponseBlocks {
    fn hash(&self, state: &mut Hasher) {
        for block in &self.blocks {
            block.hash(state);
        }
    }
}

impl ResponseBlocks {
    pub fn new(blocks: Vec<Block>) -> ResponseBlocks {
        Self { blocks }
    }
}

#[derive(Debug, Clone)]
pub enum ChainLoaderMessage {
    Request(RequestBlocks),
    Response(ResponseBlocks),
}

impl Hashable for ChainLoaderMessage {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ChainLoaderMessage::Request(r) => {
                "request".hash(state);
                r.hash(state)
            }
            ChainLoaderMessage::Response(r) => {
                "response".hash(state);
                r.hash(state)
            }
        }
    }
}

/// Limit of blocks to download starting from current known blockchain state.
const ORPHANS_BLOCK_LIMIT: u64 = 100;
/// How many epoch epoch we can load without notifying user.
const DIFF_IN_EPOCH_TO_NOTIFY: u64 = 10;
pub const CHAIN_LOADER_TOPIC: &'static str = "chain-loader";

//TODO: Support multiple blocks on each height.
pub struct ChainLoader {
    /// If we loading long chain, notify user.
    loading_long_chain: bool,
    pub blocks_queue: Vec<SealedBlockMessage>,
}

impl ChainLoader {
    pub fn new() -> Self {
        ChainLoader {
            blocks_queue: Vec::new(),
            loading_long_chain: false,
        }
    }
}

//TODO: Download blocks from different participant.
//TODO: Validate blocks signature out of order.

impl NodeService {
    /// Handle orphan block from network.
    pub fn on_orphan_block(&mut self, orphan: SealedBlockMessage) -> Result<(), Error> {
        let block_epoch = orphan.block.base_header().epoch;
        if self.chain.epoch > block_epoch {
            debug!(
                "Skipping outdated block, with epoch = {}",
                orphan.block.base_header().epoch
            );
            return Ok(());
        }
        let epoch_dif = block_epoch - self.chain.epoch;
        if let Some(last) = self.chain_loader.blocks_queue.last() {
            if Hash::digest(last) != orphan.block.base_header().previous {
                debug!("Skipping block that is not linked to the previous received.");
                return Ok(());
            }
        } else if epoch_dif > DIFF_IN_EPOCH_TO_NOTIFY {
            info!(
                "Received orphan block, starting loading chain from = {},\
                 numbers of epoch to load = {}.",
                orphan.pkey, epoch_dif
            );
            self.chain_loader.loading_long_chain = true;
        }
        let block_hash = Hash::digest(&orphan.block);
        let last_hash = Hash::digest(self.chain.last_block());
        debug!("Add orphan block to the queue block_hash = {}", block_hash);
        let sender = orphan.pkey;
        self.chain_loader.blocks_queue.push(orphan);
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(last_hash));
        self.network
            .send(sender, CHAIN_LOADER_TOPIC, msg.into_buffer()?)
    }

    /// Request block history, from one of validators.
    pub fn request_history(&mut self) -> Result<(), Error> {
        if !self.chain_loader.blocks_queue.is_empty() {
            debug!("Chain loading already in progress, skipping request from validator.");
        }
        let validators = self.chain.validators.iter().map(|(k, _)| k);
        let validators = validators.filter(|key| &self.keys.cosi_pkey != *key);

        let mut rng = rand::thread_rng();
        let pkey = if let Some(pkey) = validators.choose(&mut rng) {
            debug!(
                "Starting chain loading, request blocks history from = {}",
                pkey
            );
            pkey
        } else {
            debug!("Cannot choose one validator to request block history.");
            return Ok(());
        };
        let last_hash = Hash::digest(self.chain.last_block());
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(last_hash));
        self.network
            .send(*pkey, CHAIN_LOADER_TOPIC, msg.into_buffer()?)
    }

    fn handle_request_blocks(
        &mut self,
        pkey: secure::PublicKey,
        request: RequestBlocks,
    ) -> Result<(), Error> {
        let start_hash = request.start_block;
        let blocks = self.chain.blocks_range(&start_hash, ORPHANS_BLOCK_LIMIT);
        if let Some(blocks) = blocks {
            info!(
                "Received blocks request, sending a response with {} blocks.",
                blocks.len()
            );
            let msg = ChainLoaderMessage::Response(ResponseBlocks::new(blocks));
            self.network
                .send(pkey, CHAIN_LOADER_TOPIC, msg.into_buffer()?)?;
        } else {
            debug!(
                "Received request with unknown starting block hash, or no more blocks found, sender = {}.",
                pkey
            );
        }
        Ok(())
    }

    fn handle_response_blocks(
        &mut self,
        pkey: secure::PublicKey,
        response: ResponseBlocks,
    ) -> Result<(), Error> {
        assert!(self.chain.height() > 0);

        let first_block = if let Some(first_block) = response.blocks.first() {
            first_block
        } else {
            // TODO: later add trigger to notify user, that we end loading.
            debug!("No block in response found");
            return Ok(());
        };

        let last_block_hash = Hash::digest(self.chain.blocks().last().unwrap());
        if last_block_hash != first_block.base_header().previous {
            // in current implementation we can ask multiple times for one block range.
            debug!("Received response with first block not linked to our blockchain history.");
            return Ok(());
        }

        info!(
            "Received {} blocks from = {} trying to apply them at height={}",
            response.blocks.len(),
            pkey,
            self.chain.height()
        );

        for block in response.blocks {
            // fail if some of blocks are invalid.
            self.apply_new_block(block)?
        }

        //Try to handle queued blocks
        let sealed_blocks = mem::replace(&mut self.chain_loader.blocks_queue, Vec::new());
        for block in sealed_blocks {
            if let Err(e) = self.handle_sealed_block(block) {
                warn!("During processing outdated sealed block, error: {}", e)
            }
        }

        if self.chain_loader.blocks_queue.is_empty() {
            info!("Synchronized with actual network state.");
            self.chain_loader.loading_long_chain = false;
        }

        Ok(())
    }

    pub fn handle_chain_loader_message(
        &mut self,
        pkey: secure::PublicKey,
        msg: ChainLoaderMessage,
    ) -> Result<(), Error> {
        match msg {
            ChainLoaderMessage::Request(r) => self.handle_request_blocks(pkey, r),
            ChainLoaderMessage::Response(r) => self.handle_response_blocks(pkey, r),
        }
    }
}

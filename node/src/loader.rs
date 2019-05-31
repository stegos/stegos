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

use crate::NodeService;
use failure::{format_err, Error};
use log::*;
use rand::seq::IteratorRandom;
use stegos_blockchain::Block;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::clock;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RequestBlocks {
    pub epoch: u64,
}

impl Hashable for RequestBlocks {
    fn hash(&self, state: &mut Hasher) {
        self.epoch.hash(state);
    }
}

impl RequestBlocks {
    pub fn new(epoch: u64) -> RequestBlocks {
        Self { epoch }
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

/// Unicast topic for loading blocks.
pub const CHAIN_LOADER_TOPIC: &'static str = "chain-loader";

impl NodeService {
    /// Choose a master node to download blocks from.
    fn choose_master(&self) -> Option<pbc::PublicKey> {
        let mut rng = rand::thread_rng();
        // use latest known validators list.
        let validators = self
            .chain
            .validators()
            .into_iter()
            .map(|(k, _)| k)
            .filter(|key| self.keys.network_pkey != **key);
        let master = validators.choose(&mut rng)?.clone();
        debug!(
            "Selected a source node from the latest committed KeyBlock: hash={:?}, epoch={}, selected={:?}",
            self.chain.last_block_hash(),
            self.chain.epoch(),
            &master
        );
        return Some(master);
    }

    pub fn request_history(&mut self) -> Result<(), Error> {
        let from = if self.is_synchronized() {
            // Try to download history from the leader.
            self.chain.leader()
        } else {
            // Try to download history from a random validator.
            self.choose_master()
                .ok_or_else(|| format_err!("Failed to get validator list."))?
        };

        self.request_history_from(from)
    }

    pub fn request_history_from(&mut self, from: pbc::PublicKey) -> Result<(), Error> {
        let elapsed = clock::now().duration_since(self.last_sync_clock);
        if elapsed < self.cfg.loader_timeout {
            debug!(
                "Throttling loader: elapsed={:?}, min_interval={:?}",
                elapsed, self.cfg.loader_timeout
            );
            return Ok(());
        }

        let epoch = self.chain.epoch();
        info!("Downloading blocks: from={}, epoch={}", &from, epoch);
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(epoch));
        self.last_sync_clock = clock::now();
        self.network
            .send(from, CHAIN_LOADER_TOPIC, msg.into_buffer()?)
    }

    fn handle_request_blocks(
        &mut self,
        pkey: pbc::PublicKey,
        request: RequestBlocks,
    ) -> Result<(), Error> {
        if request.epoch > self.chain.epoch() {
            warn!(
                "Received a loader request with epoch >= our_epoch: remote_epoch={}, our_epoch={}",
                request.epoch,
                self.chain.epoch()
            );
            return Ok(());
        }

        self.send_blocks(pkey, request.epoch, 0)
    }

    pub fn send_blocks(
        &mut self,
        pkey: pbc::PublicKey,
        epoch: u64,
        offset: u32,
    ) -> Result<(), Error> {
        // Send one epoch.
        let blocks = self.chain.blocks_range(
            epoch,
            offset,
            (self.chain.cfg().micro_blocks_in_epoch as u64) * self.cfg.chain_loader_speed_in_epoch,
        );
        info!("Feeding blocks: to={}, num_blocks={}", pkey, blocks.len());
        let msg = ChainLoaderMessage::Response(ResponseBlocks::new(blocks));
        self.network
            .send(pkey, CHAIN_LOADER_TOPIC, msg.into_buffer()?)?;
        Ok(())
    }

    fn handle_response_blocks(
        &mut self,
        pkey: pbc::PublicKey,
        response: ResponseBlocks,
    ) -> Result<(), Error> {
        info!(
            "Received blocks: from={}, num_blocks={}",
            pkey,
            response.blocks.len(),
        );

        let initial_epoch = self.chain.epoch();
        for block in response.blocks {
            // Fail on the first error.
            self.handle_block(block)?;
        }

        //
        // Request more blocks in the follwing cases:
        // a) The timestamp of the latest keyblock is oudated (see is_synchronized()).
        // b) At least two blocks have been applied.
        //
        if !self.is_synchronized() || (self.chain.epoch() >= initial_epoch + 2) {
            //self.request_history()?;
        }

        Ok(())
    }

    pub fn handle_chain_loader_message(
        &mut self,
        pkey: pbc::PublicKey,
        msg: ChainLoaderMessage,
    ) -> Result<(), Error> {
        match msg {
            ChainLoaderMessage::Request(r) => self.handle_request_blocks(pkey, r),
            ChainLoaderMessage::Response(r) => self.handle_response_blocks(pkey, r),
        }
    }
}

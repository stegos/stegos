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
use failure::Error;
use log::*;
use stegos_blockchain::Block;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc;
use stegos_serialization::traits::ProtoConvert;

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
    pub fn request_history_from(
        &mut self,
        from: pbc::PublicKey,
        epoch: u64,
        reason: &str,
    ) -> Result<(), Error> {
        info!(
            "Downloading blocks: from={}, epoch={}, reason='{}'",
            &from, epoch, reason
        );
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(epoch));
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
        let mut blocks: Vec<Block> = Vec::new();
        for block in self.chain.blocks_starting(epoch, offset) {
            blocks.push(block);
            // Feed the whole epoch.
            match blocks.last().unwrap() {
                Block::MacroBlock(_) if blocks.len() > 0 => {
                    break;
                }
                Block::MacroBlock(_) => {}
                Block::MicroBlock(_) => {}
            }
        }
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
        let first_epoch = match response.blocks.first() {
            Some(Block::MacroBlock(block)) => block.header.epoch,
            Some(Block::MicroBlock(block)) => block.header.epoch,
            None => {
                // Empty response
                info!(
                    "Received blocks: from={}, num_blocks={}",
                    pkey,
                    response.blocks.len(),
                );
                return Ok(());
            }
        };
        let last_epoch = match response.blocks.last() {
            Some(Block::MacroBlock(block)) => block.header.epoch,
            Some(Block::MicroBlock(block)) => block.header.epoch,
            None => unreachable!("Checked above"),
        };
        if first_epoch > self.chain.epoch() {
            warn!(
                "Received blocks from the future: from={}, our_epoch={}, first_epoch={}",
                pkey,
                self.chain.epoch(),
                first_epoch,
            );
            return Ok(());
        } else if last_epoch < self.chain.epoch() {
            warn!(
                "Received blocks from the past: from={}, last_epoch={}, our_epoch={}",
                pkey,
                last_epoch,
                self.chain.epoch()
            );
            return Ok(());
        }

        info!(
            "Received blocks: from={}, first_epoch={}, our_epoch={}, last_epoch={}, num_blocks={}",
            pkey,
            first_epoch,
            self.chain.epoch(),
            last_epoch,
            response.blocks.len(),
        );

        for block in response.blocks {
            // Fail on the first error.
            self.handle_block(block)?;
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

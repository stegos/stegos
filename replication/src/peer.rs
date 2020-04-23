//! Replication - Peer State Machine.

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

use super::api::PeerInfo;
use super::protos::{ReplicationRequest, ReplicationResponse};
use crate::ReplicationRow;
use futures::channel::mpsc;
use futures::{
    task::{Context, Poll},
    StreamExt,
};
use log::*;
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::{Block, BlockReader, LightBlock, MacroBlockHeader, MicroBlockHeader};
use stegos_network::{Multiaddr, PeerId};
use stegos_serialization::traits::ProtoConvert;
use tokio::time::Instant;

/// How long a peer can stay without network activity.
const MAX_IDLE_DURATION: Duration = Duration::from_secs(60);
/// How long a peer can stay in Receiving/Sending state.
const MAX_STREAMING_DURATION: Duration = Duration::from_secs(60 * 10);
/// Maximal size of batch in blocks.
pub const MAX_BLOCKS_PER_BATCH: usize = 100; // Average block size is 100k.
/// Maximal size of batch in bytes.
const MAX_BYTES_PER_BATCH: u64 = 10 * 1024 * 1024; // 10Mb.

/// Replication Peer.
pub(super) enum Peer {
    /// Peer has been discovered by libp2p.
    Registered {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
    },
    /// Peer is connecting to a remote side.
    Connecting {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
    },
    /// Peer has been connected to a remote side.
    Connected {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        light: bool,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    /// Peer
    Accepted {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    Receiving {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        light: bool,
        last_clock: Instant,
        start_clock: Instant,
        #[allow(unused)] // tx is not currently used by the protocol.
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        epoch: u64,
        offset: u32,
        blocks_received: u64,
        bytes_received: u64,
    },
    Sending {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        light: bool,
        last_clock: Instant,
        start_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        epoch: u64,
        offset: u32,
        blocks_sent: u64,
        bytes_sent: u64,
    },
    Failed {
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
        error: std::io::Error,
    },
}

trait IntoReplicationResponse: Sized {
    fn into_replication_response(
        self,
        current_epoch: u64,
        current_offset: u32,
    ) -> ReplicationResponse;
}

impl IntoReplicationResponse for Block {
    fn into_replication_response(
        self,
        current_epoch: u64,
        current_offset: u32,
    ) -> ReplicationResponse {
        ReplicationResponse::Block {
            current_epoch,
            current_offset,
            block: self,
        }
    }
}

impl IntoReplicationResponse for LightBlock {
    fn into_replication_response(
        self,
        current_epoch: u64,
        current_offset: u32,
    ) -> ReplicationResponse {
        ReplicationResponse::LightBlock {
            current_epoch,
            current_offset,
            block: self,
        }
    }
}

trait NextEpochOffset {
    fn next_epoch_offset(&self, micro_blocks_in_epoch: u32) -> (u64, u32);
}

impl NextEpochOffset for MacroBlockHeader {
    fn next_epoch_offset(&self, _micro_blocks_in_epoch: u32) -> (u64, u32) {
        (self.epoch + 1, 0)
    }
}

impl NextEpochOffset for MicroBlockHeader {
    fn next_epoch_offset(&self, micro_blocks_in_epoch: u32) -> (u64, u32) {
        if self.offset + 1 >= micro_blocks_in_epoch {
            (self.epoch + 1, 0)
        } else {
            (self.epoch, self.offset + 1)
        }
    }
}

impl NextEpochOffset for Block {
    fn next_epoch_offset(&self, micro_blocks_in_epoch: u32) -> (u64, u32) {
        match self {
            Block::MacroBlock(block) => block.header.next_epoch_offset(micro_blocks_in_epoch),
            Block::MicroBlock(block) => block.header.next_epoch_offset(micro_blocks_in_epoch),
        }
    }
}

impl NextEpochOffset for LightBlock {
    fn next_epoch_offset(&self, micro_blocks_in_epoch: u32) -> (u64, u32) {
        match self {
            LightBlock::LightMacroBlock(block) => {
                block.header.next_epoch_offset(micro_blocks_in_epoch)
            }
            LightBlock::LightMicroBlock(block) => {
                block.header.next_epoch_offset(micro_blocks_in_epoch)
            }
        }
    }
}

impl Peer {
    pub(super) fn add_addr(&mut self, addr: Multiaddr) -> bool {
        trace!("Add addr = {}", addr.to_string());
        let multiaddr = match self {
            Peer::Registered { multiaddr, .. }
            | Peer::Connecting { multiaddr, .. }
            | Peer::Connected { multiaddr, .. }
            | Peer::Receiving { multiaddr, .. }
            | Peer::Accepted { multiaddr, .. }
            | Peer::Sending { multiaddr, .. }
            | Peer::Failed { multiaddr, .. } => multiaddr,
        };
        multiaddr.insert(addr, true).is_some()
    }
    pub(super) fn remove_addr(&mut self, addr: Multiaddr) {
        trace!("Remove addr = {}", addr.to_string());
        let multiaddr = match self {
            Peer::Registered { multiaddr, .. }
            | Peer::Connecting { multiaddr, .. }
            | Peer::Connected { multiaddr, .. }
            | Peer::Receiving { multiaddr, .. }
            | Peer::Accepted { multiaddr, .. }
            | Peer::Sending { multiaddr, .. }
            | Peer::Failed { multiaddr, .. } => multiaddr,
        };
        if multiaddr.get_mut(&addr).map(|addr| *addr = false).is_none() {
            error!("Removed peer that didn't exist.");
        }
    }
    ///
    /// Create a new peer in Registered state.
    ///
    pub(super) fn registered<H>(peer_id: PeerId, multiaddr: H) -> Self
    where
        H: IntoIterator<Item = (Multiaddr, bool)>,
    {
        let multiaddr = multiaddr.into_iter().collect();
        debug!("[{}] Disconnected", peer_id);
        Peer::Registered {
            peer_id,
            multiaddr,
            last_clock: Instant::now(),
        }
    }

    ///
    /// Moves to Connecting state.
    ///
    /// # Panics
    ///
    /// Panics if the current state is not Registered.
    ///
    pub(super) fn connecting(&mut self) {
        let (peer_id, multiaddr) = match self {
            Peer::Registered {
                peer_id, multiaddr, ..
            } => (peer_id.clone(), multiaddr.clone()),
            _ => {
                // Unexpected state - disconnect.
                return self.disconnected();
            }
        };
        debug!("[{}] Connecting", peer_id);
        let new_state = Peer::Connecting {
            peer_id,
            multiaddr,
            last_clock: Instant::now(),
        };
        std::mem::replace(self, new_state);
    }

    ///
    /// Moves to Connected state.
    ///
    /// # Panics
    ///
    /// Panics if the current state is not Connecting.
    ///
    pub(super) fn connected(
        &mut self,
        light: bool,
        epoch: u64,
        offset: u32,
        rx: mpsc::Receiver<Vec<u8>>,
        mut tx: mpsc::Sender<Vec<u8>>,
    ) {
        let (peer_id, multiaddr) = match self {
            Peer::Connecting {
                peer_id, multiaddr, ..
            } => (peer_id.clone(), multiaddr.clone()),
            _ => {
                // Unexpected state - disconnect.
                return self.disconnected();
            }
        };
        let request = ReplicationRequest::Subscribe {
            epoch,
            offset,
            light,
        };
        trace!("[{}] <- {:?}", peer_id, request);
        let request = request.into_buffer().unwrap();
        let new_state = match tx.try_send(request) {
            Ok(()) => {
                debug!("[{}] Connected", peer_id);
                Peer::Connected {
                    peer_id,
                    multiaddr,
                    light,
                    last_clock: Instant::now(),
                    tx,
                    rx,
                }
            }
            Err(mpsc::TrySendError { .. }) => Self::registered(peer_id, multiaddr),
        };
        std::mem::replace(self, new_state);
    }

    ///
    /// Disconnects from the upstream and moves to Discovered state.
    ///
    /// # Panics
    ///
    pub(super) fn disconnected(&mut self) {
        let (peer_id, multiaddr) = match self {
            Peer::Registered {
                peer_id, multiaddr, ..
            }
            | Peer::Connecting {
                peer_id, multiaddr, ..
            }
            | Peer::Connected {
                peer_id, multiaddr, ..
            }
            | Peer::Receiving {
                peer_id, multiaddr, ..
            }
            | Peer::Accepted {
                peer_id, multiaddr, ..
            }
            | Peer::Sending {
                peer_id, multiaddr, ..
            }
            | Peer::Failed {
                peer_id, multiaddr, ..
            } => (peer_id.clone(), multiaddr.clone()),
        };
        let new_state = Peer::registered(peer_id, multiaddr);
        std::mem::replace(self, new_state);
    }

    ///
    /// Moves to Accepted state.
    ///
    pub(super) fn accepted(&mut self, rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) {
        match self {
            Peer::Registered {
                peer_id, multiaddr, ..
            } => {
                debug!("[{}] Accepted", peer_id);
                let new_state = Peer::Accepted {
                    peer_id: peer_id.clone(),
                    multiaddr: multiaddr.clone(),
                    rx,
                    tx,
                    last_clock: Instant::now(),
                };
                std::mem::replace(self, new_state);
            }
            Peer::Connecting { peer_id, .. }
            | Peer::Connected { peer_id, .. }
            | Peer::Accepted { peer_id, .. }
            | Peer::Sending { peer_id, .. }
            | Peer::Receiving { peer_id, .. }
            | Peer::Failed { peer_id, .. } => {
                debug!("[{}] Rejected", peer_id);
            }
        }
    }
    fn format_addr((m, b): (&Multiaddr, &bool)) -> String {
        format!(
            "{} = {}",
            m.to_string(),
            if *b { "active" } else { "inactive" }
        )
    }

    ///
    /// Returns information about this peer.
    ///
    pub(super) fn info(&self, banned: bool) -> PeerInfo {
        match self {
            Peer::Registered {
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Discovered {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Connecting {
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Connecting {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Connected {
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Connected {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Receiving {
                peer_id,
                multiaddr,
                last_clock,
                epoch,
                offset,
                bytes_received,
                blocks_received,
                ..
            } => PeerInfo::Receiving {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                epoch: *epoch,
                offset: *offset,
                bytes_received: *bytes_received,
                blocks_received: *blocks_received,
            },
            Peer::Accepted {
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Accepted {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Sending {
                peer_id,
                multiaddr,
                last_clock,
                epoch,
                offset,
                bytes_sent,
                blocks_sent,
                ..
            } => PeerInfo::Sending {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                epoch: *epoch,
                offset: *offset,
                bytes_sent: *bytes_sent,
                blocks_sent: *blocks_sent,
            },
            Peer::Failed {
                peer_id,
                multiaddr,
                last_clock,
                error,
                ..
            } => PeerInfo::Failed {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                error: format!("{}", error),
            },
        }
    }

    ///
    /// Returns true if this Peer is an upstream.
    ///
    pub(super) fn is_upstream(&self) -> bool {
        match self {
            Peer::Connected { .. } | Peer::Connecting { .. } | Peer::Receiving { .. } => true,
            _ => false,
        }
    }

    ///
    /// A helper for Receiving state and on_block().
    ///
    fn send_blocks<BlocksIter, I>(
        &mut self,
        cx: &mut Context,
        blocks: BlocksIter,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
    ) where
        BlocksIter: IntoIterator<Item = I>,
        I: IntoReplicationResponse + NextEpochOffset + Sized,
    {
        let (peer_id, tx, epoch, offset, total_bytes_sent, total_blocks_sent, clock) = match self {
            Peer::Sending {
                peer_id,
                tx,
                epoch,
                offset,
                last_clock,
                bytes_sent,
                blocks_sent,
                ..
            } => (
                peer_id,
                tx,
                epoch,
                offset,
                bytes_sent,
                blocks_sent,
                last_clock,
            ),
            _ => unreachable!("Expected Sending state"),
        };

        let mut bytes_sent: u64 = 0;
        let mut blocks_sent: usize = 0;
        for block in blocks {
            if blocks_sent >= MAX_BLOCKS_PER_BATCH || bytes_sent >= MAX_BYTES_PER_BATCH {
                trace!(
                    "[{}] Wrote enough: bytes={}, blocks={}",
                    peer_id,
                    bytes_sent,
                    blocks_sent
                );
                cx.waker().wake_by_ref();
                break;
            }
            let (next_epoch, next_offset) = block.next_epoch_offset(micro_blocks_in_epoch);
            let response: ReplicationResponse =
                block.into_replication_response(current_epoch, current_offset);
            let response = response.into_buffer().unwrap();
            let response_len = response.len();
            match tx.try_send(response) {
                Ok(_) => {
                    *epoch = next_epoch;
                    *offset = next_offset;
                    bytes_sent += response_len as u64;
                    *total_bytes_sent += response_len as u64;
                    blocks_sent += 1;
                    *total_blocks_sent += 1;
                }
                Err(e) if e.is_full() => {
                    trace!(
                        "[{}] Not ready for writing: bytes={}, blocks={}",
                        peer_id,
                        bytes_sent,
                        blocks_sent
                    );
                    if Instant::now().duration_since(*clock) >= MAX_IDLE_DURATION {
                        debug!("[{}] Peer is not active, disconnecting", peer_id);
                        self.disconnected();
                        return;
                    }
                    break;
                }
                Err(_e) => {
                    self.disconnected();
                    return;
                }
            }
        }
        std::mem::replace(clock, Instant::now());
    }

    // Called when a new block is registered.
    pub(super) fn on_block(
        &mut self,
        cx: &mut Context,
        block: &Block,
        light_block: &LightBlock,
        micro_blocks_in_epoch: u32,
    ) {
        let (current_epoch, current_offset) = match &block {
            Block::MacroBlock(block) => (block.header.epoch, 0),
            Block::MicroBlock(block) => (block.header.epoch, block.header.offset),
        };
        match self {
            Peer::Sending {
                epoch,
                offset,
                light,
                ..
            } if *epoch == current_epoch && *offset == current_offset => {
                if !*light {
                    let blocks = vec![block.clone()];
                    self.send_blocks(
                        cx,
                        blocks.into_iter(),
                        current_epoch,
                        current_offset,
                        micro_blocks_in_epoch,
                    );
                } else {
                    let light_blocks = vec![light_block.clone()];
                    self.send_blocks(
                        cx,
                        light_blocks.into_iter(),
                        current_epoch,
                        current_offset,
                        micro_blocks_in_epoch,
                    );
                }
            }
            _ => {
                return;
            }
        }
    }

    ///
    /// The state machine.
    ///
    pub(super) fn poll(
        &mut self,
        cx: &mut Context,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
        block_reader: &dyn BlockReader,
    ) -> Poll<ReplicationRow> {
        match self {
            //--------------------------------------------------------------------------------------
            // Discovered
            //--------------------------------------------------------------------------------------
            Peer::Registered { peer_id, .. } => {
                trace!("[{}] Poll Registered", peer_id);
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Connecting
            //--------------------------------------------------------------------------------------
            Peer::Connecting { peer_id, .. } => {
                trace!("[{}] Poll Connecting", peer_id);
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Connected
            //--------------------------------------------------------------------------------------
            Peer::Connected {
                peer_id,
                multiaddr,
                rx,
                last_clock,
                ..
            } => {
                trace!("[{}] Poll Connected", peer_id);

                //
                // Read a response.
                //
                let response = match rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(response)) => response,
                    Poll::Ready(None) => {
                        self.disconnected();
                        return Poll::Pending;
                    }
                    Poll::Pending => {
                        if Instant::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                            debug!("[{}] Peer is not active, disconnecting", peer_id);
                            self.disconnected();
                        }
                        return Poll::Pending;
                    }
                };

                //
                // Parse the response.
                //
                trace!("[{}] -> {:?}", peer_id, response);
                let response = match ReplicationResponse::from_buffer(&response) {
                    Ok(response) => response,
                    Err(error) => {
                        let error = format!(
                            "Failed to parse response: response={:?}, error={:?}",
                            response, error
                        );
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        let new_state = Peer::Failed {
                            peer_id: peer_id.clone(),
                            multiaddr: multiaddr.clone(),
                            last_clock: Instant::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Poll::Pending;
                    }
                };

                //
                // Process the response.
                //
                trace!("[{}] -> {:?}", peer_id, response);
                let tmp_state = Self::registered(peer_id.clone(), multiaddr.clone());
                let (peer_id, multiaddr, light, rx, tx) = match std::mem::replace(self, tmp_state) {
                    Peer::Connected {
                        peer_id,
                        multiaddr,
                        rx,
                        tx,
                        light,
                        ..
                    } => (peer_id, multiaddr, light, rx, tx),
                    _ => unreachable!("Expected Connected state"),
                };
                let new_state = match response {
                    ReplicationResponse::Subscribed {
                        current_epoch,
                        current_offset,
                    } => {
                        debug!("[{}] Receiving", peer_id);
                        let now = Instant::now();
                        Peer::Receiving {
                            peer_id,
                            multiaddr,
                            light,
                            last_clock: now.clone(),
                            start_clock: now,
                            tx,
                            rx,
                            epoch: current_epoch,
                            offset: current_offset,
                            bytes_received: 0,
                            blocks_received: 0,
                        }
                    }
                    response => {
                        let error = format!(
                            "Unexpected response: expected=Subscribed, got={}",
                            response.name()
                        );
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        Peer::Failed {
                            peer_id,
                            multiaddr,
                            last_clock: Instant::now(),
                            error,
                        }
                    }
                };
                std::mem::replace(self, new_state);
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Accepted
            //--------------------------------------------------------------------------------------
            Peer::Accepted {
                peer_id,
                multiaddr,
                rx,
                last_clock,
                ..
            } => {
                trace!("[{}] Poll Accepted", peer_id);

                //
                // Read a request.
                //
                let request = match rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(request)) => request,
                    Poll::Ready(None) => {
                        self.disconnected();
                        return Poll::Pending;
                    }
                    Poll::Pending => {
                        if Instant::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                            debug!("[{}] Peer is not active, disconnecting", peer_id);
                            self.disconnected();
                        }
                        return Poll::Pending;
                    }
                };

                //
                // Parse the request.
                //
                trace!("[{}] -> {:?}", peer_id, request);
                let request = match ReplicationRequest::from_buffer(&request) {
                    Ok(request) => request,
                    Err(error) => {
                        let error = format!(
                            "Failed to parse request: request={:?}, error={:?}",
                            request, error
                        );
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        let new_state = Peer::Failed {
                            peer_id: peer_id.clone(),
                            multiaddr: multiaddr.clone(),
                            last_clock: Instant::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Poll::Pending;
                    }
                };

                //
                // Process the request.
                //
                trace!("[{}] -> {:?}", peer_id, request);
                let tmp_state = Self::registered(peer_id.clone(), multiaddr.clone());
                let (peer_id, multiaddr, rx, mut tx) = match std::mem::replace(self, tmp_state) {
                    Peer::Accepted {
                        peer_id,
                        multiaddr,
                        rx,
                        tx,
                        ..
                    } => (peer_id, multiaddr, rx, tx),
                    _ => unreachable!("Expected Accepted state"),
                };
                match request {
                    ReplicationRequest::Subscribe {
                        epoch,
                        offset,
                        light,
                    } => {
                        if epoch > current_epoch {
                            trace!("[{}] Subscribe from the future: epoch={}, offset={}, local_epoch={}, local_offset={}",
                                   peer_id, epoch, offset, current_epoch, current_offset);
                            let new_state = Self::registered(peer_id, multiaddr);
                            std::mem::replace(self, new_state);
                            return Poll::Pending;
                        }
                        let response = ReplicationResponse::Subscribed {
                            current_epoch,
                            current_offset,
                        };
                        trace!("[{}] <- {:?}", peer_id, response);
                        let response = response.into_buffer().unwrap();
                        match tx.try_send(response) {
                            Ok(()) => {
                                debug!("[{}] Sending", peer_id);
                                let new_state = Peer::Sending {
                                    peer_id,
                                    multiaddr,
                                    light,
                                    last_clock: Instant::now(),
                                    start_clock: Instant::now(),
                                    tx,
                                    rx,
                                    epoch,
                                    offset,
                                    bytes_sent: 0,
                                    blocks_sent: 0,
                                };
                                std::mem::replace(self, new_state);
                            }
                            Err(mpsc::TrySendError { .. }) => {
                                let new_state = Self::registered(peer_id, multiaddr);
                                std::mem::replace(self, new_state);
                                return Poll::Pending;
                            }
                        }
                    }
                }
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Receiving
            //--------------------------------------------------------------------------------------
            Peer::Receiving {
                peer_id,
                multiaddr,
                light,
                last_clock,
                start_clock,
                rx,
                epoch,
                offset,
                bytes_received: total_bytes_received,
                blocks_received: total_blocks_received,
                ..
            } => {
                trace!("[{}] Poll Receiving", peer_id);

                //
                // Check quota.
                //
                if Instant::now().duration_since(*start_clock) >= MAX_STREAMING_DURATION {
                    debug!("[{}] Quota exceeded, disconnected", peer_id);
                    self.disconnected();
                    return Poll::Pending;
                }

                {
                    match rx.poll_next_unpin(cx) {
                        Poll::Ready(Some(response)) => {
                            //
                            // Parse a response.
                            //
                            trace!("[{}] -> {:?}", peer_id, response);
                            let response_len = response.len();
                            let response = match ReplicationResponse::from_buffer(&response) {
                                Ok(response) => response,
                                Err(error) => {
                                    let error = format!(
                                        "Failed to parse response: response={:?}, error={:?}",
                                        response, error
                                    );
                                    error!("[{}] {}", peer_id, error);
                                    let error =
                                        std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                                    let new_state = Peer::Failed {
                                        peer_id: peer_id.clone(),
                                        multiaddr: multiaddr.clone(),
                                        last_clock: Instant::now(),
                                        error,
                                    };
                                    std::mem::replace(self, new_state);
                                    return Poll::Pending;
                                }
                            };
                            //
                            // Process the response.
                            //
                            trace!("[{}] -> {:?}", peer_id, response);
                            match response {
                                ReplicationResponse::Block {
                                    current_epoch,
                                    current_offset,
                                    block,
                                } if !*light => {
                                    std::mem::replace(last_clock, Instant::now());
                                    match &block {
                                        Block::MacroBlock(block) => {
                                            debug!(
                                                "[{}] -> MacroBlock {{ epoch = {} }}",
                                                peer_id, block.header.epoch
                                            );
                                        }
                                        Block::MicroBlock(block) => {
                                            debug!(
                                                "[{}] -> MicroBlock {{ epoch = {}, offset = {} }}",
                                                peer_id, block.header.epoch, block.header.offset
                                            );
                                        }
                                    }
                                    *total_blocks_received += 1;
                                    *total_bytes_received += response_len as u64;
                                    *epoch = current_epoch;
                                    *offset = current_offset;
                                    return Poll::Ready(ReplicationRow::Block(block));
                                }
                                ReplicationResponse::LightBlock {
                                    current_epoch,
                                    current_offset,
                                    block,
                                } if *light => {
                                    std::mem::replace(last_clock, Instant::now());
                                    match &block {
                                        LightBlock::LightMacroBlock(block) => {
                                            debug!(
                                                "[{}] -> LightMacroBlock {{ epoch = {} }}",
                                                peer_id, block.header.epoch
                                            );
                                        }
                                        LightBlock::LightMicroBlock(block) => {
                                            debug!(
                                                "[{}] -> LightMicroBlock {{ epoch = {}, offset = {} }}",
                                                peer_id, block.header.epoch, block.header.offset
                                            );
                                        }
                                    }
                                    *total_blocks_received += 1;
                                    *total_bytes_received += response_len as u64;
                                    *epoch = current_epoch;
                                    *offset = current_offset;
                                    return Poll::Ready(ReplicationRow::LightBlock(block));
                                }
                                response => {
                                    let error = format!(
                                        "Unexpected response: expected={}, got={}",
                                        if *light { "LightBlock" } else { "Block" },
                                        response.name()
                                    );
                                    trace!("[{}] {}", peer_id, error);
                                    let error =
                                        std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                                    let new_state = Peer::Failed {
                                        peer_id: peer_id.clone(),
                                        multiaddr: multiaddr.clone(),
                                        last_clock: Instant::now(),
                                        error,
                                    };
                                    std::mem::replace(self, new_state);
                                    return Poll::Pending;
                                }
                            }
                        }
                        Poll::Ready(None) => {
                            self.disconnected();
                            return Poll::Pending;
                        }
                        Poll::Pending => {
                            trace!("[{}] Not ready for reading", peer_id,);
                            if Instant::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                                debug!("[{}] Peer is not active, disconnecting", peer_id);
                                self.disconnected();
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }

            //--------------------------------------------------------------------------------------
            // Sending
            //--------------------------------------------------------------------------------------
            Peer::Sending {
                peer_id,
                multiaddr,
                light,
                start_clock,
                rx,
                epoch,
                offset,
                ..
            } => {
                trace!("[{}] Poll Sending", peer_id);

                //
                // Check quota.
                //
                if Instant::now().duration_since(*start_clock) >= MAX_STREAMING_DURATION {
                    debug!("[{}] Quota exceeded, disconnected", peer_id);
                    self.disconnected();
                    return Poll::Pending;
                }

                //
                // Process incoming responses.
                //
                match rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(response)) => {
                        let error =
                            format!("Unexpected response: expected=nothing, got={:?}", response);
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        let new_state = Peer::Failed {
                            peer_id: peer_id.clone(),
                            multiaddr: multiaddr.clone(),
                            last_clock: Instant::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Poll::Pending;
                    }
                    Poll::Ready(None) => {
                        self.disconnected();
                        return Poll::Pending;
                    }
                    Poll::Pending => {}
                }

                //
                // Send blocks.
                //
                if *epoch != current_epoch || *offset != current_offset {
                    if *light {
                        let blocks = match block_reader.light_iter_starting(*epoch, *offset) {
                            Ok(blocks) => blocks,
                            Err(e) => {
                                error!("[{}] Failed to send blocks: {}", peer_id, e);
                                self.disconnected();
                                return Poll::Pending;
                            }
                        };
                        self.send_blocks(
                            cx,
                            blocks,
                            current_epoch,
                            current_offset,
                            micro_blocks_in_epoch,
                        );
                    } else {
                        let blocks = match block_reader.iter_starting(*epoch, *offset) {
                            Ok(blocks) => blocks,
                            Err(e) => {
                                error!("[{}] Failed to send blocks: {}", peer_id, e);
                                self.disconnected();
                                return Poll::Pending;
                            }
                        };
                        self.send_blocks(
                            cx,
                            blocks,
                            current_epoch,
                            current_offset,
                            micro_blocks_in_epoch,
                        );
                    }
                }
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Failed
            //--------------------------------------------------------------------------------------
            Peer::Failed { peer_id, .. } => {
                trace!("[{}] Poll Failed", peer_id);
                Poll::Pending
            }
        }
    }
}

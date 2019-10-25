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

use super::protos::{ReplicationRequest, ReplicationResponse};
use crate::replication::api::PeerInfo;
use futures::sync::mpsc;
use futures::{task, Async, AsyncSink, Sink, Stream};
use log::*;
use std::time::{Duration, Instant};
use stegos_blockchain::{Block, Blockchain};
use stegos_network::{Multiaddr, PeerId};
use stegos_serialization::traits::ProtoConvert;
use tokio_timer::clock;

/// How long a peer can stay without network activity.
const MAX_IDLE_DURATION: Duration = Duration::from_secs(60);
/// How long a peer can stay in Receiving/Sending state.
const MAX_STREAMING_DURATION: Duration = Duration::from_secs(60 * 10);
/// Maximal size of batch in blocks.
const MAX_BLOCKS_PER_BATCH: usize = 100; // Average block size is 100k.
/// Maximal size of batch in bytes.
const MAX_BYTES_PER_BATCH: u64 = 10 * 1024 * 1024; // 10Mb.

/// Replication Peer.
pub(super) enum Peer {
    /// Peer has been discovered by libp2p.
    Registered {
        peer_id: PeerId,
        multiaddr: Multiaddr,
        last_clock: Instant,
    },
    /// Peer is connecting to a remote side.
    Connecting {
        peer_id: PeerId,
        multiaddr: Multiaddr,
        last_clock: Instant,
    },
    /// Peer has been connected to a remote side.
    Connected {
        peer_id: PeerId,
        multiaddr: Multiaddr,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    /// Peer
    Accepted {
        peer_id: PeerId,
        multiaddr: Multiaddr,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    Receiving {
        peer_id: PeerId,
        multiaddr: Multiaddr,
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
        multiaddr: Multiaddr,
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
        multiaddr: Multiaddr,
        last_clock: Instant,
        error: std::io::Error,
    },
}

impl Peer {
    ///
    /// Create a new peer in Registered state.
    ///
    pub(super) fn registered(peer_id: PeerId, multiaddr: Multiaddr) -> Self {
        debug!("[{}] Disconnected", peer_id);
        Peer::Registered {
            peer_id,
            multiaddr,
            last_clock: clock::now(),
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
            last_clock: clock::now(),
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
        let request = ReplicationRequest::Subscribe { epoch, offset };
        trace!("[{}] <- {:?}", peer_id, request);
        let request = request.into_buffer().unwrap();
        let new_state = match tx.try_send(request) {
            Ok(()) => {
                debug!("[{}] Connected", peer_id);
                Peer::Connected {
                    peer_id,
                    multiaddr,
                    last_clock: clock::now(),
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
                    last_clock: clock::now(),
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

    ///
    /// Returns information about this peer.
    ///
    pub(super) fn info(&self) -> PeerInfo {
        match self {
            Peer::Registered {
                peer_id,
                multiaddr,
                last_clock,
            } => PeerInfo::Discovered {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
            },
            Peer::Connecting {
                peer_id,
                multiaddr,
                last_clock,
            } => PeerInfo::Connecting {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
            },
            Peer::Connected {
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Connected {
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
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
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
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
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
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
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
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
                multiaddr: multiaddr.to_string(),
                idle: clock::now().duration_since(*last_clock).into(),
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
    fn send_blocks<BlocksIter>(
        &mut self,
        blocks: BlocksIter,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
    ) where
        BlocksIter: IntoIterator<Item = Block>,
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
                debug!(
                    "[{}] Wrote enough: bytes={}, blocks={}",
                    peer_id, bytes_sent, blocks_sent
                );
                task::current().notify();
                break;
            }
            let (next_epoch, next_offset) = match &block {
                Block::MacroBlock(block) => {
                    assert_eq!(block.header.epoch, *epoch);
                    debug!(
                        "[{}] <- MacroBlock {{ epoch = {} }}",
                        peer_id, block.header.epoch
                    );
                    (block.header.epoch + 1, 0)
                }
                Block::MicroBlock(block) => {
                    assert_eq!(block.header.epoch, *epoch);
                    assert_eq!(block.header.offset, *offset);
                    debug!(
                        "[{}] <- MicroBlock {{ epoch = {}, offset = {} }}",
                        peer_id, block.header.epoch, block.header.offset,
                    );
                    if block.header.offset + 1 >= micro_blocks_in_epoch {
                        (block.header.epoch + 1, 0)
                    } else {
                        (block.header.epoch, block.header.offset + 1)
                    }
                }
            };
            let response = ReplicationResponse::Block {
                current_epoch,
                current_offset,
                block,
            };
            let response = response.into_buffer().unwrap();
            let response_len = response.len();
            match tx.start_send(response) {
                Ok(AsyncSink::Ready) => {
                    *epoch = next_epoch;
                    *offset = next_offset;
                    bytes_sent += response_len as u64;
                    *total_bytes_sent += response_len as u64;
                    blocks_sent += 1;
                    *total_blocks_sent += 1;
                }
                Ok(AsyncSink::NotReady(_response)) => {
                    debug!(
                        "[{}] Not ready for writing: bytes={}, blocks={}",
                        peer_id, bytes_sent, blocks_sent
                    );
                    if clock::now().duration_since(*clock) >= MAX_IDLE_DURATION {
                        debug!("[{}] Peer is not active, disconnecting", peer_id);
                        self.disconnected();
                        return;
                    }
                    break;
                }
                Err(_e) => {
                    break;
                }
            }
        }
        if let Err(_e /* SendError */) = tx.poll_complete() {
            self.disconnected();
            return;
        }
        std::mem::replace(clock, clock::now());
    }

    // Called when a new block is registered.
    pub(super) fn on_block(&mut self, block: &Block, micro_blocks_in_epoch: u32) {
        let (current_epoch, current_offset) = match &block {
            Block::MacroBlock(block) => (block.header.epoch, 0),
            Block::MicroBlock(block) => (block.header.epoch, block.header.offset),
        };
        match self {
            Peer::Sending { epoch, offset, .. }
                if *epoch == current_epoch && *offset == current_offset =>
            {
                let blocks = vec![block.clone()];
                self.send_blocks(
                    blocks.into_iter(),
                    current_epoch,
                    current_offset,
                    micro_blocks_in_epoch,
                );
            }
            _ => {
                return;
            }
        }
    }

    ///
    /// The state machine.
    ///
    pub(super) fn poll(&mut self, chain: &Blockchain) -> Async<Vec<Block>> {
        match self {
            //--------------------------------------------------------------------------------------
            // Discovered
            //--------------------------------------------------------------------------------------
            Peer::Registered { peer_id, .. } => {
                trace!("[{}] Poll Registered", peer_id);
                Async::NotReady
            }

            //--------------------------------------------------------------------------------------
            // Connecting
            //--------------------------------------------------------------------------------------
            Peer::Connecting { peer_id, .. } => {
                trace!("[{}] Poll Connecting", peer_id);
                Async::NotReady
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
                let response = match rx.poll().unwrap() {
                    Async::Ready(Some(response)) => response,
                    Async::Ready(None) => {
                        self.disconnected();
                        return Async::NotReady;
                    }
                    Async::NotReady => {
                        if clock::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                            debug!("[{}] Peer is not active, disconnecting", peer_id);
                            self.disconnected();
                        }
                        return Async::NotReady;
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
                            last_clock: clock::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Async::NotReady;
                    }
                };

                //
                // Process the response.
                //
                trace!("[{}] -> {:?}", peer_id, response);
                let tmp_state = Self::registered(peer_id.clone(), multiaddr.clone());
                let (peer_id, multiaddr, rx, tx) = match std::mem::replace(self, tmp_state) {
                    Peer::Connected {
                        peer_id,
                        multiaddr,
                        rx,
                        tx,
                        ..
                    } => (peer_id, multiaddr, rx, tx),
                    _ => unreachable!("Expected Connected state"),
                };
                let new_state = match response {
                    ReplicationResponse::Subscribed {
                        current_epoch,
                        current_offset,
                    } => {
                        debug!("[{}] Receiving", peer_id);
                        let now = clock::now();
                        Peer::Receiving {
                            peer_id,
                            multiaddr,
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
                            "Unexpected response: expected=Subscribed, got={:?}",
                            response
                        );
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        Peer::Failed {
                            peer_id,
                            multiaddr,
                            last_clock: clock::now(),
                            error,
                        }
                    }
                };
                std::mem::replace(self, new_state);
                Async::NotReady
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
                let request = match rx.poll().unwrap() {
                    Async::Ready(Some(request)) => request,
                    Async::Ready(None) => {
                        self.disconnected();
                        return Async::NotReady;
                    }
                    Async::NotReady => {
                        if clock::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                            debug!("[{}] Peer is not active, disconnecting", peer_id);
                            self.disconnected();
                        }
                        return Async::NotReady;
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
                            last_clock: clock::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Async::NotReady;
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
                    ReplicationRequest::Subscribe { epoch, offset } => {
                        if epoch > chain.epoch() {
                            trace!("[{}] Subscribe from the future: epoch={}, offset={}, local_epoch={}, local_offset={}",
                                   peer_id, epoch, offset, chain.epoch(), chain.offset());
                            let new_state = Self::registered(peer_id, multiaddr);
                            std::mem::replace(self, new_state);
                            return Async::NotReady;
                        }
                        let response = ReplicationResponse::Subscribed {
                            current_epoch: chain.epoch(),
                            current_offset: chain.offset(),
                        };
                        trace!("[{}] <- {:?}", peer_id, response);
                        let response = response.into_buffer().unwrap();
                        match tx.try_send(response) {
                            Ok(()) => {
                                debug!("[{}] Sending", peer_id);
                                let new_state = Peer::Sending {
                                    peer_id,
                                    multiaddr,
                                    last_clock: clock::now(),
                                    start_clock: clock::now(),
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
                                return Async::NotReady;
                            }
                        }
                    }
                }
                Async::NotReady
            }

            //--------------------------------------------------------------------------------------
            // Receiving
            //--------------------------------------------------------------------------------------
            Peer::Receiving {
                peer_id,
                multiaddr,
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
                if clock::now().duration_since(*start_clock) >= MAX_STREAMING_DURATION {
                    debug!("[{}] Quota exceeded, disconnected", peer_id);
                    self.disconnected();
                    return Async::NotReady;
                }

                let mut bytes_received: u64 = 0;
                let mut blocks: Vec<Block> = Vec::with_capacity(MAX_BLOCKS_PER_BATCH);
                loop {
                    match rx.poll().unwrap() {
                        Async::Ready(Some(response)) => {
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
                                        last_clock: clock::now(),
                                        error,
                                    };
                                    std::mem::replace(self, new_state);
                                    break;
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
                                } => {
                                    std::mem::replace(last_clock, clock::now());
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
                                    blocks.push(block);
                                    *total_blocks_received += 1;
                                    bytes_received += response_len as u64;
                                    *total_bytes_received += response_len as u64;
                                    *epoch = current_epoch;
                                    *offset = current_offset;
                                    if blocks.len() >= MAX_BLOCKS_PER_BATCH
                                        || bytes_received >= MAX_BYTES_PER_BATCH
                                    {
                                        debug!(
                                            "[{}] Read enough: bytes={}, blocks={}",
                                            peer_id,
                                            bytes_received,
                                            blocks.len()
                                        );
                                        task::current().notify();
                                        break;
                                    }
                                }
                                response => {
                                    let error = format!(
                                        "Unexpected response: expected=Blocks, got={:?}",
                                        response
                                    );
                                    error!("[{}] {}", peer_id, error);
                                    let error =
                                        std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                                    let new_state = Peer::Failed {
                                        peer_id: peer_id.clone(),
                                        multiaddr: multiaddr.clone(),
                                        last_clock: clock::now(),
                                        error,
                                    };
                                    std::mem::replace(self, new_state);
                                    break;
                                }
                            }
                        }
                        Async::Ready(None) => {
                            self.disconnected();
                            break;
                        }
                        Async::NotReady => {
                            debug!(
                                "[{}] Not ready for reading: bytes={}, blocks={}",
                                peer_id,
                                bytes_received,
                                blocks.len()
                            );
                            if clock::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                                debug!("[{}] Peer is not active, disconnecting", peer_id);
                                self.disconnected();
                            }
                            break;
                        }
                    }
                }
                if blocks.is_empty() {
                    Async::NotReady
                } else {
                    Async::Ready(blocks)
                }
            }

            //--------------------------------------------------------------------------------------
            // Sending
            //--------------------------------------------------------------------------------------
            Peer::Sending {
                peer_id,
                multiaddr,
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
                if clock::now().duration_since(*start_clock) >= MAX_STREAMING_DURATION {
                    debug!("[{}] Quota exceeded, disconnected", peer_id);
                    self.disconnected();
                    return Async::NotReady;
                }

                //
                // Process incoming responses.
                //
                match rx.poll().unwrap() {
                    Async::Ready(Some(response)) => {
                        let error =
                            format!("Unexpected response: expected=nothing, got={:?}", response);
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        let new_state = Peer::Failed {
                            peer_id: peer_id.clone(),
                            multiaddr: multiaddr.clone(),
                            last_clock: clock::now(),
                            error,
                        };
                        std::mem::replace(self, new_state);
                        return Async::NotReady;
                    }
                    Async::Ready(None) => {
                        self.disconnected();
                        return Async::NotReady;
                    }
                    Async::NotReady => {}
                }

                //
                // Send blocks.
                //
                let current_epoch = chain.epoch();
                let current_offset = chain.offset();
                if *epoch != current_epoch || *offset != current_offset {
                    let micro_blocks_in_epoch = chain.cfg().micro_blocks_in_epoch;
                    let blocks = chain.blocks_starting(*epoch, *offset);
                    self.send_blocks(blocks, current_epoch, current_offset, micro_blocks_in_epoch);
                }

                Async::NotReady
            }

            //--------------------------------------------------------------------------------------
            // Failed
            //--------------------------------------------------------------------------------------
            Peer::Failed { peer_id, .. } => {
                trace!("[{}] Poll Failed", peer_id);
                Async::NotReady
            }
        }
    }
}

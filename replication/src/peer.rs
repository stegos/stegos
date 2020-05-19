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
use super::downstream::Downstream;
use super::protos::{ReplicationRequest, ReplicationResponse};
use crate::protos::RequestOutputs;
use crate::ReplicationRow;
use futures::channel::mpsc;
use futures::{
    task::{Context, Poll},
    StreamExt,
};
use log::*;
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::{Block, LightBlock};
use stegos_network::{Multiaddr, PeerId, ReplicationVersion};
use stegos_serialization::traits::ProtoConvert;
use tokio::time::Instant;

/// How long a peer can stay without network activity.
const MAX_IDLE_DURATION: Duration = Duration::from_secs(60);
/// How long a peer can stay in Receiving/Sending state.
const MAX_STREAMING_DURATION: Duration = Duration::from_secs(60 * 10);
/// Maximal size of batch in blocks.
pub const MAX_BLOCKS_PER_BATCH: usize = 100; // Average block size is 100k.

/// Replication Peer.
#[derive(Debug)]
pub(super) enum Peer {
    /// Replication protocol resolved.
    Registered {
        version: Option<ReplicationVersion>,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
    },
    /// Peer is connecting to a remote side.
    Connecting {
        version: Option<ReplicationVersion>,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
    },
    /// Peer is connected, but his connection keeped unsubscribed for future usage.
    Background {
        version: ReplicationVersion,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    /// Peer has been connected to a remote side.
    Connected {
        version: ReplicationVersion,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        light: bool,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    Receiving {
        version: ReplicationVersion,
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
    Failed {
        version: ReplicationVersion,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
        error: std::io::Error,
    },
}

impl Peer {
    pub(super) fn add_addr(&mut self, addr: Multiaddr) -> bool {
        trace!("Add addr = {}", addr.to_string());
        let multiaddr = match self {
            Peer::Registered { multiaddr, .. }
            | Peer::Connecting { multiaddr, .. }
            | Peer::Connected { multiaddr, .. }
            | Peer::Background { multiaddr, .. }
            | Peer::Receiving { multiaddr, .. }
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
            | Peer::Background { multiaddr, .. }
            | Peer::Receiving { multiaddr, .. }
            | Peer::Failed { multiaddr, .. } => multiaddr,
        };
        if multiaddr.get_mut(&addr).map(|addr| *addr = false).is_none() {
            error!("Removed peer that didn't exist.");
        }
    }
    ///
    /// Create a new peer in Registered state.
    ///
    pub(super) fn registered<H>(
        peer_id: PeerId,
        multiaddr: H,
        version: Option<ReplicationVersion>,
    ) -> Self
    where
        H: IntoIterator<Item = (Multiaddr, bool)>,
    {
        let multiaddr = multiaddr.into_iter().collect();
        debug!("[{}] Registered", peer_id);
        Peer::Registered {
            peer_id,
            multiaddr,
            last_clock: Instant::now(),
            version,
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
        let (peer_id, multiaddr, version) = match self {
            Peer::Registered {
                peer_id,
                multiaddr,
                version,
                ..
            } => (peer_id.clone(), multiaddr.clone(), version.clone()),
            _ => {
                debug!("Connecting Invalid state ={:?}", self);
                // Unexpected state - disconnect.
                return self.disconnected();
            }
        };
        debug!("[{}] Connecting", peer_id);
        let new_state = Peer::Connecting {
            version,
            peer_id,
            multiaddr,
            last_clock: Instant::now(),
        };
        *self = new_state;
    }

    ///
    /// Try send request outputs.
    ///
    /// # Panics
    ///
    /// Panics if the current state is not Background.
    ///
    pub(super) fn request_outputs(
        &mut self,
        block_epoch: u64,
        block_offset: u32,
        outputs_ids: Vec<u32>,
    ) {
        // take needed fields for disconnect
        let (peer_id, multiaddr, version) = match self {
            Peer::Background {
                peer_id,
                multiaddr,
                version,
                ..
            } => (peer_id.clone(), multiaddr.clone(), version.clone()),
            _ => {
                debug!("request_outputs Invalid state ={:?}", self);
                // Unexpected state - disconnect.
                return self.disconnected();
            }
        };

        let emptry_state = Peer::registered(peer_id, multiaddr, version.into());
        let this = std::mem::replace(self, emptry_state);
        let (peer_id, multiaddr, version, rx, mut tx) = match this {
            Peer::Background {
                peer_id,
                multiaddr,
                version,
                rx,
                tx,
                ..
            } => (peer_id, multiaddr, version, rx, tx),
            _ => unreachable!("Handled in previous match"),
        };

        let request = RequestOutputs {
            block_epoch,
            block_offset,
            outputs_ids,
        };
        let request = ReplicationRequest::RequestOutputs(request);
        trace!("[{}] <- {:?}", peer_id, request);
        let request = request.into_buffer().unwrap();
        let new_state = match tx.try_send(request) {
            Ok(()) => {
                debug!("[{}] Background", peer_id);
                Peer::Background {
                    version,
                    peer_id,
                    multiaddr,
                    last_clock: Instant::now(),
                    tx,
                    rx,
                }
            }
            Err(mpsc::TrySendError { .. }) => Self::registered(peer_id, multiaddr, version.into()),
        };
        *self = new_state;
    }

    ///
    /// Moves to Connected state.
    ///
    /// # Panics
    ///
    /// Panics if the current state is not Connecting.
    ///
    pub(super) fn subscribe(
        &mut self,
        light: bool,
        epoch: u64,
        offset: u32,
        rx: mpsc::Receiver<Vec<u8>>,
        mut tx: mpsc::Sender<Vec<u8>>,
    ) {
        let (peer_id, multiaddr, version) = match self {
            Peer::Connecting {
                peer_id,
                multiaddr,
                version,
                ..
            } if version.is_some() => (peer_id.clone(), multiaddr.clone(), version.clone()),
            _ => {
                debug!("Subscribe Invalid state ={:?}", self);
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
                    version: version.expect("is_some is handled in match"),
                    peer_id,
                    multiaddr,
                    light,
                    last_clock: Instant::now(),
                    tx,
                    rx,
                }
            }
            Err(mpsc::TrySendError { .. }) => Self::registered(peer_id, multiaddr, version.into()),
        };
        *self = new_state;
    }

    pub(super) fn background(&mut self, rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) {
        let (peer_id, multiaddr, version) = match self {
            Peer::Registered {
                // in case of multiple connections.
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Connecting {
                peer_id,
                multiaddr,
                version,
                ..
            } if version.is_some() => (peer_id.clone(), multiaddr.clone(), version.clone()),
            _ => {
                debug!("Background Invalid state ={:?}", self);
                return;
            }
        };
        debug!("[{}] Background", peer_id);
        let new_state = Peer::Background {
            version: version.expect("is_some is handled in match"),
            peer_id,
            multiaddr,
            last_clock: Instant::now(),
            tx,
            rx,
        };
        *self = new_state;
    }

    // Promote background connection to foreground.
    pub(super) fn promote_background(&mut self, epoch: u64, offset: u32, light: bool) {
        // take needed fields for disconnect
        let (peer_id, multiaddr, version) = match self {
            Peer::Background {
                peer_id,
                multiaddr,
                version,
                ..
            } => (peer_id.clone(), multiaddr.clone(), version.clone()),
            _ => {
                debug!("promote_background Invalid state ={:?}", self);
                // Unexpected state - disconnect.
                return self.disconnected();
            }
        };

        let emptry_state = Peer::registered(peer_id, multiaddr, version.into());
        let this = std::mem::replace(self, emptry_state);
        let (peer_id, multiaddr, version, rx, mut tx) = match this {
            Peer::Background {
                peer_id,
                multiaddr,
                version,
                rx,
                tx,
                ..
            } => (peer_id, multiaddr, version, rx, tx),
            _ => unreachable!("Handled in previous match"),
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
                debug!("[{}] Promoted Connected", peer_id);
                Peer::Connected {
                    version,
                    peer_id,
                    multiaddr,
                    light,
                    last_clock: Instant::now(),
                    tx,
                    rx,
                }
            }
            Err(mpsc::TrySendError { .. }) => Self::registered(peer_id, multiaddr, version.into()),
        };
        *self = new_state;
    }

    ///
    /// Disconnects from the upstream and moves to Discovered state.
    ///
    /// # Panics
    ///
    pub(super) fn disconnected(&mut self) {
        let (peer_id, multiaddr, version) = match self {
            Peer::Registered {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Connecting {
                peer_id,
                multiaddr,
                version,
                ..
            } => (peer_id.clone(), multiaddr.clone(), version.clone()),
            Peer::Connected {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Background {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Receiving {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Failed {
                peer_id,
                multiaddr,
                version,
                ..
            } => (peer_id.clone(), multiaddr.clone(), version.clone().into()),
        };

        let new_state = Peer::registered(peer_id, multiaddr, version);
        *self = new_state;
    }

    ///
    /// Moves to Accepted state.
    ///
    pub(super) fn accept(
        &self,
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
    ) -> Option<Downstream> {
        match self {
            Peer::Registered {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Connecting {
                peer_id,
                multiaddr,
                version,
                ..
            } if version.is_some() => {
                debug!("[{}] Accepted", peer_id);
                let new_state = Downstream::Accepted {
                    peer_id: peer_id.clone(),
                    multiaddr: multiaddr.clone(),
                    version: version.clone().expect("is_some is handled in match"),
                    rx,
                    tx,
                    last_clock: Instant::now(),
                };
                return Some(new_state);
            }
            Peer::Registered { peer_id, .. } | Peer::Connecting { peer_id, .. } => {
                debug!("[{}] Rejected version not resolved", peer_id)
            }
            Peer::Connected {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Background {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Receiving {
                peer_id,
                multiaddr,
                version,
                ..
            }
            | Peer::Failed {
                peer_id,
                multiaddr,
                version,
                ..
            } => {
                debug!("[{}] Accepted", peer_id);
                let new_state = Downstream::Accepted {
                    peer_id: peer_id.clone(),
                    multiaddr: multiaddr.clone(),
                    version: version.clone(),
                    rx,
                    tx,
                    last_clock: Instant::now(),
                };
                return Some(new_state);
            }
        }
        None
    }

    pub(crate) fn format_addr((m, b): (&Multiaddr, &bool)) -> String {
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
                version,
                ..
            } => PeerInfo::Discovered {
                version: version.map(|c| c.to_string()).unwrap_or("".to_string()),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Connecting {
                peer_id,
                multiaddr,
                last_clock,
                version,
                ..
            } => PeerInfo::Connecting {
                version: version.map(|c| c.to_string()).unwrap_or("".to_string()),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Connected {
                peer_id,
                multiaddr,
                last_clock,
                version,
                ..
            } => PeerInfo::Connected {
                version: version.to_string(),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Peer::Background {
                peer_id,
                multiaddr,
                last_clock,
                version,
                ..
            } => PeerInfo::Connected {
                version: version.to_string(),
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
                version,
                ..
            } => PeerInfo::Receiving {
                version: version.to_string(),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                epoch: *epoch,
                offset: *offset,
                bytes_received: *bytes_received,
                blocks_received: *blocks_received,
            },
            Peer::Failed {
                peer_id,
                multiaddr,
                last_clock,
                error,
                version,
                ..
            } => PeerInfo::Failed {
                version: version.to_string(),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Self::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                error: format!("{}", error),
            },
        }
    }

    ///
    /// Returns true if this Peer has background connection.
    ///
    pub(super) fn is_background(&self) -> bool {
        match self {
            Peer::Background { .. } => true,
            _ => false,
        }
    }

    ///
    /// Returns true if this Peer has background connection.
    ///
    pub(super) fn is_connected(&self) -> bool {
        match self {
            Peer::Connecting { .. }
            | Peer::Connected { .. }
            | Peer::Receiving { .. }
            | Peer::Background { .. } => true,
            _ => false,
        }
    }

    ///
    /// Returns true if this Peer is an upstream.
    ///
    pub(super) fn is_upstream(&self) -> bool {
        match self {
            Peer::Connected { .. } | Peer::Receiving { .. } => true,
            _ => false,
        }
    }

    ///
    /// The state machine.
    ///
    pub(super) fn poll(&mut self, cx: &mut Context) -> Poll<ReplicationRow> {
        match self {
            //--------------------------------------------------------------------------------------
            // Registered
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
                version,
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
                            version: version.clone(),
                            error,
                        };
                        *self = new_state;
                        return Poll::Pending;
                    }
                };

                //
                // Process the response.
                //
                trace!("[{}] -> {:?}", peer_id, response);
                let tmp_state =
                    Self::registered(peer_id.clone(), multiaddr.clone(), version.clone().into());
                let (peer_id, multiaddr, light, version, rx, tx) =
                    match std::mem::replace(self, tmp_state) {
                        Peer::Connected {
                            peer_id,
                            multiaddr,
                            rx,
                            tx,
                            light,
                            version,
                            ..
                        } => (peer_id, multiaddr, light, version, rx, tx),
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
                            version,
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
                            version,
                            peer_id,
                            multiaddr,
                            last_clock: Instant::now(),
                            error,
                        }
                    }
                };
                *self = new_state;
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Background
            //--------------------------------------------------------------------------------------
            Peer::Background {
                peer_id,
                multiaddr,
                rx,
                last_clock,
                version,
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
                            version: version.clone(),
                            error,
                        };
                        *self = new_state;
                        return Poll::Pending;
                    }
                };

                //
                // Process the response.
                //
                trace!("[{}] -> {:?}", peer_id, response);
                let new_state = match response {
                    ReplicationResponse::OutputsInfo(outputs_info) => {
                        return Poll::Ready(ReplicationRow::OutputsInfo(outputs_info));
                    }
                    response => {
                        let error = format!(
                            "Unexpected response: expected=OutputsInfo, got={}",
                            response.name()
                        );
                        error!("[{}] {}", peer_id, error);
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
                        Peer::Failed {
                            version: version.clone(),
                            peer_id: peer_id.clone(),
                            multiaddr: multiaddr.clone(),
                            last_clock: Instant::now(),
                            error,
                        }
                    }
                };
                *self = new_state;
                Poll::Pending
            }

            //--------------------------------------------------------------------------------------
            // Receiving
            //--------------------------------------------------------------------------------------
            Peer::Receiving {
                version,
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
                                        version: version.clone(),
                                        peer_id: peer_id.clone(),
                                        multiaddr: multiaddr.clone(),
                                        last_clock: Instant::now(),
                                        error,
                                    };
                                    *self = new_state;
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
                                    *last_clock = Instant::now();
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
                                    *last_clock = Instant::now();
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
                                        version: version.clone(),
                                        peer_id: peer_id.clone(),
                                        multiaddr: multiaddr.clone(),
                                        last_clock: Instant::now(),
                                        error,
                                    };
                                    *self = new_state;
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
            // Failed
            //--------------------------------------------------------------------------------------
            Peer::Failed { peer_id, .. } => {
                trace!("[{}] Poll Failed", peer_id);
                Poll::Pending
            }
        }
    }
}

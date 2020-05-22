use super::api::PeerInfo;
use super::peer::Peer;
use super::protos::{OutputsInfo, ReplicationRequest, ReplicationResponse};
use futures::channel::mpsc;
use futures::{
    task::{Context, Poll},
    StreamExt,
};
use log::*;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;
use stegos_blockchain::{Block, BlockReader, LightBlock};
use stegos_blockchain::{MacroBlockHeader, MicroBlockHeader};
use stegos_network::{Multiaddr, PeerId, ReplicationVersion};
use stegos_serialization::traits::ProtoConvert;
use tokio::time::Instant;

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
            (self.epoch, micro_blocks_in_epoch)
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

/// How long a peer can stay without network activity.
const MAX_IDLE_DURATION: Duration = Duration::from_secs(60);
/// How long a peer can stay in Receiving/Sending state.
const MAX_STREAMING_DURATION: Duration = Duration::from_secs(60 * 10);
/// Maximal size of batch in blocks.
pub const MAX_BLOCKS_PER_BATCH: usize = 100; // Average block size is 100k.
/// Maximal size of batch in bytes.
const MAX_BYTES_PER_BATCH: u64 = 10 * 1024 * 1024; // 10Mb.

pub enum Downstream {
    BugState,
    Accepted {
        version: ReplicationVersion,
        peer_id: PeerId,
        multiaddr: HashMap<Multiaddr, bool>,
        last_clock: Instant,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    Sending {
        version: ReplicationVersion,
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
}

impl Downstream {
    pub fn info(&self, banned: bool) -> PeerInfo {
        match self {
            Downstream::BugState {
            } => unreachable!("This state is used to move data from one state to another, and should never apear between poll()."),
            Downstream::Accepted {
                version,
                peer_id,
                multiaddr,
                last_clock,
                ..
            } => PeerInfo::Accepted {
                version: version.to_string(),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Peer::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
            },
            Downstream::Sending {
                peer_id,
                multiaddr,
                last_clock,
                epoch,
                offset,
                bytes_sent,
                blocks_sent,
                version,
                ..
            } => PeerInfo::Sending {
                version: version.to_string(),
                peer_id: peer_id.to_base58(),
                multiaddr: multiaddr.iter().map(Peer::format_addr).collect(),
                idle: Instant::now().duration_since(*last_clock).into(),
                banned,
                epoch: *epoch,
                offset: *offset,
                bytes_sent: *bytes_sent,
                blocks_sent: *blocks_sent,
            },
        }
    }

    pub fn poll(
        &mut self,
        cx: &mut Context,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
        block_reader: &dyn BlockReader,
    ) -> Poll<()> {
        match self {
            Downstream::BugState => unreachable!("This state is used to move data from one state to another, and should never apear between poll()."),
            Downstream::Accepted {
                peer_id,
                last_clock,
                rx,
                ref mut  tx,
                ..
            } => {
                trace!("[{}] Poll Accepted", peer_id);
                //
                // Read a request.
                //
                let request = match rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(request)) => request,
                    Poll::Ready(None) => {
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        if Instant::now().duration_since(*last_clock) >= MAX_IDLE_DURATION {
                            debug!("[{}] Peer is not active, disconnecting", peer_id);
                            return Poll::Ready(());
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
                        return Poll::Ready(());
                    }
                };
                //
                // Process the request.
                //
                trace!("[{}] -> {:?}", peer_id, request);
                match request {
                    ReplicationRequest::Subscribe {
                        epoch,
                        offset,
                        light,
                    } => {
                        if epoch > current_epoch {
                            trace!("[{}] Subscribe from the future: epoch={}, offset={}, local_epoch={}, local_offset={}",
                                    peer_id, epoch, offset, current_epoch, current_offset);
                            return Poll::Ready(());
                        }

                        let accepted = std::mem::replace(self, Self::BugState);
                        let (version, peer_id, multiaddr, _last_clock, mut tx, rx,) = match accepted {
                            Downstream::Accepted {
                                version, peer_id, multiaddr, last_clock, tx, rx,
                            } => (version, peer_id, multiaddr, last_clock, tx, rx,),
                            _ => unreachable!("We in accept so no other state should apear.")
                        };

                        let response = ReplicationResponse::Subscribed {
                            current_epoch,
                            current_offset,
                        };
                        trace!("[{}] <- {:?}", peer_id, response);
                        let response = response.into_buffer().unwrap();
                        match tx.try_send(response) {
                            Ok(()) => {
                                debug!("[{}] Sending", peer_id);
                                let new_state = Downstream::Sending {
                                    version,
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
                                *self = new_state;
                            }
                            Err(mpsc::TrySendError { .. }) => {
                                return Poll::Ready(());
                            }
                        }
                    }
                    ReplicationRequest::RequestOutputs(request) => {
                        debug!("Peer request outputs: {:?}", request);
                        let found_outputs = match block_reader.get_block(request.block_epoch, request.block_offset) {
                            Ok(block ) => {
                                let outputs: Box<dyn Iterator<Item=_>> = match block.borrow() {
                                    Block::MacroBlock(b) => Box::new(b.outputs.iter()),
                                    Block::MicroBlock(b) => Box::new(b.outputs()),
                                };
                                let mut resulting_outputs = Vec::new();
                                let ids: HashSet<_> = request.outputs_ids.into_iter().collect();
                                for (id, output, ) in outputs.enumerate() {
                                    if ids.contains(& (id as u32)) {
                                        resulting_outputs.push(output.clone())
                                    }
                                }
                                resulting_outputs
                            }
                            Err(e) => {
                                warn!("Peer request outputs, error during processing request ={}",e);
                                Vec::new()
                            }
                        };
                        let outputs_info = OutputsInfo {
                            block_epoch: request.block_epoch,
                            block_offset: request.block_offset,
                            found_outputs,
                        };
                        let response = ReplicationResponse::OutputsInfo(outputs_info).into_buffer().unwrap();
                        match tx.try_send(response) {
                            Ok(()) => {}
                            Err(mpsc::TrySendError { .. }) => {
                                return Poll::Ready(());
                            }
                        }
                    }
                }
                Poll::Pending
            }
            //--------------------------------------------------------------------------------------
            // Sending
            //--------------------------------------------------------------------------------------
            Downstream::Sending {
                peer_id,
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
                    return Poll::Ready(());
                }

                //
                // Process incoming responses.
                //
                match rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(response)) => {
                        let error =
                            format!("Unexpected response: expected=nothing, got={:?}", response);
                        error!("[{}] {}", peer_id, error);
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(());
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
                                return Poll::Ready(());
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
                                return Poll::Ready(());
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
    ) -> bool
    where
        BlocksIter: IntoIterator<Item = I>,
        I: IntoReplicationResponse + NextEpochOffset + Sized,
    {
        let (peer_id, tx, epoch, offset, total_bytes_sent, total_blocks_sent, clock) = match self {
            Downstream::Sending {
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
                        return false;
                    }
                    break;
                }
                Err(_e) => {
                    return false;
                }
            }
        }
        *clock = Instant::now();
        true
    }
    // Called when a new block is registered.
    pub(super) fn on_block(
        &mut self,
        cx: &mut Context,
        block: &Block,
        light_block: &LightBlock,
        micro_blocks_in_epoch: u32,
    ) -> bool {
        let (current_epoch, current_offset) = match &block {
            Block::MacroBlock(block) => (block.header.epoch, micro_blocks_in_epoch),
            Block::MicroBlock(block) => (block.header.epoch, block.header.offset),
        };
        match self {
            Downstream::Sending {
                epoch,
                offset,
                light,
                ..
            } if *epoch == current_epoch && *offset == current_offset => {
                if !*light {
                    let blocks = vec![block.clone()];
                    return self.send_blocks(
                        cx,
                        blocks.into_iter(),
                        current_epoch,
                        current_offset,
                        micro_blocks_in_epoch,
                    );
                } else {
                    let light_blocks = vec![light_block.clone()];
                    return self.send_blocks(
                        cx,
                        light_blocks.into_iter(),
                        current_epoch,
                        current_offset,
                        micro_blocks_in_epoch,
                    );
                }
            }
            _ => {
                return true;
            }
        }
    }
}

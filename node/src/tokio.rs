//! Node - Tokio-based implementation.

//
// Copyright (c) 2019-2020 Stegos AG
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

use super::api::*;
use super::protos::{ChainLoaderMessage, RequestBlocks, ResponseBlocks};
use super::{NodeIncomingEvent, NodeOutgoingEvent, NodeRequest, NodeResponse, NodeState};
use crate::{
    NodeConfig, CHAIN_LOADER_TOPIC, CONSENSUS_TOPIC, SEALED_BLOCK_TOPIC, TX_TOPIC,
    VIEW_CHANGE_DIRECT, VIEW_CHANGE_PROOFS_TOPIC, VIEW_CHANGE_TOPIC,
};
use failure::{format_err, Error};
use futures::channel::{mpsc, oneshot};
use futures::stream::SelectAll;
use futures::{
    future::{self, Fuse},
    stream,
};
use futures::{select, task::Poll, FutureExt, SinkExt, Stream, StreamExt};
use log::*;
use std::pin::Pin;
use std::thread;
use stegos_blockchain::{Block, BlockReader, Blockchain, Transaction};
use stegos_crypto::pbc;
use stegos_network::PeerId;
use stegos_network::{Network, ReplicationEvent};
use stegos_replication::{Replication, ReplicationRow};
use stegos_serialization::traits::ProtoConvert;
pub use stegos_txpool::MAX_PARTICIPANTS;
use tokio::time::{self, Delay, Instant, Interval};

#[allow(unused_macros)]
macro_rules! strace {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log::log!(log::Level::Trace, concat!("[{}] ", $fmt), $self.state.network_pkey, $($arg),*);
    );
}
#[allow(unused_macros)]
macro_rules! sdebug {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log::log!(log::Level::Debug, concat!("[{}] ", $fmt), $self.state.network_pkey, $($arg),*);
    );
}
#[allow(unused_macros)]
macro_rules! sinfo {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log::log!(log::Level::Info, concat!("[{}] ", $fmt), $self.state.network_pkey, $($arg),*);
    );
}
#[allow(unused_macros)]
macro_rules! swarn {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log::log!(log::Level::Warn, concat!("[{}] ", $fmt), $self.state.network_pkey, $($arg),*);
    );
}
#[allow(unused_macros)]
macro_rules! serror {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log::log!(log::Level::Error, concat!("[{}] ", $fmt), $self.state.network_pkey, $($arg),*);
    );
}

// ----------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------

/// Blockchain Node.
#[derive(Clone, Debug)]
pub struct Node {
    outbox: mpsc::UnboundedSender<NodeIncomingEvent>,
    network: Network,
}

impl Node {
    /// Send transaction to node and to the network.
    pub fn send_transaction(&self, transaction: Transaction) -> oneshot::Receiver<NodeResponse> {
        let (tx, rx) = oneshot::channel();
        let request = NodeRequest::BroadcastTransaction { data: transaction };
        let msg = NodeIncomingEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Node Request.
    pub fn request(&self, request: NodeRequest) -> oneshot::Receiver<NodeResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = NodeIncomingEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

/// Chain subscriber which is fed from the disk.
struct ChainReader {
    /// Current epoch.
    epoch: u64,
    /// Current offset.
    offset: u32,
    /// Channel.
    tx: mpsc::Sender<ChainNotification>,
}

impl ChainReader {
    fn advance(&mut self, chain: &Blockchain) -> Result<(), ()> {
        // Check if subscriber has already been synchronized.
        if self.epoch == chain.epoch() && self.offset == chain.offset() {
            return Ok(());
        }

        // Feed blocks from the disk.
        for block in chain.blocks_starting(self.epoch, self.offset) {
            let (msg, next_epoch, next_offset) = match block {
                Block::Macroblock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    let epoch_info = chain
                        .epoch_info(block.header.epoch)
                        .unwrap()
                        .unwrap()
                        .clone();
                    let epoch = block.header.epoch;
                    let old_epoch_info = if epoch > 0 {
                        Some(
                            chain
                                .epoch_info(epoch - 1)
                                .unwrap()
                                .expect("Expect epoch info for last Macroblock.")
                                .clone(),
                        )
                    } else {
                        None
                    };
                    let next_epoch = block.header.epoch + 1;
                    let msg = ExtendedMacroblock {
                        block,
                        epoch_info,
                        old_epoch_info,
                    };
                    let msg = ChainNotification::MacroblockCommitted(msg);
                    (msg, next_epoch, 0)
                }
                Block::Microblock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    assert_eq!(block.header.offset, self.offset);
                    let (next_epoch, next_offset) =
                        if block.header.offset + 1 < chain.cfg().blocks_in_epoch {
                            (block.header.epoch, block.header.offset + 1)
                        } else {
                            (block.header.epoch + 1, 0)
                        };
                    let msg = ChainNotification::MicroblockPrepared(block);
                    (msg, next_epoch, next_offset)
                }
            };

            match self.tx.try_send(msg) {
                Ok(()) => {
                    self.epoch = next_epoch;
                    self.offset = next_offset;
                }
                Err(e) => {
                    if e.is_full() {
                        warn!("Receiver can't receive blocks so fast, slowing down.");
                        break;
                    }
                    error!("Tx stopped = {}", e);
                    return Err(());
                }
            }
        }
        Ok(())
    }
}

pub struct NodeService {
    state: NodeState,

    /// Timer to check sync status
    check_sync: Interval,

    /// Aggregated stream of events.
    //events: Vec<Pin<Box<dyn Stream<Item = NodeIncomingEvent> + Send>>>,
    events: SelectAll<Pin<Box<dyn Stream<Item = NodeIncomingEvent> + Send>>>,
    /// Subscribers for status events.
    status_subscribers: Vec<mpsc::Sender<StatusNotification>>,
    /// Subscribers for chain events.
    chain_subscribers: Vec<mpsc::Sender<ChainNotification>>,
    /// Network interface.
    network: Network,

    /// Replication
    replication: Replication,
    replication_rx: mpsc::UnboundedReceiver<ReplicationEvent>,
    replication_tx: mpsc::UnboundedSender<ReplicationEvent>,

    outgoing_rx: mpsc::UnboundedReceiver<NodeOutgoingEvent>,

    mblock_propose_timer: Pin<Box<Fuse<oneshot::Receiver<()>>>>,
    mblock_view_change_timer: Pin<Box<Fuse<Delay>>>,
    ublock_propose_timer: Pin<Box<Fuse<oneshot::Receiver<Vec<u8>>>>>,
    ublock_view_change_timer: Pin<Box<Fuse<Delay>>>,

    now: Instant,
}

impl NodeService {
    /// Constructor.
    pub fn new(
        cfg: NodeConfig,
        chain: Blockchain,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        chain_name: String,
        peer_id: PeerId,
        replication_rx: mpsc::UnboundedReceiver<ReplicationEvent>,
    ) -> Result<(Self, Node), Error> {
        let (out_tx, out_rx) = mpsc::unbounded();
        let state = NodeState::new(cfg, chain, network_skey, network_pkey, chain_name, out_tx)?;
        let (outbox, inbox) = mpsc::unbounded();

        let status_subscribers = Vec::new();

        let mut streams = Vec::<Pin<Box<dyn Stream<Item = NodeIncomingEvent> + Send>>>::new();

        // Control messages
        streams.push(Box::pin(inbox));

        // Transaction Requests
        let transaction_rx = network
            .subscribe(&TX_TOPIC)?
            .map(|m| NodeIncomingEvent::Transaction(m));
        streams.push(transaction_rx.boxed());

        // Consensus Requests
        let consensus_rx = network
            .subscribe(&CONSENSUS_TOPIC)?
            .map(|m| NodeIncomingEvent::Consensus(m));
        streams.push(consensus_rx.boxed());

        let view_change_rx = network
            .subscribe(&VIEW_CHANGE_TOPIC)?
            .map(|m| NodeIncomingEvent::ViewChangeMessage(m));
        streams.push(view_change_rx.boxed());

        let view_change_proofs_rx = network
            .subscribe(&VIEW_CHANGE_PROOFS_TOPIC)?
            .map(|m| NodeIncomingEvent::ViewChangeProof(m));
        streams.push(view_change_proofs_rx.boxed());

        let view_change_unicast_rx = network.subscribe_unicast(&VIEW_CHANGE_DIRECT)?.map(|m| {
            NodeIncomingEvent::ViewChangeProofMessage {
                from: m.from,
                data: m.data,
            }
        });
        streams.push(view_change_unicast_rx.boxed());

        // Sealed blocks broadcast topic.
        let block_rx = network
            .subscribe(&SEALED_BLOCK_TOPIC)?
            .map(|m| NodeIncomingEvent::Block(m));
        streams.push(block_rx.boxed());

        // Chain loader messages.
        let requests_rx = network.subscribe_unicast(CHAIN_LOADER_TOPIC)?.map(|m| {
            NodeIncomingEvent::ChainLoaderMessage {
                from: m.from,
                data: m.data,
            }
        });
        streams.push(requests_rx.boxed());

        let sync_timeout = state.cfg.sync_timeout;
        let check_sync = time::interval(sync_timeout);
        let chain_subscribers = Vec::new();
        let node = Node {
            outbox,
            network: network.clone(),
        };
        let (replication_tx, proxy_rx) = mpsc::unbounded();
        let light = false;
        let replication = Replication::new(peer_id, network.clone(), light, proxy_rx);

        let service = NodeService {
            state,
            chain_subscribers,
            network: network.clone(),
            check_sync,
            events: stream::select_all(streams),
            replication,
            replication_rx,
            replication_tx,
            status_subscribers,
            outgoing_rx: out_rx,
            mblock_propose_timer: Box::pin(Fuse::terminated()),
            mblock_view_change_timer: Box::pin(Fuse::terminated()),
            ublock_propose_timer: Box::pin(Fuse::terminated()),
            ublock_view_change_timer: Box::pin(Fuse::terminated()),
            now: Instant::now(),
        };

        strace!(service, "Sync timeout = {:?}", sync_timeout);

        Ok((service, node))
    }

    /// Invoked when network is ready.
    pub fn init(&mut self) -> Result<(), Error> {
        self.state.init()
    }

    #[cfg(test)]
    pub fn state(&self) -> &NodeState {
        &self.state
    }

    #[cfg(test)]
    pub fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    #[cfg(test)]
    pub fn network(&self) -> &Network {
        return &self.network;
    }

    /// Notify all subscribers about new event.
    fn notify_subscribers<T: Clone>(subscribers: &mut Vec<mpsc::Sender<T>>, msg: T) {
        let mut i = 0;
        while i < subscribers.len() {
            let tx = &mut subscribers[i];
            match tx.try_send(msg.clone()) {
                Ok(_) => {}
                Err(e /* SendError<ChainNotification> */) => {
                    if e.is_full() {
                        warn!("Subscriber is slow, discarding message, and remove subscriber");
                    }
                    subscribers.swap_remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// Handler subscription to status.
    fn handle_subscription_to_status(
        &mut self,
    ) -> Result<mpsc::Receiver<StatusNotification>, Error> {
        let (tx, rx) = mpsc::channel(1);
        self.status_subscribers.push(tx);
        Ok(rx)
    }

    /// Handle subscription to chain.
    fn handle_subscription_to_chain(
        &mut self,
        chain_readers: &mut Vec<ChainReader>,
        epoch: u64,
        offset: u32,
    ) -> Result<mpsc::Receiver<ChainNotification>, Error> {
        if epoch > self.state.chain.epoch() {
            return Err(format_err!("Invalid epoch requested: epoch={}", epoch));
        }
        // Set buffer size to fit entire epoch plus some extra blocks.
        let buffer = self.state.chain.cfg().blocks_in_epoch as usize + 10;
        let (tx, rx) = mpsc::channel(buffer);
        let subscriber = ChainReader { tx, epoch, offset };
        chain_readers.push(subscriber);
        Ok(rx)
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    // Loader
    /////////////////////////////////////////////////////////////////////////////////////////////////

    pub fn request_history_from(&mut self, from: pbc::PublicKey) -> Result<(), Error> {
        let epoch = self.state.chain.epoch();
        sinfo!(self, "Downloading blocks: from={}, epoch={}", &from, epoch);
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(epoch));
        self.network
            .send(from, CHAIN_LOADER_TOPIC, msg.into_buffer()?)
    }

    fn handle_request_blocks(
        &mut self,
        pkey: pbc::PublicKey,
        request: RequestBlocks,
    ) -> Result<(), Error> {
        if request.epoch > self.state.chain.epoch() {
            swarn!(
                self,
                "Received a loader request with epoch >= our_epoch: remote_epoch={}, our_epoch={}",
                request.epoch,
                self.state.chain.epoch()
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
        for block in self.state.chain.blocks_starting(epoch, offset) {
            blocks.push(block);
            // Feed the whole epoch.
            match blocks.last().unwrap() {
                Block::Macroblock(_) if blocks.len() > 0 => {
                    break;
                }
                Block::Macroblock(_) => {}
                Block::Microblock(_) => {}
            }
        }
        sinfo!(
            self,
            "Feeding blocks: to={}, num_blocks={}",
            pkey,
            blocks.len()
        );
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
            Some(Block::Macroblock(block)) => block.header.epoch,
            Some(Block::Microblock(block)) => block.header.epoch,
            None => {
                // Empty response
                sinfo!(
                    self,
                    "Received blocks: from={}, num_blocks={}",
                    pkey,
                    response.blocks.len()
                );
                return Ok(());
            }
        };
        let last_epoch = match response.blocks.last() {
            Some(Block::Macroblock(block)) => block.header.epoch,
            Some(Block::Microblock(block)) => block.header.epoch,
            None => unreachable!("Checked above"),
        };
        if first_epoch > self.state.chain.epoch() {
            swarn!(
                self,
                "Received blocks from the future: from={}, our_epoch={}, first_epoch={}",
                pkey,
                self.state.chain.epoch(),
                first_epoch
            );
            return Ok(());
        } else if last_epoch < self.state.chain.epoch() {
            swarn!(
                self,
                "Received blocks from the past: from={}, last_epoch={}, our_epoch={}",
                pkey,
                last_epoch,
                self.state.chain.epoch()
            );
            return Ok(());
        }

        sinfo!(
            self,
            "Received blocks: from={}, first_epoch={}, our_epoch={}, last_epoch={}, num_blocks={}",
            pkey,
            first_epoch,
            self.state.chain.epoch(),
            last_epoch,
            response.blocks.len()
        );

        for block in response.blocks {
            // Fail on the first error.
            let event = NodeIncomingEvent::DecodedBlock(block);
            self.state.handle_event(event)?;
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

    pub async fn start(mut self) {
        loop {
            self.poll().await;
        }
    }

    pub async fn poll(&mut self) {
        strace!(self, "Polling node. Elapsed {:?}", self.now.elapsed());
        self.now = Instant::now();

        // Subscribers for chain events which are fed from the disk.
        // Automatically promoted to chain_subscribers after synchronization.
        let mut chain_readers = Vec::<ChainReader>::new();

        // handle events, then flush responses.
        select! {
            ev = self.replication_rx.next().fuse() => {
                let _ = self.replication_tx.send(ev.unwrap()).await;
            }
            // outgoign events
            ev = self.outgoing_rx.next().fuse() => {
                self.handle_outgoing(ev.unwrap()).await;
            }
            // poll timers
            _ = self.mblock_propose_timer.as_mut() => {
                let event = NodeIncomingEvent::ProposeMacroblock;
                if let Err(e) = self.state.handle_event(event) {
                    serror!(self, "Error handling event: {}", e);
                }
            },
            _ = self.mblock_view_change_timer.as_mut() => {
                let event = NodeIncomingEvent::MacroblockViewChangeTimer;
                if let Err(e) = self.state.handle_event(event) {
                    serror!(self, "Error handling event: {}", e);
                }
            },

            solution = self.ublock_propose_timer.as_mut() => {
                // Panic is possible only if thread of solver was killed, which is a bug.
                let solution = solution.expect("Solution should always be calculated, no panics expected.");
                let event = NodeIncomingEvent::ProposeMicroblock(solution);
                if let Err(e) = self.state.handle_event(event) {
                    serror!(self, "Error handling event: {}", e);
                }
            },

            _ = self.ublock_view_change_timer.as_mut() => {
                let event = NodeIncomingEvent::MicroblockViewChangeTimer;
                if let Err(e) = self.state.handle_event(event) {
                    serror!(self, "Error handling event: {}", e);
                }
            },
            interval = self.check_sync.tick().fuse() => {
                let event = NodeIncomingEvent::CheckSyncTimer;
                if let Err(e) = self.state.handle_event(event) {
                    serror!(self, "Error handling event: {}", e);
                }
            },

            event = self.events.next() => {
                let event = event.expect("Should be no end in internall event stream.");
                match event {
                    NodeIncomingEvent::Request { request, tx } => {
                        match request {
                            NodeRequest::ChangeUpstream {} => {
                                self.replication.change_upstream(false);
                                let response = NodeResponse::UpstreamChanged;
                                tx.send(response).ok(); // ignore errors.
                            }
                            NodeRequest::ReplicationInfo {} => {
                                let response =
                                    NodeResponse::ReplicationInfo(self.replication.info());
                                tx.send(response).ok(); // ignore errors.
                            }
                            NodeRequest::SubscribeChain { epoch, offset } => {
                                let response =
                                    match self.handle_subscription_to_chain(&mut chain_readers, epoch, offset) {
                                        Ok(rx) => NodeResponse::SubscribedChain {
                                            current_epoch: self.state.chain.epoch(),
                                            current_offset: self.state.chain.offset(),
                                            rx: Some(rx),
                                        },
                                        Err(e) => NodeResponse::Error {
                                            error: format!("{}", e),
                                        },
                                    };
                                tx.send(response).ok(); // ignore errors.
                            }
                            NodeRequest::SubscribeStatus {} => {
                                let response = match self.handle_subscription_to_status() {
                                    Ok(rx) => {
                                        let status = self.state.chain.status();
                                        NodeResponse::SubscribedStatus {
                                            status,
                                            rx: Some(rx),
                                        }
                                    }
                                    Err(e) => NodeResponse::Error {
                                        error: format!("{}", e),
                                    },
                                };
                                tx.send(response).ok(); // ignore errors.
                            }
                            request => {
                                let event = NodeIncomingEvent::Request { request, tx };
                                if let Err(e) = self.state.handle_event(event) {
                                    serror!(self, "Error processing outgoing event: {}", e);
                                }
                            }
                        }
                    }
                    NodeIncomingEvent::ChainLoaderMessage { from, data } => {
                        if let Err(e) = ChainLoaderMessage::from_buffer(&data)
                            .map(|data| self.handle_chain_loader_message(from, data))
                        {
                            serror!(self, "Invalid block from loader: {}", e);
                        }
                    }
                    event => {
                        if let Err(e) = self.state.handle_event(event) {
                            serror!(self, "Error handling event: {}", e);
                        }
                    }
                }
            },
        }

        strace!(self, "Processed tokio and timers, on to replication...");
        // Replication
        'inner: loop {
            // Replication interface need deep interaction with state and blockchain.
            // So we create a temporary feature that fastly return result of poll.
            // TODO: Replace by refcell and local task
            let replication_fut = future::poll_fn(|cx| {
                let blocks_in_epoch = self.state.chain.cfg().blocks_in_epoch;
                let block_reader: &dyn BlockReader = &self.state.chain;
                Poll::Ready(self.replication.poll(
                    cx,
                    self.state.chain.epoch(),
                    self.state.chain.offset(),
                    blocks_in_epoch,
                    block_reader,
                ))
            });

            match replication_fut.await {
                Poll::Ready(Some(ReplicationRow::LightBlock(_block))) => {
                    panic!("Received the light block from the replication");
                }
                Poll::Ready(Some(ReplicationRow::OutputsInfo(_outputs_info))) => {
                    panic!("Received the light node outputs info from the replication");
                }
                Poll::Ready(Some(ReplicationRow::Block(block))) => {
                    let event = NodeIncomingEvent::DecodedBlock(block);
                    if let Err(e) = self.state.handle_event(event) {
                        serror!(self, "Error handling event: {}", e);
                    }
                }
                Poll::Ready(None) => panic!(), // Shutdown main feature (replication failure).
                Poll::Pending => break 'inner,
            }
        }

        for mut reader in std::mem::replace(&mut chain_readers, Vec::new()) {
            if let Ok(_) = reader.advance(&self.state.chain) {
                chain_readers.push(reader)
            }
        }
    }

    async fn handle_outgoing(&mut self, event: NodeOutgoingEvent) {
        strace!(self, "Outgoing event = {}", event);
        let result = match event {
            NodeOutgoingEvent::FacilitatorChanged { .. } => Ok(()),
            NodeOutgoingEvent::ChangeUpstream {} => {
                self.replication.change_upstream(true);
                Ok(())
            }
            NodeOutgoingEvent::Publish { topic, data } => {
                //
                self.network.publish(&topic, data)
            }
            NodeOutgoingEvent::Send { dest, topic, data } => {
                //
                self.network.send(dest, &topic, data)
            }
            NodeOutgoingEvent::ProposeMacroblock => {
                let (tx, rx) = oneshot::channel::<()>();
                tx.send(()).ok();
                self.mblock_propose_timer.set(rx.fuse());
                self.ublock_propose_timer.set(Fuse::terminated());
                self.ublock_view_change_timer.set(Fuse::terminated());
                Ok(())
            }
            NodeOutgoingEvent::MacroblockViewChangeTimer(duration) => {
                self.mblock_view_change_timer
                    .set(time::delay_for(duration).fuse());
                self.ublock_propose_timer.set(Fuse::terminated());
                self.ublock_view_change_timer.set(Fuse::terminated());
                Ok(())
            }
            NodeOutgoingEvent::MicroblockProposeTimer {
                random,
                vdf,
                difficulty,
            } => {
                trace!("Solving VDF puzzle...");
                let (tx, rx) = oneshot::channel::<Vec<u8>>();
                let challenge = random.to_bytes();
                let solver = move || {
                    let solution = vdf.solve(&challenge, difficulty);
                    tx.send(solution).ok(); // ignore errors.
                };
                // Spawn a background thread to solve VDF puzzle.
                strace!(
                    self,
                    "Solving VDF challenge with difficulty = {}, spawning thread...",
                    difficulty
                );
                thread::spawn(solver);
                self.ublock_propose_timer.set(rx.fuse());
                self.mblock_propose_timer.set(Fuse::terminated());
                self.mblock_view_change_timer.set(Fuse::terminated());
                Ok(())
            }
            NodeOutgoingEvent::MicroblockProposeTimerCancel => {
                self.ublock_propose_timer.set(Fuse::terminated());
                Ok(())
            }
            NodeOutgoingEvent::MicroblockViewChangeTimer(duration) => {
                strace!(
                    self,
                    "Setting the Microblock view change timer to {:?}",
                    duration
                );
                self.ublock_view_change_timer
                    .set(time::delay_for(duration).fuse());
                self.mblock_propose_timer.set(Fuse::terminated());
                self.mblock_view_change_timer.set(Fuse::terminated());
                // task::current().notify();
                Ok(())
            }
            NodeOutgoingEvent::ReplicationBlock { .. } => Ok(()),
            /*
            NodeOutgoingEvent::ReplicationBlock { block, light_block } => {
                // TODO: refator on_block to be async fn.
                let block = block;
                let light_block = light_block;
                //let replication = &mut replication;
                //let state = &state;
                future::poll_fn(move |cx| {
                    self.replication.on_block(
                        cx,
                        block.clone(),
                        light_block.clone(),
                        self.state.chain.cfg().blocks_in_epoch,
                    );
                    Poll::Ready(())
                })
                .await;
                Ok(())
            }
            */
            NodeOutgoingEvent::StatusNotification(notification) => {
                Self::notify_subscribers(&mut self.status_subscribers, notification);
                Ok(())
            }
            NodeOutgoingEvent::ChainNotification(notification) => {
                Self::notify_subscribers(&mut self.chain_subscribers, notification);
                Ok(())
            }
            NodeOutgoingEvent::RequestBlocksFrom { from } => self.request_history_from(from),
            NodeOutgoingEvent::SendBlocksTo { to, epoch, offset } => {
                self.send_blocks(to, epoch, offset)
            }
        };
        if let Err(e) = result {
            error!("Error: {}", e);
        }
    }
}

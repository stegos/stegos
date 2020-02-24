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
use futures::sync::{mpsc, oneshot};
use futures::{task, Async, AsyncSink, Future, Poll, Sink, Stream};
use futures_stream_select_all_send::select_all;
use log::*;
use std::thread;
use stegos_blockchain::{Block, BlockReader, Blockchain, Transaction};
use stegos_crypto::pbc;
use stegos_network::PeerId;
use stegos_network::{Network, ReplicationEvent};
use stegos_replication::{Replication, ReplicationRow};
use stegos_serialization::traits::ProtoConvert;
use stegos_txpool::TransactionPoolService;
pub use stegos_txpool::MAX_PARTICIPANTS;
use tokio_timer::{clock, Delay, Interval};

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
    fn poll(&mut self, chain: &Blockchain) -> Poll<(), Error> {
        // Check if subscriber has already been synchronized.
        if self.epoch == chain.epoch() && self.offset == chain.offset() {
            return Ok(Async::Ready(()));
        }

        // Feed blocks from the disk.
        for block in chain.blocks_starting(self.epoch, self.offset) {
            let (msg, next_epoch, next_offset) = match block {
                Block::MacroBlock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    let epoch_info = chain.epoch_info(block.header.epoch)?.unwrap().clone();
                    let next_epoch = block.header.epoch + 1;
                    let msg = ExtendedMacroBlock { block, epoch_info };
                    let msg = ChainNotification::MacroBlockCommitted(msg);
                    (msg, next_epoch, 0)
                }
                Block::MicroBlock(block) => {
                    assert_eq!(block.header.epoch, self.epoch);
                    assert_eq!(block.header.offset, self.offset);
                    let (next_epoch, next_offset) =
                        if block.header.offset + 1 < chain.cfg().micro_blocks_in_epoch {
                            (block.header.epoch, block.header.offset + 1)
                        } else {
                            (block.header.epoch + 1, 0)
                        };
                    let msg = ChainNotification::MicroBlockPrepared(block);
                    (msg, next_epoch, next_offset)
                }
            };

            match self.tx.start_send(msg)? {
                AsyncSink::Ready => {
                    self.epoch = next_epoch;
                    self.offset = next_offset;
                }
                AsyncSink::NotReady(_msg) => {
                    break;
                }
            }
        }

        self.tx.poll_complete()?;
        Ok(Async::NotReady)
    }
}

/// Notify all subscribers about new event.
fn notify_subscribers<T: Clone>(subscribers: &mut Vec<mpsc::Sender<T>>, msg: T) {
    let mut i = 0;
    while i < subscribers.len() {
        let tx = &mut subscribers[i];
        match tx.start_send(msg.clone()) {
            Ok(AsyncSink::Ready) => {}
            Ok(AsyncSink::NotReady(_msg)) => {
                log::warn!("Subscriber is slow, discarding messages");
            }
            Err(_e /* SendError<ChainNotification> */) => {
                subscribers.swap_remove(i);
                continue;
            }
        }
        if let Err(_e) = tx.poll_complete() {
            subscribers.swap_remove(i);
            continue;
        }
        i += 1;
    }
}

pub struct NodeService {
    state: NodeState,

    /// Timer to check sync status
    check_sync: Interval,

    /// Aggregated stream of events.
    events: Box<dyn Stream<Item = NodeIncomingEvent, Error = ()> + Send>,

    /// Subscribers for status events.
    status_subscribers: Vec<mpsc::Sender<StatusNotification>>,
    /// Subscribers for chain events.
    chain_subscribers: Vec<mpsc::Sender<ChainNotification>>,
    /// Subscribers for chain events which are fed from the disk.
    /// Automatically promoted to chain_subscribers after synchronization.
    chain_readers: Vec<ChainReader>,
    /// Network interface.
    network: Network,

    macro_block_propose_timer: Option<Delay>,
    macro_block_view_change_timer: Option<Delay>,
    micro_block_propose_timer: Option<oneshot::Receiver<Vec<u8>>>,
    micro_block_view_change_timer: Option<Delay>,

    /// Txpool
    txpool_service: Option<TransactionPoolService>,

    /// Replication
    replication: Replication,
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
        let state = NodeState::new(cfg, chain, network_skey, network_pkey, chain_name)?;
        let (outbox, inbox) = mpsc::unbounded();

        let status_subscribers = Vec::new();

        let mut streams =
            Vec::<Box<dyn Stream<Item = NodeIncomingEvent, Error = ()> + Send>>::new();

        // Control messages
        streams.push(Box::new(inbox));

        // Transaction Requests
        let transaction_rx = network
            .subscribe(&TX_TOPIC)?
            .map(|m| NodeIncomingEvent::Transaction(m));
        streams.push(Box::new(transaction_rx));

        // Consensus Requests
        let consensus_rx = network
            .subscribe(&CONSENSUS_TOPIC)?
            .map(|m| NodeIncomingEvent::Consensus(m));
        streams.push(Box::new(consensus_rx));

        let view_change_rx = network
            .subscribe(&VIEW_CHANGE_TOPIC)?
            .map(|m| NodeIncomingEvent::ViewChangeMessage(m));
        streams.push(Box::new(view_change_rx));

        let view_change_proofs_rx = network
            .subscribe(&VIEW_CHANGE_PROOFS_TOPIC)?
            .map(|m| NodeIncomingEvent::ViewChangeProof(m));
        streams.push(Box::new(view_change_proofs_rx));

        let view_change_unicast_rx = network.subscribe_unicast(&VIEW_CHANGE_DIRECT)?.map(|m| {
            NodeIncomingEvent::ViewChangeProofMessage {
                from: m.from,
                data: m.data,
            }
        });
        streams.push(Box::new(view_change_unicast_rx));

        // Sealed blocks broadcast topic.
        let block_rx = network
            .subscribe(&SEALED_BLOCK_TOPIC)?
            .map(|m| NodeIncomingEvent::Block(m));
        streams.push(Box::new(block_rx));

        // Chain loader messages.
        let requests_rx = network.subscribe_unicast(CHAIN_LOADER_TOPIC)?.map(|m| {
            NodeIncomingEvent::ChainLoaderMessage {
                from: m.from,
                data: m.data,
            }
        });
        streams.push(Box::new(requests_rx));

        let events = select_all(streams);

        let check_sync = Interval::new_interval(state.cfg.sync_change_timeout);
        let chain_readers = Vec::new();
        let chain_subscribers = Vec::new();
        let node = Node {
            outbox,
            network: network.clone(),
        };
        let txpool_service = None;
        let light = false;
        let replication = Replication::new(peer_id, network.clone(), light, replication_rx);

        let service = NodeService {
            state,
            chain_readers,
            chain_subscribers,
            network: network.clone(),
            macro_block_propose_timer: None,
            macro_block_view_change_timer: None,
            micro_block_propose_timer: None,
            micro_block_view_change_timer: None,
            check_sync,
            events,
            txpool_service,
            replication,
            status_subscribers,
        };

        Ok((service, node))
    }

    /// Invoked when network is ready.
    pub fn init(&mut self) -> Result<(), Error> {
        self.state.init()
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
        epoch: u64,
        offset: u32,
    ) -> Result<mpsc::Receiver<ChainNotification>, Error> {
        if epoch > self.state.chain.epoch() {
            return Err(format_err!("Invalid epoch requested: epoch={}", epoch));
        }
        // Set buffer size to fit entire epoch plus some extra blocks.
        let buffer = self.state.chain.cfg().micro_blocks_in_epoch as usize + 10;
        let (tx, rx) = mpsc::channel(buffer);
        let subscriber = ChainReader { tx, epoch, offset };
        self.chain_readers.push(subscriber);
        task::current().notify();
        Ok(rx)
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    // Loader
    /////////////////////////////////////////////////////////////////////////////////////////////////

    pub fn request_history_from(&mut self, from: pbc::PublicKey) -> Result<(), Error> {
        let epoch = self.state.chain.epoch();
        info!("Downloading blocks: from={}, epoch={}", &from, epoch);
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
            warn!(
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
                    response.blocks.len()
                );
                return Ok(());
            }
        };
        let last_epoch = match response.blocks.last() {
            Some(Block::MacroBlock(block)) => block.header.epoch,
            Some(Block::MicroBlock(block)) => block.header.epoch,
            None => unreachable!("Checked above"),
        };
        if first_epoch > self.state.chain.epoch() {
            warn!(
                "Received blocks from the future: from={}, our_epoch={}, first_epoch={}",
                pkey,
                self.state.chain.epoch(),
                first_epoch
            );
            return Ok(());
        } else if last_epoch < self.state.chain.epoch() {
            warn!(
                "Received blocks from the past: from={}, last_epoch={}, our_epoch={}",
                pkey,
                last_epoch,
                self.state.chain.epoch()
            );
            return Ok(());
        }

        info!(
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
            self.state.handle_event(event);
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

// Event loop.
impl Future for NodeService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(timer) = &mut self.macro_block_propose_timer {
            match timer.poll().unwrap() {
                Async::Ready(()) => {
                    std::mem::replace(&mut self.macro_block_propose_timer, None);
                    let event = NodeIncomingEvent::MacroBlockProposeTimer;
                    self.state.handle_event(event);
                }
                Async::NotReady => {}
            }
        }
        if let Some(timer) = &mut self.macro_block_view_change_timer {
            match timer.poll().unwrap() {
                Async::Ready(()) => {
                    std::mem::replace(&mut self.macro_block_view_change_timer, None);
                    let event = NodeIncomingEvent::MacroBlockViewChangeTimer;
                    self.state.handle_event(event);
                }
                Async::NotReady => {}
            }
        }
        if let Some(solver) = &mut self.micro_block_propose_timer {
            match solver.poll().unwrap() {
                Async::Ready(solution) => {
                    std::mem::replace(&mut self.micro_block_propose_timer, None);
                    let event = NodeIncomingEvent::MicroBlockProposeTimer(solution);
                    self.state.handle_event(event);
                }
                Async::NotReady => {}
            }
        }
        if let Some(timer) = &mut self.micro_block_view_change_timer {
            match timer.poll().unwrap() {
                Async::Ready(()) => {
                    std::mem::replace(&mut self.micro_block_view_change_timer, None);
                    let event = NodeIncomingEvent::MicroBlockViewChangeTimer;
                    self.state.handle_event(event);
                }
                Async::NotReady => {}
            }
        }

        loop {
            match self.check_sync.poll() {
                Ok(Async::Ready(Some(_))) => {
                    let event = NodeIncomingEvent::CheckSyncTimer;
                    self.state.handle_event(event);
                    break;
                }
                Ok(Async::Ready(None)) => {
                    error!("Error during process sync status");
                    return Ok(Async::Ready(()));
                }
                Err(e) => {
                    error!("Error: {}", e);
                    return Err(());
                }
                Ok(Async::NotReady) => {
                    break;
                }
            }
        }

        // Poll chain readers.
        let mut i = 0;
        while i < self.chain_readers.len() {
            match self.chain_readers[i].poll(&self.state.chain) {
                Ok(Async::Ready(())) => {
                    // Synchronized with node, convert into a subscription.
                    let subscriber = self.chain_readers.swap_remove(i);
                    self.chain_subscribers.push(subscriber.tx);
                }
                Ok(Async::NotReady) => {
                    i += 1;
                }
                Err(_e) => {
                    self.chain_readers.swap_remove(i);
                }
            }
        }

        if let Some(ref mut txpool_service) = &mut self.txpool_service {
            match txpool_service.poll().unwrap() {
                Async::Ready(()) => return Ok(Async::Ready(())), // Shutdown.
                Async::NotReady => {}
            };
        }
        // Poll internal events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => {
                    match event {
                        NodeIncomingEvent::Request { request, tx } => {
                            match request {
                                NodeRequest::ChangeUpstream {} => {
                                    self.replication.change_upstream();
                                    let response = NodeResponse::UpstreamChanged;
                                    tx.send(response).ok(); // ignore errors.
                                    continue;
                                }
                                NodeRequest::ReplicationInfo {} => {
                                    let response =
                                        NodeResponse::ReplicationInfo(self.replication.info());
                                    tx.send(response).ok(); // ignore errors.
                                    continue;
                                }
                                NodeRequest::SubscribeChain { epoch, offset } => {
                                    let response =
                                        match self.handle_subscription_to_chain(epoch, offset) {
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
                                    continue;
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
                                    continue;
                                }
                                request => {
                                    let event = NodeIncomingEvent::Request { request, tx };
                                    self.state.handle_event(event)
                                }
                            }
                        }
                        NodeIncomingEvent::ChainLoaderMessage { from, data } => {
                            if let Err(e) = ChainLoaderMessage::from_buffer(&data)
                                .map(|data| self.handle_chain_loader_message(from, data))
                            {
                                error!("Invalid block from loader: {}", e);
                            }
                        }
                        event => self.state.handle_event(event),
                    }
                }
                Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
                Async::NotReady => break,
            }
        }
        // Replication
        loop {
            let micro_blocks_in_epoch = self.state.chain.cfg().micro_blocks_in_epoch;
            let block_reader: &dyn BlockReader = &self.state.chain;
            match self.replication.poll(
                self.state.chain.epoch(),
                self.state.chain.offset(),
                micro_blocks_in_epoch,
                block_reader,
            ) {
                Async::Ready(Some(ReplicationRow::LightBlock(_block))) => {
                    panic!("Received the light block from the replication");
                }
                Async::Ready(Some(ReplicationRow::Block(block))) => {
                    let event = NodeIncomingEvent::DecodedBlock(block);
                    self.state.handle_event(event);
                }
                Async::Ready(None) => return Ok(Async::Ready(())), // Shutdown.
                Async::NotReady => break,
            }
        }

        //
        // Flush events.
        //
        for event in std::mem::replace(&mut self.state.outgoing, Vec::new()) {
            let result = match event {
                NodeOutgoingEvent::FacilitatorChanged { facilitator } => {
                    if facilitator == self.state.network_pkey {
                        info!("I am facilitator");
                        let txpool_service = TransactionPoolService::new(self.network.clone());
                        self.txpool_service = Some(txpool_service);
                    } else {
                        info!("Facilitator is {}", facilitator);
                        self.txpool_service = None;
                    }
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
                NodeOutgoingEvent::MacroBlockProposeTimer(duration) => {
                    let deadline = clock::now() + duration;
                    self.macro_block_propose_timer = Some(Delay::new(deadline));
                    task::current().notify();
                    Ok(())
                }
                NodeOutgoingEvent::MacroBlockViewChangeTimer(duration) => {
                    let deadline = clock::now() + duration;
                    self.macro_block_view_change_timer = Some(Delay::new(deadline));
                    task::current().notify();
                    Ok(())
                }
                NodeOutgoingEvent::MicroBlockProposeTimer {
                    random,
                    vdf,
                    difficulty,
                } => {
                    let (tx, rx) = oneshot::channel::<Vec<u8>>();
                    let challenge = random.to_bytes();
                    let solver = move || {
                        let solution = vdf.solve(&challenge, difficulty);
                        tx.send(solution).ok(); // ignore errors.
                    };
                    // Spawn a background thread to solve VDF puzzle.
                    thread::spawn(solver);
                    self.micro_block_propose_timer = Some(rx);
                    task::current().notify();
                    Ok(())
                }
                NodeOutgoingEvent::MicroBlockViewChangeTimer(duration) => {
                    let deadline = clock::now() + duration;
                    self.micro_block_view_change_timer = Some(Delay::new(deadline));
                    task::current().notify();
                    Ok(())
                }
                NodeOutgoingEvent::ReplicationBlock { block, light_block } => {
                    self.replication.on_block(
                        block,
                        light_block,
                        self.state.chain.cfg().micro_blocks_in_epoch,
                    );
                    Ok(())
                }
                NodeOutgoingEvent::StatusNotification(notification) => {
                    notify_subscribers(&mut self.status_subscribers, notification);
                    Ok(())
                }
                NodeOutgoingEvent::ChainNotification(notification) => {
                    notify_subscribers(&mut self.chain_subscribers, notification);
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
        Ok(Async::NotReady)
    }
}

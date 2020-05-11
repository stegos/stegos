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
use futures::{
    future::{self, Fuse, OptionFuture},
    stream,
};
use futures::{select, task::Poll, FutureExt, SinkExt, Stream, StreamExt};
use log::*;
use pin_utils::pin_mut;
use std::pin::Pin;
use std::thread;
use stegos_blockchain::{Block, BlockReader, Blockchain, Transaction};
use stegos_crypto::pbc;
use stegos_network::PeerId;
use stegos_network::{Network, ReplicationEvent};
use stegos_replication::{Replication, ReplicationRow};
use stegos_serialization::traits::ProtoConvert;
use stegos_txpool::TransactionPoolService;
pub use stegos_txpool::MAX_PARTICIPANTS;
use tokio::time::{self, Interval};

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
                Block::MacroBlock(block) => {
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
                                .expect("Expect epoch info for last macroblock.")
                                .clone(),
                        )
                    } else {
                        None
                    };
                    let next_epoch = block.header.epoch + 1;
                    let msg = ExtendedMacroBlock {
                        block,
                        epoch_info,
                        old_epoch_info,
                    };
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
    events: Vec<Pin<Box<dyn Stream<Item = NodeIncomingEvent> + Send>>>,

    /// Subscribers for status events.
    status_subscribers: Vec<mpsc::Sender<StatusNotification>>,
    /// Subscribers for chain events.
    chain_subscribers: Vec<mpsc::Sender<ChainNotification>>,
    /// Network interface.
    network: Network,

    /// Txpool
    txpool_service: Option<TransactionPoolService>,

    replication_rx: mpsc::UnboundedReceiver<ReplicationEvent>,
    replication_tx: mpsc::UnboundedSender<ReplicationEvent>,

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

        let check_sync = time::interval(state.cfg.sync_change_timeout);
        let chain_subscribers = Vec::new();
        let node = Node {
            outbox,
            network: network.clone(),
        };
        let (replication_tx, proxy_rx) = mpsc::unbounded();
        let txpool_service = None;
        let light = false;
        let replication = Replication::new(peer_id, network.clone(), light, proxy_rx);

        let service = NodeService {
            state,
            chain_subscribers,
            network: network.clone(),
            check_sync,
            events: streams,
            txpool_service,
            replication,
            replication_rx,
            replication_tx,
            status_subscribers,
        };

        Ok((service, node))
    }

    /// Invoked when network is ready.
    pub fn init(&mut self) -> Result<(), Error> {
        self.state.init()
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
                        log::warn!("Subscriber is slow, discarding message, and remove subscriber");
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
        status_subscribers: &mut Vec<mpsc::Sender<StatusNotification>>,
    ) -> Result<mpsc::Receiver<StatusNotification>, Error> {
        let (tx, rx) = mpsc::channel(1);
        status_subscribers.push(tx);
        Ok(rx)
    }

    /// Handle subscription to chain.
    fn handle_subscription_to_chain(
        state: &NodeState,
        chain_readers: &mut Vec<ChainReader>,
        epoch: u64,
        offset: u32,
    ) -> Result<mpsc::Receiver<ChainNotification>, Error> {
        if epoch > state.chain.epoch() {
            return Err(format_err!("Invalid epoch requested: epoch={}", epoch));
        }
        // Set buffer size to fit entire epoch plus some extra blocks.
        let buffer = state.chain.cfg().micro_blocks_in_epoch as usize + 10;
        let (tx, rx) = mpsc::channel(buffer);
        let subscriber = ChainReader { tx, epoch, offset };
        chain_readers.push(subscriber);
        Ok(rx)
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    // Loader
    /////////////////////////////////////////////////////////////////////////////////////////////////

    pub fn request_history_from(
        network: &mut Network,
        state: &NodeState,
        from: pbc::PublicKey,
    ) -> Result<(), Error> {
        let epoch = state.chain.epoch();
        info!("Downloading blocks: from={}, epoch={}", &from, epoch);
        let msg = ChainLoaderMessage::Request(RequestBlocks::new(epoch));
        network.send(from, CHAIN_LOADER_TOPIC, msg.into_buffer()?)
    }

    fn handle_request_blocks(
        network: &mut Network,
        state: &NodeState,
        pkey: pbc::PublicKey,
        request: RequestBlocks,
    ) -> Result<(), Error> {
        if request.epoch > state.chain.epoch() {
            warn!(
                "Received a loader request with epoch >= our_epoch: remote_epoch={}, our_epoch={}",
                request.epoch,
                state.chain.epoch()
            );
            return Ok(());
        }

        Self::send_blocks(network, state, pkey, request.epoch, 0)
    }

    pub fn send_blocks(
        network: &mut Network,
        state: &NodeState,
        pkey: pbc::PublicKey,
        epoch: u64,
        offset: u32,
    ) -> Result<(), Error> {
        let mut blocks: Vec<Block> = Vec::new();
        for block in state.chain.blocks_starting(epoch, offset) {
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
        network.send(pkey, CHAIN_LOADER_TOPIC, msg.into_buffer()?)?;
        Ok(())
    }

    fn handle_response_blocks(
        state: &mut NodeState,
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
        if first_epoch > state.chain.epoch() {
            warn!(
                "Received blocks from the future: from={}, our_epoch={}, first_epoch={}",
                pkey,
                state.chain.epoch(),
                first_epoch
            );
            return Ok(());
        } else if last_epoch < state.chain.epoch() {
            warn!(
                "Received blocks from the past: from={}, last_epoch={}, our_epoch={}",
                pkey,
                last_epoch,
                state.chain.epoch()
            );
            return Ok(());
        }

        info!(
            "Received blocks: from={}, first_epoch={}, our_epoch={}, last_epoch={}, num_blocks={}",
            pkey,
            first_epoch,
            state.chain.epoch(),
            last_epoch,
            response.blocks.len()
        );

        for block in response.blocks {
            // Fail on the first error.
            let event = NodeIncomingEvent::DecodedBlock(block);
            state.handle_event(event);
        }

        Ok(())
    }

    pub fn handle_chain_loader_message(
        network: &mut Network,
        state: &mut NodeState,
        pkey: pbc::PublicKey,
        msg: ChainLoaderMessage,
    ) -> Result<(), Error> {
        match msg {
            ChainLoaderMessage::Request(r) => Self::handle_request_blocks(network, state, pkey, r),
            ChainLoaderMessage::Response(r) => Self::handle_response_blocks(state, pkey, r),
        }
    }

    pub async fn start(self) {
        let macro_block_propose_timer = Fuse::terminated();
        let macro_block_view_change_timer = Fuse::terminated();
        let micro_block_propose_timer: Fuse<oneshot::Receiver<Vec<u8>>> = Fuse::terminated();
        let micro_block_view_change_timer = Fuse::terminated();
        pin_mut!(
            macro_block_propose_timer,
            macro_block_view_change_timer,
            micro_block_propose_timer,
            micro_block_view_change_timer
        );

        // let mut chain_readers = future::select_all(self.chain_readers.into_iter().map(Box::pin)).fuse();
        // Subscribers for chain events which are fed from the disk.
        // Automatically promoted to chain_subscribers after synchronization.
        let mut chain_readers = Vec::<ChainReader>::new();
        let mut status_subscribers = self.status_subscribers;
        let mut chain_subscribers = self.chain_subscribers.clone();
        let mut events = stream::select_all(self.events);
        let mut replication = self.replication;
        let mut state = self.state;
        let mut txpool_service: OptionFuture<_> = self.txpool_service.map(FutureExt::fuse).into();
        let mut check_sync = self.check_sync;
        let mut network = self.network;

        let mut replication_rx = self.replication_rx;
        let mut replication_tx = self.replication_tx;

        loop {
            // handle events, then flush responses.
            select! {
                ev = replication_rx.next().fuse() => {let _ = replication_tx.send(ev.unwrap()).await;}
                // poll timers
                _ = macro_block_propose_timer => {
                    let event = NodeIncomingEvent::MacroBlockProposeTimer;
                    state.handle_event(event);
                },
                _ = macro_block_view_change_timer => {
                    let event = NodeIncomingEvent::MacroBlockViewChangeTimer;
                    state.handle_event(event);
                },

                solution = micro_block_propose_timer => {
                    // Panic is possible only if thread of solver was killed, which is a bug.
                    let solution = solution.expect("Solution should always be calculated, no panics expected.");
                    let event = NodeIncomingEvent::MicroBlockProposeTimer(solution);
                    state.handle_event(event);
                },

                _ = micro_block_view_change_timer => {
                    let event = NodeIncomingEvent::MicroBlockViewChangeTimer;
                    state.handle_event(event);
                },
                interval = check_sync.tick().fuse() => {
                    let event = NodeIncomingEvent::CheckSyncTimer;
                    state.handle_event(event);
                },

                _ = txpool_service => {/*do nothing*/},
                event = events.next() => {
                    let event = event.expect("Should be no end in internall event stream.");
                    match event {
                        NodeIncomingEvent::Request { request, tx } => {
                            match request {
                                NodeRequest::ChangeUpstream {} => {
                                    replication.change_upstream(false);
                                    let response = NodeResponse::UpstreamChanged;
                                    tx.send(response).ok(); // ignore errors.
                                    continue;
                                }
                                NodeRequest::ReplicationInfo {} => {
                                    let response =
                                        NodeResponse::ReplicationInfo(replication.info());
                                    tx.send(response).ok(); // ignore errors.
                                    continue;
                                }
                                NodeRequest::SubscribeChain { epoch, offset } => {
                                    let response =
                                        match Self::handle_subscription_to_chain(&mut state, &mut chain_readers, epoch, offset) {
                                            Ok(rx) => NodeResponse::SubscribedChain {
                                                current_epoch: state.chain.epoch(),
                                                current_offset: state.chain.offset(),
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
                                    let response = match Self::handle_subscription_to_status(&mut status_subscribers) {
                                        Ok(rx) => {
                                            let status = state.chain.status();
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
                                    state.handle_event(event)
                                }
                            }
                        }
                        NodeIncomingEvent::ChainLoaderMessage { from, data } => {
                            if let Err(e) = ChainLoaderMessage::from_buffer(&data)
                                .map(|data| Self::handle_chain_loader_message(&mut network, &mut state, from, data))
                            {
                                error!("Invalid block from loader: {}", e);
                            }
                        }
                        event => state.handle_event(event),
                    }
                },

            }
            // Replication
            'inner: loop {
                // Replication interface need deep interaction with state and blockchain.
                // So we create a temporary feature that fastly return result of poll.
                // TODO: Replace by refcell and local task
                let replication_fut = future::poll_fn(|cx| {
                    let micro_blocks_in_epoch = state.chain.cfg().micro_blocks_in_epoch;
                    let block_reader: &dyn BlockReader = &state.chain;
                    Poll::Ready(replication.poll(
                        cx,
                        state.chain.epoch(),
                        state.chain.offset(),
                        micro_blocks_in_epoch,
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
                        state.handle_event(event);
                    }
                    Poll::Ready(None) => return (), // Shutdown main feature (replication failure).
                    Poll::Pending => break 'inner,
                }
            }

            for event in std::mem::replace(&mut state.outgoing, Vec::new()) {
                trace!("Outgoing event = {:?}", event);
                let result = match event {
                    NodeOutgoingEvent::FacilitatorChanged { facilitator } => {
                        if facilitator == state.network_pkey {
                            info!("I am facilitator");
                            let txpool = TransactionPoolService::new(network.clone());
                            txpool_service = OptionFuture::from(Some(txpool).map(FutureExt::fuse));
                        } else {
                            info!("Facilitator is {}", facilitator);
                            txpool_service = OptionFuture::from(None);
                        }
                        Ok(())
                    }
                    NodeOutgoingEvent::ChangeUpstream {} => {
                        replication.change_upstream(true);
                        Ok(())
                    }
                    NodeOutgoingEvent::Publish { topic, data } => {
                        //
                        network.publish(&topic, data)
                    }
                    NodeOutgoingEvent::Send { dest, topic, data } => {
                        //
                        network.send(dest, &topic, data)
                    }
                    NodeOutgoingEvent::MacroBlockProposeTimer(duration) => {
                        macro_block_propose_timer.set(time::delay_for(duration).fuse());
                        micro_block_propose_timer.set(Fuse::terminated());
                        micro_block_view_change_timer.set(Fuse::terminated());
                        Ok(())
                    }
                    NodeOutgoingEvent::MacroBlockProposeTimerCancel => {
                        macro_block_propose_timer.set(Fuse::terminated());
                        Ok(())
                    }
                    NodeOutgoingEvent::MacroBlockViewChangeTimer(duration) => {
                        macro_block_view_change_timer.set(time::delay_for(duration).fuse());
                        micro_block_propose_timer.set(Fuse::terminated());
                        micro_block_view_change_timer.set(Fuse::terminated());
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
                        micro_block_propose_timer.set(rx.fuse());
                        macro_block_propose_timer.set(Fuse::terminated());
                        macro_block_view_change_timer.set(Fuse::terminated());
                        // task::current().notify();
                        Ok(())
                    }
                    NodeOutgoingEvent::MicroBlockProposeTimerCancel => {
                        micro_block_propose_timer.set(Fuse::terminated());
                        Ok(())
                    }
                    NodeOutgoingEvent::MicroBlockViewChangeTimer(duration) => {
                        micro_block_view_change_timer.set(time::delay_for(duration).fuse());
                        macro_block_propose_timer.set(Fuse::terminated());
                        macro_block_view_change_timer.set(Fuse::terminated());
                        // task::current().notify();
                        Ok(())
                    }
                    NodeOutgoingEvent::ReplicationBlock { block, light_block } => {
                        // TODO: refator on_block to be async fn.
                        let block = block;
                        let light_block = light_block;
                        let replication = &mut replication;
                        let state = &state;
                        future::poll_fn(move |cx| {
                            replication.on_block(
                                cx,
                                block.clone(),
                                light_block.clone(),
                                state.chain.cfg().micro_blocks_in_epoch,
                            );
                            Poll::Ready(())
                        })
                        .await;
                        Ok(())
                    }
                    NodeOutgoingEvent::StatusNotification(notification) => {
                        Self::notify_subscribers(&mut status_subscribers, notification);
                        Ok(())
                    }
                    NodeOutgoingEvent::ChainNotification(notification) => {
                        Self::notify_subscribers(&mut chain_subscribers, notification);
                        Ok(())
                    }
                    NodeOutgoingEvent::RequestBlocksFrom { from } => {
                        Self::request_history_from(&mut network, &state, from)
                    }
                    NodeOutgoingEvent::SendBlocksTo { to, epoch, offset } => {
                        Self::send_blocks(&mut network, &mut state, to, epoch, offset)
                    }
                };
                if let Err(e) = result {
                    error!("Error: {}", e);
                }
            }

            for mut reader in std::mem::replace(&mut chain_readers, Vec::new()) {
                if let Ok(_) = reader.advance(&state.chain) {
                    chain_readers.push(reader)
                }
            }
        }
    }
}

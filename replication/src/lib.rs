//! Replication.

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

pub mod api;
mod downstream;
mod peer;
mod protos;

use self::api::*;
use self::downstream::*;
pub use self::peer::MAX_BLOCKS_PER_BATCH;
pub use crate::protos::OutputsInfo;
use futures::channel::mpsc;
use futures::{
    task::{Context, Poll},
    FutureExt, StreamExt,
};
use log::*;
use peer::Peer;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use stegos_blockchain::{Block, BlockReader, LightBlock};
use stegos_network::{Network, PeerId, ReplicationEvent, ReplicationVersion};
use tokio::time::{self, Delay, Instant};

pub enum ReplicationRow {
    Block(Block),
    LightBlock(LightBlock),
    OutputsInfo(OutputsInfo),
}

pub struct ReplicationConfig {
    /// How many connections should we maximum have.
    max_background_connections: usize,
    /// How many connections should we keep.
    background_connections_factor: f32,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            max_background_connections: 4,
            background_connections_factor: 0.5,
        }
    }
}

impl ReplicationConfig {
    fn background_connections(&self, peers_count: usize) -> usize {
        let connections_count = if peers_count != 0 {
            (peers_count - 1) as f32 * self.background_connections_factor
        } else {
            0.
        };
        std::cmp::min(connections_count as usize, self.max_background_connections)
    }
}

pub struct Replication {
    /// My Peer ID.
    peer_id: PeerId,

    /// A map of connected peers.
    peers: HashMap<PeerId, Peer>,

    /// A map of accepted peers.
    downstreams: HashMap<PeerId, Downstream>,

    /// A list of banned peers.
    banned_peers: HashSet<PeerId>,

    /// A timer to handle periodic events.
    periodic_delay: Delay,

    /// True if the light node protocol is used.
    light: bool,

    /// A channel with incoming replication events.
    events: mpsc::UnboundedReceiver<ReplicationEvent>,

    /// Network API.
    network: Network,

    /// Replication connection config
    config: ReplicationConfig,
}

const UPSTREAM_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

impl Replication {
    ///
    /// Initialize replication subsystem.
    ///
    pub fn new(
        peer_id: PeerId,
        network: Network,
        light: bool,
        events: mpsc::UnboundedReceiver<ReplicationEvent>,
    ) -> Self {
        let peers = HashMap::new();
        let downstreams = HashMap::new();
        let periodic_delay = time::delay_for(UPSTREAM_UPDATE_INTERVAL);
        Self {
            peer_id,
            peers,
            downstreams,
            banned_peers: HashSet::new(),
            periodic_delay,
            light,
            events,
            network,
            config: Default::default(),
        }
    }

    /// Returns list of unbanned peers, that is ready to accept our connections.
    pub fn registered_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter_map(|(peer_id, peer)| match &peer {
                Peer::Registered { .. } => Some(peer_id),
                _ => None,
            })
            .filter(|peer_id| !self.banned_peers.contains(*peer_id))
            .cloned()
            .collect()
    }

    /// Returns true if we have active upstream.
    pub fn has_upstream(&self) -> bool {
        for (_peer_id, peer) in self.peers.iter() {
            if peer.is_upstream() {
                return true;
            }
        }
        false
    }
    //
    // Change the current upstream (if any).
    //
    pub fn change_upstream(&mut self, error: bool) {
        for (peer_id, peer) in self.peers.iter_mut() {
            if peer.is_upstream() {
                info!("[{}] Disconnect by the user", peer_id);
                peer.disconnected();
                if error {
                    self.banned_peers.insert(peer_id.clone());
                }
            }
        }
        // A new upstream will be selected on the next poll().
    }

    ///
    /// Processes a new block.
    ///
    pub fn on_block(
        &mut self,
        cx: &mut Context,
        block: Block,
        light_block: LightBlock,
        micro_blocks_in_epoch: u32,
    ) {
        self.downstreams.retain(|_peer_id, peer| {
            peer.on_block(cx, &block, &light_block, micro_blocks_in_epoch)
        });
    }

    ///
    /// Request outputs from random background connection.
    ///
    pub fn try_request_outputs(
        &mut self,
        block_epoch: u64,
        block_offset: u32,
        outputs_ids: Vec<u32>,
    ) -> bool {
        let mut peers = Vec::new();
        for (peer_id, peer) in self.peers.iter_mut() {
            match peer {
                Peer::Background { .. } => peers.push(peer_id.clone()),
                _ => {}
            }
        }
        let mut rng = thread_rng();
        let random_peer = peers.choose(&mut rng);

        if let Some(peer_id) = random_peer {
            debug!("Selected peer is {}", peer_id);
            let peer = self.peers.get_mut(peer_id).unwrap();
            peer.request_outputs(block_epoch, block_offset, outputs_ids);
            return true;
        }

        trace!("Can't find a background connection ");
        false
    }

    ///
    /// Returns replication status.
    ///
    pub fn info(&self) -> ReplicationInfo {
        let mut peers = Vec::with_capacity(self.peers.len());
        for (peer_id, peer) in self.peers.iter() {
            peers.push(peer.info(self.banned_peers.contains(peer_id)));
        }
        for (peer_id, peer) in self.downstreams.iter() {
            peers.push(peer.info(self.banned_peers.contains(peer_id)));
        }
        let my_info = PeerInfo::Localhost {
            peer_id: self.peer_id.to_base58(),
            version: ReplicationVersion::latest().to_string(),
        };
        peers.push(my_info);

        ReplicationInfo { peers }
    }

    ///
    /// Polls events.
    ///
    pub fn poll(
        &mut self,
        cx: &mut Context,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
        block_reader: &dyn BlockReader,
    ) -> Poll<Option<ReplicationRow>> {
        trace!("Poll");

        // Process replication events.
        loop {
            match self.events.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => match event {
                    ReplicationEvent::Registered { peer_id, multiaddr } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Registered: multiaddr={}", peer_id, multiaddr);
                        let peer = Peer::registered(peer_id.clone(), None, None);
                        if self
                            .peers
                            .entry(peer_id)
                            .or_insert(peer)
                            .add_addr(multiaddr.clone())
                        {
                            error!(
                                "Addres was already marked as registred: multiaddr={}",
                                multiaddr
                            )
                        }
                    }
                    ReplicationEvent::ResolvedVersion { peer_id, version } => {
                        debug!("[{}] Resolved peer version: version={}", peer_id, version);
                        let new_version = version;
                        match self.peers.get_mut(&peer_id) {
                            Some(p) => {
                                match p {
                                    Peer::Connecting {ref mut version, ..} |  Peer::Registered {ref mut version, ..} => {
                                        if version.is_some() {
                                            debug!("Change peer registered version, new_version = {}", new_version)
                                        }
                                        *version = Some(new_version);
                                    },
                                    Peer::Connected {ref mut version, ..} => {
                                        debug!("Change peer registered version, new_version = {}", new_version);
                                        *version = new_version;
                                    }
                                    state => {
                                        debug!("Resolved peer version, when peer at unexpected state: state={:?}", state.info(self.banned_peers.contains(&peer_id)))
                                    }
                                }
                            },
                            None => {
                                error!("Resolved peer version of unknown peer = {}", peer_id)
                            }
                        }
                    }
                    ReplicationEvent::Unregistered { peer_id, multiaddr } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Unregistered: multiaddr={}", peer_id, multiaddr);
                        let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                        peer.remove_addr(multiaddr);
                    }
                    ReplicationEvent::Disconnected { peer_id } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Disconnected.", peer_id);
                        let _peer = self.peers.remove(&peer_id).expect("peer is known");
                    }
                    ReplicationEvent::Connected { peer_id, rx, tx } => {
                        assert_ne!(peer_id, self.peer_id);
                        if !self.has_upstream() {
                            debug!("[{}] Subscribing.", peer_id);
                            let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                            peer.subscribe(self.light, current_epoch, current_offset, rx, tx);
                        } else {
                            debug!("[{}] Background.", peer_id);
                            let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                            peer.background(rx, tx);
                        }
                    }
                    ReplicationEvent::Accepted { peer_id, rx, tx } => {
                        assert_ne!(peer_id, self.peer_id);
                        if self.downstreams.get(&peer_id).is_some() {
                            debug!(
                                "[{}] Already connected to us, ignoring Accepted event",
                                peer_id
                            );
                        } else {
                            let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                            if let Some(downstream) = peer.accept(rx, tx) {
                                assert!(self.downstreams.insert(peer_id, downstream).is_none());
                            }
                        }
                    }
                    ReplicationEvent::ConnectionFailed { peer_id, error } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Connection failed: {:?}", peer_id, error);
                        let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                        peer.disconnected();
                    }
                },
                Poll::Ready(None) => {
                    // Shutdown.
                    return Poll::Ready(None);
                }
                Poll::Pending => break,
            }
        }

        self.downstreams.retain(|_peer_id, peer| {
            match peer.poll(
                cx,
                current_epoch,
                current_offset,
                micro_blocks_in_epoch,
                block_reader,
            ) {
                Poll::Ready(()) => false,
                Poll::Pending => true,
            }
        });

        let mut has_upstream = false;
        let mut connecting_nodes = 0;
        for (_peer_id, peer) in self.peers.iter_mut() {
            match peer.poll(cx) {
                Poll::Ready(block) => {
                    return Poll::Ready(Some(block));
                }
                Poll::Pending => {}
            }
            if peer.is_upstream() {
                has_upstream = true;
            }
            if peer.is_connected() {
                connecting_nodes += 1;
            }
        }

        // Process timer.
        if let Poll::Ready(()) = self.periodic_delay.poll_unpin(cx) {
            self.periodic_delay
                .reset(Instant::now() + UPSTREAM_UPDATE_INTERVAL);
            trace!("Timer fired");
        }

        // Chose a new upstream from existing connections.
        if !has_upstream && connecting_nodes > 0 {
            for (_peer_id, peer) in self.peers.iter_mut() {
                if peer.is_background() {
                    peer.promote_background(current_epoch, current_offset, self.light);
                    has_upstream = true;
                    connecting_nodes -= 1;
                    break;
                }
            }
        }

        // If upstream stil missing but we have ongoing connection, it will be marked as upstream.
        if !has_upstream && connecting_nodes > 0 {
            has_upstream = true;
        }

        if !has_upstream {
            trace!("Upstream is missing, trying to choose a new one");
            //
            // Choose a new upstream.
            //

            let mut potential_upstreams: Vec<PeerId> = self.registered_peers();

            if potential_upstreams.is_empty() && !self.banned_peers.is_empty() {
                debug!("No unbanned potential upstreams left, give banned peers one more chance.");
                // give banned peers one more chance to replicate
                self.banned_peers.clear();
                potential_upstreams = self.registered_peers();
            }

            let mut rng = thread_rng();
            let new_upstream = potential_upstreams.choose(&mut rng);
            if let Some(peer_id) = new_upstream {
                debug!("Selected upstream is {}", peer_id);
                let peer = self.peers.get_mut(peer_id).unwrap();
                peer.connecting();
                self.network
                    .replication_connect(peer_id.clone())
                    .expect("network is alive");
            } else {
                trace!("Can't find a new upstream");
            }
        }
        let needed_connections = self.config.background_connections(self.peers.len());

        if connecting_nodes < needed_connections + 1 {
            debug!(
                "Background connections count is not enought: needed={}, available={}",
                needed_connections, connecting_nodes
            );
            let potential_upstreams: Vec<PeerId> = self.registered_peers();

            let mut rng = thread_rng();
            debug!(
                "Creating {} background connections",
                needed_connections - connecting_nodes
            );
            let new_upstreams = potential_upstreams
                .choose_multiple(&mut rng, needed_connections - connecting_nodes);

            for peer_id in new_upstreams {
                debug!("Selected peer for background connection is {}", peer_id);
                let peer = self.peers.get_mut(peer_id).unwrap();
                peer.connecting();
                self.network
                    .replication_connect(peer_id.clone())
                    .expect("network is alive");
            }
        }
        Poll::Pending
    }
}

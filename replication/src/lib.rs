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
mod peer;
mod protos;

use self::api::*;
use futures::sync::mpsc;
use futures::{Async, Future, Stream};
use log::*;
use peer::Peer;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashMap;
use std::time::Duration;
use stegos_blockchain::{Block, BlockReader, LightBlock};
use stegos_network::{Network, PeerId, ReplicationEvent};
use tokio_timer::{clock, Delay};

pub enum ReplicationRow {
    Block(Block),
    LightBlock(LightBlock),
}

pub struct Replication {
    /// My Peer ID.
    peer_id: PeerId,

    /// A map of connected peers.
    peers: HashMap<PeerId, Peer>,

    /// A timer to handle periodic events.
    periodic_delay: Delay,

    /// True if the light node protocol is used.
    light: bool,

    /// A channel with incoming replication events.
    events: mpsc::UnboundedReceiver<ReplicationEvent>,

    /// Network API.
    network: Network,
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
        let periodic_delay = Delay::new(clock::now() + UPSTREAM_UPDATE_INTERVAL);
        Self {
            peer_id,
            peers,
            periodic_delay,
            light,
            events,
            network,
        }
    }

    //
    // Change the current upstream (if any).
    //
    pub fn change_upstream(&mut self) {
        for (peer_id, peer) in self.peers.iter_mut() {
            if peer.is_upstream() {
                info!("[{}] Disconnect by the user", peer_id);
                peer.disconnected();
            }
        }
        // A new upstream will be selected on the next poll().
    }

    ///
    /// Processes a new block.
    ///
    pub fn on_block(&mut self, block: Block, light_block: LightBlock, micro_blocks_in_epoch: u32) {
        for (_peer_id, peer) in self.peers.iter_mut() {
            peer.on_block(&block, &light_block, micro_blocks_in_epoch);
        }
    }

    ///
    /// Returns replication status.
    ///
    pub fn info(&self) -> ReplicationInfo {
        let mut peers = Vec::with_capacity(self.peers.len());
        for (_peer_id, peer) in self.peers.iter() {
            peers.push(peer.info());
        }
        let my_info = PeerInfo::Localhost {
            peer_id: self.peer_id.to_base58(),
        };
        peers.push(my_info);

        ReplicationInfo { peers }
    }

    ///
    /// Polls events.
    ///
    pub fn poll(
        &mut self,
        current_epoch: u64,
        current_offset: u32,
        micro_blocks_in_epoch: u32,
        block_reader: &dyn BlockReader,
    ) -> Async<Option<ReplicationRow>> {
        trace!("Poll");

        // Process replication events.
        loop {
            match self.events.poll().unwrap() {
                Async::Ready(Some(event)) => match event {
                    ReplicationEvent::Registered { peer_id, multiaddr } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Registered: multiaddr={}", peer_id, multiaddr);
                        let peer = Peer::registered(peer_id.clone(), multiaddr);
                        let prev = self.peers.insert(peer_id, peer);
                        assert!(prev.is_none(), "peer is new");
                    }
                    ReplicationEvent::Unregistered { peer_id, multiaddr } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Unregistered: multiaddr={}", peer_id, multiaddr);
                        let _peer = self.peers.remove(&peer_id).expect("peer is known");
                    }
                    ReplicationEvent::Connected { peer_id, rx, tx } => {
                        assert_ne!(peer_id, self.peer_id);
                        let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                        peer.connected(self.light, current_epoch, current_offset, rx, tx);
                    }
                    ReplicationEvent::Accepted { peer_id, rx, tx } => {
                        assert_ne!(peer_id, self.peer_id);
                        let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                        peer.accepted(rx, tx);
                    }
                    ReplicationEvent::ConnectionFailed { peer_id, error } => {
                        assert_ne!(peer_id, self.peer_id);
                        debug!("[{}] Connection failed: {:?}", peer_id, error);
                        let peer = self.peers.get_mut(&peer_id).expect("peer is known");
                        peer.disconnected();
                    }
                },
                Async::Ready(None) => {
                    // Shutdown.
                    return Async::Ready(None);
                }
                Async::NotReady => break,
            }
        }

        let mut has_upstream = false;
        for (_peer_id, peer) in self.peers.iter_mut() {
            match peer.poll(
                current_epoch,
                current_offset,
                micro_blocks_in_epoch,
                block_reader,
            ) {
                Async::Ready(block) => {
                    return Async::Ready(Some(block));
                }
                Async::NotReady => {}
            }
            if peer.is_upstream() {
                has_upstream = true;
            }
        }

        // Process timer.
        if let Async::Ready(()) = self.periodic_delay.poll().unwrap() {
            self.periodic_delay
                .reset(clock::now() + UPSTREAM_UPDATE_INTERVAL);
            trace!("Timer fired");
        }

        if !has_upstream {
            trace!("Upstream is missing, trying to choose a new one");
            //
            // Choose a new upstream.
            //
            let new_upstream = {
                let potential_upstreams: Vec<&PeerId> = self
                    .peers
                    .iter()
                    .filter_map(|(peer_id, peer)| match &peer {
                        Peer::Registered { .. } => Some(peer_id),
                        _ => None,
                    })
                    .collect();
                let mut rng = thread_rng();
                potential_upstreams
                    .as_slice()
                    .choose(&mut rng)
                    .map(|x| (*x).clone())
            };

            if let Some(peer_id) = new_upstream {
                debug!("Selected upstream is {}", peer_id);
                let peer = self.peers.get_mut(&peer_id).unwrap();
                peer.connecting();
                self.network
                    .replication_connect(peer_id.clone())
                    .expect("network is alive");
            } else {
                trace!("Can't find a new upstream");
            }
        }
        Async::NotReady
    }
}

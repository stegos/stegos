//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::kad::{Kademlia, KademliaTopology};
use libp2p::{core::ProtocolsHandler, PeerId};
use log::*;
use std::cmp;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;

/// Kademlia-based network discovery
pub struct KadBehaviour<TSubstream> {
    /// Kademlia systems
    kademlia: Kademlia<TSubstream>,
    /// When to send random request to gather network info
    next_query: Delay,
    /// Delay to the next random poll
    delay_between_queries: Duration,
}

impl<TSubstream> KadBehaviour<TSubstream> {
    pub fn new(local_peer_id: PeerId) -> Self {
        KadBehaviour {
            kademlia: Kademlia::new(local_peer_id),
            next_query: Delay::new(Instant::now()),
            delay_between_queries: Duration::from_secs(1),
        }
    }

    pub fn add_providing(&mut self, key: PeerId) {
        self.kademlia.add_providing(key);
    }
}

impl<TSubstream, TTopology> NetworkBehaviour<TTopology> for KadBehaviour<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
    TTopology: KademliaTopology,
{
    type ProtocolsHandler = <Kademlia<TSubstream> as NetworkBehaviour<TTopology>>::ProtocolsHandler;
    type OutEvent = <Kademlia<TSubstream> as NetworkBehaviour<TTopology>>::OutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NetworkBehaviour::<TTopology>::new_handler(&mut self.kademlia)
    }

    fn inject_connected(&mut self, peer_id: PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::<TTopology>::inject_connected(&mut self.kademlia, peer_id, endpoint)
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::<TTopology>::inject_disconnected(&mut self.kademlia, peer_id, endpoint)
    }

    fn inject_node_event(
        &mut self,
        peer_id: PeerId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        NetworkBehaviour::<TTopology>::inject_node_event(&mut self.kademlia, peer_id, event)
    }

    fn poll(
        &mut self,
        params: &mut PollParameters<TTopology>,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        match self.kademlia.poll(params) {
            Async::Ready(action) => return Async::Ready(action),
            Async::NotReady => (),
        }

        // Initiate new shake of DHT network
        loop {
            match self.next_query.poll() {
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(_)) => {
                    debug!("Shooting at DHT to gather nodes information");
                    let random_peer_id = PeerId::random();
                    self.kademlia.find_node(random_peer_id);

                    // Reset the `Delay` to the next random.
                    self.next_query
                        .reset(Instant::now() + self.delay_between_queries);
                    self.delay_between_queries =
                        cmp::min(self.delay_between_queries * 2, Duration::from_secs(60));
                }
                Err(err) => {
                    error!("Kad discovery timer errored: {:?}", err);
                    break;
                }
            }
        }

        Async::NotReady
    }
}

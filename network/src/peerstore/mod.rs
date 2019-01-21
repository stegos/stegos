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

use crate::PeerStore;
use libp2p::core::topology::Topology;
use libp2p::{core::PublicKey, Multiaddr, PeerId};
use std::collections::HashMap;

/// Topology of the network stored in memory.
pub struct MemoryPeerstore {
    list: HashMap<PeerId, Vec<Multiaddr>>,
    local_peer_id: PeerId,
    local_public_key: PublicKey,
}

impl MemoryPeerstore {
    /// Creates an empty topology.
    #[inline]
    pub fn empty(peer_id: PeerId, pubkey: PublicKey) -> MemoryPeerstore {
        MemoryPeerstore {
            list: Default::default(),
            local_peer_id: peer_id,
            local_public_key: pubkey,
        }
    }

    /// Returns true if the topology is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Adds an address to the topology.
    #[inline]
    pub fn add_address(&mut self, peer: PeerId, addr: Multiaddr) {
        let addrs = self.list.entry(peer).or_insert_with(|| Vec::new());
        if addrs.iter().all(|a| a != &addr) {
            addrs.push(addr);
        }
    }

    /// Returns an iterator to all the entries in the topology.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Multiaddr)> {
        self.list
            .iter()
            .flat_map(|(p, l)| l.iter().map(move |ma| (p, ma)))
    }
}

impl Topology for MemoryPeerstore {
    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        self.list.get(peer).map(|v| v.clone()).unwrap_or(Vec::new())
    }

    fn add_local_external_addrs<TIter>(&mut self, addrs: TIter)
    where
        TIter: Iterator<Item = Multiaddr>,
    {
        for addr in addrs {
            let id = self.local_peer_id.clone();
            self.add_address(id, addr);
        }
    }

    #[inline]
    fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    #[inline]
    fn local_public_key(&self) -> &PublicKey {
        &self.local_public_key
    }
}

impl PeerStore for MemoryPeerstore {
    #[inline]
    fn store_address(&mut self, peer: PeerId, addr: Multiaddr) {
        self.add_address(peer, addr);
    }

    /// Returns a list of all the known peers in the topology.
    #[inline]
    fn peers(&self) -> Vec<&PeerId> {
        self.list.keys().collect()
    }
}

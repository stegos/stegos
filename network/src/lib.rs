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

mod config;
mod libp2p_network;
mod ncp;
pub mod peerstore;
pub mod unicast_send;
pub use config::*;

use failure::{Error, Fail};
use futures::sync::mpsc;
use libp2p::core::{topology::Topology, Multiaddr, PeerId};
use std::fmt;
use stegos_crypto::pbc::secure;

pub use self::libp2p_network::Libp2pNetwork;
pub use self::peerstore::MemoryPeerstore;
pub use self::unicast_send::{UnicastDataMessage, UnicastSend};

pub type Network = Box<dyn NetworkProvider + Send>;

pub trait NetworkProvider
where
    Self: fmt::Debug,
{
    /// Subscribe to topic, returns Stream<Vec<u8>> of messages incoming to topic
    fn subscribe(&self, topic: &str) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error>;

    /// Published message to topic
    fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Subscribe to unicast messages, returns Stream<Vec<u8>> of messages incoming to topic
    fn subscribe_unicast(
        &self,
        protocol_id: &str,
    ) -> Result<mpsc::UnboundedReceiver<UnicastMessage>, Error>;

    /// Send unicast message to peer identified by network public key
    fn send(&self, dest: secure::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Helper for cloning boxed object
    fn box_clone(&self) -> Network;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastMessage {
    pub from: secure::PublicKey,
    pub data: Vec<u8>,
}

impl Clone for Network {
    fn clone(&self) -> Network {
        self.box_clone()
    }
}

pub trait PeerStore: Topology {
    fn store_address(&mut self, peer: PeerId, addr: Multiaddr);
    /// Returns a list of all the known peers in the topology.
    fn peers(&self) -> Vec<&PeerId>;
    // We know peer is failing, so don't try to connect to it...
    fn known_failed(&self, _peer: &PeerId) -> bool {
        false
    }
    // Mark peer as failed, so skip following attepts to dial it...
    fn mark_as_failed(&mut self, _peer: &PeerId) {}
}

/// Placeholder for NetworkError definitions
/// TODO: Add/implement real errors
#[derive(Clone, Debug, Fail, PartialEq, Eq)]
pub enum NetworkError {
    #[fail(display = "Generic network error talking to node: {:#?}", _0)]
    GenericError(secure::PublicKey),
}

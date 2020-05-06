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

// #![deny(warnings)]

use failure::{Error, Fail};
use futures::channel::{mpsc, oneshot};
use std::fmt;
use stegos_crypto::pbc;

pub mod gatekeeper;
mod libp2p_network;
pub mod metrics;
mod old_protos;
mod proto;
pub use old_protos::*;

pub use self::replication::{ReplicationEvent, ReplicationVersion};
pub mod replication;

pub mod utils;
pub use self::gatekeeper::NetworkName;
pub use self::libp2p_network::Libp2pNetwork;
pub use self::libp2p_network::Multiaddr;
pub use self::libp2p_network::PeerId;
pub use self::libp2p_network::NETWORK_STATUS_TOPIC;

mod config;
pub use self::config::*;
pub use self::old_protos::ncp::NodeInfo;
use std::time::Duration;

pub const NETWORK_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

pub type Network = Box<dyn NetworkProvider + Send + Sync>;

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
    fn send(&self, dest: pbc::PublicKey, protocol_id: &str, data: Vec<u8>) -> Result<(), Error>;

    /// Connect to a replication upstream.
    fn replication_connect(&self, peer_id: PeerId) -> Result<(), Error>;

    /// Disconnect from a replication upstream.
    fn replication_disconnect(&self, peer_id: PeerId) -> Result<(), Error>;
    /// Request list of connected nodes
    fn list_connected_nodes(&self) -> Result<oneshot::Receiver<NetworkResponse>, Error>;

    /// Helper for cloning boxed object
    fn box_clone(&self) -> Network;

    /// Change network keys
    fn change_network_keys(
        &self,
        _new_pkey: pbc::PublicKey,
        _new_skey: pbc::SecretKey,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicastMessage {
    pub from: pbc::PublicKey,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum NetworkResponse {
    ConnectedNodes { nodes: Vec<NodeInfo> },
}

impl Clone for Network {
    fn clone(&self) -> Network {
        self.box_clone()
    }
}

/// Placeholder for NetworkError definitions
/// TODO: Add/implement real errors
#[derive(Clone, Debug, Fail, PartialEq, Eq)]
pub enum NetworkError {
    #[fail(display = "Generic network error talking to node: {:#?}", _0)]
    GenericError(pbc::PublicKey),
    #[fail(display = "Error returning result to API call: {}", _0)]
    APIResponseError(String),
}

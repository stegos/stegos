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

mod expiring_queue;
mod lru_bimap;
mod multihash;
mod peer_id_key;

pub use self::expiring_queue::ExpiringQueue;
pub use self::lru_bimap::LruBimap;
pub use self::multihash::IntoMultihash;
pub use self::peer_id_key::PeerIdKey;
use libp2p_core::multiaddr::{Multiaddr, Protocol};
use std::net::SocketAddr;

pub fn socket_to_multi_addr(addr: &SocketAddr) -> Multiaddr {
    let mut maddr: Multiaddr = addr.ip().into();
    maddr.push(Protocol::Tcp(addr.port()));
    maddr
}

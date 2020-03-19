//
// MIT License
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

//! Helper data type to add Ord to libp2p::PeerId
//!

use libp2p_core::PeerId;
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct PeerIdKey(PeerId);

impl PeerIdKey {
    pub fn new(peer_id: PeerId) -> Self {
        PeerIdKey(peer_id)
    }
}

impl From<PeerId> for PeerIdKey {
    fn from(p: PeerId) -> Self {
        PeerIdKey(p)
    }
}

impl Into<PeerId> for PeerIdKey {
    fn into(self) -> PeerId {
        self.0
    }
}

impl Ord for PeerIdKey {
    fn cmp(&self, other: &PeerIdKey) -> Ordering {
        self.0.as_bytes().cmp(&other.0.as_bytes())
    }
}

impl PartialOrd for PeerIdKey {
    fn partial_cmp(&self, other: &PeerIdKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PeerIdKey {
    fn eq(&self, other: &PeerIdKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for PeerIdKey {}

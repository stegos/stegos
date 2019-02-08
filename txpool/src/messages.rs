//
// Copyright (c) 2019 Stegos
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

use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc::secure;

/// A topic used for Join requests.
pub const POOL_JOIN_TOPIC: &'static str = "txpool_join";
/// A topic for PoolInfo messages.
pub const POOL_ANNOUNCE_TOPIC: &'static str = "txpool_announce";

/// Send when node wants to join TxPool.
#[derive(Debug, Clone)]
pub struct PoolJoin {}

/// Sent when a new transaction pool is formed.
#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub participants: Vec<secure::PublicKey>,
}

impl Hashable for PoolJoin {
    fn hash(&self, state: &mut Hasher) {
        "PoolJoin".hash(state);
    }
}

impl Hashable for PoolInfo {
    fn hash(&self, state: &mut Hasher) {
        "PoolInfo".hash(state);
        for participant in &self.participants {
            participant.hash(state);
        }
    }
}

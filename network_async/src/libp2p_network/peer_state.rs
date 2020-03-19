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

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChainProtocol {
    Pubsub,
    Ncp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeerProtos {
    pub wanted_incoming: HashSet<ChainProtocol>,
    pub enabled_incoming: HashSet<ChainProtocol>,
    pub wanted_outgoing: HashSet<ChainProtocol>,
    pub enabled_outgoing: HashSet<ChainProtocol>,
}

impl PeerProtos {
    pub fn new() -> Self {
        PeerProtos {
            wanted_incoming: HashSet::new(),
            enabled_incoming: HashSet::new(),
            wanted_outgoing: HashSet::new(),
            enabled_outgoing: HashSet::new(),
        }
    }

    pub fn want_listener(&mut self) {
        self.wanted_incoming.insert(ChainProtocol::Pubsub);
        self.wanted_incoming.insert(ChainProtocol::Ncp);
    }

    pub fn want_dialer(&mut self) {
        self.wanted_outgoing.insert(ChainProtocol::Pubsub);
        self.wanted_outgoing.insert(ChainProtocol::Ncp);
    }
}

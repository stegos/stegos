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

use failure::Error;
use futures::prelude::*;
use std::collections::{hash_map::Keys as HashMapKeys, HashMap};
use std::hash::Hash;
use std::time::Duration;
use tokio::timer::{delay_queue, DelayQueue};

/// HashMap (used as HashSet) with TTL of peers
pub struct ExpiringQueue<T>
where
    T: Hash + Clone + Eq,
{
    ttl: Duration,
    entries: HashMap<T, delay_queue::Key>,
    expirations: DelayQueue<T>,
}

impl<T> ExpiringQueue<T>
where
    T: Hash + Clone + Eq,
{
    pub fn new(ttl: u64) -> Self {
        ExpiringQueue {
            ttl: Duration::from_secs(ttl),
            entries: HashMap::<T, delay_queue::Key>::new(),
            expirations: DelayQueue::<T>::new(),
        }
    }

    pub fn insert(&mut self, key: &T) {
        let delay = self.expirations.insert(key.clone(), self.ttl);

        self.entries.insert(key.clone(), delay);
    }

    pub fn keys(&self) -> HashMapKeys<T, delay_queue::Key> {
        self.entries.keys()
    }

    pub fn contains(&self, key: &T) -> bool {
        self.entries.contains_key(key)
    }

    pub fn remove(&mut self, key: &T) {
        if let Some(cache_key) = self.entries.remove(key) {
            self.expirations.remove(&cache_key);
        }
    }

    pub fn poll(&mut self) -> Poll<T, Error> {
        loop {
            match self.expirations.poll() {
                Ok(Async::Ready(Some(entry))) => {
                    let expired = entry.get_ref().clone();
                    self.entries.remove(entry.get_ref());
                    return Ok(Async::Ready(expired));
                }
                Ok(Async::Ready(None)) => return Ok(Async::NotReady),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

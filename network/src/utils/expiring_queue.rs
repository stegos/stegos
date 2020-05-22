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
use futures::task::{Context, Poll};
use std::collections::{hash_map::Keys as HashMapKeys, HashMap};
use std::hash::Hash;
use std::time::Duration;
use tokio::time::{delay_queue, DelayQueue};

/// HashMap (used as HashSet) with TTL of peers
pub struct ExpiringQueue<K, V>
where
    K: Hash + Clone + Eq,
{
    ttl: Duration,
    entries: HashMap<K, (delay_queue::Key, V)>,
    expirations: DelayQueue<K>,
}

impl<K, V> ExpiringQueue<K, V>
where
    K: Hash + Clone + Eq,
{
    pub fn new(ttl: Duration) -> Self {
        ExpiringQueue {
            ttl,
            entries: HashMap::<K, (delay_queue::Key, V)>::new(),
            expirations: DelayQueue::<K>::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, key: K, value: V) {
        if let Some((cache_key, _)) = self.entries.remove(&key) {
            self.expirations.remove(&cache_key);
        }
        let delay = self.expirations.insert(key.clone(), self.ttl);

        self.entries.insert(key, (delay, value));
    }

    pub fn keys(&self) -> HashMapKeys<K, (delay_queue::Key, V)> {
        self.entries.keys()
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn reset(&mut self, key: &K, timeout: Duration) {
        if let Some((queue_key, _)) = self.entries.get(key) {
            self.expirations.reset(queue_key, timeout);
        }
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        if let Some((_, v)) = self.entries.get(key) {
            Some(v)
        } else {
            None
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some((cache_key, v)) = self.entries.remove(key) {
            self.expirations.remove(&cache_key);
            Some(v)
        } else {
            None
        }
    }

    pub fn poll(&mut self, cx: &mut Context) -> Poll<Result<(K, Option<V>), Error>> {
        match self.expirations.poll_expired(cx) {
            Poll::Ready(Some(Ok(entry))) => {
                let expired = entry.get_ref().clone();
                let v = match self.entries.remove(entry.get_ref()) {
                    Some((_, v)) => Some(v),
                    None => None,
                };
                Poll::Ready(Ok((expired, v)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e.into())),
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }
}

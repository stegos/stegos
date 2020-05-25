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

//! Partial mix of LRU time cache and BiMap

use lru_time_cache::LruCache;
use std::collections::hash_map::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Duration;

pub struct LruBimap<K, V>
where
    K: Ord + Clone + Debug,
    V: Hash + Eq + Clone + Debug,
{
    kv: LruCache<K, V>,
    vk: HashMap<V, K>,
}

impl<K, V> LruBimap<K, V>
where
    K: Ord + Clone + Debug,
    V: Hash + Eq + Clone + Debug,
{
    pub fn with_capacity(capacity: usize) -> LruBimap<K, V> {
        LruBimap {
            kv: LruCache::<K, V>::with_capacity(capacity),
            vk: HashMap::new(),
        }
    }
    pub fn with_expiry_duration(time_to_live: Duration) -> LruBimap<K, V> {
        LruBimap {
            kv: LruCache::<K, V>::with_expiry_duration(time_to_live),
            vk: HashMap::new(),
        }
    }
    pub fn with_expiry_duration_and_capacity(
        time_to_live: Duration,
        capacity: usize,
    ) -> LruBimap<K, V> {
        LruBimap {
            kv: LruCache::<K, V>::with_expiry_duration_and_capacity(time_to_live, capacity),
            vk: HashMap::new(),
        }
    }
    // Inserts key and value, pointing at each other. Any mappings to the same key and value are dropped
    pub fn insert(&mut self, key: K, value: V) {
        if let Some(old_val) = self.kv.remove(&key) {
            self.vk.remove(&old_val);
        }
        if let Some(old_key) = self.vk.remove(&value) {
            self.kv.remove(&old_key);
        }

        let (_, expired) = self.kv.notify_insert(key.clone(), value.clone());
        // remove expired values from value->key mapping
        for e in expired.iter() {
            self.vk.remove(&e.1);
        }

        self.vk.insert(value, key);
        if self.vk.len() > self.kv.len() {
            let mut removed_keys: Vec<V> = Vec::new();
            for (k, v) in self.vk.iter() {
                if !self.kv.contains_key(v) {
                    removed_keys.push(k.clone())
                }
            }
            for k in removed_keys.iter() {
                self.vk.remove(k);
            }
        }
        debug_assert_eq!(self.kv.len(), self.vk.len());
    }
    pub fn remove_by_key(&mut self, key: &K) -> Option<(K, V)> {
        if let Some(v) = self.kv.remove(&key) {
            let expired_key = self
                .vk
                .remove(&v)
                .expect("both arms of LruBimap should be in sync");
            debug_assert_eq!(*key, expired_key);
            debug_assert_eq!(self.kv.len(), self.vk.len());
            return Some((expired_key, v));
        }
        None
    }
    pub fn remove_by_value(&mut self, value: &V) -> Option<(K, V)> {
        if let Some(k) = self.vk.remove(&value) {
            let expired_val = self
                .kv
                .remove(&k)
                .expect("both arms of LruBimap should be in sync");
            debug_assert_eq!(*value, expired_val);
            debug_assert_eq!(self.kv.len(), self.vk.len());
            return Some((k, expired_val));
        }
        None
    }
    pub fn contains_key(&self, key: &K) -> bool {
        self.kv.contains_key(key)
    }
    pub fn contains_value(&self, value: &V) -> bool {
        self.vk.contains_key(value)
    }
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.kv.len(), self.vk.len());
        self.kv.len()
    }
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.kv.len(), self.vk.len());
        self.kv.is_empty()
    }
    pub fn get_by_key(&mut self, key: &K) -> Option<&V> {
        let (v, expired) = self.kv.notify_get(key);
        for e in expired.iter() {
            self.vk.remove(&e.1);
        }
        v
    }
    pub fn get_by_value(&mut self, value: &V) -> Option<&K> {
        let key: K = match self.vk.get(value) {
            Some(k) => k.clone(),
            None => return None,
        };

        // process expired enties, if any
        if self.get_by_key(&key).is_none() {
            self.vk.remove(value);
        }
        self.vk.get(value)
    }
}

#[cfg(test)]
mod tests {
    use super::LruBimap;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn check_insert() {
        let mut my_map = LruBimap::<u64, u64>::with_capacity(3);
        my_map.insert(1, 101);
        assert_eq!(*my_map.get_by_key(&1).unwrap(), 101);
        assert_eq!(*my_map.get_by_value(&101).unwrap(), 1);
    }

    #[test]
    fn check_replace() {
        let mut my_map = LruBimap::<u64, u64>::with_capacity(3);
        my_map.insert(1, 101);
        my_map.insert(2, 202);
        my_map.insert(1, 202);
        assert_eq!(my_map.len(), 1);
        assert_eq!(*my_map.get_by_key(&1).unwrap(), 202);
        assert_eq!(*my_map.get_by_value(&202).unwrap(), 1);
        assert!(my_map.get_by_key(&2).is_none());
        assert!(my_map.get_by_value(&101).is_none());
    }
    #[test]
    fn check_capacity_bound() {
        let mut my_map = LruBimap::<u64, u64>::with_capacity(3);
        my_map.insert(1, 101);
        my_map.insert(2, 202);
        my_map.insert(3, 303);
        my_map.insert(4, 404);
        assert_eq!(my_map.len(), 3);
        assert_eq!(*my_map.get_by_key(&4).unwrap(), 404);
        assert!(my_map.get_by_value(&101).is_none());
    }
    #[test]
    fn check_time_bound() {
        let mut my_map =
            LruBimap::<u64, u64>::with_expiry_duration_and_capacity(Duration::from_secs(4), 3);
        my_map.insert(1, 101);
        thread::sleep(Duration::from_secs(2));
        my_map.insert(2, 202);
        my_map.insert(3, 303);
        assert_eq!(my_map.len(), 3);
        thread::sleep(Duration::from_secs(2));
        assert!(my_map.get_by_key(&1).is_none());
        assert_eq!(my_map.len(), 2);
        thread::sleep(Duration::from_secs(2));
        assert!(my_map.get_by_value(&202).is_none());
    }
}

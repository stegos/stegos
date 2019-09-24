//! Multi-versioned map.

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

use std::borrow::Borrow;
use std::collections::btree_map::IntoIter;
pub use std::collections::btree_map::Iter;
pub use std::collections::btree_map::Keys;
pub use std::collections::btree_map::Range;
pub use std::collections::btree_map::Values;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::RangeBounds;

/// The Undo record.
/// Used to undo changes when a map is rolled back.
/// And to publish changes when macroblock committed.
#[derive(Debug, Clone)]
pub enum UndoRecord<K, V, LSN>
where
    K: Debug,
    V: Debug,
    LSN: Debug,
{
    Remove { lsn: LSN, key: K },
    Insert { lsn: LSN, key: K, value: V },
}

/// A wrapper around standard btree map which supports versioning.
///
/// # Examples
///
/// ```
/// use stegos_blockchain::mvcc::MultiVersionedMap;
///
/// let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
/// let lsn = 1;
/// map.insert(lsn, 101, 1001);
/// map.insert(lsn, 102, 1002);
/// let lsn = 2;
/// map.insert(lsn, 102, 2002); // overwrite 102
/// map.insert(lsn, 103, 2003);
/// // Restore lsn == 1.
/// map.rollback_to_lsn(2);
/// // map is [(101, 1001), (102, 1002)]
/// // Finalize the map and remove the rollback information.
/// map.checkpoint();
/// ```
///
#[derive(Debug, Clone)]
pub struct MultiVersionedMap<K, V, LSN = usize>
where
    K: Debug + Eq + Ord + Clone,
    V: Debug + Clone,
    LSN: Debug + Default + Copy + PartialOrd + Ord,
{
    /// The actual underlying storage.
    map: BTreeMap<K, V>,
    /// The undo log a.k.a the rollback segment.
    undo: Vec<UndoRecord<K, V, LSN>>,
    /// The lsn of the latest checkpoint.
    checkpoint_lsn: LSN,
}

impl<K, V, LSN> MultiVersionedMap<K, V, LSN>
where
    K: Debug + Eq + Ord + Clone,
    V: Debug + Clone,
    LSN: Debug + Default + Copy + Ord,
{
    /// Creates an empty `MultiVersionedMap`.
    pub fn new() -> Self {
        let map: BTreeMap<K, V> = BTreeMap::new();
        let undo: Vec<UndoRecord<K, V, LSN>> = Vec::new();
        let checkpoint_lsn: LSN = Default::default();
        MultiVersionedMap {
            map,
            undo,
            checkpoint_lsn,
        }
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned. The key is not updated, though; this matters for
    /// types that can be `==` without being identical. See the [module-level
    /// documentation] for more.
    ///
    /// # Arguments
    ///
    /// * `lsn` - A non-decreasing log sequence number of this change.
    /// * `key` - A key.
    /// * `value` - A value.
    ///
    pub fn insert(&mut self, lsn: LSN, key: K, value: V) -> Option<V> {
        assert!(lsn >= self.current_lsn(), "lsn must not decrease");
        let r: Option<V> = self.map.insert(key.clone(), value.clone());
        if let Some(ref prev_value) = r {
            let undo_insert = UndoRecord::Insert {
                lsn,
                key: key.clone(),
                value: prev_value.clone(),
            };
            self.undo.push(undo_insert);
        }
        let undo_remove = UndoRecord::Remove {
            lsn,
            key: key.clone(),
        };
        self.undo.push(undo_remove);
        r
    }

    /// Removes a key from the map, returning the value at the key if the key
    /// was previously in the map.
    ///
    /// The key may be any borrowed form of the map's key type, but
    /// [`Hash`] and [`Eq`] on the borrowed form *must* match those for
    /// the key type.
    ///
    /// # Arguments
    ///
    /// * `lsn` - A non-decreasing log sequence number of this change.
    /// * `key` - A key.
    ///
    pub fn remove(&mut self, lsn: LSN, key: &K) -> Option<V> {
        assert!(lsn >= self.current_lsn(), "lsn must not decrease");
        let r: Option<V> = self.map.remove(key);
        if let Some(ref prev_value) = r {
            let undo_insert = UndoRecord::Insert::<K, V, LSN> {
                lsn,
                key: key.clone(),
                value: prev_value.clone(),
            };
            self.undo.push(undo_insert);
        }
        r
    }

    /// Returns the maximal value of `lsn` of records in this map.
    pub fn current_lsn(&self) -> LSN {
        match self.undo.last() {
            Some(UndoRecord::Insert { lsn, .. }) => *lsn,
            Some(UndoRecord::Remove { lsn, .. }) => *lsn,
            None => self.checkpoint_lsn,
        }
    }

    /// Returns the maximal value of `lsn` of records in this map at the time of checkpoint.
    pub fn checkpoint_lsn(&self) -> LSN {
        self.checkpoint_lsn
    }

    ///
    /// Finalizes this map and discards all undo records.
    /// No rollback operations are possible after the checkpoint.
    ///
    pub fn checkpoint(&mut self) -> BTreeMap<K, Option<V>> {
        let checkpoint_lsn = self.current_lsn();
        let undo = std::mem::replace(&mut self.undo, Vec::new());
        self.checkpoint_lsn = checkpoint_lsn;
        assert_eq!(self.current_lsn(), self.checkpoint_lsn());
        self.reverse_patch(undo)
    }

    ///
    /// Rolls back this map to specified lsn.
    ///
    /// # Panics
    ///
    ///  Panics if `to_lsn` < `self.checkpoint_lsn()`.
    ///  Panics if `to_lsn` > `self.current_lsn()`.
    ///
    pub fn rollback_to_lsn(&mut self, to_lsn: LSN) {
        assert!(to_lsn >= self.checkpoint_lsn(), "too old");

        while self.current_lsn() > to_lsn {
            assert!(!self.undo.is_empty(), "rollback before the checkpoint");
            let undo = self.undo.pop().unwrap();
            match undo {
                UndoRecord::Insert { lsn, key, value } => {
                    assert!(lsn > to_lsn);
                    let r = self.map.insert(key, value);
                    assert!(r.is_none(), "duplicate key");
                }
                UndoRecord::Remove { lsn, key } => {
                    assert!(lsn > to_lsn);
                    let r = self.map.remove(&key);
                    assert!(r.is_some(), "key exists");
                }
            }
        }

        assert!(self.current_lsn() <= to_lsn);
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord,
    {
        self.map.get(key)
    }

    /// Constructs a double-ended iterator over a sub-range of elements in the map.
    /// The simplest way is to use the range syntax `min..max`, thus `range(min..max)` will
    /// yield elements from min (inclusive) to max (exclusive).
    /// The range may also be entered as `(Bound<T>, Bound<T>)`, so for example
    /// `range((Excluded(4), Included(10)))` will yield a left-exclusive, right-inclusive
    /// range from 4 to 10.
    #[inline]
    pub fn range<T: ?Sized, R>(&self, range: R) -> Range<K, V>
    where
        T: Ord,
        K: Borrow<T>,
        R: RangeBounds<T>,
    {
        self.map.range(range)
    }

    /// Returns true if the map contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the number of elements in the map.
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// An iterator visiting all keys in arbitrary order.
    /// The iterator element type is `&'a K`.
    pub fn keys(&self) -> Keys<K, V> {
        self.map.keys()
    }

    /// An iterator visiting all values in arbitrary order.
    /// The iterator element type is `&'a V`.
    pub fn values(&self) -> Values<K, V> {
        self.map.values()
    }

    /// An iterator visiting all key-value pairs in arbitrary order.
    /// The iterator element type is `(&'a K, &'a V)`.
    pub fn iter(&self) -> Iter<K, V> {
        self.map.iter()
    }

    /// An iterator visiting all key-value pairs in arbitrary order.
    /// The iterator element type is `(K, V)`
    pub fn into_iter(self) -> IntoIter<K, V> {
        self.map.into_iter()
    }

    /// Returns pointer to inner map.
    pub fn inner(&self) -> &BTreeMap<K, V> {
        &self.map
    }

    /// Reset state and rollback to initial state.
    pub fn reset(&mut self) {
        self.map.clear();
        self.undo.clear();
        self.checkpoint_lsn = Default::default();
    }

    // Convert UndoLog into Diff.
    fn reverse_patch(&self, undo: Vec<UndoRecord<K, V, LSN>>) -> BTreeMap<K, Option<V>> {
        let mut result = BTreeMap::new();
        for record in undo {
            match record {
                UndoRecord::Insert { key, .. } | UndoRecord::Remove { key, .. } => {
                    if result.get(&key).is_some() {
                        continue;
                    }
                    let value = self.map.get(&key).cloned();

                    assert!(result.insert(key, value).is_none())
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_map {
        ($left:expr, $right:expr) => {{
            match (&$left, &$right) {
                (map, values) => {
                    let mut values2: Vec<(u32, u32)> = map.iter().map(|(k, v)| (*k, *v)).collect();
                    values2.sort();
                    assert_eq!(&values2, values)
                }
            }
        }};
    }

    #[test]
    fn basic() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert!(map.is_empty());
        assert_eq!(map.iter().len(), 0);
        assert_eq!(map.keys().len(), 0);
        assert_eq!(map.values().len(), 0);

        map.insert(1, 101, 1001);
        assert!(!map.is_empty());
        assert_eq!(map.iter().next().unwrap(), (&101, &1001));
        assert_eq!(map.keys().next().unwrap(), &101);
        assert_eq!(map.values().next().unwrap(), &1001);

        map.remove(1, &101);
        assert!(map.is_empty());
        assert_eq!(map.iter().len(), 0);
        assert_eq!(map.keys().len(), 0);
        assert_eq!(map.values().len(), 0);
    }

    #[test]
    fn rollback() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);

        map.rollback_to_lsn(0);
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);
        assert_map!(&map, vec![]);

        map.insert(1, 101, 1001);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(1, map.current_lsn());

        map.insert(1, 102, 1002);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(1, map.current_lsn());

        map.insert(2, 102, 2002); // overwrite 102
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(2, map.current_lsn());

        map.insert(2, 103, 2003);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(2, map.current_lsn());
        assert_map!(&map, vec![(101, 1001), (102, 2002), (103, 2003)]);

        map.rollback_to_lsn(2);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(2, map.current_lsn());
        assert_map!(&map, vec![(101, 1001), (102, 2002), (103, 2003)]);

        map.rollback_to_lsn(1);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(1, map.current_lsn());
        assert_map!(&map, vec![(101, 1001), (102, 1002)]);

        map.rollback_to_lsn(1);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(1, map.current_lsn());
        assert_map!(&map, vec![(101, 1001), (102, 1002)]);

        map.rollback_to_lsn(0);
        assert_eq!(0, map.checkpoint_lsn());
        assert_eq!(0, map.current_lsn());
        assert_map!(&map, vec![]);
    }

    #[test]
    fn checkpoint() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        map.insert(1, 102, 1002);
        map.insert(2, 102, 2002); // overwrite 102
        map.insert(2, 103, 2003);
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 2);
        map.checkpoint();
        assert_eq!(map.checkpoint_lsn(), 2);
        assert_eq!(map.current_lsn(), 2);
    }

    #[test]
    #[should_panic]
    fn decreasing_lsns_on_insert() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        assert_eq!(map.current_lsn(), 1);
        map.insert(0, 101, 1001);
    }

    #[test]
    #[should_panic]
    fn decreasing_lsns_on_insert_after_checkpoint() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 1);
        map.checkpoint();
        assert_eq!(map.checkpoint_lsn(), 1);
        assert_eq!(map.current_lsn(), 1);
        map.insert(0, 101, 1001);
    }

    #[test]
    #[should_panic]
    fn decreasing_lsns_on_remove() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        assert_eq!(map.current_lsn(), 1);
        map.remove(0, &101);
    }

    #[test]
    #[should_panic]
    fn decreasing_lsns_on_remove_after_checkpoint() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        map.checkpoint();
        assert_eq!(map.checkpoint_lsn(), 1);
        assert_eq!(map.current_lsn(), 1);
        map.insert(0, 101, 1001);
    }

    #[test]
    #[should_panic]
    fn too_old() {
        let mut map: MultiVersionedMap<u32, u32> = MultiVersionedMap::new();
        assert_eq!(map.checkpoint_lsn(), 0);
        assert_eq!(map.current_lsn(), 0);
        map.insert(1, 101, 1001);
        assert_eq!(map.current_lsn(), 1);
        map.checkpoint();
        assert_eq!(map.current_lsn(), 1);
        assert_eq!(map.current_lsn(), 1);
        map.rollback_to_lsn(0);
    }
}

//! A Merkle Tree.

//
// Copyright (c) 2018 Stegos AG
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

use failure::Fail;
use std::fmt;
use std::vec::Vec;
use stegos_crypto::hash::{Hash, Hashable, Hasher};

///
/// Merkle tree is a tree in which every leaf node is labelled with the hash of a data block and
/// every non-leaf node is labelled with the cryptographic hash of the labels of its child nodes.
///
/// ```text
///             root = h(h12 + h34)
///          /                      \
///   h12 = h(h1 + h2)         h34 = h(h3 + h4)
///   /            \            /          \
/// h1 = h(v1)  h2 = h(v2)  h3 = h(v2)  h4 = h(v4)
/// ```

/// Merkle Tree Node.
#[derive(Clone, Debug)]
struct Node<T> {
    /// Hash value.
    hash: Hash,
    /// Left subtree.
    left: Option<Box<Node<T>>>,
    /// Right subtree.
    right: Option<Box<Node<T>>>,
    /// Value (stored only in leafs).
    ///
    /// At first glance Rust's enums are more appropriate to use here.
    /// We've made several attempts to use enums here and realized that they increase the overall
    /// complexity of all algorithms significantly without providing any benefits in terms of
    /// memory footprint. It seems that every Rust enum has a hidden usize value for discriminator.
    /// Enums like Option<Box> are especially optimized to the have the same size as usize [1].
    /// Since T is also usually boxed, enums here don't decrease the memory footprint in this case.
    ///
    /// [1]: https://doc.rust-lang.org/1.29.1/std/num/struct.NonZeroUsize.html
    ///
    value: Option<T>,
}

/// Serialized Merkle Tree Node.
/// See serialize().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedNode<T> {
    /// Hash value.
    pub hash: Hash,
    /// Left subtree.
    pub left: Option<usize>,
    /// Right subtree.
    pub right: Option<usize>,
    /// Value (stored only in leafs).
    pub value: Option<T>,
}

#[derive(Debug, Fail)]
pub enum MerkleError {
    /// Invalid serialized representation
    #[fail(display = "Invalid serialized representation")]
    InvalidStructure,
    /// Validation error
    #[fail(display = "Validation error: expected={}, got={}", _0, _1)]
    ValidationError(Hash, Hash),
}

/// 2**256 is more than anyone needed.
type Height = u8;

#[derive(Clone)]
pub struct Merkle<T: Hashable> {
    root: Box<Node<T>>,
}

// -------------------------------------

const INNER_PREFIX: &'static str = "Inner";
const LEAF_PREFIX: &'static str = "Leaf";

/// 2**32 is the maximal number of elements.
type Path = u32;

/// Bit vector of path in Merkle Tree.
/// 0 bit - go to the left subtree
/// 1 bit - go to the right subtree
/// Stored in inverted order - from leaf to root
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerklePath(Path);

// -------------------------------------

/// Calculate the next power of two
fn next_pow2(mut n: usize) -> usize {
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n + 1
}

/// Calculate expected tree height
fn expected_height(n: usize) -> Height {
    return next_pow2(n).trailing_zeros() as Height;
}

// -------------------------------------

impl<T: Hashable + fmt::Debug> Merkle<T> {
    pub fn roothash(&self) -> &Hash {
        &self.root.hash
    }

    /// A helper to create full inner nodes in tree.
    fn pull(nodes: &mut Vec<Box<Node<T>>>, heights: &mut Vec<Height>) {
        assert!(nodes.len() == heights.len() && nodes.len() > 1);
        assert_eq!(heights[heights.len() - 2], heights[heights.len() - 1]);

        // Create parent node while there are two nodes on the same level
        let right = nodes.pop().unwrap();
        let left = nodes.pop().unwrap();
        let height = heights.pop().unwrap();
        let height1 = heights.pop().unwrap();
        assert_eq!(height, height1);

        let mut hasher = Hasher::new();
        INNER_PREFIX.hash(&mut hasher);
        left.hash.hash(&mut hasher);
        right.hash.hash(&mut hasher);
        let hash = hasher.result();

        let node = Box::new(Node {
            hash,
            left: Some(left),
            right: Some(right),
            value: None,
        });

        // Push created node onto the stack
        nodes.push(node);
        heights.push(height + 1);
    }

    /// A helper to create left inner nodes in tree.
    fn pull_left(nodes: &mut Vec<Box<Node<T>>>, heights: &mut Vec<Height>) {
        assert!(nodes.len() == heights.len() && nodes.len() > 1);
        assert_ne!(heights[heights.len() - 2], heights[heights.len() - 1]);

        let left = nodes.pop().unwrap();
        let height = heights.pop().unwrap();

        // Pair node with itself if it doesn't have right sibling.
        let mut hasher = Hasher::new();
        INNER_PREFIX.hash(&mut hasher);
        left.hash.hash(&mut hasher);
        left.hash.hash(&mut hasher);
        let hash = hasher.result();

        let node = Box::new(Node {
            hash,
            left: Some(left),
            right: None,
            value: None,
        });

        // Push created node onto the stack
        nodes.push(node);
        heights.push(height + 1);
    }

    /// Create a Merkle Tree and return the root hash.
    pub fn root_hash_from_array(src: &[T]) -> Hash
    where
        T: Clone,
    {
        let tree = Self::from_array(src);
        tree.roothash().clone()
    }

    /// Create a Merkle Tree from an array.
    ///
    /// Returns the new tree.
    ///
    pub fn from_array(src: &[T]) -> Merkle<T>
    where
        T: Clone,
    {
        assert!(src.len() <= Path::max_value() as usize);

        // Special case - empty tree.
        if src.len() == 0 {
            let root = Box::new(Node {
                hash: Hash::zero(),
                left: None,
                right: None,
                value: None,
            });

            return Merkle { root };
        }

        let mut nodes: Vec<Box<Node<T>>> = Vec::with_capacity(src.len() + 1);
        let mut heights: Vec<Height> = Vec::with_capacity(src.len() + 1);

        for value in src.iter() {
            let mut hasher = Hasher::new();
            LEAF_PREFIX.hash(&mut hasher);
            value.hash(&mut hasher);
            let hash = hasher.result();

            // Create a leaf
            let node = Box::new(Node {
                hash,
                left: None,
                right: None,
                value: Some(value.clone()),
            });

            nodes.push(node);
            heights.push(0);

            // Create parent nodes
            while nodes.len() > 1 && heights[heights.len() - 2] == heights[heights.len() - 1] {
                Merkle::pull(&mut nodes, &mut heights);
            }
        }

        // Executed only if the number of elements is not power of two
        while nodes.len() > 1 {
            if heights[heights.len() - 2] == heights[heights.len() - 1] {
                // Create full inner nodes
                Merkle::pull(&mut nodes, &mut heights);
            } else {
                // Create a left inner nodes
                Merkle::pull_left(&mut nodes, &mut heights);
            }
        }

        assert_eq!(nodes.len(), 1);
        assert_eq!(heights.len(), 1);

        let root = nodes.pop().unwrap();
        let height = heights.pop().unwrap();

        assert_eq!(height, expected_height(src.len()));

        Merkle { root }
    }

    /// Lookup an element by path
    pub fn lookup(&self, path: &MerklePath) -> Option<&T> {
        let mut node = &self.root;
        let mut path = path.0;

        // Traverse via inner nodes
        loop {
            // true - go left, false - go right
            let left_direction = (path & 1) == 0;
            path >>= 1;

            node = match **node {
                Node {
                    left: Some(ref left),
                    value: None, // node is not a leaf
                    ..
                } if left_direction => left, // going left, has the left subtree
                Node {
                    right: Some(ref right),
                    value: None, // node is not a leaf
                    ..
                } if !left_direction => right, // going right, has the right subtree
                Node {
                    left: None,
                    right: None,
                    value: Some(ref value),
                    ..
                } => return Some(value),
                Node {
                    value: None, // node is not a leaf
                    ..
                } => return None, // missing subtree
                _ => unreachable!(), // a leaf, doesn't happen in this algorithm
            };
        }
    }

    // A recursive helper for prune_r().
    // Although the pruning algorithm is straightforward and doesn't require recursion
    // for implementation, we had to use it here in order to deal with Rust's borrow checker.
    //
    fn prune_r(node: &mut Box<Node<T>>, path: Path) -> Option<T> {
        if node.left.is_none() && node.right.is_none() {
            // Leaf nodes
            return match node.value {
                // Magic happens here - take() extracts the original T and puts None instead.
                // Now value is own by recursion.
                Some(_) => node.value.take(),
                None => None,
            };
        }

        // Non-leaf nodes
        // Sic: this code is real boilerplate. Say thanks to Rust for the underdeveloped enums.
        let left_direction = (path & 1) == 0;
        let value = if left_direction {
            if let Some(ref mut left) = node.left {
                Merkle::prune_r(left, path >> 1)
            } else {
                unreachable!(); // Left subtree always exists
            }
        } else {
            if let Some(ref mut right) = node.right {
                Merkle::prune_r(right, path >> 1)
            } else {
                return None; // Missing a right subtree
            }
        };

        if value.is_none() {
            return None; // Not found
        }

        // Check if this node doesn't have subtrees anymore and can be removed
        let left_empty = match &node.left {
            Some(left) => {
                if left.left.is_none() && left.right.is_none() && left.value.is_none() {
                    true
                } else {
                    false
                }
            }
            None => true,
        };
        let right_empty = match &node.right {
            Some(right) => {
                if right.left.is_none() && right.right.is_none() && right.value.is_none() {
                    true
                } else {
                    false
                }
            }
            None => true,
        };

        if left_empty && right_empty {
            // Prune left and right subtrees
            node.left = None;
            node.right = None;
        }

        value
    }

    /// Lookup an element by path.
    pub fn prune(&mut self, path: &MerklePath) -> Option<T> {
        let path = path.0;
        Merkle::prune_r(&mut self.root, path)
    }

    /// A recursive helper for leafs().
    fn leafs_r<'a>(r: &mut Vec<(&'a T, MerklePath)>, node: &'a Node<T>, path: Path, h: Height) {
        match node {
            Node {
                left: Some(ref left),
                right: Some(ref right),
                value: None,
                ..
            } => {
                // An inner node with both subtree
                Merkle::leafs_r(r, &left, path, h + 1);
                Merkle::leafs_r(r, &right, path | 1 << h, h + 1);
            }
            Node {
                left: Some(ref left),
                right: None,
                value: None,
                ..
            } => {
                // An inner node with only a left subtree
                Merkle::leafs_r(r, &left, path, h + 1);
            }
            Node {
                left: None,
                right: None,
                value: Some(ref value),
                ..
            } => {
                // A leaf
                r.push((value, MerklePath(path)));
            }
            Node {
                left: None,
                right: None,
                value: None,
                ..
            } => {
                // An empty leaf - can only happen if tree is empty
            }
            _ => unreachable!(), // No more cases
        }
    }

    ///
    /// Return a vector of all leafs with pathes.
    /// These paths can be used to lookup() or prune() elements.
    ///
    pub fn leafs(&self) -> Vec<(&T, MerklePath)> {
        let mut r = Vec::<(&T, MerklePath)>::new();
        Merkle::leafs_r(&mut r, &self.root, 0, 0);
        r
    }

    /// A recursive helper for validate().
    fn validate_r(node: &Node<T>) -> Result<(), MerkleError> {
        match node {
            // An inner node with both subtree
            Node {
                hash,
                left: Some(ref left),
                right: Some(ref right),
                value: None,
                ..
            } => {
                // Check left and right subtrees recursively.
                Merkle::validate_r(&left)?;
                Merkle::validate_r(&right)?;

                // Check hash
                let mut hasher = Hasher::new();
                INNER_PREFIX.hash(&mut hasher);
                left.hash.hash(&mut hasher);
                right.hash.hash(&mut hasher);
                let check_hash = hasher.result();
                if *hash != check_hash {
                    return Err(MerkleError::ValidationError(*hash, check_hash));
                }

                return Ok(());
            }
            // An inner node with only a left subtree
            Node {
                hash,
                left: Some(ref left),
                right: None,
                value: None,
                ..
            } => {
                // Check left subtree recursively.
                Merkle::validate_r(&left)?;

                // Check hash.
                let mut hasher = Hasher::new();
                INNER_PREFIX.hash(&mut hasher);
                left.hash.hash(&mut hasher);
                left.hash.hash(&mut hasher);
                let check_hash = hasher.result();
                if *hash != check_hash {
                    return Err(MerkleError::ValidationError(*hash, check_hash));
                }

                return Ok(());
            }
            // A leaf
            Node {
                hash,
                left: None,
                right: None,
                value: Some(ref value),
                ..
            } => {
                // Check hash.
                let mut hasher = Hasher::new();
                LEAF_PREFIX.hash(&mut hasher);
                value.hash(&mut hasher);
                let check_hash = hasher.result();
                if *hash != check_hash {
                    return Err(MerkleError::ValidationError(*hash, check_hash));
                }
                return Ok(());
            }
            // An empty leaf - can only happen if tree is empty
            Node {
                left: None,
                right: None,
                value: None,
                ..
            } => {
                return Ok(());
            }
            // Invalid structure
            _ => return Err(MerkleError::InvalidStructure),
        }
    }

    /// Validate Merkle Tree.
    pub fn validate(&self) -> Result<(), MerkleError> {
        Merkle::validate_r(&self.root)
    }

    /// A recursive helper for serialize().
    fn serialize_r(r: &mut Vec<SerializedNode<T>>, node: &Node<T>) -> usize
    where
        T: Clone,
    {
        return match node {
            // An inner node with both subtrees
            Node {
                hash,
                left: Some(ref left),
                right: Some(ref right),
                value: None,
                ..
            } => {
                let left = Merkle::serialize_r(r, &left);
                let right = Merkle::serialize_r(r, &right);
                let node = SerializedNode {
                    hash: hash.clone(),
                    left: Some(left),
                    right: Some(right),
                    value: None,
                };
                let id = r.len();
                r.push(node);
                id
            }
            // An inner node with only a left subtree
            Node {
                hash,
                left: Some(ref left),
                right: None,
                value: None,
                ..
            } => {
                let left = Merkle::serialize_r(r, &left);
                let node = SerializedNode {
                    hash: hash.clone(),
                    left: Some(left),
                    right: None,
                    value: None,
                };
                let id = r.len();
                r.push(node);
                id
            }
            // A leaf
            Node {
                hash,
                left: None,
                right: None,
                value: Some(ref value),
                ..
            } => {
                let node = SerializedNode {
                    hash: hash.clone(),
                    left: None,
                    right: None,
                    value: Some(value.clone()),
                };
                let id = r.len();
                r.push(node);
                id
            }
            // An empty leaf - can only happen if tree is empty
            Node {
                hash,
                left: None,
                right: None,
                value: None,
                ..
            } => {
                let node = SerializedNode {
                    hash: hash.clone(),
                    left: None,
                    right: None,
                    value: None,
                };
                let id = r.len();
                r.push(node);
                id
            }
            _ => unreachable!(), // No more cases
        };
    }

    /// Linearize and serialize the tree.
    pub fn serialize(&self) -> Vec<SerializedNode<T>>
    where
        T: Clone,
    {
        let mut r = Vec::<SerializedNode<T>>::new();
        Merkle::serialize_r(&mut r, &self.root);
        r
    }

    /// Create a Merkle Tree from serialized representation.
    pub fn deserialize(snodes: &[SerializedNode<T>]) -> Result<Merkle<T>, MerkleError>
    where
        T: Clone,
    {
        if snodes.len() < 1 {
            return Err(MerkleError::InvalidStructure);
        }

        let mut nodes = Vec::<Option<Box<Node<T>>>>::with_capacity(snodes.len());
        for snode in snodes {
            let mut node = Box::new(Node {
                hash: snode.hash.clone(),
                left: None,
                right: None,
                value: None,
            });

            // Restore left subtree.
            if let Some(left) = snode.left {
                if left >= nodes.len() || nodes[left].is_none() {
                    return Err(MerkleError::InvalidStructure);
                }
                node.left = nodes[left].take();
            }

            // Restore right subtree.
            if let Some(right) = snode.right {
                if right >= nodes.len() || nodes[right].is_none() {
                    return Err(MerkleError::InvalidStructure);
                }
                node.right = nodes[right].take();
            }

            // Restore value.
            if let Some(ref value) = snode.value {
                node.value = Some(value.clone());
            }

            nodes.push(Some(node));
        }

        assert!(nodes[nodes.len() - 1].is_some());
        let root = nodes.pop().unwrap().take().unwrap();

        // Check that all nodes are processed.
        for node in &nodes {
            if node.is_some() {
                return Err(MerkleError::InvalidStructure);
            }
        }
        drop(nodes);

        // Validate Merkle Tree.
        Merkle::validate_r(&root)?;

        let tree = Merkle { root };

        Ok(tree)
    }

    /// A recursive helper for fmt().
    fn fmt_r(f: &mut fmt::Formatter<'_>, node: &Node<T>, h: usize) -> fmt::Result {
        match node {
            Node {
                left: Some(ref left),
                right: Some(ref right),
                value: None,
                ..
            } => {
                // An inner node with both subtree
                Merkle::fmt_r(f, &left, h + 1)?;
                write!(
                    f,
                    "{}: Node({}, l={}, r={})\n",
                    h, node.hash, left.hash, right.hash
                )?;
                Merkle::fmt_r(f, &right, h + 1)
            }
            Node {
                left: Some(ref left),
                right: None,
                value: None,
                ..
            } => {
                // An inner node with only a left subtree
                Merkle::fmt_r(f, &left, h + 1)?;
                write!(
                    f,
                    "{}: Node({:?}, l={:?}, r=None)\n",
                    h, node.hash, left.hash
                )
            }
            Node {
                left: None,
                right: None,
                value: Some(ref value),
                ..
            } => {
                // A leaf
                write!(f, "{}: Leaf({:?}, value={:?})\n", h, &node.hash, &value)
            }
            Node {
                left: None,
                right: None,
                value: None,
                ..
            } => {
                // An empty leaf - can only happen if tree is empty
                write!(f, "{:?}: Empty({:?})\n", h, &node.hash)
            }
            _ => unreachable!(), // No more cases
        }
    }

    /// Debug formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\n")?;
        Merkle::fmt_r(f, &self.root, 0)
    }
}

impl<T: Hashable + fmt::Debug> fmt::Debug for Merkle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt(f)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use log::*;
    use rand::prelude::*;
    use rand::seq::SliceRandom;
    use simple_logger;

    /// Reverse the order of bits in a byte
    fn reverse_u32(mut n: u32) -> u32 {
        n = (n >> 1) & 0x55555555 | (n << 1) & 0xaaaaaaaa;
        n = (n >> 2) & 0x33333333 | (n << 2) & 0xcccccccc;
        n = (n >> 4) & 0x0f0f0f0f | (n << 4) & 0xf0f0f0f0;
        n = (n >> 8) & 0x00ff00ff | (n << 8) & 0xff00ff00;
        n = (n >> 16) & 0x0000ffff | (n << 16) & 0xffff0000;
        n
    }

    fn expected_paths(count: usize, height: Height) -> Vec<MerklePath> {
        // Create MerklePath for all leafs.
        //
        // It's not obvious, but in the full binary tree (like we have here) the binary
        // representation of a leaf number makes bitwise path from this LEAF to the ROOT.
        // For example, the leftmost leaf has path 0b0000, its right sibling - 0b1000 and so on.
        //
        // We reverse this path in order to get the path FROM the root to a leaf.
        // In other words, (path & 1) == 1 means that you need to go right from the root
        // in order to find that leaf.
        //
        (0..count)
            .map(|x| MerklePath(reverse_u32((x << (32 - height)) as Path)))
            .collect::<Vec<MerklePath>>()
    }

    #[test]
    fn no_items() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        // Is not supported
        let data: [u32; 0] = [];
        let tree = Merkle::from_array(&data);
        match *tree.root {
            Node {
                hash,
                left: None,
                right: None,
                value: None,
            } => {
                assert_eq!(hash, Hash::zero());
            }
            _ => panic!(),
        }
        assert_eq!(tree.leafs().len(), 0);
    }

    #[test]
    fn single_item() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let data: [u32; 1] = [1];
        let mut tree = Merkle::from_array(&data);

        // Check structure
        debug!("Tree: {:?}", tree);
        assert_eq!(
            tree.roothash().to_hex(),
            "49df10d89947b56ab336a751c23454b61f276392ade7b902b19b7c17f5a537e6"
        );

        // Check hashes
        tree.validate().unwrap();

        // Check leafs
        {
            let leafs = tree.leafs();
            for (left, (right, _path)) in data.iter().zip(leafs) {
                assert_eq!(*left, *right);
            }
        };

        // Tree of one element has the only one leaf without intermediate nodes
        assert!(if let (None, None) = (&tree.root.left, &tree.root.right) {
            true
        } else {
            false
        });
        assert_eq!(tree.root.value, Some(data[0]));

        // Root hash must be the same as data[0].hash()
        let mut expected_roothash = Hasher::new();
        LEAF_PREFIX.hash(&mut expected_roothash);
        data[0].hash(&mut expected_roothash);
        let expected_roothash = expected_roothash.result();
        assert_eq!(*tree.roothash(), expected_roothash);

        // Check paths
        let paths = tree
            .leafs()
            .iter()
            .map(|(_elem, path)| *path)
            .collect::<Vec<MerklePath>>();
        let epaths = expected_paths(data.len(), expected_height(data.len()));
        assert_eq!(paths.len(), epaths.len());
        for (left, right) in paths.iter().zip(epaths.iter()) {
            assert_eq!(*left, *right);
        }

        // Check valid lookups
        assert_eq!(tree.lookup(&paths[0]), Some(&data[0]));

        // Check pruning
        assert_ne!(tree.lookup(&paths[0]), None);
        let value = tree.prune(&paths[0]);
        assert_eq!(value, Some(data[0]));
        debug!("Tree after pruning: {:?}", tree);
        assert_eq!(tree.root.value, None);
        assert_eq!(tree.lookup(&paths[0]), None);
        assert_eq!(tree.prune(&paths[0]), None);
        assert_eq!(tree.root.value, None);
        tree.validate().unwrap();
    }

    #[test]
    fn multiple_items() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        // Expected structure:
        // ```text
        //                            root = h(h1234 + h5678)
        //                     /                              \
        //             h1234 = h(h12 + h34)                    h5678 = h(h56 + n56)
        //          /                      \                     /
        //   h12 = h(h1 + h2)        h34 = h(h3 + h4)            h56 = h(h5 + n5)
        //   /            \            /          \               /
        // h1 = h(1)  h2 = h(2)     h3 = h(3)  h4 = h(4)      h3 = h(5)
        // ```

        let data: [u32; 5] = [1, 2, 3, 4, 5];
        let mut tree = Merkle::from_array(&data);

        // Check structure
        debug!("Tree: {:?}", tree);
        assert_eq!(
            tree.roothash().to_hex(),
            "7f0d4c7739a71cf3757a1d5a1de25bd30b6d2ad8d96ea1ad870db84d76268a06"
        );

        // Check hashes
        tree.validate().unwrap();

        // Check leafs
        {
            let leafs = tree.leafs();
            for (left, (right, _path)) in data.iter().zip(leafs) {
                assert_eq!(*left, *right);
            }
        }

        // Check paths
        let paths = tree
            .leafs()
            .iter()
            .map(|(_elem, path)| *path)
            .collect::<Vec<MerklePath>>();
        let epaths = expected_paths(data.len(), expected_height(data.len()));
        assert_eq!(paths.len(), epaths.len());
        for (left, right) in paths.iter().zip(epaths.iter()) {
            assert_eq!(*left, *right);
        }

        // Check valid lookups
        for (value, path) in data.iter().zip(&paths) {
            assert_eq!(value, tree.lookup(path).unwrap());
        }

        // Check invalid lookups
        let missing_path = MerklePath((next_pow2(data.len()) - 1) as Path);
        assert_eq!(tree.lookup(&missing_path), None);

        // Pruning
        assert_eq!(tree.prune(&paths[0]), Some(data[0]));
        assert_eq!(tree.lookup(&paths[0]), None);
        assert_eq!(tree.lookup(&paths[1]).unwrap(), &data[1]);
        match *tree.root {
            Node {
                left: Some(ref node1234),
                right: Some(_),
                ..
            } => match **node1234 {
                Node {
                    left: Some(ref node12),
                    right: Some(_),
                    ..
                } => match **node12 {
                    Node {
                        left: Some(ref node1),
                        right: Some(ref node2),
                        ..
                    } => {
                        assert_eq!(node1.value, None);
                        assert_eq!(node2.value, Some(data[1]));
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        tree.validate().unwrap();

        assert_eq!(tree.prune(&paths[1]), Some(data[1]));
        assert_eq!(tree.lookup(&paths[1]), None);
        match *tree.root {
            Node {
                left: Some(ref node1234),
                right: Some(_),
                ..
            } => match **node1234 {
                Node {
                    left: Some(ref node12),
                    right: Some(_),
                    ..
                } => match **node12 {
                    Node {
                        left: None,
                        right: None,
                        ..
                    } => {}
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        tree.validate().unwrap();

        // Remove n34 and n1234
        assert_eq!(tree.prune(&paths[3]), Some(data[3]));
        assert_eq!(tree.lookup(&paths[3]), None);
        assert_eq!(tree.lookup(&paths[2]).unwrap(), &data[2]);
        assert_eq!(tree.prune(&paths[2]), Some(data[2]));
        assert_eq!(tree.lookup(&paths[2]), None);
        match *tree.root {
            Node {
                left: Some(ref node1234),
                right: Some(_),
                ..
            } => match **node1234 {
                Node {
                    left: None,
                    right: None,
                    ..
                } => {}
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        tree.validate().unwrap();

        // Remove n56
        assert_eq!(tree.prune(&paths[4]), Some(data[4]));
        assert_eq!(tree.lookup(&paths[4]), None);
        match *tree.root {
            Node {
                left: None,
                right: None,
                ..
            } => {}
            _ => unreachable!(),
        };
        tree.validate().unwrap();

        // Tree is completely empty now
        for path in paths {
            assert_eq!(tree.lookup(&path), None);
        }
    }

    #[test]
    fn validate() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();
        let data: [u32; 3] = [1, 2, 3];
        let node12_hash =
            Hash::try_from_hex("8b0a2385d83c8bf7be27e59996f7d881d3bf1fc6606f81ce600b753ad94192a2")
                .unwrap();
        let node34_hash =
            Hash::try_from_hex("8b0a2385d83c8bf7be27e59996f7d881d3bf1fc6606f81ce600b753ad94192a2")
                .unwrap();

        //
        // Leafs
        //
        let mut tree = Merkle::from_array(&data);
        {
            let root = &mut tree.root;
            let node12 = root.left.as_mut().unwrap();
            let node1 = node12.left.as_mut().unwrap();
            node1.value = Some(0);
        }
        match tree.validate() {
            Err(MerkleError::ValidationError(expected, got)) => {
                let mut expected2 = Hasher::new();
                LEAF_PREFIX.hash(&mut expected2);
                1u32.hash(&mut expected2);
                let expected2 = expected2.result();
                assert_eq!(expected, expected2);
                let mut got2 = Hasher::new();
                LEAF_PREFIX.hash(&mut got2);
                0u32.hash(&mut got2);
                let got2 = got2.result();
                assert_eq!(got, got2);
            }
            _ => unreachable!(),
        }

        //
        // Full inner node
        //
        let mut tree = Merkle::from_array(&data);
        {
            let root = &mut tree.root;
            let node12 = root.left.as_mut().unwrap();
            let node1 = node12.left.as_mut().unwrap();
            node1.value = Some(0u32);
            node1.hash = Hash::digest(&0u32);
        }
        match tree.validate() {
            Err(MerkleError::ValidationError(expected, _got)) => {
                assert_eq!(expected, node12_hash);
            }
            _ => unreachable!(),
        }

        //
        // Full node with invalid left subtree
        //
        let mut tree = Merkle::from_array(&data);
        {
            let val = tree.prune(&MerklePath(2)).unwrap();
            assert_eq!(val, 2);
            let root = &mut tree.root;
            let node12 = root.left.as_mut().unwrap();
            let node1 = node12.left.as_mut().unwrap();
            node1.value = Some(0u32);
            node1.hash = Hash::digest(&0u32);
        }
        match tree.validate() {
            Err(MerkleError::ValidationError(expected, _got)) => {
                assert_eq!(expected, node12_hash);
            }
            _ => unreachable!(),
        }

        //
        // Full node with invalid right subtree
        //
        let mut tree = Merkle::from_array(&data);
        {
            let val = tree.prune(&MerklePath(0)).unwrap();
            assert_eq!(val, 1);
            let root = &mut tree.root;
            let node12 = root.left.as_mut().unwrap();
            let node2 = node12.right.as_mut().unwrap();
            node2.value = Some(0u32);
            node2.hash = Hash::digest(&0u32);
        }
        match tree.validate() {
            Err(MerkleError::ValidationError(expected, _got)) => {
                assert_eq!(expected, node12_hash);
            }
            _ => unreachable!(),
        }

        //
        // Left node
        //
        let mut tree = Merkle::from_array(&data);
        {
            let val = tree.prune(&MerklePath(0)).unwrap();
            assert_eq!(val, 1);
            let root = &mut tree.root;
            let node34 = root.right.as_mut().unwrap();
            let node3 = node34.left.as_mut().unwrap();
            node3.value = Some(0u32);
            node3.hash = Hash::digest(&0u32);
        }
        match tree.validate() {
            Err(MerkleError::ValidationError(expected, _got)) => {
                assert_eq!(expected, node34_hash);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn random() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        // Generate random tree
        let mut rng = thread_rng();
        let size = rng.gen_range(100, 500);
        let data: Vec<u64> = (0..size).map(|_| rng.gen()).collect();

        let mut tree = Merkle::from_array(&data);

        // Check hashes
        tree.validate().unwrap();

        // Check leafs
        {
            let leafs = tree.leafs();
            for (left, (right, _path)) in data.iter().zip(leafs) {
                assert_eq!(*left, *right);
            }
        }

        // Shuffle original numbers
        let mut indexes: Vec<usize> = (0..size).collect();
        indexes.shuffle(&mut rng);

        // Check paths
        let paths = tree
            .leafs()
            .iter()
            .map(|(_elem, path)| *path)
            .collect::<Vec<MerklePath>>();

        // Check valid lookups
        for i in &indexes {
            assert_eq!(*tree.lookup(&paths[*i]).unwrap(), data[*i]);
        }

        // Prune
        for i in &indexes {
            assert_eq!(tree.prune(&paths[*i]).unwrap(), data[*i]);
            tree.validate().unwrap();
        }

        // Tree is completely empty now
        for path in paths {
            assert_eq!(tree.lookup(&path), None);
        }
    }

    #[test]
    fn serialize_errors() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let data: [u32; 5] = [1, 2, 3, 4, 5];
        let tree = Merkle::from_array(&data);

        // Zero elements
        let mut serialized = tree.serialize();
        serialized.clear();
        match Merkle::deserialize(&serialized) {
            Err(MerkleError::InvalidStructure) => {}
            _ => unreachable!(),
        };

        // Missing elements
        let mut serialized = tree.serialize();
        serialized.pop();
        match Merkle::deserialize(&serialized) {
            Err(MerkleError::InvalidStructure) => {}
            _ => unreachable!(),
        };

        // Extra elements
        let mut serialized = tree.serialize();
        serialized.push(SerializedNode {
            hash: Hash::digest(&0u64),
            left: None,
            right: None,
            value: None,
        });
        match Merkle::deserialize(&serialized) {
            Err(MerkleError::InvalidStructure) => {}
            _ => unreachable!(),
        };

        // Validation error
        let mut serialized = tree.serialize();
        serialized[0].value = Some(0);
        match Merkle::deserialize(&serialized) {
            Err(MerkleError::ValidationError(expected, got)) => {
                let mut expected2 = Hasher::new();
                LEAF_PREFIX.hash(&mut expected2);
                1u32.hash(&mut expected2);
                let expected2 = expected2.result();
                assert_eq!(expected, expected2);
                let mut got2 = Hasher::new();
                LEAF_PREFIX.hash(&mut got2);
                0u32.hash(&mut got2);
                let got2 = got2.result();
                assert_eq!(got, got2);
            }
            _ => unreachable!(),
        };
    }

    fn check_serialize_rt(tree: &Merkle<u32>) {
        let serialized = tree.serialize();
        let tree2 = Merkle::deserialize(&serialized).unwrap();
        assert_eq!(tree.roothash(), tree2.roothash());
        let serialized2 = tree2.serialize();
        assert_eq!(serialized, serialized2);
        //assert_eq!(tree.height, tree2.height);
        let leafs = tree.leafs();
        let leafs2 = tree2.leafs();
        assert_eq!(leafs, leafs2);
    }

    #[test]
    fn serialize_single_item() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let data: [u32; 1] = [1];
        let tree = Merkle::from_array(&data);
        check_serialize_rt(&tree);
    }

    #[test]
    fn serialize_multiple_items() {
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let data: [u32; 5] = [1, 2, 3, 4, 5];
        let mut tree = Merkle::from_array(&data);
        let paths = tree
            .leafs()
            .iter()
            .map(|(_elem, path)| *path)
            .collect::<Vec<MerklePath>>();

        check_serialize_rt(&tree);

        let val1 = tree.prune(&paths[1]).unwrap();
        assert_eq!(val1, data[1]);
        check_serialize_rt(&tree);

        let val0 = tree.prune(&paths[0]).unwrap();
        assert_eq!(val0, data[0]);
        check_serialize_rt(&tree);

        let val4 = tree.prune(&paths[4]).unwrap();
        assert_eq!(val4, data[4]);
        check_serialize_rt(&tree);

        let val2 = tree.prune(&paths[2]).unwrap();
        assert_eq!(val2, data[2]);
        check_serialize_rt(&tree);

        let val3 = tree.prune(&paths[3]).unwrap();
        assert_eq!(val3, data[3]);
        check_serialize_rt(&tree);
    }
}

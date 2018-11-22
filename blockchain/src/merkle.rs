//! A Merkle Tree.

//
// Copyright (c) 2018 Stegos
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

/// 2**256 is more than anyone needed.
type Height = u8;

pub struct Merkle<T: Hashable> {
    root: Box<Node<T>>,
    pub height: Height,
}

// -------------------------------------

/// 2**32 is the maximal number of elements.
type Path = u32;

/// Bit vector of path in Merkle Tree.
/// 0 bit - go to the left subtree
/// 1 bit - go to the right subtree
/// Stored in inverted order - from leaf to root
#[derive(Clone)]
pub struct MerklePath(Path);

// -------------------------------------

/// Reverse the order of bits in a byte
fn reverse_u32(mut n: u32) -> u32 {
    n = (n >> 1) & 0x55555555 | (n << 1) & 0xaaaaaaaa;
    n = (n >> 2) & 0x33333333 | (n << 2) & 0xcccccccc;
    n = (n >> 4) & 0x0f0f0f0f | (n << 4) & 0xf0f0f0f0;
    n = (n >> 8) & 0x00ff00ff | (n << 8) & 0xff00ff00;
    n = (n >> 16) & 0x0000ffff | (n << 16) & 0xffff0000;
    n
}

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

impl<T: Hashable + Clone + fmt::Debug + fmt::Display> Merkle<T> {
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

        // Pair the hash of both nodes
        let mut hasher = Hasher::new();
        left.hash.hash(&mut hasher);
        left.hash.hash(&mut hasher);
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

    /// Create a Merkle Tree from an array.
    ///
    /// Returns the new tree and a paths for each element in `src`.
    /// These paths can be used to lookup() or prune() elements.
    ///
    pub fn from_array(src: &[T]) -> (Merkle<T>, Vec<MerklePath>) {
        assert!(src.len() > 0 && src.len() <= Path::max_value() as usize);

        let mut nodes: Vec<Box<Node<T>>> = Vec::with_capacity(src.len() + 1);
        let mut heights: Vec<Height> = Vec::with_capacity(src.len() + 1);

        for value in src.iter() {
            let mut hasher = Hasher::new();
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

        let tree = Merkle { root, height };

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
        let paths: Vec<MerklePath> = (0..src.len())
            .map(|x| MerklePath(reverse_u32((x << (32 - height)) as Path)))
            .collect();
        (tree, paths)
    }

    /// Lookup an element by path
    pub fn lookup(&self, path: &MerklePath) -> Option<&T> {
        let mut node = &self.root;
        let mut path = path.0;

        // Traverse via inner nodes
        for _ in 0..self.height {
            // true - go left, false - go right
            let left_direction = (path & 1) == 0;
            path >>= 1;

            node = match **node {
                Node {
                    left: Some(ref left),
                    value: None, // node is not a leaf
                    ..
                }
                    if left_direction =>
                {
                    left
                } // going left, has the left subtree
                Node {
                    right: Some(ref right),
                    value: None, // node is not a leaf
                    ..
                }
                    if !left_direction =>
                {
                    right
                } // going right, has the right subtree
                Node {
                    value: None, // node is not a leaf
                    ..
                } => return None, // missing subtree
                _ => unreachable!(), // a leaf, doesn't happen in this algorithm
            };
        }

        // Handle leaf node
        match node.value {
            // Regular case
            Some(ref value) => Some(value),
            // Can happen in case if tree has the only one element (i.e. root=leaf) and
            // this element has been pruned.
            None => None,
        }
    }

    // A recursive helper for prune_r().
    // Although the pruning algorithm is straightforward and doesn't require recursion
    // for implementation, we had to use it here in order to deal with Rust's borrow checker.
    //
    // The return protocol works as follow:
    //
    // (subtree_is_empty_and_must_be_removed: bool, value_which_has_been_found_in_a_leaf: Option<T>)
    //
    fn prune_r(node: &mut Box<Node<T>>, remain: Height, path: Path) -> (bool, Option<T>) {
        if remain == 0 {
            // Leaf nodes
            return match node.value {
                // Magic happens here - take() extracts the original T and puts None instead.
                // Now value is own by recursion.
                Some(_) => (true, node.value.take()),
                None => return (false, None),
            };
        }

        // Non-leaf nodes
        // Sic: this code is real boilerplate. Say thanks to Rust for the underdeveloped enums.
        let left_direction = (path & 1) == 0;
        let value = if left_direction {
            let (remove, value) = if let Some(ref mut left) = node.left {
                Merkle::prune_r(left, remain - 1, path >> 1)
            } else {
                return (false, None); // Missing a left subtree
            };
            if remove {
                node.left = None; // Discard the left subtree
            };
            value
        } else {
            let (remove, value) = if let Some(ref mut right) = node.right {
                Merkle::prune_r(right, remain - 1, path >> 1)
            } else {
                return (false, None); // Missing a right subtree
            };
            if remove {
                node.right = None; // Discard the right subtree
            };
            value
        };

        // Check if this node doesn't have subtrees anymore and can be removed
        match **node {
            Node {
                left: None,
                right: None,
                ..
            } => (true, value), // report to the caller that this subtree should be removed
            _ => (false, value), // still have some subtrees, don't remove
        }
    }

    /// Lookup an element by path.
    pub fn prune(&mut self, path: &MerklePath) -> Option<T> {
        let path = path.0;
        let (remove, value) = Merkle::prune_r(&mut self.root, self.height, path);
        if remove {
            // Special case for handling empty tree
            if path & 1 == 0 {
                self.root.left = None;
            } else {
                self.root.right = None;
            }
        };
        value
    }

    /// A recursive helper for fmt().
    fn fmt_r(f: &mut fmt::Formatter, node: &Node<T>, h: usize) -> fmt::Result {
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
                write!(f, "{}: Node({}, l={}, r=None)\n", h, node.hash, left.hash)
            }
            Node {
                left: None,
                right: Some(ref right),
                value: None,
                ..
            } => {
                // An inner node with only a right subtree
                write!(f, "{}: Node({}, l=None, r={})\n", h, node.hash, right.hash)?;
                Merkle::fmt_r(f, &right, h + 1)
            }
            Node {
                left: None,
                right: None,
                value: Some(ref value),
                ..
            } => {
                // A leaf
                write!(f, "{}: Leaf({}, value={})\n", h, &node.hash, &value)
            }
            Node {
                left: None,
                right: None,
                value: None,
                ..
            } => {
                // An empty leaf - can only happen if tree is empty
                write!(f, "{}: Empty({})\n", h, &node.hash)
            }
            _ => unreachable!(), // No more cases
        }
    }

    /// Debug formatting.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\n")?;
        Merkle::fmt_r(f, &self.root, 0)
    }
}

impl<T: Hashable + Clone + fmt::Debug + fmt::Display> fmt::Debug for Merkle<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(f)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::prelude::*;
    use rand::seq::SliceRandom;

    #[test]
    #[should_panic]
    fn no_items() {
        // Is not supported
        let data: [u32; 0] = [];
        Merkle::from_array(&data);
    }

    #[test]
    fn single_item() {
        let data: [u32; 1] = [1];
        let (mut tree, paths) = Merkle::from_array(&data);

        // Check structure
        debug!("Tree: {:?}", tree);
        assert_eq!(
            tree.roothash().into_hex(),
            "295cd1698c6ac5bd804a09e50f19f8549475e52db1c6ebd441ed0c7b256e1ddf"
        );

        // Check height
        assert_eq!(tree.height, 0);

        // Tree of one element has the only one leaf without intermediate nodes
        assert!(if let (None, None) = (&tree.root.left, &tree.root.right) {
            true
        } else {
            false
        });
        assert_eq!(tree.root.value, Some(data[0]));

        // Root hash must be the same as data[0].hash()
        assert_eq!(*tree.roothash(), Hasher::digest(&data[0]));

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
    }

    #[test]
    fn multiple_items() {
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
        let (mut tree, paths) = Merkle::from_array(&data);

        // Check structure
        debug!("Tree: {:?}", tree);
        assert_eq!(
            tree.roothash().into_hex(),
            "d5a54245486913be1e0926802666157aa940d445f3558d886a654ea7117213e0"
        );

        // Check height
        assert_eq!(tree.height, 3);

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
                        left: None,
                        right: Some(ref node2),
                        ..
                    } => {
                        assert_eq!(node2.value, Some(data[1]));
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        assert_eq!(tree.prune(&paths[1]), Some(data[1]));
        assert_eq!(tree.lookup(&paths[1]), None);
        match *tree.root {
            Node {
                left: Some(ref node1234),
                ..
            } => match **node1234 {
                Node {
                    left: None,
                    right: Some(_),
                    ..
                } => {}
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        // Remove n34 and n1234
        assert_eq!(tree.prune(&paths[3]), Some(data[3]));
        assert_eq!(tree.lookup(&paths[3]), None);
        assert_eq!(tree.lookup(&paths[2]).unwrap(), &data[2]);
        assert_eq!(tree.prune(&paths[2]), Some(data[2]));
        assert_eq!(tree.lookup(&paths[2]), None);
        match *tree.root {
            Node { left: None, .. } => {}
            _ => unreachable!(),
        };

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

        // Tree is completely empty now
        for path in paths {
            assert_eq!(tree.lookup(&path), None);
        }
    }

    #[test]
    fn random() {
        // Generate random tree
        let mut rng = thread_rng();
        let size = rng.gen_range(500, 1000);
        let data: Vec<u64> = (0..size).map(|_| rng.gen()).collect();

        let (mut tree, paths) = Merkle::from_array(&data);

        // Shuffle original numbers
        let mut indexes: Vec<usize> = (0..size).collect();
        indexes.shuffle(&mut rng);

        // Check valid lookups
        for i in &indexes {
            assert_eq!(*tree.lookup(&paths[*i]).unwrap(), data[*i]);
        }

        // Prune
        for i in &indexes {
            assert_eq!(tree.prune(&paths[*i]).unwrap(), data[*i]);
        }

        // Tree is completely empty now
        for path in paths {
            assert_eq!(tree.lookup(&path), None);
        }
    }
}

// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0
// Adapted from aptos-labs/jellyfish-merkle
// Modified to be generic over choice of hash function

#![forbid(unsafe_code)]

//! This module implements [`JellyfishMerkleTree`] backed by storage module. The tree itself doesn't
//! persist anything, but realizes the logic of R/W only. The write path will produce all the
//! intermediate results in a batch for storage layer to commit and the read path will return
//! results directly. The public APIs are only [`new`], [`batch_put_value_set`], and
//! [`get_with_proof`]. After each put with a `value_set` based on a known version, the tree will
//! return a new root hash with a [`TreeUpdateBatch`] containing all the new nodes and indices of
//! stale nodes.
//!
//! A Jellyfish Merkle Tree itself logically is a 256-bit sparse Merkle tree with an optimization
//! that any subtree containing 0 or 1 leaf node will be replaced by that leaf node or a placeholder
//! node with default hash value. With this optimization we can save CPU by avoiding hashing on
//! many sparse levels in the tree. Physically, the tree is structurally similar to the modified
//! Patricia Merkle tree of Ethereum but with some modifications. A standard Jellyfish Merkle tree
//! will look like the following figure:
//!
//! ```text
//!                                    .──────────────────────.
//!                            _.─────'                        `──────.
//!                       _.──'                                        `───.
//!                   _.─'                                                  `──.
//!               _.─'                                                          `──.
//!             ,'                                                                  `.
//!          ,─'                                                                      '─.
//!        ,'                                                                            `.
//!      ,'                                                                                `.
//!     ╱                                                                                    ╲
//!    ╱                                                                                      ╲
//!   ╱                                                                                        ╲
//!  ╱                                                                                          ╲
//! ;                                                                                            :
//! ;                                                                                            :
//!;                                                                                              :
//!│                                                                                              │
//!+──────────────────────────────────────────────────────────────────────────────────────────────+
//! .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.  .''.
//!/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \/    \
//!+----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----+
//! (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//! (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//! (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//! (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//!  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )  )
//! (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (  (
//! ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■  ■
//! ■: the [`Value`] type this tree stores.
//! ```
//!
//! A Jellyfish Merkle Tree consists of [`InternalNode`] and [`LeafNode`]. [`InternalNode`] is like
//! branch node in ethereum patricia merkle with 16 children to represent a 4-level binary tree and
//! [`LeafNode`] is similar to that in patricia merkle too. In the above figure, each `bell` in the
//! jellyfish is an [`InternalNode`] while each tentacle is a [`LeafNode`]. It is noted that
//! Jellyfish merkle doesn't have a counterpart for `extension` node of ethereum patricia merkle.
//!
//! [`JellyfishMerkleTree`]: struct.JellyfishMerkleTree.html
//! [`new`]: struct.JellyfishMerkleTree.html#method.new
//! [`put_value_sets`]: struct.JellyfishMerkleTree.html#method.put_value_sets
//! [`put_value_set`]: struct.JellyfishMerkleTree.html#method.put_value_set
//! [`get_with_proof`]: struct.JellyfishMerkleTree.html#method.get_with_proof
//! [`TreeUpdateBatch`]: struct.TreeUpdateBatch.html
//! [`InternalNode`]: node_type/struct.InternalNode.html
//! [`LeafNode`]: node_type/struct.LeafNode.html

use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};

use errors::CodecError;
use hash::{HashValue, TreeHash};
use metrics::{inc_deletion_count_if_enabled, set_leaf_count_if_enabled};
use node_type::{Child, Children, InternalNode, LeafNode, Node, NodeKey};
use parallel::{parallel_process_range_if_enabled, run_on_io_pool_if_enabled};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use types::nibble::{nibble_path::NibblePath, Nibble};

pub mod errors;
pub mod hash;
pub mod metrics;
pub mod node_type;
pub mod parallel;
pub mod proof;
pub mod types;

pub type Version = u64;

#[cfg(any(test, feature = "fuzzing"))]
/// The size of HashValues for testing
pub const TEST_DIGEST_SIZE: usize = 32;

#[derive(Error, Debug)]
#[error("Missing state root node at version {version}, probably pruned.")]
pub struct MissingRootError {
    pub version: Version,
}

// TODO: consider removing AsRef<u8> and TryFrom in favor of a concrete
// serde serialization scheme
pub trait Key:
    AsRef<[u8]>
    + for<'a> TryFrom<&'a [u8], Error = Self::FromBytesErr>
    + Clone
    + Serialize
    + DeserializeOwned
    + Send
    + Sync
    + 'static
{
    type FromBytesErr: std::error::Error;
    fn key_size(&self) -> usize;
}

/// `TreeReader` defines the interface between
/// [`JellyfishMerkleTree`](struct.JellyfishMerkleTree.html)
/// and underlying storage holding nodes.
pub trait TreeReader<K, H, const N: usize> {
    type Error: Into<CodecError> + Send + Sync + TreeError;
    // // TODO
    /// Gets node given a node key. Returns error if the node does not exist.
    ///
    /// Recommended impl: ```no_run
    /// self.get_node_option(node_key)?.ok_or_else(|| Self::Error::from(format!("Missing node at {:?}.", node_key)))
    /// ```
    fn get_node(&self, node_key: &NodeKey<N>) -> Result<Node<K, H, N>, Self::Error>;

    /// Gets node given a node key. Returns `None` if the node does not exist.
    fn get_node_option(&self, node_key: &NodeKey<N>) -> Result<Option<Node<K, H, N>>, Self::Error>;

    /// Gets the rightmost leaf at a version. Note that this assumes we are in the process of
    /// restoring the tree and all nodes are at the same version.
    fn get_rightmost_leaf(
        &self,
        version: Version,
    ) -> Result<Option<(NodeKey<N>, LeafNode<K, H, N>)>, Self::Error>;
}

pub trait TreeError {
    fn invalid_null() -> Self;
}

// TODO
pub trait TreeWriter<K, const N: usize>: Send + Sync {}

/// Indicates a node becomes stale since `stale_since_version`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct StaleNodeIndex<const N: usize> {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey<N>,
}

/// This is a wrapper of [`NodeBatch`](type.NodeBatch.html),
/// [`StaleNodeIndexBatch`](type.StaleNodeIndexBatch.html) and some stats of nodes that represents
/// the incremental updates of a tree and pruning indices after applying a write set,
/// which is a vector of `hashed_account_address` and `new_value` pairs.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TreeUpdateBatch<K: Key, H, const N: usize> {
    pub node_batch: Vec<Vec<(NodeKey<N>, Node<K, H, N>)>>,
    pub stale_node_index_batch: Vec<Vec<StaleNodeIndex<N>>>,
    pub num_new_leaves: usize,
    pub num_stale_leaves: usize,
}

impl<K, H, const N: usize> TreeUpdateBatch<K, H, N>
where
    K: Key,
    H: TreeHash<N>,
{
    pub fn new() -> Self {
        Self {
            node_batch: vec![vec![]],
            stale_node_index_batch: vec![vec![]],
            num_new_leaves: 0,
            num_stale_leaves: 0,
        }
    }

    pub fn combine(&mut self, other: Self) {
        let Self {
            node_batch,
            stale_node_index_batch,
            num_new_leaves,
            num_stale_leaves,
        } = other;

        self.node_batch.extend(node_batch);
        self.stale_node_index_batch.extend(stale_node_index_batch);
        self.num_new_leaves += num_new_leaves;
        self.num_stale_leaves += num_stale_leaves;
    }

    #[cfg(test)]
    pub fn num_stale_node(&self) -> usize {
        self.stale_node_index_batch.iter().map(Vec::len).sum()
    }

    fn inc_num_new_leaves(&mut self) {
        self.num_new_leaves += 1;
    }

    fn inc_num_stale_leaves(&mut self) {
        self.num_stale_leaves += 1;
    }

    pub fn put_node(&mut self, node_key: NodeKey<N>, node: Node<K, H, N>) {
        if node.is_leaf() {
            self.inc_num_new_leaves();
        }
        self.node_batch[0].push((node_key, node))
    }

    pub fn put_stale_node(
        &mut self,
        node_key: NodeKey<N>,
        stale_since_version: Version,
        node: &Node<K, H, N>,
    ) {
        if node.is_leaf() {
            self.inc_num_stale_leaves();
        }
        self.stale_node_index_batch[0].push(StaleNodeIndex {
            node_key,
            stale_since_version,
        });
    }
}

/// An iterator that iterates the index range (inclusive) of each different nibble at given
/// `nibble_idx` of all the keys in a sorted key-value pairs which have the identical HashValue
/// prefix (up to nibble_idx).
pub struct NibbleRangeIterator<'a, K, const N: usize> {
    sorted_kvs: &'a [(HashValue<N>, K)],
    nibble_idx: usize,
    pos: usize,
}

impl<'a, K, const N: usize> NibbleRangeIterator<'a, K, N> {
    fn new(sorted_kvs: &'a [(HashValue<N>, K)], nibble_idx: usize) -> Self {
        assert!(nibble_idx < HashValue::<N>::ROOT_NIBBLE_HEIGHT);
        NibbleRangeIterator {
            sorted_kvs,
            nibble_idx,
            pos: 0,
        }
    }
}

impl<'a, K, const N: usize> std::iter::Iterator for NibbleRangeIterator<'a, K, N> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let left = self.pos;
        if self.pos < self.sorted_kvs.len() {
            let cur_nibble: u8 = self.sorted_kvs[left].0.nibble(self.nibble_idx);
            let (mut i, mut j) = (left, self.sorted_kvs.len() - 1);
            // Find the last index of the cur_nibble.
            while i < j {
                let mid = j - (j - i) / 2;
                if self.sorted_kvs[mid].0.nibble(self.nibble_idx) > cur_nibble {
                    j = mid - 1;
                } else {
                    i = mid;
                }
            }
            self.pos = i + 1;
            Some((left, i))
        } else {
            None
        }
    }
}

/// The Jellyfish Merkle tree data structure. See [`crate`] for description.
pub struct JellyfishMerkleTree<'a, R, K, H, const N: usize> {
    reader: &'a R,
    phantom_key: PhantomData<K>,
    phantom_hasher: PhantomData<H>,
}

impl<'a, R, K, H, const N: usize> JellyfishMerkleTree<'a, R, K, H, N>
where
    R: 'a + TreeReader<K, H, N> + Sync,
    K: Key,
    H: TreeHash<N>,
{
    /// Creates a `JellyfishMerkleTree` backed by the given [`TreeReader`](trait.TreeReader.html).
    pub fn new(reader: &'a R) -> Self {
        Self {
            reader,
            phantom_key: PhantomData,
            phantom_hasher: PhantomData,
        }
    }

    /// Get the node hash from the cache if cache is provided, otherwise (for test only) compute it.
    fn get_hash(
        node_key: &NodeKey<N>,
        node: &Node<K, H, N>,
        hash_cache: &Option<&HashMap<NibblePath<N>, HashValue<N>>>,
    ) -> HashValue<N> {
        if let Some(cache) = hash_cache {
            match cache.get(node_key.nibble_path()) {
                Some(hash) => *hash,
                None => unreachable!("{:?} can not be found in hash cache", node_key),
            }
        } else {
            node.hash()
        }
    }

    /// For each value set:
    /// Returns the new nodes and values in a batch after applying `value_set`. For
    /// example, if after transaction `T_i` the committed state of tree in the persistent storage
    /// looks like the following structure:
    ///
    /// ```text
    ///              S_i
    ///             /   \
    ///            .     .
    ///           .       .
    ///          /         \
    ///         o           x
    ///        / \
    ///       A   B
    ///        storage (disk)
    /// ```
    ///
    /// where `A` and `B` denote the states of two adjacent accounts, and `x` is a sibling subtree
    /// of the path from root to A and B in the tree. Then a `value_set` produced by the next
    /// transaction `T_{i+1}` modifies other accounts `C` and `D` exist in the subtree under `x`, a
    /// new partial tree will be constructed in memory and the structure will be:
    ///
    /// ```text
    ///                 S_i      |      S_{i+1}
    ///                /   \     |     /       \
    ///               .     .    |    .         .
    ///              .       .   |   .           .
    ///             /         \  |  /             \
    ///            /           x | /               x'
    ///           o<-------------+-               / \
    ///          / \             |               C   D
    ///         A   B            |
    ///           storage (disk) |    cache (memory)
    /// ```
    ///
    /// With this design, we are able to query the global state in persistent storage and
    /// generate the proposed tree delta based on a specific root hash and `value_set`. For
    /// example, if we want to execute another transaction `T_{i+1}'`, we can use the tree `S_i` in
    /// storage and apply the `value_set` of transaction `T_{i+1}`. Then if the storage commits
    /// the returned batch, the state `S_{i+1}` is ready to be read from the tree by calling
    /// [`get_with_proof`](struct.JellyfishMerkleTree.html#method.get_with_proof). Anything inside
    /// the batch is not reachable from public interfaces before being committed.
    pub fn batch_put_value_set(
        &self,
        value_set: Vec<(HashValue<N>, Option<&(HashValue<N>, K)>)>,
        node_hashes: Option<&HashMap<NibblePath<N>, HashValue<N>>>,
        persisted_version: Option<Version>,
        version: Version,
    ) -> Result<(HashValue<N>, TreeUpdateBatch<K, H, N>), R::Error> {
        let deduped_and_sorted_kvs = value_set
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();

        let mut batch = TreeUpdateBatch::new();
        let root_node_opt = if let Some(persisted_version) = persisted_version {
            run_on_io_pool_if_enabled(|| {
                self.batch_insert_at(
                    &NodeKey::new_empty_path(persisted_version),
                    version,
                    deduped_and_sorted_kvs.as_slice(),
                    0,
                    &node_hashes,
                    &mut batch,
                )
            })?
        } else {
            self.batch_update_subtree(
                &NodeKey::new_empty_path(version),
                version,
                deduped_and_sorted_kvs.as_slice(),
                0,
                &node_hashes,
                &mut batch,
            )?
        };

        let node_key = NodeKey::new_empty_path(version);
        let root_hash = if let Some(root_node) = root_node_opt {
            set_leaf_count_if_enabled(root_node.leaf_count());
            let hash = root_node.hash();
            batch.put_node(node_key, root_node);
            hash
        } else {
            set_leaf_count_if_enabled(0);
            batch.put_node(node_key, Node::Null);
            H::SPARSE_MERKLE_PLACEHOLDER_HASH
        };

        Ok((root_hash, batch))
    }

    fn batch_insert_at(
        &self,
        node_key: &NodeKey<N>,
        version: Version,
        kvs: &[(HashValue<N>, Option<&(HashValue<N>, K)>)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath<N>, HashValue<N>>>,
        batch: &mut TreeUpdateBatch<K, H, N>,
    ) -> Result<Option<Node<K, H, N>>, R::Error> {
        let node = self.reader.get_node(node_key)?;
        batch.put_stale_node(node_key.clone(), version, &node);

        match node {
            Node::Internal(internal_node) => {
                // There is a small possibility that the old internal node is intact.
                // Traverse all the path touched by `kvs` from this internal node.
                let range_iter = NibbleRangeIterator::new(kvs, depth);
                let mapper =
                    |left: usize, right: usize, batch_ref: &mut TreeUpdateBatch<K, H, N>| {
                        self.insert_at_child(
                            node_key,
                            &internal_node,
                            version,
                            kvs,
                            left,
                            right,
                            depth,
                            hash_cache,
                            batch_ref,
                        )
                    };

                let new_children: Vec<_> = parallel_process_range_if_enabled::<R, K, H, _, N>(
                    depth, range_iter, batch, mapper,
                )?;

                // Reuse the current `InternalNode` in memory to create a new internal node.
                let mut old_children: Children<N> = internal_node.into();
                let mut new_created_children = HashMap::new();
                for (child_nibble, child_option) in new_children {
                    if let Some(child) = child_option {
                        new_created_children.insert(child_nibble, child);
                    } else {
                        old_children.remove(&child_nibble);
                    }
                }

                if old_children.is_empty() && new_created_children.is_empty() {
                    return Ok(None);
                } else if old_children.len() <= 1 && new_created_children.len() <= 1 {
                    if let Some((new_nibble, new_child)) = new_created_children.iter().next() {
                        if let Some((old_nibble, _old_child)) = old_children.iter().next() {
                            if old_nibble == new_nibble && new_child.is_leaf() {
                                return Ok(Some(new_child.clone()));
                            }
                        } else if new_child.is_leaf() {
                            return Ok(Some(new_child.clone()));
                        }
                    } else {
                        let (old_child_nibble, old_child) =
                            old_children.iter().next().expect("must exist");
                        if old_child.is_leaf() {
                            let old_child_node_key =
                                node_key.gen_child_node_key(old_child.version, *old_child_nibble);
                            let old_child_node = self.reader.get_node(&old_child_node_key)?;
                            batch.put_stale_node(old_child_node_key, version, &old_child_node);
                            return Ok(Some(old_child_node));
                        }
                    }
                }

                let mut new_children = old_children;
                for (child_index, new_child_node) in new_created_children {
                    let new_child_node_key = node_key.gen_child_node_key(version, child_index);
                    new_children.insert(
                        child_index,
                        Child::new(
                            Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                            version,
                            new_child_node.node_type(),
                        ),
                    );
                    batch.put_node(new_child_node_key, new_child_node);
                }
                let new_internal_node = InternalNode::new(new_children);
                Ok(Some(new_internal_node.into()))
            }
            Node::Leaf(leaf_node) => self.batch_update_subtree_with_existing_leaf(
                node_key, version, leaf_node, kvs, depth, hash_cache, batch,
            ),
            Node::Null => {
                if depth == 0 {
                    return Err(R::Error::invalid_null());
                }
                self.batch_update_subtree(node_key, version, kvs, 0, hash_cache, batch)
            }
        }
    }

    fn insert_at_child(
        &self,
        node_key: &NodeKey<N>,
        internal_node: &InternalNode<H, N>,
        version: Version,
        kvs: &[(HashValue<N>, Option<&(HashValue<N>, K)>)],
        left: usize,
        right: usize,
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath<N>, HashValue<N>>>,
        batch: &mut TreeUpdateBatch<K, H, N>,
    ) -> Result<(Nibble, Option<Node<K, H, N>>), R::Error> {
        let child_index = kvs[left].0.get_nibble(depth);
        let child = internal_node.child(child_index);

        let new_child_node_option = match child {
            Some(child) => self.batch_insert_at(
                &node_key.gen_child_node_key(child.version, child_index),
                version,
                &kvs[left..=right],
                depth + 1,
                hash_cache,
                batch,
            )?,
            None => self.batch_update_subtree(
                &node_key.gen_child_node_key(version, child_index),
                version,
                &kvs[left..=right],
                depth + 1,
                hash_cache,
                batch,
            )?,
        };

        Ok((child_index, new_child_node_option))
    }

    fn batch_update_subtree_with_existing_leaf(
        &self,
        node_key: &NodeKey<N>,
        version: Version,
        existing_leaf_node: LeafNode<K, H, N>,
        kvs: &[(HashValue<N>, Option<&(HashValue<N>, K)>)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath<N>, HashValue<N>>>,
        batch: &mut TreeUpdateBatch<K, H, N>,
    ) -> Result<Option<Node<K, H, N>>, R::Error> {
        let existing_leaf_key = existing_leaf_node.account_key();

        if kvs.len() == 1 && kvs[0].0 == existing_leaf_key {
            if let (key, Some((value_hash, state_key))) = kvs[0] {
                let new_leaf_node = Node::new_leaf(key, *value_hash, (state_key.clone(), version));
                Ok(Some(new_leaf_node))
            } else {
                inc_deletion_count_if_enabled(1);
                Ok(None)
            }
        } else {
            let existing_leaf_bucket = existing_leaf_key.get_nibble(depth);
            let mut isolated_existing_leaf = true;
            let mut children = vec![];
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                if let Some(new_child_node) = if existing_leaf_bucket == child_index {
                    isolated_existing_leaf = false;
                    self.batch_update_subtree_with_existing_leaf(
                        &child_node_key,
                        version,
                        existing_leaf_node.clone(),
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        batch,
                    )?
                } else {
                    self.batch_update_subtree(
                        &child_node_key,
                        version,
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        batch,
                    )?
                } {
                    children.push((child_index, new_child_node));
                }
            }
            if isolated_existing_leaf {
                children.push((existing_leaf_bucket, existing_leaf_node.into()));
            }

            if children.is_empty() {
                Ok(None)
            } else if children.len() == 1 && children[0].1.is_leaf() {
                let (_, child) = children.pop().expect("Must exist");
                Ok(Some(child))
            } else {
                let new_internal_node = InternalNode::new(
                    children
                        .into_iter()
                        .map(|(child_index, new_child_node)| {
                            let new_child_node_key =
                                node_key.gen_child_node_key(version, child_index);
                            let result = (
                                child_index,
                                Child::new(
                                    Self::get_hash(
                                        &new_child_node_key,
                                        &new_child_node,
                                        hash_cache,
                                    ),
                                    version,
                                    new_child_node.node_type(),
                                ),
                            );
                            batch.put_node(new_child_node_key, new_child_node);
                            result
                        })
                        .collect(),
                );
                Ok(Some(new_internal_node.into()))
            }
        }
    }

    fn batch_update_subtree(
        &self,
        node_key: &NodeKey<N>,
        version: Version,
        kvs: &[(HashValue<N>, Option<&(HashValue<N>, K)>)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath<N>, HashValue<N>>>,
        batch: &mut TreeUpdateBatch<K, H, N>,
    ) -> Result<Option<Node<K, H, N>>, R::Error> {
        if kvs.len() == 1 {
            if let (key, Some((value_hash, state_key))) = kvs[0] {
                let new_leaf_node = Node::new_leaf(key, *value_hash, (state_key.clone(), version));
                Ok(Some(new_leaf_node))
            } else {
                Ok(None)
            }
        } else {
            let mut children = vec![];
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                if let Some(new_child_node) = self.batch_update_subtree(
                    &child_node_key,
                    version,
                    &kvs[left..=right],
                    depth + 1,
                    hash_cache,
                    batch,
                )? {
                    children.push((child_index, new_child_node))
                }
            }
            if children.is_empty() {
                Ok(None)
            } else if children.len() == 1 && children[0].1.is_leaf() {
                let (_, child) = children.pop().expect("Must exist");
                Ok(Some(child))
            } else {
                let new_internal_node = InternalNode::new(
                    children
                        .into_iter()
                        .map(|(child_index, new_child_node)| {
                            let new_child_node_key =
                                node_key.gen_child_node_key(version, child_index);
                            let result = (
                                child_index,
                                Child::new(
                                    Self::get_hash(
                                        &new_child_node_key,
                                        &new_child_node,
                                        hash_cache,
                                    ),
                                    version,
                                    new_child_node.node_type(),
                                ),
                            );
                            batch.put_node(new_child_node_key, new_child_node);
                            result
                        })
                        .collect(),
                );
                Ok(Some(new_internal_node.into()))
            }
        }
    }
}

trait NibbleExt<const N: usize> {
    fn get_nibble(&self, index: usize) -> Nibble;
    fn common_prefix_nibbles_len(&self, other: HashValue<N>) -> usize;
}

impl<const N: usize> NibbleExt<N> for HashValue<N> {
    /// Returns the `index`-th nibble.
    fn get_nibble(&self, index: usize) -> Nibble {
        Nibble::from(if index % 2 == 0 {
            self[index / 2] >> 4
        } else {
            self[index / 2] & 0x0F
        })
    }

    /// Returns the length of common prefix of `self` and `other` in nibbles.
    fn common_prefix_nibbles_len(&self, other: HashValue<N>) -> usize {
        self.common_prefix_bits_len(other) / 4
    }
}

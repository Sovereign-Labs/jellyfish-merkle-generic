use crate::{
    types::nibble::{nibble_path::NibblePath, Nibble},
    Version,
};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

/// The unique key of each node.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeKey<const N: usize> {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath<N>,
}

impl<const N: usize> NodeKey<N> {
    /// Creates a new `NodeKey`.
    pub fn new(version: Version, nibble_path: NibblePath<N>) -> Self {
        Self {
            version,
            nibble_path,
        }
    }

    /// A shortcut to generate a node key consisting of a version and an empty nibble path.
    pub fn new_empty_path(version: Version) -> Self {
        Self::new(version, NibblePath::new_even(vec![]))
    }

    /// Gets the version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Gets the nibble path.
    pub fn nibble_path(&self) -> &NibblePath<N> {
        &self.nibble_path
    }

    /// Generates a child node key based on this node key.
    pub fn gen_child_node_key(&self, version: Version, n: Nibble) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        node_nibble_path.push(n);
        Self::new(version, node_nibble_path)
    }

    /// Generates parent node key at the same version based on this node key.
    pub fn gen_parent_node_key(&self) -> Self {
        let mut node_nibble_path = self.nibble_path().clone();
        assert!(
            node_nibble_path.pop().is_some(),
            "Current node key is root.",
        );
        Self::new(self.version, node_nibble_path)
    }

    /// Sets the version to the given version.
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    // TODO: Add back if necessary. Prefer to delegate to serialization scheme
    // /// Serializes to bytes for physical storage enforcing the same order as that in memory.
    // pub fn encode(&self) -> Result<Vec<u8>> {
    //     let mut out = vec![];
    //     out.write_u64::<BigEndian>(self.version())?;
    //     out.write_u8(self.nibble_path().num_nibbles() as u8)?;
    //     out.write_all(self.nibble_path().bytes())?;
    //     Ok(out)
    // }

    // /// Recovers from serialized bytes in physical storage.
    // pub fn decode(val: &[u8]) -> Result<NodeKey<N>> {
    //     let mut reader = Cursor::new(val);
    //     let version = reader.read_u64::<BigEndian>()?;
    //     let num_nibbles = reader.read_u8()? as usize;
    //     ensure!(
    //         num_nibbles <= ROOT_NIBBLE_HEIGHT,
    //         "Invalid number of nibbles: {}",
    //         num_nibbles,
    //     );
    //     let mut nibble_bytes = Vec::with_capacity((num_nibbles + 1) / 2);
    //     reader.read_to_end(&mut nibble_bytes)?;
    //     ensure!(
    //         (num_nibbles + 1) / 2 == nibble_bytes.len(),
    //         "encoded num_nibbles {} mismatches nibble path bytes {:?}",
    //         num_nibbles,
    //         nibble_bytes
    //     );
    //     let nibble_path = if num_nibbles % 2 == 0 {
    //         NibblePath::new_even(nibble_bytes)
    //     } else {
    //         let padding = nibble_bytes.last().unwrap() & 0x0F;
    //         ensure!(
    //             padding == 0,
    //             "Padding nibble expected to be 0, got: {}",
    //             padding,
    //         );
    //         NibblePath::new_odd(nibble_bytes)
    //     };
    //     Ok(NodeKey::new(version, nibble_path))
    // }

    pub fn unpack(self) -> (Version, NibblePath<N>) {
        (self.version, self.nibble_path)
    }
}

use super::*;

pub struct DB<'a, R, W, K, H, const N: usize> {
    jmt: JellyfishMerkleTree<'a, R, K, H, N>,
    reader: &'a R,
    writer: &'a W,
}

impl<'a, R, W, K, H, const N: usize> DB<'a, R, W, K, H, N>
where
    W: TreeWriter<K, H, N>,
    R: TreeReader<K, H, N> + Send + Sync,
    K: Key,
    H: TreeHash<N>,
{
    pub fn new(writer: &'a W, reader: &'a R) -> Self {
        Self {
            jmt: JellyfishMerkleTree::new(reader),
            reader,
            writer,
        }
    }

    pub fn get(&self, key: K, version: Version) -> Result<Vec<u8>, JmtError<R::Error>> {
        Ok(self.reader.get_value(&key, version)?)
    }

    pub fn set(&self, k: K, version: Version, value: Vec<u8>) {
        let key_hash = KeyHash(H::hash(&k));
        let hash_value = ValueHash(H::hash(value));

        let hash_and_key = &(hash_value, k);
        let value_set = vec![(key_hash, Some(hash_and_key))];

        let update_batch = self
            .jmt
            .batch_put_value_set(value_set, None, None, version)
            .unwrap();

        let node_batch = update_batch
            .1
            .node_batch
            .into_iter()
            .map(|x| x.into_iter())
            .flatten()
            .collect();

        self.writer.write_node_batch(&node_batch).unwrap();

        todo!()
    }

    pub fn get_with_proof(
        &self,
        k: KeyHash<N>,
        version: Version,
    ) -> Result<
        (Option<(ValueHash<N>, (K, u64))>, SparseMerkleProof<H, N>),
        JmtError<<R as TreeReader<K, H, N>>::Error>,
    > {
        self.jmt.get_with_proof(k, version)
    }
}

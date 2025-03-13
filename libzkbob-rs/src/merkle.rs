use std::collections::HashMap;

use crate::utils::zero_note;
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_memorydb::InMemory as MemoryDatabase;
#[cfg(feature = "native")]
use kvdb_rocksdb::{Database as NativeDatabase, DatabaseConfig};
#[cfg(feature = "web")]
use kvdb_web::Database as WebDatabase;
use libzeropool::{
    constants,
    fawkes_crypto::core::sizedvec::SizedVec,
    fawkes_crypto::ff_uint::{Num, PrimeField},
    fawkes_crypto::native::poseidon::{poseidon, MerkleProof},
    native::params::PoolParams,
};
use serde::{Deserialize, Serialize};

pub type Hash<F> = Num<F>;

const NUM_COLUMNS: u32 = 4;
const NEXT_INDEX_KEY: &[u8] = br"next_index";
const FIRST_INDEX_KEY: &[u8] = br"first_index";
enum DbCols {
    Leaves = 0,
    TempLeaves = 1,
    NamedIndex = 2,
    NextIndex = 3,
}

pub struct MerkleTree<D: KeyValueDB, P: PoolParams> {
    db: D,
    params: P,
    default_hashes: Vec<Hash<P::Fr>>,
    zero_note_hashes: Vec<Hash<P::Fr>>,
    first_index: Option<u64>,
    next_index: u64,
}

#[cfg(feature = "native")]
pub type NativeMerkleTree<P> = MerkleTree<NativeDatabase, P>;

#[cfg(feature = "web")]
pub type WebMerkleTree<P> = MerkleTree<WebDatabase, P>;

#[cfg(feature = "web")]
impl<P: PoolParams> MerkleTree<WebDatabase, P> {
    pub async fn new_web(name: &str, params: P) -> MerkleTree<WebDatabase, P> {
        let db = WebDatabase::open(name.to_owned(), NUM_COLUMNS).await.unwrap();

        Self::new(db, params)
    }
}

#[cfg(feature = "native")]
impl<P: PoolParams> MerkleTree<NativeDatabase, P> {
    pub fn new_native(
        _config: DatabaseConfig,
        path: &str,
        params: P,
    ) -> std::io::Result<MerkleTree<NativeDatabase, P>> {
        let c= DatabaseConfig::with_columns(NUM_COLUMNS);
        
        let db = NativeDatabase::open(&c, path)?;

        Ok(Self::new(db, params))
    }
}

impl<P: PoolParams> MerkleTree<MemoryDatabase, P> {
    pub fn new_test(params: P) -> MerkleTree<MemoryDatabase, P> {
        Self::new(kvdb_memorydb::create(NUM_COLUMNS), params)
    }
}

// TODO: Proper error handling.
impl<D: KeyValueDB, P: PoolParams> MerkleTree<D, P> {
    pub fn new(db: D, params: P) -> Self {
        let db_next_index = db.get(DbCols::NextIndex as u32, NEXT_INDEX_KEY);
        let next_index = match db_next_index {
            Ok(Some(next_index)) => next_index
                .as_slice()
                .read_u64::<BigEndian>()
                .unwrap(),
            _ => {
                let mut cur_next_index = 0;
                for k_v in db.iter(0) {
                    let (height, index) = Self::parse_node_key(&k_v.unwrap().0);
        
                    if height == 0 && index >= cur_next_index {
                        cur_next_index = Self::calc_next_index(index);
                    } else if height == constants::OUTPLUSONELOG as u32 &&
                            (index << constants::OUTPLUSONELOG) >= cur_next_index
                    {
                        // in case of we hold just a commitment instead leafs
                        cur_next_index = (index + 1) << constants::OUTPLUSONELOG;
                    }
                }
                cur_next_index
            }
        };

        // we store first index for the partial Merkle tree support (when it synced not from start)
        let db_first_index = db.get(DbCols::NextIndex as u32, FIRST_INDEX_KEY);
        let first_index = match db_first_index {
            Ok(Some(first_index)) => first_index
                .as_slice()
                .read_u64::<BigEndian>()
                .ok(),
            _ => {
                let mut cur_first_index = u64::MAX;
                for k_v in db.iter(0) {
                    let (height, index) = Self::parse_node_key(&k_v.unwrap().0);
        
                    if height == 0 && index < cur_first_index {
                        cur_first_index = index;
                    } else if height == constants::OUTPLUSONELOG as u32 &&
                            (index << constants::OUTPLUSONELOG) < cur_first_index
                    {
                        // in case of we hold just a commitment instead leafs
                        cur_first_index = index << constants::OUTPLUSONELOG;
                    }
                }
                if cur_first_index != u64::MAX {
                    Some(cur_first_index)
                } else {
                    None
                }
            }
        };


        MerkleTree {
            db,
            default_hashes: Self::gen_default_hashes(&params),
            zero_note_hashes: Self::gen_empty_note_hashes(&params),
            params,
            first_index,
            next_index,
        }
    }

    /// Add hash for an element with a certain index at a certain height
    /// Set `temporary` to true if you want this leaf and all unneeded connected nodes to be removed
    /// during cleanup.
    pub fn add_hash_at_height(
        &mut self,
        height: u32,
        index: u64,
        hash: Hash<P::Fr>,
        temporary: bool,
    ) {
        // todo: revert index change if update fails?
        let next_index_was_updated = self.update_next_index_from_node(height, index);

        if height == 0 || height == constants::OUTPLUSONELOG as u32 {
            self.update_first_index_from_node(height, index);
        }

        if hash == self.zero_note_hashes[height as usize] && !next_index_was_updated {
            return;
        }

        let mut batch = self.db.transaction();

        // add leaf
        let temporary_leaves_count = u64::from(temporary);
        self.set_batched(&mut batch, height, index, hash, temporary_leaves_count);

        // update inner nodes
        self.update_path_batched(&mut batch, height, index, hash, temporary_leaves_count);

        self.db.write(batch).unwrap();
    }

    pub fn add_hash(&mut self, index: u64, hash: Hash<P::Fr>, temporary: bool) {
        self.add_hash_at_height(0, index, hash, temporary)
    }

    pub fn append_hash(&mut self, hash: Hash<P::Fr>, temporary: bool) -> u64 {
        let index = self.next_index;
        self.add_hash(index, hash, temporary);
        index
    }

    pub fn add_leafs_and_commitments(
        &mut self, 
        leafs: Vec<(u64, Vec<Hash<P::Fr>>)>, 
        commitments: Vec<(u64, Hash<P::Fr>)>
    ) {
        self.add_leafs_commitments_and_siblings(leafs, commitments, None)
    }

    // The common method which can be used for full or partial tree update
    // Supposed that partial tree can omit its left part and should have no other gaps
    // Siblings are tree nodes to restore correct tree root in case of left tree part absence
    // Siblings for concrete index should be generated with MerkleTree::get_left_siblings method
    // The leafs or commitments MUST be started with an index which was used to generating siblings,
    //  e.g. if siblings were generated for index 1024, the commitment@8 or leaf@1024 must be presented
    //  !otherwise tree becomes corrupted!
    pub fn add_leafs_commitments_and_siblings(
        &mut self, 
        leafs: Vec<(u64, Vec<Hash<P::Fr>>)>, 
        commitments: Vec<(u64, Hash<P::Fr>)>, 
        siblings: Option<Vec<Node<P::Fr>>>
    ) {
        if leafs.is_empty() && commitments.is_empty() {
            return;
        }

        let mut last_bound_index: u64 = 0;
        let mut first_bound_index: u64 = u64::MAX;  // left bound includes optional siblings part
        let mut first_effective_index: u64 = u64::MAX;  // leaf or commitment (no siblings bounds)

        // add commitments @ height OUTPLUSONELOG
        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = commitments
            .into_iter()
            .map(|(index, hash)| {
                assert_eq!(index & ((1 << constants::OUTPLUSONELOG) - 1), 0);
                first_effective_index = first_effective_index.min(index);
                first_bound_index = first_bound_index.min(index);
                last_bound_index = last_bound_index.max(index);
                ((constants::OUTPLUSONELOG as u32, index  >> constants::OUTPLUSONELOG), hash)
            })
            .collect();
        
        // add leafs (accounts + notes) @ height 0
        leafs.into_iter()
            .filter(|(_, leafs)| !leafs.is_empty())
            .for_each(|(index, leafs)| {
                assert_eq!(index & ((1 << constants::OUTPLUSONELOG) - 1), 0);
                first_effective_index = first_effective_index.min(index);
                first_bound_index = first_bound_index.min(index);
                last_bound_index = last_bound_index.max(index + leafs.len() as u64 - 1);
                (0..constants::OUTPLUSONELOG)
                    .for_each(|height| {
                        let level_index = ((index + leafs.len() as u64 - 1) >> height) + 1;
                        if level_index < ((index + (constants::OUT as u64 + 1)) >> height) && level_index % 2 == 1 {
                            virtual_nodes.insert((height as u32, level_index), self.zero_note_hashes[height]);
                        }
                    });
                leafs.into_iter().enumerate().for_each(|(i, leaf)| {
                    virtual_nodes.insert((0_u32, index + i as u64), leaf);
                });
            });

        // append sibling nodes
        virtual_nodes.extend(siblings
            .unwrap_or_default()
            .into_iter()
            .map(|node| {
                first_bound_index = first_bound_index.min(node.index << node.height);
                last_bound_index = last_bound_index.max(((node.index + 1) << node.height) - 1);
                ((node.height, node.index), node.value)
            })
        );

        let original_next_index = self.next_index;
        self.update_next_index_from_node(0, last_bound_index);

        if first_effective_index != u64::MAX {
            self.update_first_index_from_node(0, first_effective_index);
        }

        let update_boundaries = UpdateBoundaries {
            updated_range_left_index: original_next_index,
            updated_range_right_index: self.next_index,
            new_hashes_left_index: first_bound_index,
            new_hashes_right_index: last_bound_index + 1,
        };

        // calculate new hashes
        self.get_virtual_node_full(
            constants::HEIGHT as u32,
            0,
            &mut virtual_nodes,
            &update_boundaries,
        );

        // add new hashes to tree
        self.put_hashes(virtual_nodes);
    }

    pub fn add_hashes<I>(&mut self, start_index: u64, hashes: I)
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        // check that index is correct
        assert_eq!(start_index & ((1 << constants::OUTPLUSONELOG) - 1), 0);

        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = hashes
            .into_iter()
            // todo: check that there are no zero holes?
            .filter(|hash| *hash != self.zero_note_hashes[0])
            .enumerate()
            .map(|(index, hash)| ((0, start_index + index as u64), hash))
            .collect();
        let new_hashes_count = virtual_nodes.len() as u64;

        assert!(new_hashes_count <= (2u64 << constants::OUTPLUSONELOG));

        let original_next_index = self.next_index;
        if new_hashes_count > 0 {
            self.update_next_index_from_node(0, start_index);
            self.update_first_index_from_node(0, start_index);
        }

        let update_boundaries = UpdateBoundaries {
            updated_range_left_index: original_next_index,
            updated_range_right_index: self.next_index,
            new_hashes_left_index: start_index,
            new_hashes_right_index: start_index + new_hashes_count,
        };

        // calculate new hashes
        self.get_virtual_node_full(
            constants::HEIGHT as u32,
            0,
            &mut virtual_nodes,
            &update_boundaries,
        );

        // add new hashes to tree
        self.put_hashes(virtual_nodes);
    }

    fn put_hashes(&mut self, virtual_nodes: HashMap<(u32, u64), Hash<<P as PoolParams>::Fr>>) {
        let mut batch = self.db.transaction();

        for ((height, index), value) in virtual_nodes {
            self.set_batched(&mut batch, height, index, value, 0);
        }

        self.db.write(batch).unwrap();
    }

    // This method is used in tests.
    #[cfg(test)]
    fn add_subtree_root(&mut self, height: u32, index: u64, hash: Hash<P::Fr>) {
        self.update_next_index_from_node(height, index);

        let mut batch = self.db.transaction();

        // add root
        self.set_batched(&mut batch, height, index, hash, 1 << height);

        // update path
        self.update_path_batched(&mut batch, height, index, hash, 1 << height);

        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: u32, index: u64) -> Hash<P::Fr> {
        self.get_with_next_index(height, index, self.next_index)
    }

    fn get_with_next_index(&self, height: u32, index: u64, next_index: u64) -> Hash<P::Fr> {
        match self.get_opt(height, index) {
            Some(val) => val,
            _ => {
                let next_leave_index = u64::pow(2, height) * (index + 1);
                if next_leave_index <= next_index {
                    self.zero_note_hashes[height as usize]
                } else {
                    self.default_hashes[height as usize]
                }
            }
        }
    }

    pub fn last_leaf(&self) -> Hash<P::Fr> {
        // todo: can last leaf be an zero note?
        match self.get_opt(0, self.next_index.saturating_sub(1)) {
            Some(val) => val,
            _ => self.default_hashes[0],
        }
    }

    pub fn get_root(&self) -> Hash<P::Fr> {
        self.get(constants::HEIGHT as u32, 0)
    }

    // Get root at specified index (without rollback)
    // This method can be used for tree integrity check
    // `index` is a position within Merkle tree level 0
    // it should be <= next_index
    pub fn get_root_at(&self, index: u64) -> Option<Hash<P::Fr>> {
        if index > self.next_index() {
            return None;
        }

        let non_zero_sibling_height = (index.trailing_zeros() as usize).min(constants::HEIGHT);
        let mut hash = self.default_hashes[non_zero_sibling_height];

        for height in non_zero_sibling_height..constants::HEIGHT {
            let sibling_index = (index >> height) ^ 1;
            let is_right = sibling_index & 1 != 0;

            let pair = if is_right {
                [hash, self.default_hashes[height]]
            } else {
                // node at `sibling_index` is always expected to be present
                // if it is not, then the tree is corrupted
                [self.get_opt(height as u32, sibling_index)?, hash]
            };

            hash = poseidon(pair.as_ref(), self.params.compress());
        }
        Some(hash)
    }

    pub fn get_root_after_virtual<I>(
        &self,
        new_commitments: I,
    ) -> Hash<P::Fr>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        let next_leaf_index = self.next_index;
        let next_commitment_index = next_leaf_index / 2u64.pow(constants::OUTPLUSONELOG as u32);
        let index_step = constants::OUT as u64 + 1;

        let mut virtual_commitment_nodes: HashMap<(u32, u64), Hash<P::Fr>> = new_commitments
            .into_iter()
            .enumerate()
            .map(|(index, hash)| ((constants::OUTPLUSONELOG as u32, next_commitment_index + index as u64), hash))
            .collect();
        let new_commitments_count = virtual_commitment_nodes.len() as u64;

        self.get_virtual_node(
            constants::HEIGHT as u32,
            0,
            &mut virtual_commitment_nodes,
            next_leaf_index,
            next_leaf_index + new_commitments_count * index_step,
        )
    }

    pub fn get_root_optimistic(
        &self,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        update_boundaries: &UpdateBoundaries,
    ) -> Hash<P::Fr>
    {
        self.get_virtual_node_full(constants::HEIGHT as u32, 0, virtual_nodes, update_boundaries)
    }

    pub fn get_opt(&self, height: u32, index: u64) -> Option<Hash<P::Fr>> {
        assert!(height <= constants::HEIGHT as u32);

        let key = Self::node_key(height, index);
        let res = self.db.get(0, &key);

        match res {
            Ok(Some(ref val)) => Some(Hash::<P::Fr>::try_from_slice(val).unwrap()),
            _ => None,
        }
    }

    // Partial tree support
    // To build Merkle tree from the specified index we should generate left siblings
    // from the commitment height (in case of index is a multiple of constants::OUT + 1) to the root height
    // This method should be used on the relayer side to provide the client needed siblings
    pub fn get_left_siblings(&self, index: u64) -> Option<Vec<Node<P::Fr>>> {
        if index > self.next_index {
            return None
        }
        let array = (0..constants::HEIGHT)
            .into_iter()
            .filter_map(|h| {
                let level_idx = index >> h;
                if level_idx % 2 == 1 {
                    let sibling_idx = level_idx ^ 1;
                    let hash = self.get(h as u32, sibling_idx);
                    return Some(Node {
                        index: sibling_idx,
                        height: h as u32,
                        value: hash,
                    });
                }

                None
            })
            .collect();

        Some(array)
    }

    pub fn get_proof_unchecked<const H: usize>(&self, index: u64) -> MerkleProof<P::Fr, { H }> {
        let mut sibling: SizedVec<_, { H }> = (0..H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { H }> = (0..H).map(|_| false).collect();

        let start_height = constants::HEIGHT - H;

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_right))| {
                let cur_height = (start_height + h) as u32;
                *is_right = x % 2 == 1;
                *sibling = self.get(cur_height, x ^ 1);

                x / 2
            },
        );

        MerkleProof { sibling, path }
    }

    pub fn get_leaf_proof(&self, index: u64) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>> {
        let key = Self::node_key(0, index);
        let node_present = self.db.get(0, &key).map_or(false, |value| value.is_some());
        if !node_present {
            return None;
        }
        Some(self.get_proof_unchecked(index))
    }

    // This method is used in tests.
    #[cfg(test)]
    fn get_proof_after<I>(
        &mut self,
        new_hashes: I,
    ) -> Vec<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        let new_hashes: Vec<_> = new_hashes.into_iter().collect();
        let size = new_hashes.len() as u64;

        // TODO: Optimize, no need to mutate the database.
        let index_offset = self.next_index;
        self.add_hashes(index_offset, new_hashes);

        let proofs = (index_offset..index_offset + size)
            .map(|index| {
                self.get_leaf_proof(index)
                    .expect("Leaf was expected to be present (bug)")
            })
            .collect();

        // Restore next_index.
        self.next_index = index_offset;
        // FIXME: Not all nodes are deleted here
        for index in index_offset..index_offset + size {
            self.remove_leaf(index);
        }

        proofs
    }

    pub fn get_proof_after_virtual<I>(
        &self,
        new_hashes: I,
    ) -> Vec<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        let index_offset = self.next_index;

        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = new_hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| ((0, index_offset + index as u64), hash))
            .collect();
        let new_hashes_count = virtual_nodes.len() as u64;

        let update_boundaries = UpdateBoundaries {
            updated_range_left_index: index_offset,
            updated_range_right_index: Self::calc_next_index(index_offset),
            new_hashes_left_index: index_offset,
            new_hashes_right_index: index_offset + new_hashes_count,
        };

        (index_offset..index_offset + new_hashes_count)
            .map(|index| self.get_proof_virtual(index, &mut virtual_nodes, &update_boundaries))
            .collect()
    }

    pub fn get_proof_virtual_index<I>(
        &self,
        index: u64,
        new_hashes: I,
    ) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        let index_offset = self.next_index;

        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = new_hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| ((0, index_offset + index as u64), hash))
            .collect();
        let new_hashes_count = virtual_nodes.len() as u64;

        let update_boundaries = UpdateBoundaries {
            updated_range_left_index: index_offset,
            updated_range_right_index: index_offset + new_hashes_count,
            new_hashes_left_index: index_offset,
            new_hashes_right_index: index_offset + new_hashes_count,
        };

        Some(self.get_proof_virtual(index, &mut virtual_nodes, &update_boundaries))
    }


    pub fn get_virtual_subtree<I1, I2>(
        &self,
        new_hashes: I1,
        new_commitments: I2,
    ) -> (HashMap<(u32, u64), Hash<P::Fr>>, UpdateBoundaries)
    where
        I1: IntoIterator<Item = (u64, Vec<Hash<P::Fr>>)>,
        I2: IntoIterator<Item = (u64, Hash<P::Fr>)>,
    {
        let mut last_bound_index: Option<u64> = None;
        let mut first_bound_index: Option<u64> = None;
        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = new_commitments
            .into_iter()
            .map(|(index, hash)| {
                assert_eq!(index & ((1 << constants::OUTPLUSONELOG) - 1), 0);
                first_bound_index = Some(first_bound_index.unwrap_or(u64::MAX).min(index));
                last_bound_index = Some(last_bound_index.unwrap_or(0).max(index));
                ((constants::OUTPLUSONELOG as u32, index  >> constants::OUTPLUSONELOG), hash)
            })
            .collect();
        
        new_hashes.into_iter().for_each(|(index, leafs)| {
            assert_eq!(index & ((1 << constants::OUTPLUSONELOG) - 1), 0);
            first_bound_index = Some(first_bound_index.unwrap_or(u64::MAX).min(index));
            last_bound_index = Some(last_bound_index.unwrap_or(0).max(index + leafs.len() as u64 - 1));
            (0..constants::OUTPLUSONELOG)
                .for_each(|height| {
                    let level_index = ((index + leafs.len() as u64 - 1) >> height) + 1;
                    if level_index < ((index + (constants::OUT as u64 + 1)) >> height) && level_index % 2 == 1 {
                        virtual_nodes.insert((height as u32, level_index), self.zero_note_hashes[height]);
                    }
                });
            leafs.into_iter().enumerate().for_each(|(i, leaf)| {
                virtual_nodes.insert((0_u32, index + i as u64), leaf);
            });
        });

        let update_boundaries = {
            if let (Some(first_bound_index), Some(last_bound_index)) = (first_bound_index, last_bound_index) {
                UpdateBoundaries {
                    updated_range_left_index: self.next_index,
                    updated_range_right_index: Self::calc_next_index(last_bound_index),
                    new_hashes_left_index: first_bound_index,
                    new_hashes_right_index: last_bound_index + 1,
                }
            } else {
                UpdateBoundaries {
                    updated_range_left_index: self.next_index,
                    updated_range_right_index: self.next_index,
                    new_hashes_left_index: self.next_index,
                    new_hashes_right_index: self.next_index,
                }
            }
        };

        // calculate new hashes
        self.get_virtual_node_full(
            constants::HEIGHT as u32,
            0,
            &mut virtual_nodes,
            &update_boundaries,
        );

        (virtual_nodes, update_boundaries)
    }
    

    pub fn get_proof_optimistic_index(
        &self,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        update_boundaries: &UpdateBoundaries,
    ) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>>
    {
        Some(self.get_proof_virtual(index, virtual_nodes, update_boundaries))
    }

    fn get_proof_virtual<const H: usize>(
        &self,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        update_boundaries: &UpdateBoundaries,
    ) -> MerkleProof<P::Fr, { H }> {
        let mut sibling: SizedVec<_, { H }> = (0..H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { H }> = (0..H).map(|_| false).collect();

        let start_height = constants::HEIGHT - H;

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_right))| {
                let cur_height = (start_height + h) as u32;
                *is_right = x % 2 == 1;
                *sibling =
                    self.get_virtual_node_full(cur_height, x ^ 1, virtual_nodes, update_boundaries);

                x / 2
            },
        );

        MerkleProof { sibling, path }
    }

    pub fn get_virtual_node(
        &self,
        height: u32,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        new_hashes_left_index: u64,
        new_hashes_right_index: u64,
    ) -> Hash<P::Fr> {
        let update_boundaries = UpdateBoundaries {
            updated_range_left_index: new_hashes_left_index,
            updated_range_right_index: new_hashes_right_index,
            new_hashes_left_index,
            new_hashes_right_index,
        };

        self.get_virtual_node_full(height, index, virtual_nodes, &update_boundaries)
    }

    fn get_virtual_node_full(
        &self,
        height: u32,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        update_boundaries: &UpdateBoundaries,
    ) -> Hash<P::Fr> {
        let node_left = index * (1 << height);
        let node_right = (index + 1) * (1 << height);
        if node_right <= update_boundaries.updated_range_left_index
            || update_boundaries.updated_range_right_index <= node_left
        {
            return self.get(height, index);
        }
        if (node_right <= update_boundaries.new_hashes_left_index
            || update_boundaries.new_hashes_right_index <= node_left)
            && update_boundaries.updated_range_left_index <= node_left
            && node_right <= update_boundaries.updated_range_right_index
        {
            return self.zero_note_hashes[height as usize];
        }

        let key = (height, index);
        match virtual_nodes.get(&key) {
            Some(hash) => *hash,
            None => {
                let left_child = self.get_virtual_node_full(
                    height - 1,
                    2 * index,
                    virtual_nodes,
                    update_boundaries,
                );
                let right_child = self.get_virtual_node_full(
                    height - 1,
                    2 * index + 1,
                    virtual_nodes,
                    update_boundaries,
                );
                let pair = [left_child, right_child];
                let hash = poseidon(pair.as_ref(), self.params.compress());
                virtual_nodes.insert(key, hash);

                hash
            }
        }
    }

    pub fn clean(&mut self) -> u64 {
        self.clean_before_index(u64::MAX)
    }

    pub fn clean_before_index(&mut self, clean_before_index: u64) -> u64 {
        let mut batch = self.db.transaction();

        // get all nodes
        // todo: improve performance?
        let keys: Vec<(u32, u64)> = self
            .db
            .iter(0)
            .map(|k_v| Self::parse_node_key(&k_v.unwrap().0))
            .collect();
        // remove unnecessary nodes
        for (height, index) in keys {
            // leaves have no children
            if height == 0 {
                continue;
            }

            // remove only nodes before specified index
            if (index + 1) * (1 << height) > clean_before_index {
                continue;
            }

            if self.subtree_contains_only_temporary_leaves(height, index) {
                // all leaves in subtree are temporary, we can keep only subtree root
                self.remove_batched(&mut batch, height - 1, 2 * index);
                self.remove_batched(&mut batch, height - 1, 2 * index + 1);
            }
        }

        self.set_clean_index_batched(&mut batch, clean_before_index);

        self.db.write(batch).unwrap();

        self.next_index
    }

    // Returns tree root after rollback (None if lack of nodes)
    // CAUTION: if this method returns None the Merkle tree is likely corrupted!
    //          You strongly need to rebuild or restore it in a some way
    pub fn rollback(&mut self, rollback_index: u64) -> Option<Hash<P::Fr>> {
        let rollback_index = if Some(rollback_index) <= self.first_index() {
            0   // supporting rollback for the partial tree
                // (if we rollback to the left of first_index - clear all tree)
        } else {
            rollback_index
        };

        // check that nodes that are necessary for rollback were not removed by clean
        let clean_index = self.get_clean_index();
        if rollback_index < clean_index {
            // find what nodes are missing
            let mut nodes_request_index = self.next_index;
            let mut index = rollback_index;
            for height in 0..constants::HEIGHT as u32 {
                let sibling_index = index ^ 1;
                if sibling_index < index
                    && !self.subtree_contains_only_temporary_leaves(height, sibling_index)
                {
                    let leaf_index = index * (1 << height);
                    if leaf_index < nodes_request_index {
                        nodes_request_index = leaf_index
                    }
                }
                index /= 2;
            }
            if nodes_request_index < clean_index {
                return None;
            }
        }
        


        // Update next_index.
        let new_next_index = if rollback_index > 0 {
            Self::calc_next_index(rollback_index - 1)
        } else {
            0
        };
        self.write_index_to_database(NEXT_INDEX_KEY, Some(new_next_index));
        self.next_index = new_next_index;
        
        // Updating first index
        if rollback_index == 0 {
            self.write_index_to_database(FIRST_INDEX_KEY, None);
            self.first_index = None;
        }

        // remove unnecessary nodes
        let mut remove_batch = self.db.transaction();
        self.db
            .iter(DbCols::Leaves as u32)
            .for_each(|k_v| {
                let data = k_v.unwrap();
                let (height, index) = Self::parse_node_key(&data.0);
                //let left_index = index << height;
                let right_index = (index + 1) << height;
                if right_index > rollback_index {
                    remove_batch.delete(DbCols::Leaves as u32, &data.0);
                    remove_batch.delete(DbCols::TempLeaves as u32, &data.0);
                    //self.remove_batched(&mut remove_batch, height, index);
                }
            });
        self.db.write(remove_batch).unwrap();

        // build the root node and restore intermediate ones
        let mut update_batch = self.db.transaction();        
        let new_root = self.get_node_full_batched(constants::HEIGHT as u32, 0, &mut update_batch, new_next_index);
        self.db.write(update_batch).unwrap();

        if self.next_index() < self.get_last_stable_index() {
            self.set_last_stable_index(None);
        }

        new_root
    }

    // The rollback helper: build node (e.g. root) within 
    // nodes before right_index (at level 0)
    // It's supposed that the current tree has no nodes
    // which subtree placed to the right of right_index
    // Returns None in case of lack of nodes
    // NOTE: as get_virtual_node_full routine, but not virtual one :)
    //       it operates only with the currently filled nodes and update
    //       the transaction batch to update the database
    fn get_node_full_batched(
        &mut self,
        height: u32,
        index: u64,
        batch: &mut DBTransaction,
        right_index: u64,
    ) -> Option<Hash<P::Fr>> {
        let node_left = index * (1 << height);
        //let node_right = (index + 1) * (1 << height);
        if node_left >= right_index {
            //print!("💬[{}.{}]  ", height, index);
            return Some(self.default_hashes[height as usize]);
        }

        match self.get_opt(height, index) {
            Some(hash) => {
                //print!("✅[{}.{}]  ", height, index);
                Some(hash)
            },
            None => {
                if height > 0 {
                    let left_child = self.get_node_full_batched(
                        height - 1,
                        2 * index,
                        batch,
                        right_index,
                    );
                    let right_child = self.get_node_full_batched(
                        height - 1,
                        2 * index + 1,
                        batch,
                        right_index,
                    );

                    if let (Some(left_child), Some(right_child)) = 
                        (left_child, right_child)
                    {
                        let pair = [left_child, right_child];
                        let hash = poseidon(pair.as_ref(), self.params.compress());

                        //print!("🧮[{}.{}]={}.{}+{}.{}  ", height, index, height - 1, index << 1, height - 1, (index << 1) + 1);
                        
                        self.set_batched(batch, height, index, hash, 0);

                        Some(hash)
                    } else {
                        //print!("❌[{}.{}]  ", height, index);
                        None
                    }
                } else {
                    //print!("❌[{}.{}]  ", height, index);
                    None
                }
            }
        }
    }

    pub fn wipe(&mut self) {
        let mut wipe_batch = self.db.transaction();   
        
        // ???: It works fine in the local tests,
        // but has no effect within kvdb-web for unknown reason
        //wipe_batch.delete_prefix(DbCols::Leaves as u32, &[][..]);
        //wipe_batch.delete_prefix(DbCols::TempLeaves as u32, &[][..]);

        self.db
            .iter(DbCols::Leaves as u32)
            .for_each(|k_v| {
                wipe_batch.delete(DbCols::Leaves as u32, &k_v.unwrap().0); 
            });

        self.db
            .iter(DbCols::TempLeaves as u32)
            .for_each(|k_v| {
                wipe_batch.delete(DbCols::TempLeaves as u32, &k_v.unwrap().0); 
            });


        self.db.write(wipe_batch).unwrap();

        self.first_index = None;
        self.next_index = 0;
        self.write_index_to_database(FIRST_INDEX_KEY, None);
        self.write_index_to_database(NEXT_INDEX_KEY, Some(self.next_index));
        self.set_last_stable_index(None);
    }

    pub fn get_all_nodes(&self) -> Vec<Node<P::Fr>> {
        self.db
            .iter(0)
            .map(|k_v| {
                let data = k_v.unwrap();
                Self::build_node(&data.0, &data.1)
            })
            .collect()
    }

    pub fn get_leaves(&self) -> Vec<Node<P::Fr>> {
        self.get_leaves_after(0)
    }

    pub fn get_leaves_after(&self, index: u64) -> Vec<Node<P::Fr>> {
        let prefix = (0u32).to_be_bytes();
        self.db
            .iter_with_prefix(0, &prefix)
            .map(|k_v| {
                let data = k_v.unwrap();
                Self::build_node(&data.0, &data.1)
            })
            .filter(|node| node.index >= index)
            .collect()
    }

    pub fn first_index(&self) -> Option<u64> {
        self.first_index
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn get_last_stable_index(&self) -> u64 {
        match self.get_named_index_opt("stable_index") {
            Some(val) => val,
            _ => 0,
        }
    }

    pub fn set_last_stable_index(&mut self, value: Option<u64>) {
        self.set_named_index("stable_index", value);
    }

    fn update_first_index(&mut self, first_index: Option<u64>) -> bool {
        if first_index != self.first_index {
            if first_index.is_some() &&
                self.first_index.is_some() &&
                first_index >= self.first_index
            {
                return false;
            }

            self.write_index_to_database(FIRST_INDEX_KEY, first_index);
            self.first_index = first_index;

            true
        } else {
            false
        }
    }

    fn update_next_index(&mut self,  next_index: u64) -> bool {
        if next_index >= self.next_index {
            self.write_index_to_database(NEXT_INDEX_KEY, Some(next_index));
            self.next_index = next_index;
            
            true
        } else {
            false
        }
    }

    // remove value by specified key in case of index is None
    fn write_index_to_database(&mut self, index_db_key: &[u8], index: Option<u64>) {
        let mut transaction = self.db.transaction();
        if let Some(index) = index {
            let mut data = [0u8; 8];
            {
                let mut bytes = &mut data[..];
                let _ = bytes.write_u64::<BigEndian>(index);
            }
            transaction.put(DbCols::NextIndex as u32, index_db_key, &data);
        } else {
            transaction.delete(DbCols::NextIndex as u32, index_db_key);
        }
        self.db.write(transaction).unwrap();
    }

    fn update_first_index_from_node(&mut self, height: u32, index: u64) -> bool {
        let leaf_index = u64::pow(2, height) * index;
        self.update_first_index(Some(Self::calc_first_index(leaf_index)))
    }

    fn update_next_index_from_node(&mut self, height: u32, index: u64) -> bool {
        let leaf_index = u64::pow(2, height) * (index + 1) - 1;
        self.update_next_index(Self::calc_next_index(leaf_index))
    }

    #[inline]
    fn calc_first_index(leaf_index: u64) -> u64 {
        (leaf_index >> constants::OUTPLUSONELOG) << constants::OUTPLUSONELOG
    }

    #[inline]
    fn calc_next_index(leaf_index: u64) -> u64 {
        ((leaf_index >> constants::OUTPLUSONELOG) + 1) << constants::OUTPLUSONELOG
    }

    fn update_path_batched(
        &mut self,
        batch: &mut DBTransaction,
        height: u32,
        index: u64,
        hash: Hash<P::Fr>,
        temporary_leaves_count: u64,
    ) {
        let mut child_index = index;
        let mut child_hash = hash;
        let mut child_temporary_leaves_count = temporary_leaves_count;
        // todo: improve
        for current_height in height + 1..=constants::HEIGHT as u32 {
            let parent_index = child_index / 2;

            // get pair of children
            let second_child_index = child_index ^ 1;

            // compute hash
            let pair = if child_index % 2 == 0 {
                [child_hash, self.get(current_height - 1, second_child_index)]
            } else {
                [self.get(current_height - 1, second_child_index), child_hash]
            };
            let hash = poseidon(pair.as_ref(), self.params.compress());

            // compute temporary leaves count
            let second_child_temporary_leaves_count =
                self.get_temporary_count(current_height - 1, second_child_index);
            let parent_temporary_leaves_count =
                child_temporary_leaves_count + second_child_temporary_leaves_count;

            self.set_batched(
                batch,
                current_height,
                parent_index,
                hash,
                parent_temporary_leaves_count,
            );

            /*if parent_temporary_leaves_count == (1 << current_height) {
                // all leaves in subtree are temporary, we can keep only subtree root
                self.remove_batched(batch, current_height - 1, child_index);
                self.remove_batched(batch, current_height - 1, second_child_index);
            }*/

            child_index = parent_index;
            child_hash = hash;
            child_temporary_leaves_count = parent_temporary_leaves_count;
        }
    }

    fn set_batched(
        &mut self,
        batch: &mut DBTransaction,
        height: u32,
        index: u64,
        hash: Hash<P::Fr>,
        temporary_leaves_count: u64,
    ) {
        let key = Self::node_key(height, index);
        if hash != self.zero_note_hashes[height as usize] {
            batch.put(DbCols::Leaves as u32, &key, &hash.try_to_vec().unwrap());
        } else {
            batch.delete(DbCols::Leaves as u32, &key);
        }
        if temporary_leaves_count > 0 {
            batch.put(DbCols::TempLeaves as u32, &key, &temporary_leaves_count.to_be_bytes());
        } else if self.db.has_key(DbCols::TempLeaves as u32, &key).unwrap_or(false) {
            batch.delete(DbCols::TempLeaves as u32, &key);
        }
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: u32, index: u64) {
        let key = Self::node_key(height, index);
        batch.delete(DbCols::Leaves as u32, &key);
        batch.delete(DbCols::TempLeaves as u32, &key);
    }

    #[cfg(test)]
    fn remove_leaf(&mut self, index: u64) {
        let mut batch = self.db.transaction();

        self.remove_batched(&mut batch, 0, index);
        self.update_path_batched(&mut batch, 0, index, self.default_hashes[0], 0);

        self.db.write(batch).unwrap();
    }

    fn get_clean_index(&self) -> u64 {
        match self.get_named_index_opt("clean_index") {
            Some(val) => val,
            _ => 0,
        }
    }

    fn set_clean_index_batched(&mut self, batch: &mut DBTransaction, value: u64) {
        self.set_named_index_batched(batch, "clean_index", value);
    }

    fn get_named_index_opt(&self, key: &str) -> Option<u64> {
        let res = self.db.get(2, key.as_bytes());
        match res {
            Ok(Some(ref val)) => Some((&val[..]).read_u64::<BigEndian>().unwrap()),
            _ => None,
        }
    }

    fn set_named_index(&mut self, key: &str, value: Option<u64>) {
        let mut batch = self.db.transaction();
        match value {
            Some(val) => batch.put(DbCols::NamedIndex as u32, key.as_bytes(), &val.to_be_bytes()),
            None => batch.delete(DbCols::NamedIndex as u32, key.as_bytes())
        }
        self.db.write(batch).unwrap();
    }

    fn set_named_index_batched(&mut self, batch: &mut DBTransaction, key: &str, value: u64) {
        batch.put(DbCols::NamedIndex as u32, key.as_bytes(), &value.to_be_bytes());
    }

    fn get_temporary_count(&self, height: u32, index: u64) -> u64 {
        match self.get_temporary_count_opt(height, index) {
            Some(val) => val,
            _ => 0,
        }
    }

    fn get_temporary_count_opt(&self, height: u32, index: u64) -> Option<u64> {
        assert!(height <= constants::HEIGHT as u32);

        let key = Self::node_key(height, index);
        let res = self.db.get(1, &key);

        match res {
            Ok(Some(ref val)) => Some((&val[..]).read_u64::<BigEndian>().unwrap()),
            _ => None,
        }
    }

    fn subtree_contains_only_temporary_leaves(&self, height: u32, index: u64) -> bool {
        self.get_temporary_count(height, index) == (1 << height)
    }

    #[inline]
    fn node_key(height: u32, index: u64) -> [u8; 12] {
        let mut data = [0u8; 12];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u32::<BigEndian>(height);
            let _ = bytes.write_u64::<BigEndian>(index);
        }

        data
    }

    fn parse_node_key(data: &[u8]) -> (u32, u64) {
        let mut bytes = data;
        let height = bytes.read_u32::<BigEndian>().unwrap();
        let index = bytes.read_u64::<BigEndian>().unwrap();

        (height, index)
    }

    fn build_node(key: &[u8], value: &[u8]) -> Node<P::Fr> {
        let (height, index) = Self::parse_node_key(key);
        let value = Hash::try_from_slice(value).unwrap();

        Node {
            index,
            height,
            value,
        }
    }

    fn gen_default_hashes(params: &P) -> Vec<Hash<P::Fr>> {
        let mut default_hashes = vec![Num::ZERO; constants::HEIGHT + 1];

        Self::fill_default_hashes(&mut default_hashes, params);

        default_hashes
    }

    fn gen_empty_note_hashes(params: &P) -> Vec<Hash<P::Fr>> {
        let empty_note_hash = zero_note().hash(params);

        let mut empty_note_hashes = vec![empty_note_hash; constants::HEIGHT + 1];

        Self::fill_default_hashes(&mut empty_note_hashes, params);

        empty_note_hashes
    }

    fn fill_default_hashes(default_hashes: &mut Vec<Hash<P::Fr>>, params: &P) {
        for i in 1..default_hashes.len() {
            let t = default_hashes[i - 1];
            default_hashes[i] = poseidon([t, t].as_ref(), params.compress());
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Node<F: PrimeField> {
    pub index: u64,
    pub height: u32,
    #[serde(bound(serialize = "", deserialize = ""))]
    pub value: Num<F>,
}

pub struct UpdateBoundaries {
    updated_range_left_index: u64,
    updated_range_right_index: u64,
    new_hashes_left_index: u64,
    new_hashes_right_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::CustomRng;
    use kvdb_memorydb::create;
    use libzeropool::fawkes_crypto::ff_uint::rand::Rng;
    use libzeropool::POOL_PARAMS;
    use libzeropool::native::tx;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use test_case::test_case;

    #[test]
    fn test_add_hashes_first_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let hashes: Vec<_> = (0..3).map(|_| rng.gen()).collect();
        tree.add_hashes(0, hashes.clone());

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 4);

        for h in 0..constants::HEIGHT as u32 {
            assert!(tree.get_opt(h, 0).is_some()); // TODO: Compare with expected hash
        }

        for (i, hash) in hashes.into_iter().enumerate() {
            assert_eq!(tree.get(0, i as u64), hash);
        }
    }

    #[test]
    fn test_add_hashes_last_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let max_index = (1 << constants::HEIGHT) - 1;
        let hashes: Vec<_> = (0..3).map(|_| rng.gen()).collect();
        tree.add_hashes(max_index - 127, hashes.clone());

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 4);

        for h in constants::OUTPLUSONELOG as u32 + 1..constants::HEIGHT as u32 {
            let index = max_index / 2u64.pow(h);
            assert!(tree.get_opt(h, index).is_some()); // TODO: Compare with expected hash
        }

        for (i, hash) in hashes.into_iter().enumerate() {
            assert_eq!(tree.get(0, max_index - 127 + i as u64), hash);
        }
    }

    #[test]
    fn test_add_hashes() {
        let mut tree_expected = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut tree_actual = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // add first subtree
        add_hashes_to_test_trees(&mut tree_expected, &mut tree_actual, 0, 3);
        check_trees_are_equal(&tree_expected, &tree_actual);

        // add second subtree
        add_hashes_to_test_trees(&mut tree_expected, &mut tree_actual, 128, 8);
        check_trees_are_equal(&tree_expected, &tree_actual);

        // add third subtree
        add_hashes_to_test_trees(&mut tree_expected, &mut tree_actual, 256, 1);
        check_trees_are_equal(&tree_expected, &tree_actual);
    }

    #[test]
    fn test_add_hashes_with_gap() {
        let mut tree_expected = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut tree_actual = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // add first subtree
        add_hashes_to_test_trees(&mut tree_expected, &mut tree_actual, 0, 3);
        check_trees_are_equal(&tree_expected, &tree_actual);

        tree_expected.add_hash_at_height(
            constants::OUTPLUSONELOG as u32,
            1,
            tree_expected.zero_note_hashes[constants::OUTPLUSONELOG],
            false,
        );

        // add third subtree, second subtree contains zero node hashes
        add_hashes_to_test_trees(&mut tree_expected, &mut tree_actual, 256, 7);
        check_trees_are_equal(&tree_expected, &tree_actual);
    }

    fn add_hashes_to_test_trees<D: KeyValueDB, P: PoolParams>(
        tree_expected: &mut MerkleTree<D, P>,
        tree_actual: &mut MerkleTree<D, P>,
        start_index: u64,
        count: u64,
    ) {
        let mut rng = CustomRng;

        let hashes: Vec<_> = (0..count).map(|_| rng.gen()).collect();

        for (i, hash) in hashes.clone().into_iter().enumerate() {
            tree_expected.add_hash(start_index + i as u64, hash, false);
        }
        tree_actual.add_hashes(start_index, hashes);
    }

    fn check_trees_are_equal<D: KeyValueDB, P: PoolParams>(
        tree_first: &MerkleTree<D, P>,
        tree_second: &MerkleTree<D, P>,
    ) {
        assert_eq!(tree_first.next_index, tree_second.next_index);
        assert_eq!(tree_first.get_root(), tree_second.get_root());

        let mut first_nodes = tree_first.get_all_nodes();
        let mut second_nodes = tree_second.get_all_nodes();
        assert_eq!(first_nodes.len(), second_nodes.len());

        first_nodes.sort_by_key(|node| (node.height, node.index));
        second_nodes.sort_by_key(|node| (node.height, node.index));

        assert_eq!(first_nodes, second_nodes);
    }

    // #[test]
    // fn test_unnecessary_temporary_nodes_are_removed() {
    //     let mut rng = CustomRng;
    //     let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
    //
    //     let mut hashes: Vec<_> = (0..6).map(|_| rng.gen()).collect();
    //
    //     // make some hashes temporary
    //     // these two must remain after cleanup
    //     hashes[1].2 = true;
    //     hashes[3].2 = true;
    //
    //     // these two must be removed
    //     hashes[4].2 = true;
    //     hashes[5].2 = true;
    //
    //     tree.add_hashes(0, hashes);
    //
    //     let next_index = tree.clean();
    //     assert_eq!(next_index, tree.next_index);
    //
    //     let nodes = tree.get_all_nodes();
    //     assert_eq!(nodes.len(), constants::HEIGHT + 7);
    //     assert_eq!(tree.get_opt(0, 4), None);
    //     assert_eq!(tree.get_opt(0, 5), None);
    // }

    #[test]
    fn test_get_leaf_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let proof = tree.get_leaf_proof(123);

        assert!(proof.is_none());

        tree.add_hash(123, rng.gen(), false);
        let proof = tree.get_leaf_proof(123).unwrap();

        assert_eq!(proof.sibling.as_slice().len(), constants::HEIGHT);
        assert_eq!(proof.path.as_slice().len(), constants::HEIGHT);
    }

    #[test]
    fn test_get_proof_unchecked() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // Get proof for the right child of the root of the tree
        const SUBROOT_HEIGHT: usize = 1;
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_eq!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.default_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );

        assert_eq!(proof.sibling.as_slice().len(), SUBROOT_HEIGHT);
        assert_eq!(proof.path.as_slice().len(), SUBROOT_HEIGHT);

        // If we add leaf to the right branch,
        // then left child of the root should not be affected directly
        tree.add_hash(1 << 47, rng.gen(), false);
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_eq!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.zero_note_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );

        // But if we add leaf to the left branch, then left child of the root should change
        tree.add_hash((1 << 47) - 1, rng.gen(), false);
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_ne!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.zero_note_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );
    }

    #[test]
    fn test_temporary_nodes_are_used_to_calculate_hashes_first() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let hash0: Hash<_> = rng.gen();
        let hash1: Hash<_> = rng.gen();

        // add hash for index 0
        tree.add_hash(0, hash0, true);

        // add hash for index 1
        tree.add_hash(1, hash1, false);

        let parent_hash = tree.get(1, 0);
        let expected_parent_hash = poseidon([hash0, hash1].as_ref(), POOL_PARAMS.compress());

        assert_eq!(parent_hash, expected_parent_hash);
    }

    #[test_case(0, 5)]
    #[test_case(1, 5)]
    #[test_case(2, 5)]
    #[test_case(4, 5)]
    #[test_case(5, 5)]
    #[test_case(5, 8)]
    #[test_case(10, 15)]
    #[test_case(12, 15)]
    fn test_all_temporary_nodes_in_subtree_are_removed(subtree_height: u32, full_height: usize) {
        let mut rng = CustomRng;

        let subtree_size = 1 << subtree_height;
        let subtrees_count = (1 << full_height) / subtree_size;
        let start_index = 1 << 12;
        let mut subtree_indexes: Vec<_> = (0..subtrees_count).map(|i| start_index + i).collect();
        subtree_indexes.shuffle(&mut thread_rng());

        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        for subtree_index in subtree_indexes {
            tree.add_subtree_root(subtree_height, subtree_index, rng.gen());
        }

        tree.clean();

        let tree_nodes = tree.get_all_nodes();
        assert_eq!(
            tree_nodes.len(),
            constants::HEIGHT - full_height + 1,
            "Some temporary subtree nodes were not removed."
        );
    }

    #[test]
    fn test_rollback_all_works_correctly() {
        let tree_size: u64 = 256;
        let remove_size: u64 = 128;
        let first_part: u64 = tree_size - remove_size;

        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let original_root = tree.get_root();

        for index in 0..first_part {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let one_more_root = tree.get_root();

        for index in first_part..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        // 1st rollback
        let rollback1_result = tree.rollback(first_part);
        assert!(rollback1_result.is_some());
        let rollback1_root = tree.get_root();
        assert_eq!(rollback1_root, one_more_root);
        assert_eq!(rollback1_root, rollback1_result.unwrap());
        assert_eq!(tree.next_index, first_part);

        // 2nd rollback
        let rollback2_result = tree.rollback(0);
        assert!(rollback2_result.is_some());
        let rollback2_root = tree.get_root();
        assert_eq!(rollback2_root, original_root);
        assert_eq!(rollback2_root, rollback2_result.unwrap());
        assert_eq!(tree.next_index, 0);
    }

    #[test_case(32, 16)]
    #[test_case(16, 0)]
    #[test_case(11, 7)]
    fn test_rollback_removes_nodes_correctly(keep_size: u64, remove_size: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..keep_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }
        let original_root = tree.get_root();

        for index in 0..remove_size {
            let leaf = rng.gen();
            tree.add_hash(128 + index, leaf, false);
        }

        let rollback_result = tree.rollback(128);
        assert!(rollback_result.is_some());
        let rollback_root = tree.get_root();
        assert_eq!(rollback_root, original_root);
        assert_eq!(rollback_root, rollback_result.unwrap());
        assert_eq!(tree.next_index, 128);
    }

    // #[test]
    // fn test_rollback_works_correctly_after_clean() {
    //     let mut rng = CustomRng;
    //     let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
    //
    //     for index in 0..4 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //     for index in 4..6 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, false);
    //     }
    //     for index in 6..12 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //     let original_root = tree.get_root();
    //     for index in 12..16 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //
    //     tree.clean_before_index(10);
    //
    //     let rollback_result = tree.rollback(12);
    //     assert!(rollback_result.is_none());
    //     let rollback_root = tree.get_root();
    //     assert_eq!(rollback_root, original_root);
    //     assert_eq!(tree.next_index, 12)
    // }
    //
    // #[test]
    // fn test_rollback_of_cleaned_nodes() {
    //     let mut rng = CustomRng;
    //     let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
    //
    //     for index in 0..4 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //     for index in 4..6 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, false);
    //     }
    //     for index in 6..7 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //     let original_root = tree.get_root();
    //     for index in 7..16 {
    //         let leaf = rng.gen();
    //         tree.add_hash(index, leaf, true);
    //     }
    //
    //     tree.clean_before_index(10);
    //
    //     let rollback_result = tree.rollback(7);
    //     assert_eq!(rollback_result.unwrap(), 6);
    //     let rollback_root = tree.get_root();
    //     assert_ne!(rollback_root, original_root);
    //     assert_eq!(tree.next_index, 7)
    // }

    #[test]
    fn test_get_leaves() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leaves_count = 6;

        for index in 0..leaves_count {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        let leaves = tree.get_leaves();

        assert_eq!(leaves.len(), leaves_count as usize);
        for index in 0..leaves_count {
            assert!(leaves.iter().any(|node| node.index == index));
        }
    }

    #[test]
    fn test_get_leaves_after() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leaves_count = 6;
        let skip_count = 2;

        for index in 0..leaves_count {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        let leaves = tree.get_leaves_after(skip_count);

        assert_eq!(leaves.len(), (leaves_count - skip_count) as usize);
        for index in skip_count..leaves_count {
            assert!(leaves.iter().any(|node| node.index == index));
        }
    }

    #[test]
    fn test_get_proof_after() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let tree_size = 6;
        let new_hashes_size = 3;

        for index in 0..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let root_before_call = tree.get_root();

        let new_hashes: Vec<_> = (0..new_hashes_size).map(|_| rng.gen()).collect();
        tree.get_proof_after(new_hashes);

        let root_after_call = tree.get_root();

        assert_eq!(root_before_call, root_after_call);
    }

    #[test_case(12, 4)]
    #[test_case(13, 5)]
    #[test_case(0, 1)]
    #[test_case(0, 5)]
    #[test_case(0, 8)]
    #[test_case(4, 16)]
    fn test_get_proof_after_virtual(tree_size: u64, new_hashes_size: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let new_hashes: Vec<_> = (0..new_hashes_size).map(|_| rng.gen()).collect();

        let root_before_call = tree.get_root();

        let proofs_virtual = tree.get_proof_after_virtual(new_hashes.clone());
        let proofs_simple = tree.get_proof_after(new_hashes);

        let root_after_call = tree.get_root();

        assert_eq!(root_before_call, root_after_call);
        assert_eq!(proofs_simple.len(), proofs_virtual.len());
        for (simple_proof, virtual_proof) in proofs_simple.iter().zip(proofs_virtual) {
            for (simple_sibling, virtual_sibling) in simple_proof
                .sibling
                .iter()
                .zip(virtual_proof.sibling.iter())
            {
                assert_eq!(simple_sibling, virtual_sibling);
            }
            for (simple_path, virtual_path) in
                simple_proof.path.iter().zip(virtual_proof.path.iter())
            {
                assert_eq!(simple_path, virtual_path);
            }
        }
    }

    #[test]
    fn test_default_hashes_are_added_correctly() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // Empty tree contains default hashes.
        assert_eq!(tree.get(0, 0), tree.default_hashes[0]);
        assert_eq!(tree.get(0, 3), tree.default_hashes[0]);
        assert_eq!(tree.get(2, 0), tree.default_hashes[2]);

        let hashes: Vec<_> = (0..3).map(|_| rng.gen()).collect();
        tree.add_hashes(0, hashes);

        // Hashes were added.
        assert_ne!(tree.get(2, 0), tree.zero_note_hashes[2]);
        assert_ne!(tree.get(2, 0), tree.default_hashes[2]);
        // First subtree contains zero note hashes instead of default hashes.
        assert_eq!(tree.get(0, 4), tree.zero_note_hashes[0]);
        assert_eq!(tree.get(0, 127), tree.zero_note_hashes[0]);
        assert_eq!(tree.get(2, 1), tree.zero_note_hashes[2]);
        // Second subtree still contains default hashes.
        assert_eq!(tree.get(0, 128), tree.default_hashes[0]);
        assert_eq!(tree.get(7, 1), tree.default_hashes[7]);

        let hashes: Vec<_> = (0..2).map(|_| rng.gen()).collect();
        tree.add_hashes(128, hashes);
        // Second subtree contains zero note hashes instead of default hashes.
        assert_eq!(tree.get(0, 128 + 4), tree.zero_note_hashes[0]);
        assert_eq!(tree.get(0, 128 + 127), tree.zero_note_hashes[0]);
        assert_eq!(tree.get(2, 32 + 1), tree.zero_note_hashes[2]);
        // Third subtree still contains default hashes.
        assert_eq!(tree.get(0, 128 + 128), tree.default_hashes[0]);
        assert_eq!(tree.get(7, 2), tree.default_hashes[7]);
    }

    #[test_case(0, 0, 0.0)]
    #[test_case(1, 1, 0.0)]
    #[test_case(1, 1, 1.0)]
    #[test_case(4, 2, 0.0)]
    #[test_case(4, 2, 0.5)]
    #[test_case(4, 2, 1.0)]
    #[test_case(15, 7, 0.0)]
    #[test_case(15, 7, 0.5)]
    #[test_case(15, 7, 1.0)]
    #[test_case(15, 100, 0.0)]
    #[test_case(15, 128, 0.0)]
    fn test_add_leafs_and_commitments(tx_count: u64, max_leafs_count: u32, commitments_probability: f64) {
        let mut rng = CustomRng;
        let mut first_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut second_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                let leafs_count: u32 =  1 + (rng.gen::<u32>() % max_leafs_count);
                (i * (constants::OUT + 1) as u64, (0..leafs_count).map(|_| rng.gen()).collect())
            })
            .collect();

        let now = std::time::Instant::now();
        for (index, leafs) in leafs.clone().into_iter() {
            first_tree.add_hashes(index, leafs)
        }
        println!("({}, {}, {}) add_hashes elapsed: {}", tx_count, max_leafs_count, commitments_probability, now.elapsed().as_millis());
        
        let commitments: Vec<(u64, _)> = leafs.clone().into_iter().map(|(index, leafs)| {
            let mut out_hashes = leafs.clone();
            out_hashes.resize(constants::OUT+1, first_tree.zero_note_hashes[0]);
            let commitment = tx::out_commitment_hash(out_hashes.as_slice(), &POOL_PARAMS.clone());
            (index, commitment)
        }).collect();

        commitments.iter().for_each(|(index, commitment)| {
            assert_eq!(first_tree.get(constants::OUTPLUSONELOG as u32, *index >> constants::OUTPLUSONELOG), *commitment);
        });
        
        let mut sub_leafs: Vec<(u64, Vec<_>)> = Vec::new();
        let mut sub_commitments: Vec<(u64, _)> = Vec::new();
        (0..tx_count).for_each(|i| {
            if rng.gen_bool(commitments_probability) {
                sub_commitments.push(commitments[i as usize]);
            } else {
                sub_leafs.push((leafs[i as usize].0, leafs[i as usize].1.clone()));
            }
        });
        
        let now = std::time::Instant::now();
        second_tree.add_leafs_and_commitments(sub_leafs, sub_commitments);
        println!("({}, {}, {}) add_leafs_and_commitments elapsed: {}", tx_count, max_leafs_count, commitments_probability, now.elapsed().as_millis());

        assert_eq!(first_tree.get_root().to_string(), second_tree.get_root().to_string());
        assert_eq!(first_tree.next_index(), second_tree.next_index());
    }

    #[test_case(2, 1)]
    #[test_case(2, 2)]
    #[test_case(2, 64)]
    #[test_case(2, 65)]
    #[test_case(2, 100)]
    #[test_case(2, 127)]
    #[test_case(2, 128)] 
    fn test_add_leafs_and_commitments_multinotes(tx_count: u64, leafs_count: u32) {
        let mut rng = CustomRng;
        let mut first_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut second_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                (i * (constants::OUT + 1) as u64, (0..leafs_count).map(|_| rng.gen()).collect())
            })
            .collect();

        for (index, leafs) in leafs.clone().into_iter() {
            first_tree.add_hashes(index, leafs)
        }
        
        let commitments: Vec<(u64, _)> = leafs.clone().into_iter().map(|(index, leafs)| {
            let mut out_hashes = leafs.clone();
            out_hashes.resize(constants::OUT+1, first_tree.zero_note_hashes[0]);
            let commitment = tx::out_commitment_hash(out_hashes.as_slice(), &POOL_PARAMS.clone());
            (index, commitment)
        }).collect();

        commitments.iter().for_each(|(index, commitment)| {
            assert_eq!(first_tree.get(constants::OUTPLUSONELOG as u32, *index >> constants::OUTPLUSONELOG), *commitment);
        });
        
        let mut sub_leafs: Vec<(u64, Vec<_>)> = Vec::new();
        let sub_commitments: Vec<(u64, _)> = Vec::new();
        (0..leafs.len()).for_each(|i| {
            /*if rng.gen_bool(commitments_probability) {
                sub_commitments.push(commitments[i as usize]);
            } else {
                sub_leafs.push((leafs[i as usize].0, leafs[i as usize].1.clone()));
            }*/
            sub_leafs.push((leafs[i as usize].0, leafs[i as usize].1.clone()));
        });
        
        second_tree.add_leafs_and_commitments(sub_leafs, sub_commitments);

        assert_eq!(first_tree.get_root().to_string(), second_tree.get_root().to_string());
        assert_eq!(first_tree.next_index(), second_tree.next_index());
    }


    #[test_case(0, 0, 0.0)]
    #[test_case(1, 1, 0.0)]
    #[test_case(1, 1, 1.0)]
    #[test_case(4, 2, 0.0)]
    #[test_case(4, 2, 0.5)]
    #[test_case(4, 2, 1.0)]
    #[test_case(15, 7, 0.0)]
    #[test_case(15, 7, 0.5)]
    #[test_case(15, 7, 1.0)]
    #[test_case(15, 128, 0.0)]
    fn test_get_root_optimistic(tx_count: u64, max_leafs_count: u32, commitments_probability: f64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                let leafs_count: u32 =  1 + (rng.gen::<u32>() % max_leafs_count);
                (i * (constants::OUT + 1) as u64, (0..leafs_count).map(|_| rng.gen()).collect())
            })
            .collect();
        
        let commitments: Vec<(u64, _)> = leafs.clone().into_iter().map(|(index, leafs)| {
            let mut out_hashes = leafs.clone();
            out_hashes.resize(constants::OUT+1, tree.zero_note_hashes[0]);
            let commitment = tx::out_commitment_hash(out_hashes.as_slice(), &POOL_PARAMS.clone());
            (index, commitment)
        }).collect();
        
        let mut sub_leafs: Vec<(u64, Vec<_>)> = Vec::new();
        let mut sub_commitments: Vec<(u64, _)> = Vec::new();
        (0..tx_count).for_each(|i| {
            if rng.gen_bool(commitments_probability) {
                sub_commitments.push(commitments[i as usize]);
            } else {
                sub_leafs.push((leafs[i as usize].0, leafs[i as usize].1.clone()));
            }
        });

        let (mut virtual_nodes, update_boundaries) = tree.get_virtual_subtree(sub_leafs.clone(), sub_commitments.clone());
        let optimistic_root = tree.get_root_optimistic(&mut virtual_nodes, &update_boundaries);

        tree.add_leafs_and_commitments(sub_leafs, sub_commitments);
        let root = tree.get_root();

        assert_eq!(optimistic_root.to_string(), root.to_string());
    }


    #[test_case(10, 0, 1, 0.5)]
    #[test_case(10, 2, 1, 0.5)]
    #[test_case(10, 9, 1, 0.5)]
    #[test_case(20, 5, 2, 0.5)]
    #[test_case(50, 0, 10, 0.5)]
    #[test_case(50, 42, 10, 0.5)]
    #[test_case(50, 49, 127, 0.5)]
    fn test_partial_tree(tx_count: u64, skip_txs_count: u64, leafs_count: u64, commitments_probability: f64) {
        let mut rng = CustomRng;
        let mut full_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut partial_tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let zero_root = full_tree.get_root();

        assert!(full_tree.first_index().is_none());
        assert!(partial_tree.first_index().is_none());

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                (i * (constants::OUT + 1) as u64, (0..leafs_count).map(|_| rng.gen()).collect())
            })
            .collect();

        let commitments: Vec<(u64, _)> = leafs
            .clone()
            .into_iter()
            .map(|(index, leafs)| {
                let mut out_hashes = leafs.clone();
                out_hashes.resize(constants::OUT+1, full_tree.zero_note_hashes[0]);
                let commitment = tx::out_commitment_hash(out_hashes.as_slice(), &POOL_PARAMS.clone());
                (index, commitment)
            }).collect();

        for (index, leafs) in leafs.clone().into_iter() {
            full_tree.add_hashes(index, leafs)
        }
        
        // part of the full tree
        let mut sub_leafs: Vec<(u64, Vec<_>)> = Vec::new();
        let mut sub_commitments: Vec<(u64, _)> = Vec::new();
        (skip_txs_count as usize..leafs.len()).for_each(|i| {
            if rng.gen_bool(commitments_probability) {
                sub_commitments.push(commitments[i as usize]);
            } else {
                sub_leafs.push((leafs[i as usize].0, leafs[i as usize].1.clone()));
            }
        });
        
        // get left siblings for the partial tree
        let partial_tree_start_index = skip_txs_count << constants::OUTPLUSONELOG;
        let siblings = full_tree.get_left_siblings(partial_tree_start_index);
        assert!(siblings.is_some());
        
        // add the tree part to the second tree
        partial_tree.add_leafs_commitments_and_siblings(sub_leafs, sub_commitments, siblings);

        assert_eq!(full_tree.first_index(), Some(0));
        assert_eq!(partial_tree.first_index(), Some(partial_tree_start_index));
        assert_eq!(full_tree.next_index(), partial_tree.next_index());
        assert_eq!(full_tree.get_root().to_string(), partial_tree.get_root().to_string());

        if tx_count - skip_txs_count > 1 {
            let check_rollback_index = (skip_txs_count + 1) << constants::OUTPLUSONELOG;
            partial_tree.rollback(check_rollback_index);
            assert_eq!(partial_tree.next_index(), check_rollback_index);
            assert_eq!(partial_tree.first_index(), Some(partial_tree_start_index));
            assert_eq!(full_tree.get_root_at(check_rollback_index).unwrap().to_string(), 
                        partial_tree.get_root().to_string());
        }

        partial_tree.rollback(partial_tree_start_index);
        assert_eq!(partial_tree.next_index(), 0);
        assert_eq!(partial_tree.first_index(), None);
        assert_eq!(partial_tree.get_root(), zero_root);
        
    }

    #[test_case(10, 1, 1)]
    #[test_case(10, 1, 2)]
    #[test_case(10, 1, 5)]
    #[test_case(10, 65, 8)]
    #[test_case(20, 127, 17)]
    fn test_root_at(tx_count: u64, leafs_count: u64, check_root_tx_index: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // get root on a void tree
        let root_0 = tree.get_root();

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                (i * (constants::OUT + 1) as u64, (0..leafs_count).map(|_| rng.gen()).collect())
            })
            .collect();

        let check_tx_next_index = check_root_tx_index * (constants::OUT as u64 + 1);

        // build the first part of tree
        for (index, leafs) in leafs.clone().into_iter() {
            if index < check_tx_next_index {
                tree.add_hashes(index, leafs)
            }
        }

        // get root at checkpoint
        let root_checkpoint = tree.get_root();

        // build the second part of tree
        for (index, leafs) in leafs.clone().into_iter() {
            if index >= check_root_tx_index {
                tree.add_hashes(index, leafs)
            }
        }

        // get root on a full tree
        let root_last = tree.get_root();

        // get roots at the specified indexes
        let root_at_0 = tree.get_root_at(0);
        let root_at_checkpoint = tree.get_root_at(check_tx_next_index);
        let root_at_last = tree.get_root_at(tree.next_index);

        assert!(root_at_0.is_some());
        assert!(root_at_checkpoint.is_some());
        assert!(root_at_last.is_some());
        assert_eq!(root_at_0.unwrap(), root_0);
        assert_eq!(root_at_checkpoint.unwrap(), root_checkpoint);
        assert_eq!(root_at_last.unwrap(), root_last);
    }

    #[test_case(0, 1)]
    #[test_case(1, 1)]
    #[test_case(10, 2)]
    #[test_case(20, 128)]
    #[test_case(42, 7)]
    fn test_wipe(tx_count: u64, leaves_count: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let zero_root = tree.get_root();

        let leafs: Vec<(u64, Vec<_>)> = (0..tx_count)
            .map(|i| {
                (i * (constants::OUT + 1) as u64, (0..leaves_count).map(|_| rng.gen()).collect())
            })
            .collect();

        for (index, leafs) in leafs.clone().into_iter() {
            tree.add_hashes(index, leafs)
        }

        tree.wipe();

        assert_eq!(tree.get_root(), zero_root);
        assert_eq!(tree.first_index(), None);
        assert_eq!(tree.next_index(), 0);
        assert_eq!(tree.get_leaves().len(), 0);
    }

   
    #[test]
    fn test_stable_index() {
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        assert_eq!(tree.get_last_stable_index(), 0);

        tree.set_last_stable_index(Some(1024));
        assert_eq!(tree.get_last_stable_index(), 1024);

        tree.set_last_stable_index(None);
        assert_eq!(tree.get_last_stable_index(), 0);
    }
}

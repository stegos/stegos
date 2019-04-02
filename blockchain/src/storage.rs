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

//! Implementation of block list on rocksdb.

use byteorder::{BigEndian, ByteOrder};
use failure::Error;
use rocksdb::{Direction, IteratorMode, WriteBatch, DB};
use stegos_serialization::traits::ProtoConvert;
use tempdir::TempDir;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use std::path::Path;

use super::block::Block;

/// Database for storing Blocks in List maner.
pub struct ListDb {
    /// Guard object for temporary directory.
    _temp_dir: Option<TempDir>,
    /// RocksDB database object.
    database: DB,
}

impl ListDb {
    /// Creates new ListDB instance.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let database = DB::open_default(path).expect("couldn't open database");
        Self {
            database,
            _temp_dir: None,
        }
    }

    /// Creates new testing ListDB instance.
    pub fn testing() -> Self {
        // we need to generate random string, to avoid conflicts in tests.
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        let temp_dir = TempDir::new(&rand_string).expect("couldn't create temp dir");
        let database = DB::open_default(temp_dir.path()).expect("couldn't open temp database");;

        Self {
            _temp_dir: Some(temp_dir),
            database,
        }
    }

    pub fn insert(&self, height: u64, block: Block) -> Result<(), Error> {
        let data = block.into_buffer().expect("couldn't serialize block.");

        let mut batch = WriteBatch::default();
        // writebatch put fails if size exceeded u32::max, which is not our case.
        batch.put(&Self::key_u64_to_bytes(height), &data)?;
        self.database.write(batch)?;
        Ok(())
    }

    /// Get record by id.
    pub fn get(&self, height: u64) -> Result<Option<Block>, Error> {
        let key = Self::key_u64_to_bytes(height);
        match self.database.get(&key)? {
            Some(buffer) => Ok(Some(Block::from_buffer(&buffer)?)),
            None => Ok(None),
        }
    }

    /// Remove record by id.
    pub fn remove(&self, height: u64) -> Result<(), Error> {
        let key = Self::key_u64_to_bytes(height);
        self.database.delete(&key)?;
        Ok(())
    }

    /// Create iterator that traverse fully block collection.
    pub fn iter(&self) -> impl Iterator<Item = Block> {
        let mode = IteratorMode::Start;
        self.database
            .full_iterator(mode)
            .map(|(_, v)| Block::from_buffer(&*v).expect("couldn't deserialize block."))
    }

    /// Create iterator starting from height and going forward.
    pub fn iter_starting(&self, height: u64) -> impl Iterator<Item = Block> {
        let key = Self::key_u64_to_bytes(height);
        let mode = IteratorMode::From(&key, Direction::Forward);
        self.database
            .iterator(mode)
            .map(|(_, v)| Block::from_buffer(&*v).expect("couldn't deserialize block."))
    }

    fn key_u64_to_bytes(len: u64) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        BigEndian::write_u64(&mut bytes, len);
        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::block::{BaseBlockHeader, KeyBlock};
    use std::time::SystemTime;
    use stegos_crypto::hash::Hash;
    use stegos_crypto::pbc::secure;

    fn create_block(previous: Hash) -> Block {
        let (skey0, _pkey0, _sig0) = secure::make_random_keys();
        let version: u64 = 1;
        let epoch: u64 = 1;
        let timestamp = SystemTime::now();

        let base = BaseBlockHeader::new(version, previous, epoch, 0, timestamp);

        let random = secure::make_VRF(&skey0, &Hash::digest("random"));

        let block = KeyBlock::new(base, random);
        Block::KeyBlock(block)
    }
    #[test]
    fn push_iter() {
        let previous = Hash::digest(&"test".to_string());
        let block1 = create_block(previous);
        let block2 = create_block(Hash::digest(&block1));
        let block3 = create_block(Hash::digest(&block2));
        let blocks = vec![block1, block2, block3];

        let db = ListDb::testing();
        for (height, block) in blocks.iter().enumerate() {
            db.insert(height as u64, block.clone()).unwrap();
        }

        for (block, saved) in blocks.iter().zip(db.iter()) {
            match (block, &saved) {
                (Block::KeyBlock(b1), Block::KeyBlock(b2)) => {
                    assert_eq!(Hash::digest(b1), Hash::digest(b2));
                }
                _ => panic!("different blocks found in database and generated."),
            }
        }
    }

    #[test]
    fn iter_starting() {
        let previous = Hash::digest(&"test".to_string());
        let block1 = create_block(previous);
        let block2 = create_block(Hash::digest(&block1));
        let block3 = create_block(Hash::digest(&block2));
        let blocks = vec![block1, block2, block3];

        let db = ListDb::testing();
        for (height, block) in blocks.iter().enumerate() {
            db.insert(height as u64, block.clone()).unwrap();
        }
        for (block, saved) in blocks.iter().skip(2).zip(db.iter_starting(2)) {
            assert_eq!(Hash::digest(block), Hash::digest(&saved));
        }
    }
    #[test]
    fn iter_order() {
        let previous = Hash::digest(&"test".to_string());
        let block1 = create_block(previous);

        let mut blocks = vec![block1];
        for _i in 0..257 {
            let block = create_block(Hash::digest(blocks.last().unwrap()));
            blocks.push(block);
        }

        let db = ListDb::testing();
        for (height, block) in blocks.iter().enumerate() {
            db.insert(height as u64, block.clone()).unwrap();
        }

        for (block, saved) in blocks.iter().zip(db.iter()) {
            assert_eq!(Hash::digest(block), Hash::digest(&saved));
        }
    }
}

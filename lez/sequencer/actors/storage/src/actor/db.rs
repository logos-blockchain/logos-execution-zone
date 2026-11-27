use std::{ops::Range, path::Path};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    Result, Storable,
    error::Error,
    protocol::RangeStart,
    storable::{ColumnFamily, decode_key, encode_key, key_range, range_bounds, start_key},
    writes::{StagedWrite, StagedWrites, Writes},
};

/// Memtable size for the families holding small records, well above
/// what they take between flushes.
const SMALL_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Values above this are large enough to be worth keeping out of the
/// LSM tree.
const MIN_BLOB_SIZE: u64 = 4 * 1024;

/// Zstandard compression level used for dumps.
///
/// Keeps a committed dump small, at a decompression cost that stays
/// negligible.
const ZSTD_LEVEL: i32 = 19;

pub struct Database {
    db: rocksdb::DB,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self> {
        let cfs = ColumnFamily::ALL
            .into_iter()
            .map(|cf| rocksdb::ColumnFamilyDescriptor::new(cf.name(), options(cf)))
            .collect::<Vec<_>>();

        let mut db_opts = rocksdb::Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = rocksdb::DB::open_cf_descriptors(&db_opts, path, cfs)?;

        Ok(Self { db })
    }

    /// Opens the database at `path`, writing `dump` into it.
    pub fn restore(path: &Path, dump: &Dump) -> Result<Self> {
        let database = Self::new(path)?;

        let mut batch = rocksdb::WriteBatch::default();
        for entry in &dump.entries {
            let cf = database
                .db
                .cf_handle(&entry.column_family)
                .ok_or_else(|| Error::UnknownColumnFamily(entry.column_family.clone()))?;
            batch.put_cf(cf, &entry.key, &entry.value);
        }
        database.db.write(batch)?;

        Ok(database)
    }

    pub fn put<T: Storable>(&self, key: &T::Key, value: &T) -> Result<()> {
        let bytes = borsh::to_vec(value)?;
        self.db.put_cf(
            self.column_family(T::COLUMN_FAMILY),
            encode_key::<T>(key),
            bytes,
        )?;

        Ok(())
    }

    /// Commits every write of `writes` together, in order, encoding their values.
    pub fn write(&self, writes: &dyn Writes) -> Result<()> {
        let mut staged = StagedWrites::new();
        writes.write_to(&mut staged)?;
        if staged.writes.is_empty() {
            return Ok(());
        }

        let mut batch = rocksdb::WriteBatch::default();
        for StagedWrite {
            column_family,
            key,
            value,
        } in staged.writes
        {
            let cf = self.column_family(column_family);
            match value {
                Some(value) => batch.put_cf(cf, key, value),
                None => batch.delete_cf(cf, key),
            }
        }
        self.db.write(batch)?;
        Ok(())
    }

    pub fn get<T: Storable>(&self, key: &T::Key) -> Result<Option<T>> {
        let Some(bytes) = self.get_bytes::<T>(key)? else {
            return Ok(None);
        };

        let value = T::try_from_slice(&bytes)?;
        Ok(Some(value))
    }

    /// The stored bytes for `key`, undecoded.
    pub fn get_bytes<T: Storable>(&self, key: &T::Key) -> Result<Option<Vec<u8>>> {
        self.get_raw(T::COLUMN_FAMILY, &encode_key::<T>(key))
    }

    /// Get an iterator over all items of the given type.
    ///
    /// Order of items is determined by lexicographic order of their encoded keys, see
    /// [`Storable::Key`] for more details.
    #[must_use]
    pub fn iter<T: Storable>(&self) -> Iter<'_, T> {
        Iter {
            values: self.values(T::COLUMN_FAMILY, key_range::<T>()),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Iterator over the items of the given type from `start` to `end`, with their keys.
    ///
    /// `end` is included if stored, and `None` stops at the last key.
    pub fn iter_range<T: Storable>(
        &self,
        start: &RangeStart<T>,
        end: Option<&T::Key>,
    ) -> impl Iterator<Item = Result<(T::Key, T)>> + '_ {
        let bounds = range_bounds::<T>(start_key(start), end);
        let empty = bounds.start >= bounds.end;
        let mut values = self
            .db
            .raw_iterator_cf_opt(self.column_family(T::COLUMN_FAMILY), iterate_opts(bounds));
        values.seek_to_first();

        std::iter::from_fn(move || {
            if empty {
                return None;
            }
            let item = decode_entry::<T>(values.key()?, values.value()?);
            values.next();
            Some(item)
        })
    }

    /// How many items of the given type are stored, counted without decoding
    /// any of them.
    #[must_use]
    pub fn count<T: Storable>(&self) -> usize {
        self.count_raw(T::COLUMN_FAMILY, key_range::<T>())
    }

    pub fn delete<T: Storable>(&self, key: &T::Key) -> Result<()> {
        self.db
            .delete_cf(self.column_family(T::COLUMN_FAMILY), encode_key::<T>(key))?;
        Ok(())
    }

    /// Every entry of every column family, as the bytes they are stored as.
    pub fn dump(&self) -> Result<Dump> {
        let mut entries = Vec::new();

        for column_family in ColumnFamily::ALL {
            let cf = self.column_family(column_family);

            for entry in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                let (key, value) = entry?;
                entries.push(DumpEntry {
                    column_family: column_family.name().to_owned(),
                    key: key.into_vec(),
                    value: value.into_vec(),
                });
            }
        }

        Ok(Dump { entries })
    }

    fn get_raw(&self, column_family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get_cf(self.column_family(column_family), key)?)
    }

    fn values(&self, column_family: ColumnFamily, keys: Range<Vec<u8>>) -> Values<'_> {
        Values::new(&self.db, self.column_family(column_family), keys)
    }

    fn count_raw(&self, column_family: ColumnFamily, keys: Range<Vec<u8>>) -> usize {
        let mut iter = self
            .db
            .raw_iterator_cf_opt(self.column_family(column_family), iterate_opts(keys));
        iter.seek_to_first();

        let mut count = 0_usize;
        while iter.valid() {
            count = count.saturating_add(1);
            iter.next();
        }

        count
    }

    fn column_family(&self, column_family: ColumnFamily) -> &rocksdb::ColumnFamily {
        let name = column_family.name();
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("Column family {name:?} must be present"))
    }
}

/// Snapshot of a whole database: every key/value pair across all of its column
/// families, taken by [`Database::dump`] and written back by
/// [`Database::restore`].
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Dump {
    entries: Vec<DumpEntry>,
}

/// One key/value pair of a [`Dump`], under the name of the family holding it.
#[derive(BorshSerialize, BorshDeserialize)]
struct DumpEntry {
    column_family: String,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Dump {
    /// The single compressed blob a dump ships as.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = borsh::to_vec(self)?;
        zstd::encode_all(bytes.as_slice(), ZSTD_LEVEL).map_err(Error::Compression)
    }

    /// Reads back a blob [`Self::to_bytes`] produced.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = zstd::decode_all(bytes).map_err(Error::Compression)?;
        borsh::from_slice(&bytes).map_err(Into::into)
    }
}

/// Iterator over the items of one type in the database, with their keys.
///
/// Order of items is determined by lexicographic order of their encoded keys, see
/// [`Storable::Key`] for more details.
pub struct Iter<'db, T: Storable> {
    values: Values<'db>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Storable> Iterator for Iter<'_, T> {
    type Item = Result<(T::Key, T)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.values
            .next()
            .map(|(key, value)| decode_entry::<T>(&key, &value))
    }
}

impl<T: Storable> DoubleEndedIterator for Iter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.values
            .next_back()
            .map(|(key, value)| decode_entry::<T>(&key, &value))
    }
}

/// Stored keys and values in a range, from both ends towards each other.
struct Values<'db> {
    front: rocksdb::DBRawIterator<'db>,
    back: rocksdb::DBRawIterator<'db>,
}

impl<'db> Values<'db> {
    fn new(db: &'db rocksdb::DB, cf: &rocksdb::ColumnFamily, keys: Range<Vec<u8>>) -> Self {
        let mut front = db.raw_iterator_cf_opt(cf, iterate_opts(keys.clone()));
        front.seek_to_first();

        let mut back = db.raw_iterator_cf_opt(cf, iterate_opts(keys));
        back.seek_to_last();

        Self { front, back }
    }

    /// Whether the ends have met, meaning every value has been yielded.
    ///
    /// Relies on keys being ordered bytewise, which holds for the default comparator.
    fn ends_met(&self) -> bool {
        match (self.front.key(), self.back.key()) {
            (Some(front), Some(back)) => front > back,
            _ => true,
        }
    }
}

impl Iterator for Values<'_> {
    /// The encoded key and the value.
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.ends_met() {
            return None;
        }

        let entry = (self.front.key()?.to_vec(), self.front.value()?.to_vec());
        self.front.next();
        Some(entry)
    }
}

impl DoubleEndedIterator for Values<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.ends_met() {
            return None;
        }

        let entry = (self.back.key()?.to_vec(), self.back.value()?.to_vec());
        self.back.prev();
        Some(entry)
    }
}

/// Options `column_family` is created and opened with.
fn options(column_family: ColumnFamily) -> rocksdb::Options {
    let mut options = rocksdb::Options::default();

    match column_family {
        ColumnFamily::Appended | ColumnFamily::Index => {
            // Written in bursts, so more memtables to fill while one flushes.
            options.set_max_write_buffer_number(4);
        }
        ColumnFamily::LargeRewritten | ColumnFamily::LargeAppended => {
            // Large values rewritten or appended often. Blob files keep them
            // out of compaction, which would otherwise copy every one of them
            // through each level.
            options.set_enable_blob_files(true);
            options.set_min_blob_size(MIN_BLOB_SIZE);
            options.set_enable_blob_gc(true);
        }
        ColumnFamily::LongLived | ColumnFamily::ShortLived => {
            options.set_write_buffer_size(SMALL_WRITE_BUFFER_SIZE);
        }
    }

    options
}

/// Read options confining an iterator to the keys in `keys`.
fn iterate_opts(keys: Range<Vec<u8>>) -> rocksdb::ReadOptions {
    let mut read_opts = rocksdb::ReadOptions::default();
    read_opts.set_iterate_lower_bound(keys.start);
    read_opts.set_iterate_upper_bound(keys.end);
    read_opts
}

/// The key and the value of a `T` stored as `encoded_key` and `value`.
fn decode_entry<T: Storable>(encoded_key: &[u8], value: &[u8]) -> Result<(T::Key, T)> {
    let key = decode_key::<T>(encoded_key).ok_or(Error::KeyDecoding(T::TYPE_NAME))?;
    Ok((key, T::try_from_slice(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::{BigEndian, SingletonKey},
        full_type_name,
    };

    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct Number {
        id: u64,
    }

    impl Storable for Number {
        type Key = BigEndian<u64>;

        const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
        const TYPE_NAME: &'static str = full_type_name!(Number);
    }

    /// Shares the column family with [`Number`], under a name [`Number`]'s is a
    /// prefix of.
    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct NumberPair {
        ids: (u64, u64),
    }

    impl Storable for NumberPair {
        type Key = BigEndian<u64>;

        const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
        const TYPE_NAME: &'static str = full_type_name!(NumberPair);
    }

    /// Shares the column family with [`Number`], keyed by nothing at all.
    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct NumberCount {
        count: u64,
    }

    impl Storable for NumberCount {
        type Key = SingletonKey;

        const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
        const TYPE_NAME: &'static str = full_type_name!(NumberCount);
    }

    /// Opens a database at `dir` holding a [`Number`] per id in `ids`.
    fn database_with(dir: &tempfile::TempDir, ids: &[u64]) -> Database {
        let db = Database::new(dir.path()).expect("Failed to open db");
        for &id in ids {
            db.put(&BigEndian::new(&id), &Number { id })
                .expect("Failed to put a number");
        }
        db
    }

    fn collect_ids(iter: impl Iterator<Item = Result<(BigEndian<u64>, Number)>>) -> Vec<u64> {
        iter.map(|entry| entry.expect("Failed to read a number").1.id)
            .collect()
    }

    /// Restoring a dump has to bring back every family's entries under the keys
    /// they were stored at, and nothing else.
    #[test]
    fn a_restored_database_holds_what_the_dumped_one_held() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1, 2]);
        db.put(&SingletonKey, &NumberCount { count: 3 })
            .expect("Failed to put a number count");

        let bytes = db
            .dump()
            .expect("Failed to dump the database")
            .to_bytes()
            .expect("Failed to serialize the dump");

        let restored_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let restored = Database::restore(
            restored_dir.path(),
            &Dump::from_bytes(&bytes).expect("Failed to read the dump back"),
        )
        .expect("Failed to restore the database");

        assert_eq!(collect_ids(restored.iter::<Number>()), vec![0, 1, 2]);
        assert_eq!(
            restored
                .get::<NumberCount>(&SingletonKey)
                .expect("Failed to read the number count"),
            Some(NumberCount { count: 3 })
        );
    }

    /// A dump of another schema names families this database has none of, and
    /// has to be refused rather than silently dropped.
    #[test]
    fn restoring_a_dump_of_an_unknown_column_family_fails() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let dump = Dump {
            entries: vec![DumpEntry {
                column_family: "no family of this database".to_owned(),
                key: vec![0],
                value: vec![1],
            }],
        };

        let Err(error) = Database::restore(dir.path(), &dump) else {
            panic!("Restore must refuse an unknown column family");
        };

        assert!(matches!(error, Error::UnknownColumnFamily(_)));
    }

    #[test]
    fn a_dump_of_an_empty_database_restores_to_an_empty_one() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[]);

        let dump = db.dump().expect("Failed to dump the database");

        let restored_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let restored =
            Database::restore(restored_dir.path(), &dump).expect("Failed to restore the database");

        assert_eq!(collect_ids(restored.iter::<Number>()), Vec::<u64>::new());
    }

    /// Values of different types under the same key bytes are distinct entries.
    #[test]
    fn types_sharing_a_column_family_do_not_collide() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[7]);

        db.put(&BigEndian::new(&7), &NumberPair { ids: (7, 8) })
            .expect("Failed to put a number pair");
        db.put(&SingletonKey, &NumberCount { count: 2 })
            .expect("Failed to put a number count");

        assert_eq!(
            db.get::<Number>(&BigEndian::new(&7))
                .expect("Failed to read the number"),
            Some(Number { id: 7 })
        );
        assert_eq!(
            db.get::<NumberPair>(&BigEndian::new(&7))
                .expect("Failed to read the number pair"),
            Some(NumberPair { ids: (7, 8) })
        );
        assert_eq!(
            db.get::<NumberCount>(&SingletonKey)
                .expect("Failed to read the number count"),
            Some(NumberCount { count: 2 })
        );
    }

    #[test]
    fn deleting_a_type_leaves_the_others_sharing_the_column_family_alone() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[7]);

        db.put(&BigEndian::new(&7), &NumberPair { ids: (7, 8) })
            .expect("Failed to put a number pair");

        db.delete::<Number>(&BigEndian::new(&7))
            .expect("Failed to delete the number");

        assert_eq!(
            db.get::<NumberPair>(&BigEndian::new(&7))
                .expect("Failed to read the number pair"),
            Some(NumberPair { ids: (7, 8) })
        );
    }

    #[test]
    fn iter_yields_only_the_items_of_its_own_type() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1, 2]);

        for id in [0, 1, 2] {
            db.put(&BigEndian::new(&id), &NumberPair { ids: (id, id) })
                .expect("Failed to put a number pair");
        }
        db.put(&SingletonKey, &NumberCount { count: 3 })
            .expect("Failed to put a number count");

        assert_eq!(collect_ids(db.iter::<Number>()), vec![0, 1, 2]);
        assert_eq!(collect_ids(db.iter::<Number>().rev()), vec![2, 1, 0]);
    }

    #[test]
    fn iter_yields_items_in_lexicographical_key_order() {
        // `Number` uses `BigEndian` for its keys, so the iteration order will be ascending
        // according to the lexicographical order of the encoded keys.

        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[277, 0, 500, 1, 2, 256]);

        assert_eq!(
            collect_ids(db.iter::<Number>()),
            vec![0, 1, 2, 256, 277, 500]
        );
    }

    #[test]
    fn iter_over_empty_column_family_yields_nothing() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[]);

        assert_eq!(collect_ids(db.iter::<Number>()), Vec::<u64>::new());
    }

    #[test]
    fn iter_keeps_yielding_none_after_exhaustion() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1]);

        let mut iter = db.iter::<Number>();
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());

        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn next_back_yields_the_last_item() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1, 2]);

        let (key, last) = db
            .iter::<Number>()
            .next_back()
            .expect("Iterator must yield the last number")
            .expect("Failed to read the last number");

        assert_eq!(key.as_ref(), BigEndian::new(&2_u64).as_ref());
        assert_eq!(last.id, 2);
    }

    #[test]
    fn rev_yields_items_in_descending_key_order() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1, 2, 3, 4]);

        assert_eq!(collect_ids(db.iter::<Number>().rev()), vec![4, 3, 2, 1, 0]);
    }

    /// `next` and `next_back` walk towards each other over one shared sequence, so
    /// alternating between them must consume every item exactly once.
    #[test]
    fn next_and_next_back_never_yield_the_same_item() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let db = database_with(&dir, &[0, 1, 2, 3]);

        let read = |item: Option<Result<(BigEndian<u64>, Number)>>| {
            item.expect("Iterator must yield every number")
                .expect("Failed to read a number")
                .1
                .id
        };

        let mut iter = db.iter::<Number>();
        let mut seen = vec![
            read(iter.next()),
            read(iter.next_back()),
            read(iter.next()),
            read(iter.next_back()),
        ];

        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3]);
        assert!(iter.next().is_none());
    }
}

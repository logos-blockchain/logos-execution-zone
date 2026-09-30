#![expect(
    clippy::arbitrary_source_item_ordering,
    reason = "Can't place macro export before its definition"
)]

use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};

macro_rules! type_name {
    ($t:ty) => {{
        // Ensure it's a real type, protecting from unwanted mismatch after refactoring.
        const fn _ensure_type(_: &$t) {}

        stringify!($t)
    }};
}

pub(crate) use type_name;

/// Separates the type name from the key it prefixes.
///
/// Type names never contain it, so no key can be read as another type's.
const TYPE_NAME_SEPARATOR: u8 = 0;

/// First byte past [`TYPE_NAME_SEPARATOR`], bounding a type's key range from above.
const TYPE_NAME_SEPARATOR_END: u8 = TYPE_NAME_SEPARATOR + 1;

/// Zstandard compression level used for dumps.
///
/// Keeps a committed dump small, at a decompression cost that stays
/// negligible.
const ZSTD_LEVEL: i32 = 19;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("RocksDb error")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Borsh encoding error")]
    BorshEncoding(#[from] borsh::io::Error),

    #[error("Compression error")]
    Compression(#[source] std::io::Error),

    #[error("Dump holds entries of column family {0:?}, which this database has none of")]
    UnknownColumnFamily(String),
}

/// Column families affects how data is stored on disk and are used to group data which requires
/// common configuration.
pub trait ColumnFamilies: Into<&'static str> + enum_iterator::Sequence {
    /// Options the family is created and opened with.
    fn options(&self) -> rocksdb::Options {
        rocksdb::Options::default()
    }
}

pub trait Storable<C: ColumnFamilies>: BorshSerialize + BorshDeserialize {
    /// Key the value is stored under.
    ///
    /// Key bytes are compared lexicographically to determine order in the column family.
    type Key: AsRef<[u8]>;

    const COLUMN_FAMILY: C;

    /// Name telling this type apart from the others sharing its column family.
    ///
    /// Consider using `type_name!(TypeName)` for it.
    const TYPE_NAME: &'static str;
}

pub struct Database<C: ColumnFamilies> {
    db: rocksdb::DB,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: ColumnFamilies> Database<C> {
    pub fn new(path: &Path) -> Result<Self> {
        let cfs = enum_iterator::all::<C>()
            .map(|cf| {
                let options = cf.options();
                rocksdb::ColumnFamilyDescriptor::new(cf.into(), options)
            })
            .collect::<Vec<_>>();

        let mut db_opts = rocksdb::Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = rocksdb::DB::open_cf_descriptors(&db_opts, path, cfs)?;

        Ok(Self {
            db,
            _phantom: std::marker::PhantomData,
        })
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

    pub fn put<T: Storable<C>>(&self, key: &T::Key, value: &T) -> Result<()> {
        let cf = self.column_family::<T>();

        let mut bytes = Vec::new();
        value.serialize(&mut bytes)?;

        self.db.put_cf(cf, Self::encode_key::<T>(key), bytes)?;

        Ok(())
    }

    pub fn put_batch<T: Storable<C>>(
        &self,
        write_batch: &mut WriteBatch,
        key: &T::Key,
        value: &T,
    ) -> Result<()> {
        let cf = self.column_family::<T>();

        let mut bytes = Vec::new();
        value.serialize(&mut bytes)?;

        write_batch.0.put_cf(cf, Self::encode_key::<T>(key), bytes);

        Ok(())
    }

    pub fn write(&self, batch: WriteBatch) -> Result<()> {
        if batch.0.is_empty() {
            return Ok(());
        }

        self.db.write(batch.0)?;
        Ok(())
    }

    pub fn get<T: Storable<C>>(&self, key: &T::Key) -> Result<Option<T>> {
        let cf = self.column_family::<T>();

        let Some(bytes) = self.db.get_cf(cf, Self::encode_key::<T>(key))? else {
            return Ok(None);
        };

        let value = T::try_from_slice(&bytes)?;
        Ok(Some(value))
    }

    /// Get an iterator over all items of the given type.
    ///
    /// Order of items is determined by lexicographic order of their encoded keys, see
    /// [`Storable::Key`] for more details.
    #[must_use]
    pub fn iter<T: Storable<C>>(&self) -> Iter<'_, C, T> {
        let cf = self.column_family::<T>();
        Iter::new(&self.db, cf)
    }

    /// How many items of the given type are stored, counted without decoding
    /// any of them.
    #[must_use]
    pub fn count<T: Storable<C>>(&self) -> usize {
        let cf = self.column_family::<T>();
        let mut iter = self.db.raw_iterator_cf_opt(cf, Self::iterate_opts::<T>());
        iter.seek_to_first();

        let mut count = 0_usize;
        while iter.valid() {
            count = count.saturating_add(1);
            iter.next();
        }

        count
    }

    pub fn delete<T: Storable<C>>(&self, key: &T::Key) -> Result<()> {
        let cf = self.column_family::<T>();
        self.db.delete_cf(cf, Self::encode_key::<T>(key))?;
        Ok(())
    }

    pub fn delete_batch<T: Storable<C>>(&self, write_batch: &mut WriteBatch, key: &T::Key) {
        let cf = self.column_family::<T>();
        write_batch.0.delete_cf(cf, Self::encode_key::<T>(key));
    }

    /// Bytes `key` is stored under: the name of `T` and the key itself, so that
    /// types sharing a column family stay in disjoint key ranges.
    fn encode_key<T: Storable<C>>(key: &T::Key) -> Vec<u8> {
        [
            T::TYPE_NAME.as_bytes(),
            &[TYPE_NAME_SEPARATOR],
            key.as_ref(),
        ]
        .concat()
    }

    /// Key range holding every `T`: the prefix all of its keys share, and the
    /// first key past them.
    fn key_range<T: Storable<C>>() -> (Vec<u8>, Vec<u8>) {
        let type_name = T::TYPE_NAME.as_bytes();

        (
            [type_name, &[TYPE_NAME_SEPARATOR]].concat(),
            [type_name, &[TYPE_NAME_SEPARATOR_END]].concat(),
        )
    }

    /// Read options confining an iterator to the keys of `T`.
    fn iterate_opts<T: Storable<C>>() -> rocksdb::ReadOptions {
        let (start, end) = Self::key_range::<T>();

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(start);
        read_opts.set_iterate_upper_bound(end);
        read_opts
    }

    /// Every entry of every column family, as the bytes they are stored as.
    pub fn dump(&self) -> Result<Dump> {
        let mut entries = Vec::new();

        for column_family in enum_iterator::all::<C>() {
            let name: &'static str = column_family.into();
            let cf = self.column_family_by_name(name);

            for entry in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                let (key, value) = entry?;
                entries.push(DumpEntry {
                    column_family: name.to_owned(),
                    key: key.into_vec(),
                    value: value.into_vec(),
                });
            }
        }

        Ok(Dump { entries })
    }

    fn column_family<T: Storable<C>>(&self) -> &rocksdb::ColumnFamily {
        self.column_family_by_name(T::COLUMN_FAMILY.into())
    }

    fn column_family_by_name(&self, name: &'static str) -> &rocksdb::ColumnFamily {
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

#[derive(Default)]
pub struct WriteBatch(rocksdb::WriteBatch);

/// Iterator over the items of one type in a column family of the database.
///
/// Order of items is determined by lexicographic order of their encoded keys, see
/// [`Storable::Key`] for more details.
pub struct Iter<'db, C: ColumnFamilies, T: Storable<C>> {
    front: rocksdb::DBRawIterator<'db>,
    back: rocksdb::DBRawIterator<'db>,
    _phantom: std::marker::PhantomData<(C, T)>,
}

impl<'db, C: ColumnFamilies, T: Storable<C>> Iter<'db, C, T> {
    fn new(db: &'db rocksdb::DB, cf: &rocksdb::ColumnFamily) -> Self {
        let mut front = db.raw_iterator_cf_opt(cf, Database::<C>::iterate_opts::<T>());
        front.seek_to_first();

        let mut back = db.raw_iterator_cf_opt(cf, Database::<C>::iterate_opts::<T>());
        back.seek_to_last();

        Self {
            front,
            back,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Whether the ends have met, meaning every item has been yielded.
    ///
    /// Relies on keys being ordered bytewise, which holds for the default comparator.
    fn ends_met(&self) -> bool {
        match (self.front.key(), self.back.key()) {
            (Some(front), Some(back)) => front > back,
            _ => true,
        }
    }
}

impl<C: ColumnFamilies, T: Storable<C>> Iterator for Iter<'_, C, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ends_met() {
            return None;
        }

        let item = T::try_from_slice(self.front.value()?).map_err(Into::into);
        self.front.next();
        Some(item)
    }
}

impl<C: ColumnFamilies, T: Storable<C>> DoubleEndedIterator for Iter<'_, C, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.ends_met() {
            return None;
        }

        let item = T::try_from_slice(self.back.value()?).map_err(Into::into);
        self.back.prev();
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::encoding::{BigEndian, SingletonKey};

    #[derive(strum::IntoStaticStr, enum_iterator::Sequence)]
    enum TestColumnFamily {
        Numbers,
    }

    impl ColumnFamilies for TestColumnFamily {}

    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct Number {
        id: u64,
    }

    impl Storable<TestColumnFamily> for Number {
        type Key = BigEndian<u64>;

        const COLUMN_FAMILY: TestColumnFamily = TestColumnFamily::Numbers;
        const TYPE_NAME: &'static str = type_name!(Number);
    }

    /// Shares the column family with [`Number`], under a name [`Number`]'s is a
    /// prefix of.
    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct NumberPair {
        ids: (u64, u64),
    }

    impl Storable<TestColumnFamily> for NumberPair {
        type Key = BigEndian<u64>;

        const COLUMN_FAMILY: TestColumnFamily = TestColumnFamily::Numbers;
        const TYPE_NAME: &'static str = type_name!(NumberPair);
    }

    /// Shares the column family with [`Number`], keyed by nothing at all.
    #[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct NumberCount {
        count: u64,
    }

    impl Storable<TestColumnFamily> for NumberCount {
        type Key = SingletonKey;

        const COLUMN_FAMILY: TestColumnFamily = TestColumnFamily::Numbers;
        const TYPE_NAME: &'static str = type_name!(NumberCount);
    }

    /// Opens a database at `dir` holding a [`Number`] per id in `ids`.
    fn database_with(dir: &tempfile::TempDir, ids: &[u64]) -> Database<TestColumnFamily> {
        let db = Database::new(dir.path()).expect("Failed to open db");
        for &id in ids {
            db.put(&BigEndian::new(&id), &Number { id })
                .expect("Failed to put a number");
        }
        db
    }

    fn collect_ids(iter: impl Iterator<Item = Result<Number>>) -> Vec<u64> {
        iter.map(|number| number.expect("Failed to read a number").id)
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
        let restored = Database::<TestColumnFamily>::restore(
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

        let Err(error) = Database::<TestColumnFamily>::restore(dir.path(), &dump) else {
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
        let restored = Database::<TestColumnFamily>::restore(restored_dir.path(), &dump)
            .expect("Failed to restore the database");

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

        let last = db
            .iter::<Number>()
            .next_back()
            .expect("Iterator must yield the last number")
            .expect("Failed to read the last number");

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

        let read = |item: Option<Result<Number>>| {
            item.expect("Iterator must yield every number")
                .expect("Failed to read a number")
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

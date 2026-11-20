//! What a type needs to be kept in the store.

use borsh::{BorshDeserialize, BorshSerialize};

/// Full name of a type including module path as a string, failing to compile if the type does not
/// exist.
///
/// Meant for [`Storable::TYPE_NAME`] invoked from the same module the type is defined in.
#[macro_export]
macro_rules! full_type_name {
    ($t:ty) => {{
        // Ensure it's a real type, protecting from unwanted mismatch after refactoring.
        const fn _ensure_type(_: &$t) {}

        concat!(module_path!(), "::", stringify!($t))
    }};
}

/// Separates the type name from the key it prefixes.
///
/// Type names never contain it, so no key can be read as another type's.
const TYPE_NAME_SEPARATOR: u8 = 0;

/// First byte past [`TYPE_NAME_SEPARATOR`], bounding a type's key range from above.
#[cfg(any(feature = "actor", feature = "mock"))]
const TYPE_NAME_SEPARATOR_END: u8 = TYPE_NAME_SEPARATOR + 1;

/// Groups stored types by how they are written, not by what they mean: types
/// sharing a family are still kept under disjoint keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColumnFamily {
    /// Many medium-sized records, appended and scanned in key order.
    Appended,
    /// A handful of large values, rewritten often.
    LargeRewritten,
    /// Small records that live as long as the database.
    LongLived,
    /// Small records deleted as the work they track settles.
    ShortLived,
    /// Many small records written in bursts, like index entries.
    Index,
    /// Large records, appended in key order.
    LargeAppended,
}

/// A type the store can keep.
pub trait Storable: BorshSerialize + BorshDeserialize + Send + Sync + 'static {
    /// Key the value is stored under.
    ///
    /// Key bytes are compared lexicographically to determine the order of the
    /// values of the type. A key is read back from its bytes.
    type Key: AsRef<[u8]> + for<'bytes> TryFrom<&'bytes [u8]> + Send + Sync + 'static;

    const COLUMN_FAMILY: ColumnFamily;

    /// Name telling this type apart from every other stored type.
    ///
    /// It prefixes every key of the type, so it must be unique across the whole
    /// store and must not change once values are stored under it.
    ///
    /// Consider using `full_type_name!(TypeName)` for it.
    const TYPE_NAME: &'static str;
}

/// Dyn-compatible version of [`Storable`], implemented for every type that implements [`Storable`].
#[cfg_attr(
    not(any(feature = "actor", feature = "mock")),
    expect(dead_code, reason = "Only the actor and its mock encode the values")
)]
pub(crate) trait DynStorable: Send + Sync {
    fn column_family(&self) -> ColumnFamily;

    fn encode(&self) -> borsh::io::Result<Vec<u8>>;
}

impl<T: Storable> DynStorable for T {
    fn column_family(&self) -> ColumnFamily {
        T::COLUMN_FAMILY
    }

    fn encode(&self) -> borsh::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }
}

impl ColumnFamily {
    /// Every family, in the order a database dump lists them.
    pub const ALL: [Self; 6] = [
        Self::Appended,
        Self::LargeRewritten,
        Self::LongLived,
        Self::ShortLived,
        Self::Index,
        Self::LargeAppended,
    ];

    /// Name the family is kept under on disk.
    ///
    /// Spelled out instead of derived, so that renaming a variant does not
    /// change the database layout.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Appended => "Appended",
            Self::LargeRewritten => "LargeRewritten",
            Self::LongLived => "LongLived",
            Self::ShortLived => "ShortLived",
            Self::Index => "Index",
            Self::LargeAppended => "LargeAppended",
        }
    }
}

/// Bytes `key` is stored under: the name of `T` and the key itself, so that
/// types sharing a column family stay in disjoint key ranges.
pub(crate) fn encode_key<T: Storable>(key: &T::Key) -> Vec<u8> {
    [
        T::TYPE_NAME.as_bytes(),
        &[TYPE_NAME_SEPARATOR],
        key.as_ref(),
    ]
    .concat()
}

/// The key a `T` is stored under as `encoded`. `None` when the bytes after the name of `T` are not
/// a key of `T`.
#[cfg(any(feature = "actor", feature = "mock"))]
pub(crate) fn decode_key<T: Storable>(encoded: &[u8]) -> Option<T::Key> {
    let key = encoded.get(T::TYPE_NAME.len().saturating_add(1)..)?;
    T::Key::try_from(key).ok()
}

/// Key range holding every `T`: from the prefix all of its keys share up to
/// the first key past them.
#[cfg(any(feature = "actor", feature = "mock"))]
pub(crate) fn key_range<T: Storable>() -> std::ops::Range<Vec<u8>> {
    let type_name = T::TYPE_NAME.as_bytes();

    [type_name, &[TYPE_NAME_SEPARATOR]].concat()..[type_name, &[TYPE_NAME_SEPARATOR_END]].concat()
}

/// Encoded key a range from `start` starts at. `None` starts at the first key of `T`.
#[cfg(any(feature = "actor", feature = "mock"))]
pub(crate) fn start_key<T: Storable>(start: &crate::protocol::RangeStart<T>) -> Option<Vec<u8>> {
    use crate::protocol::RangeStart;

    match start {
        RangeStart::First => None,
        RangeStart::At(key) => Some(encode_key::<T>(key)),
        RangeStart::After(key) => Some(past(encode_key::<T>(key))),
    }
}

/// Key range of `T` from the encoded `start` up to the first key past `end`. `None` starts at the
/// first key, or stops at the last one.
#[cfg(any(feature = "actor", feature = "mock"))]
pub(crate) fn range_bounds<T: Storable>(
    start: Option<Vec<u8>>,
    end: Option<&T::Key>,
) -> std::ops::Range<Vec<u8>> {
    let all = key_range::<T>();
    let lower = start.unwrap_or(all.start);
    let upper = end.map_or(all.end, |key| past(encode_key::<T>(key)));
    lower..upper
}

/// The first encoded key past `encoded`: a zero byte appended.
#[cfg(any(feature = "actor", feature = "mock"))]
fn past(mut encoded: Vec<u8>) -> Vec<u8> {
    encoded.push(0);
    encoded
}

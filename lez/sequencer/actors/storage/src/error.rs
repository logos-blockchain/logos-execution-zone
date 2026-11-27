#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "actor")]
    #[error("RocksDB error")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Failed to encode or decode a stored value")]
    Encoding(#[from] borsh::io::Error),

    #[error("A stored key of {0} does not decode")]
    KeyDecoding(&'static str),

    #[error("Failed to compress or decompress a database dump")]
    Compression(#[source] std::io::Error),

    #[error("Dump holds entries of column family {0:?}, which this database has none of")]
    UnknownColumnFamily(String),
}

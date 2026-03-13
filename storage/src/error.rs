#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("RocksDb error: {}", additional_info.as_deref().unwrap_or("No additional info"))]
    RocksDbError {
        #[source]
        error: rocksdb::Error,
        additional_info: Option<String>,
    },
    #[error("Serialization error: {}", additional_info.as_deref().unwrap_or("No additional info"))]
    SerializationError {
        #[source]
        error: borsh::io::Error,
        additional_info: Option<String>,
    },
    #[error("Logic Error: {additional_info}")]
    DbInteractionError { additional_info: String },
}

impl DbError {
    #[must_use]
    pub const fn rocksdb_cast_message(rerr: rocksdb::Error, message: Option<String>) -> Self {
        Self::RocksDbError {
            error: rerr,
            additional_info: message,
        }
    }

    #[must_use]
    pub const fn borsh_cast_message(berr: borsh::io::Error, message: Option<String>) -> Self {
        Self::SerializationError {
            error: berr,
            additional_info: message,
        }
    }

    #[must_use]
    pub const fn db_interaction_error(message: String) -> Self {
        Self::DbInteractionError {
            additional_info: message,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error")]
    DatabaseError(#[from] storage::error::DbError),
    #[error("Serializaton error")]
    SerializationError(#[from] serde_json::Error),
}

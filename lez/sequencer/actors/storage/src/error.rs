#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error: {0}")]
    DatabaseError(String),
}

#[cfg(feature = "actor")]
impl From<storage::error::DbError> for Error {
    fn from(error: storage::error::DbError) -> Self {
        Self::DatabaseError(format!("{error:#}"))
    }
}

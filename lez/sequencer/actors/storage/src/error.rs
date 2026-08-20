#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error")]
    DatabaseError(#[from] storage::error::DbError),
}

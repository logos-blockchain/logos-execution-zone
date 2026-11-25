#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error")]
    DatabaseError(#[source] anyhow::Error),
}

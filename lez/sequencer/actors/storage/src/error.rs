#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error")]
    DatabaseError(anyhow::Error),

    #[error("Too many pending cross-zone dispatches (max: {max})")]
    TooManyPendingCrossZoneDispatches { max: usize },
}

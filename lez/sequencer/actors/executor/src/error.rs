#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("One of the sequencer's background tasks has finished unexpectedly")]
    BackgroundTaskFinishedUnexpectedly,

    #[error("The sequencer's block publisher has finished unexpectedly")]
    BlockPublisherFinishedUnexpectedly,

    #[error("The mempool is full")]
    MempoolIsFull,

    #[error("Storage error")]
    StorageError(#[from] storage::error::DbError),

    #[error(transparent)]
    BlockProductionFailed(anyhow::Error),
}

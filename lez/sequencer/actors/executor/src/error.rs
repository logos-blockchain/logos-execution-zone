#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("One of the sequencer's background tasks has finished unexpectedly")]
    BackgroundTaskFinishedUnexpectedly,

    #[error("The sequencer's block publisher has finished unexpectedly")]
    BlockPublisherFinishedUnexpectedly,

    #[error("The mempool is full")]
    MempoolIsFull,

    #[error("Storage request failed")]
    StorageRequestFailed(
        #[source] kameo::error::SendError<NoMatter, sequencer_storage_actor::error::Error>,
    ),

    #[error("Block production failed")]
    BlockProductionFailed(#[source] anyhow::Error),

    #[error("Failed to read the cross-zone dead letter")]
    CrossZoneDeadLettersUnavailable(#[source] anyhow::Error),

    #[error("Failed to requeue the cross-zone dead letter: {0}")]
    CrossZoneDeadLetterRequeueFailed(#[source] anyhow::Error),
}

/// A dummy struct replacing message type in [`kameo::error::SendError`]
/// as we don't want to expose the message type in the public API.
pub struct NoMatter;

impl<M> From<kameo::error::SendError<M, sequencer_storage_actor::error::Error>> for Error {
    fn from(err: kameo::error::SendError<M, sequencer_storage_actor::error::Error>) -> Self {
        Self::StorageRequestFailed(err.map_msg(|_| NoMatter))
    }
}

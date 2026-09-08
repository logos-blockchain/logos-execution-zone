use sequencer_actors_common::{EraseMessage as _, ErasedMessage};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("One of the sequencer's background tasks has finished unexpectedly")]
    BackgroundTaskFinishedUnexpectedly,

    #[error("The sequencer's block publisher has finished unexpectedly")]
    BlockPublisherFinishedUnexpectedly,

    #[error("The mempool is full")]
    MempoolIsFull,

    #[error("Failed to start the sequencer")]
    SequencerStartFailed(#[source] anyhow::Error),

    #[error("Storage request failed")]
    StorageRequestFailed(
        #[source] kameo::error::SendError<ErasedMessage, sequencer_storage_actor::error::Error>,
    ),

    #[error("Bedrock request failed")]
    BedrockRequestFailed(
        #[source] kameo::error::SendError<ErasedMessage, sequencer_bedrock_actor::error::Error>,
    ),

    #[error("Failed to read the cross-zone dead letter")]
    CrossZoneDeadLettersUnavailable(#[source] anyhow::Error),

    #[error("Failed to requeue the cross-zone dead letter")]
    CrossZoneDeadLetterRequeueFailed(#[source] anyhow::Error),

    #[error("Incorrect fee")]
    IncorrectFee(#[source] anyhow::Error),
}

impl<M> From<kameo::error::SendError<M, sequencer_storage_actor::error::Error>> for Error {
    fn from(err: kameo::error::SendError<M, sequencer_storage_actor::error::Error>) -> Self {
        Self::StorageRequestFailed(err.erase_message())
    }
}

impl<M> From<kameo::error::SendError<M, sequencer_bedrock_actor::error::Error>> for Error {
    fn from(err: kameo::error::SendError<M, sequencer_bedrock_actor::error::Error>) -> Self {
        Self::BedrockRequestFailed(err.erase_message())
    }
}

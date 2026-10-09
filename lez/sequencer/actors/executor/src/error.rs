use sequencer_actors_common::{EraseMessage as _, ErasedMessage};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("One of the sequencer's background tasks has finished unexpectedly")]
    BackgroundTaskFinishedUnexpectedly,

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

    /// Metering is a full apply on the head state, so this is the failure
    /// settlement would hit: an effect the state cannot absorb (insufficient
    /// balance, a program refusing the write, the gas budget), a shard that
    /// changed since the wallet planned, or an unknown program.
    #[error("The private transaction's public effects fail on the head state")]
    PrivateEffectsFailed(#[source] anyhow::Error),

    #[error("The public transaction would be rejected at settlement")]
    PublicDryRunFailed(#[source] anyhow::Error),

    /// `dryRunPublicTransaction` was given a privacy-preserving transaction.
    /// Those are priced by `dryRunPrivateEffects` on their deferred
    /// public effects, before the proof exists.
    #[error("Only a public transaction can be dry-run; a privacy-preserving one was given")]
    DryRunNotPublic,
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

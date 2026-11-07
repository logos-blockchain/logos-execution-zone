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

    /// The transaction can never be valid: a signer fails authentication at its account's nonce,
    /// or its nonce is below its account's.
    #[error("Invalid transaction")]
    InvalidTransaction(#[source] lee::error::LeeError),

    /// A signer ahead of its account's nonce fails against the key a pending transaction in
    /// this node's mempool commits it to.
    #[error("Fails authentication against a pending transaction")]
    PendingAuthentication(#[source] lee::error::LeeError),

    /// A slot the transaction claims is already pending, or a signer's account is at its limit.
    #[error("Refused by the mempool")]
    PendingSlot(#[source] sequencer_core::pending::PendingRefusal),

    /// A privacy-preserving transaction's reserve the head fee outgrew: priced again off a fresh
    /// quote, it may pass.
    #[error(
        "Privacy-preserving fee reserve {reserve} is below the {required} required at the head"
    )]
    PrivateFeeBelowHead { required: u128, reserve: u128 },
}

impl Error {
    /// Whether the transaction can never be valid, whatever the node's head: fee and mempool
    /// refusals depend on the head, and may pass elsewhere or later.
    #[must_use]
    pub const fn is_definitive(&self) -> bool {
        matches!(self, Self::InvalidTransaction(_))
    }
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

use chain_state::ChainMismatch;
use kameo::error::SendError;
use lee_core::BlockId;
use sequencer_actors_common::{ErasedMessage, SendErrorExt as _};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Sequencer store diverges from the Bedrock channel ({0}). \
         Delete the sequencer storage directory or point at the correct channel."
    )]
    StoreAndChannelDivergence(ChainMismatch),

    #[error("Invalid sequencer key")]
    InvalidSequencerKey,

    #[error("Signing key is not provided")]
    InvalidSigningKey(#[source] anyhow::Error),

    #[error("Failed to (de-)encode checkpoint")]
    CheckpointEncodingFailed(#[source] anyhow::Error),

    #[error("Founding committee contains no keys")]
    FoundingCommitteeContainsNoKeys,

    #[error("Failed to reconstruct block {block_id} while bootstrapping")]
    BlockReconstructionFailed {
        block_id: BlockId,
        #[source]
        source: chain_state::ingest_error::BlockIngestError,
    },

    #[error(
        "sequencer_stake config account is absent or undecodable; \
         this chain's state is not one this sequencer can operate on"
    )]
    SequencerStakeConfigNotFound,

    #[error("The sequencer is not online, wait until bootstrap completes")]
    NotOnline,

    #[error("One of the sequencer's background tasks has finished unexpectedly")]
    BackgroundTaskFinishedUnexpectedly,

    #[error("The sequencer's block publisher has finished unexpectedly")]
    BlockPublisherFinishedUnexpectedly,

    #[error("The mempool is full")]
    MempoolIsFull,

    #[error("Failed to start the sequencer")]
    SequencerStartFailed(#[source] anyhow::Error),

    #[error("Storage inconsistency detected: {0}")]
    StorageInconsistency(String),

    #[error("Storage request failed")]
    StorageRequestFailed(#[source] SendError<ErasedMessage, sequencer_storage_actor::error::Error>),

    #[error("Bedrock request failed")]
    BedrockRequestFailed(#[source] SendError<ErasedMessage, sequencer_bedrock_actor::error::Error>),

    #[error("Failed to read the cross-zone dead letter")]
    CrossZoneDeadLettersUnavailable(#[source] anyhow::Error),

    #[error("Failed to requeue the cross-zone dead letter")]
    CrossZoneDeadLetterRequeueFailed(#[source] anyhow::Error),

    #[error("Incorrect fee")]
    IncorrectFee(#[source] anyhow::Error),
}

impl<M> From<SendError<M, sequencer_storage_actor::error::Error>> for Error {
    fn from(err: SendError<M, sequencer_storage_actor::error::Error>) -> Self {
        Self::StorageRequestFailed(err.erase_message())
    }
}

impl<M> From<SendError<M, sequencer_bedrock_actor::error::Error>> for Error {
    fn from(err: SendError<M, sequencer_bedrock_actor::error::Error>) -> Self {
        Self::BedrockRequestFailed(err.erase_message())
    }
}

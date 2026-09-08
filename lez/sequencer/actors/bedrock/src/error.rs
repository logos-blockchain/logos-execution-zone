use kameo::error::Infallible;
use sequencer_actors_common::{EraseMessage as _, ErasedMessage};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage request failed")]
    StorageRequestFailed(
        #[source] kameo::error::SendError<ErasedMessage, sequencer_storage_actor::error::Error>,
    ),

    #[error("Broker publish failed")]
    BrokerPublishFailed(#[source] kameo::error::SendError<ErasedMessage, Infallible>),

    #[error("Checkpoint (de-)serialization failed")]
    CheckpointSerializationFailed(#[from] logos_blockchain_core::codec::Error),

    #[error("Zone-sdk readiness channel closed before becoming ready")]
    ReadinessChannelClosed,

    #[error("Node request failed")]
    NodeRequestFailed(#[source] anyhow::Error),

    #[error("Transaction build failed")]
    TransactionBuildFailed(#[from] logos_blockchain_core::mantle::transactions::TxBuilderError),

    #[error("Creating the channel requires our own key first; creation gives the turn to index 0")]
    ChannelCreationRequiresOurKey,

    #[error("Block encoding failed")]
    BlockEncodingFailed(#[source] std::io::Error),

    #[error("Block exceeds maximum allowed size")]
    BlockTooLarge,

    #[error("Inscription exceeds maximum allowed size")]
    InscriptionTooLarge,

    #[error("Invalid channel key list")]
    InvalidChannelKeyList(#[source] anyhow::Error),

    #[error("Failed to assemble channel multi-sig proof")]
    ChannelMultiSigProofAssemblyFailed(
        #[from] logos_blockchain_core::proofs::channel_multi_sig_proof::Error,
    ),

    #[error("Too many operation proofs")]
    TooManyOperationProofs(#[source] anyhow::Error),

    #[error("Failed to submit signed transaction")]
    SubmitSignedTransactionFailed(#[source] anyhow::Error),

    #[error("Failed to publish atomic withdraw transaction")]
    PublishAtomicWithdrawFailed(#[source] anyhow::Error),

    // TODO: Not a technical limitation, but rather a complexity of dealing with zone sdk
    #[error("Cannot publish block on parent with withdrawals")]
    CannotPublishBlockOnParentWithWithdrawals,

    #[error("Zone-sdk error")]
    ZoneSdkError(#[from] logos_blockchain_zone_sdk::sequencer::Error),
}

impl<M> From<kameo::error::SendError<M, sequencer_storage_actor::error::Error>> for Error {
    fn from(err: kameo::error::SendError<M, sequencer_storage_actor::error::Error>) -> Self {
        Self::StorageRequestFailed(err.erase_message())
    }
}

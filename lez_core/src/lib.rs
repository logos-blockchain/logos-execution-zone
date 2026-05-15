use nssa::AccountId;

pub mod privacy_preserving_tx;

#[derive(Debug, thiserror::Error)]
pub enum ExecutionFailureKind {
    #[error("Failed to get data from sequencer")]
    SequencerError(#[source] anyhow::Error),
    #[error("Inputs amounts does not match outputs")]
    AmountMismatchError,
    #[error("Accounts key not found")]
    KeyNotFoundError,
    #[error("Sequencer client error")]
    SequencerClientError(#[from] sequencer_service_rpc::ClientError),
    #[error("Can not pay for operation")]
    InsufficientFundsError,
    #[error("Account {0} data is invalid")]
    AccountDataError(AccountId),
    #[error("Failed to build transaction: {0}")]
    TransactionBuildError(#[from] nssa::error::NssaError),
}
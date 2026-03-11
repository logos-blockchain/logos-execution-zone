use nssa::AccountId;
use serde::Deserialize;

use crate::rpc_primitives::errors::RpcError;

#[derive(Debug, Clone, Deserialize)]
pub struct SequencerRpcError {
    pub jsonrpc: String,
    pub error: RpcError,
    pub id: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum SequencerClientError {
    #[error("HTTP error")]
    HTTPError(#[from] reqwest::Error),
    #[error("Serde error")]
    SerdeError(#[from] serde_json::Error),
    #[error("Internal error: {0:?}")]
    InternalError(SequencerRpcError),
}

impl From<SequencerRpcError> for SequencerClientError {
    fn from(value: SequencerRpcError) -> Self {
        Self::InternalError(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionFailureKind {
    #[error("Failed to get data from sequencer")]
    SequencerError(#[source] anyhow::Error),
    #[error("Inputs amounts does not match outputs")]
    AmountMismatchError,
    #[error("Accounts key not found")]
    KeyNotFoundError,
    #[error("Sequencer client error: {0:?}")]
    SequencerClientError(#[from] SequencerClientError),
    #[error("Can not pay for operation")]
    InsufficientFundsError,
    #[error("Account {0} data is invalid")]
    AccountDataError(AccountId),
}

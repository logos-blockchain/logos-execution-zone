//! An enum rather than a generic wrapper, so no other wallet function has to dispatch.

use std::collections::BTreeMap;

use lee::Actor;
use lee_core::CommitmentPosition;
use sequencer_service_rpc::{ClientError, SequencerClient};
use wallet::{ExecutionFailureKind, WalletSequencerClient};

use crate::sequencer_ffi_client::{FfiSequencerClientError, SequencerServiceFFIWrapper};

#[derive(Clone)]
pub enum WalletClient {
    Embedded(SequencerServiceFFIWrapper),
    Http(SequencerClient),
}

#[derive(Debug, thiserror::Error)]
pub enum WalletClientError {
    #[error(transparent)]
    Embedded(#[from] FfiSequencerClientError),
    #[error(transparent)]
    Http(#[from] ClientError),
}

impl From<WalletClientError> for ExecutionFailureKind {
    fn from(value: WalletClientError) -> Self {
        match value {
            WalletClientError::Embedded(e) => e.into(),
            WalletClientError::Http(e) => e.into(),
        }
    }
}

impl WalletSequencerClient for WalletClient {
    type Error = WalletClientError;

    async fn send_transaction(
        &self,
        tx: common::transaction::LeeTransaction,
    ) -> Result<common::HashType, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.send_transaction(tx).await?),
            Self::Http(client) => Ok(client.send_transaction(tx).await?),
        }
    }

    async fn get_block(
        &self,
        block_id: lee_core::BlockId,
    ) -> Result<Option<common::block::Block>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_block(block_id).await?),
            Self::Http(client) => Ok(client.get_block(block_id).await?),
        }
    }

    async fn get_block_range(
        &self,
        start_block_id: lee_core::BlockId,
        end_block_id: lee_core::BlockId,
    ) -> Result<Vec<common::block::Block>, Self::Error> {
        match self {
            Self::Embedded(client) => {
                Ok(client.get_block_range(start_block_id, end_block_id).await?)
            }
            Self::Http(client) => Ok(client.get_block_range(start_block_id, end_block_id).await?),
        }
    }

    async fn get_last_block_id(&self) -> Result<lee_core::BlockId, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_last_block_id().await?),
            Self::Http(client) => Ok(client.get_last_block_id().await?),
        }
    }

    async fn get_account_balance(&self, account_id: lee::AccountId) -> Result<u128, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_account_balance(account_id).await?),
            Self::Http(client) => Ok(client.get_account_balance(account_id).await?),
        }
    }

    async fn get_transaction(
        &self,
        tx_hash: common::HashType,
    ) -> Result<Option<(common::transaction::LeeTransaction, lee_core::BlockId)>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_transaction(tx_hash).await?),
            Self::Http(client) => Ok(client.get_transaction(tx_hash).await?),
        }
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<lee::AccountId>,
    ) -> Result<Vec<lee_core::account::Nonce>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_accounts_nonces(account_ids).await?),
            Self::Http(client) => Ok(client.get_accounts_nonces(account_ids).await?),
        }
    }

    async fn get_account_view(
        &self,
        actor_state_selector: Actor,
    ) -> Result<Option<lee::Account>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_account_view(actor_state_selector).await?),
            Self::Http(client) => Ok(client.get_account_view(actor_state_selector).await?),
        }
    }

    async fn get_proofs_and_root(
        &self,
        commitments: Vec<lee_core::Commitment>,
        message_positions: Vec<CommitmentPosition>,
    ) -> Result<
        (
            Vec<Option<lee_core::MembershipProof>>,
            Vec<Option<lee_core::MembershipProof>>,
            lee_core::CommitmentSetDigest,
        ),
        Self::Error,
    > {
        match self {
            Self::Embedded(client) => Ok(client
                .get_proofs_and_root(commitments, message_positions)
                .await?),
            Self::Http(client) => Ok(client
                .get_proofs_and_root(commitments, message_positions)
                .await?),
        }
    }

    async fn get_fee_state(&self) -> Result<wallet::FeeStateQuote, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_fee_state().await?),
            Self::Http(client) => Ok(client.get_fee_state().await?),
        }
    }

    async fn get_account(
        &self,
        account_id: lee::AccountId,
    ) -> Result<Option<lee::Account>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_account(account_id).await?),
            Self::Http(client) => Ok(client.get_account(account_id).await?),
        }
    }

    async fn get_program_ids(&self) -> Result<BTreeMap<String, lee::ProgramId>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_program_ids().await?),
            Self::Http(client) => Ok(client.get_program_ids().await?),
        }
    }

    async fn get_publications(
        &self,
        from_position: CommitmentPosition,
        limit: common::PageLimit,
    ) -> Result<Vec<(CommitmentPosition, lee::Publication)>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_publications(from_position, limit).await?),
            Self::Http(client) => Ok(client.get_publications(from_position, limit).await?),
        }
    }

    async fn get_recovery_binding(
        &self,
        address: lee::AccountId,
    ) -> Result<Option<lee::EncryptedNote>, Self::Error> {
        match self {
            Self::Embedded(client) => Ok(client.get_recovery_binding(address).await?),
            Self::Http(client) => Ok(client.get_recovery_binding(address).await?),
        }
    }
}

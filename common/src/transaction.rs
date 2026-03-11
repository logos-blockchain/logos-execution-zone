use borsh::{BorshDeserialize, BorshSerialize};
use log::warn;
use nssa::{AccountId, V02State};
use serde::{Deserialize, Serialize};

use crate::HashType;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NSSATransaction {
    Public(nssa::PublicTransaction),
    PrivacyPreserving(nssa::PrivacyPreservingTransaction),
    ProgramDeployment(nssa::ProgramDeploymentTransaction),
}

impl NSSATransaction {
    #[must_use]
    pub fn hash(&self) -> HashType {
        HashType(match self {
            Self::Public(tx) => tx.hash(),
            Self::PrivacyPreserving(tx) => tx.hash(),
            Self::ProgramDeployment(tx) => tx.hash(),
        })
    }

    #[must_use]
    pub fn affected_public_account_ids(&self) -> Vec<AccountId> {
        match self {
            Self::ProgramDeployment(tx) => tx.affected_public_account_ids(),
            Self::Public(tx) => tx.affected_public_account_ids(),
            Self::PrivacyPreserving(tx) => tx.affected_public_account_ids(),
        }
    }

    // TODO: Introduce type-safe wrapper around checked transaction, e.g. AuthenticatedTransaction
    pub fn transaction_stateless_check(self) -> Result<Self, TransactionMalformationError> {
        // Stateless checks here
        match self {
            Self::Public(tx) => {
                if tx.witness_set().is_valid_for(tx.message()) {
                    Ok(Self::Public(tx))
                } else {
                    Err(TransactionMalformationError::InvalidSignature)
                }
            }
            Self::PrivacyPreserving(tx) => {
                if tx.witness_set().signatures_are_valid_for(tx.message()) {
                    Ok(Self::PrivacyPreserving(tx))
                } else {
                    Err(TransactionMalformationError::InvalidSignature)
                }
            }
            Self::ProgramDeployment(tx) => Ok(Self::ProgramDeployment(tx)),
        }
    }

    pub fn execute_check_on_state(
        self,
        state: &mut V02State,
    ) -> Result<Self, nssa::error::NssaError> {
        match &self {
            Self::Public(tx) => state.transition_from_public_transaction(tx),
            Self::PrivacyPreserving(tx) => state.transition_from_privacy_preserving_transaction(tx),
            Self::ProgramDeployment(tx) => state.transition_from_program_deployment_transaction(tx),
        }
        .inspect_err(|err| warn!("Error at transition {err:#?}"))?;

        Ok(self)
    }
}

impl From<nssa::PublicTransaction> for NSSATransaction {
    fn from(value: nssa::PublicTransaction) -> Self {
        Self::Public(value)
    }
}

impl From<nssa::PrivacyPreservingTransaction> for NSSATransaction {
    fn from(value: nssa::PrivacyPreservingTransaction) -> Self {
        Self::PrivacyPreserving(value)
    }
}

impl From<nssa::ProgramDeploymentTransaction> for NSSATransaction {
    fn from(value: nssa::ProgramDeploymentTransaction) -> Self {
        Self::ProgramDeployment(value)
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize,
)]
pub enum TxKind {
    Public,
    PrivacyPreserving,
    ProgramDeployment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum TransactionMalformationError {
    #[error("Invalid signature(-s)")]
    InvalidSignature,
    #[error("Failed to decode transaction with hash: {tx:?}")]
    FailedToDecode { tx: HashType },
    #[error("Transaction size {size} exceeds maximum allowed size of {max} bytes")]
    TransactionTooLarge { size: usize, max: usize },
}

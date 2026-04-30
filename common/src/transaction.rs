use borsh::{BorshDeserialize, BorshSerialize};
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use log::warn;
use nssa::{AccountId, V03State, ValidatedStateDiff};
use nssa_core::{BlockId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::HashType;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NSSATransaction {
    Public(nssa::PublicTransaction),
    PrivacyPreserving(nssa::PrivacyPreservingTransaction),
    ProgramDeployment(nssa::ProgramDeploymentTransaction),
}

impl Serialize for NSSATransaction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::borsh_base64::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for NSSATransaction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::borsh_base64::deserialize(deserializer)
    }
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

    /// Validates the transaction against the current state and returns the resulting diff
    /// without applying it. Rejects transactions that modify clock system accounts.
    pub fn validate_on_state(
        &self,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<ValidatedStateDiff, nssa::error::NssaError> {
        let diff = match self {
            Self::Public(tx) => {
                ValidatedStateDiff::from_public_transaction(tx, state, block_id, timestamp)
            }
            Self::PrivacyPreserving(tx) => ValidatedStateDiff::from_privacy_preserving_transaction(
                tx, state, block_id, timestamp,
            ),
            Self::ProgramDeployment(tx) => {
                ValidatedStateDiff::from_program_deployment_transaction(tx, state)
            }
        }?;

        let public_diff = diff.public_diff();
        let touches_clock = nssa::CLOCK_PROGRAM_ACCOUNT_IDS.iter().any(|id| {
            public_diff
                .get(id)
                .is_some_and(|post| *post != state.get_account_by_id(*id))
        });
        if touches_clock {
            return Err(nssa::error::NssaError::InvalidInput(
                "Transaction modifies system clock accounts".into(),
            ));
        }

        Ok(diff)
    }

    /// Validates the transaction against the current state, rejects modifications to clock
    /// system accounts, and applies the resulting diff to the state.
    pub fn execute_check_on_state(
        self,
        state: &mut V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, nssa::error::NssaError> {
        let diff = self
            .validate_on_state(state, block_id, timestamp)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        state.apply_state_diff(diff);
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
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
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

impl From<TransactionMalformationError> for ErrorObjectOwned {
    fn from(err: TransactionMalformationError) -> Self {
        ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), err.to_string(), None::<()>)
    }
}

/// Returns the canonical Clock Program invocation transaction for the given block timestamp.
/// Every valid block must end with exactly one occurrence of this transaction.
#[must_use]
pub fn clock_invocation(timestamp: clock_core::Instruction) -> nssa::PublicTransaction {
    let message = nssa::public_transaction::Message::try_new(
        nssa::program::Program::clock().id(),
        clock_core::CLOCK_PROGRAM_ACCOUNT_IDS.to_vec(),
        vec![],
        timestamp,
    )
    .expect("Clock invocation message should always be constructable");
    nssa::PublicTransaction::new(
        message,
        nssa::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

#[cfg(test)]
mod malformation_error_tests {
    use jsonrpsee::types::ErrorCode;

    use super::*;

    #[test]
    fn from_too_large_produces_invalid_params_code() {
        let err = TransactionMalformationError::TransactionTooLarge { size: 100, max: 50 };
        let rpc_err: jsonrpsee::types::ErrorObjectOwned = err.into();
        assert_eq!(rpc_err.code(), ErrorCode::InvalidParams.code());
        assert!(rpc_err.message().contains("exceeds maximum"));
    }

    #[test]
    fn from_failed_decode_produces_invalid_params_code() {
        let err = TransactionMalformationError::FailedToDecode { tx: crate::HashType([0; 32]) };
        let rpc_err: jsonrpsee::types::ErrorObjectOwned = err.into();
        assert_eq!(rpc_err.code(), ErrorCode::InvalidParams.code());
    }

    #[test]
    fn from_invalid_signature_produces_invalid_params_code() {
        let err = TransactionMalformationError::InvalidSignature;
        let rpc_err: jsonrpsee::types::ErrorObjectOwned = err.into();
        assert_eq!(rpc_err.code(), ErrorCode::InvalidParams.code());
    }
}

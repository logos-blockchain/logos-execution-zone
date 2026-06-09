use borsh::{BorshDeserialize, BorshSerialize};
use lee::{AccountId, V03State, ValidatedStateDiff};
use lee_core::{BlockId, Timestamp};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::HashType;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum LeeTransaction {
    Public(lee::PublicTransaction),
    PrivacyPreserving(lee::PrivacyPreservingTransaction),
    ProgramDeployment(lee::ProgramDeploymentTransaction),
}

impl Serialize for LeeTransaction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::borsh_base64::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for LeeTransaction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::borsh_base64::deserialize(deserializer)
    }
}

impl LeeTransaction {
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
    /// without applying it. Rejects transactions that modify clock, faucet or bridge accounts,
    /// whether directly or indirectly via chain calls.
    ///
    /// This check is required for all user transactions. Only sequencer transactions may bypass
    /// this check.
    pub fn validate_on_state(
        &self,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<ValidatedStateDiff, lee::error::LeeError> {
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

        let system_accounts = lee::CLOCK_PROGRAM_ACCOUNT_IDS.iter().copied().chain([
            lee::system_faucet_account_id(),
            lee::system_bridge_account_id(),
        ]);
        for account_id in system_accounts {
            validate_doesnt_modify_account(state, &diff, account_id)?;
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
    ) -> Result<Self, lee::error::LeeError> {
        let diff = self
            .validate_on_state(state, block_id, timestamp)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        state.apply_state_diff(diff);
        Ok(self)
    }
}

impl From<lee::PublicTransaction> for LeeTransaction {
    fn from(value: lee::PublicTransaction) -> Self {
        Self::Public(value)
    }
}

impl From<lee::PrivacyPreservingTransaction> for LeeTransaction {
    fn from(value: lee::PrivacyPreservingTransaction) -> Self {
        Self::PrivacyPreserving(value)
    }
}

impl From<lee::ProgramDeploymentTransaction> for LeeTransaction {
    fn from(value: lee::ProgramDeploymentTransaction) -> Self {
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
}

/// Returns the canonical Clock Program invocation transaction for the given block timestamp.
/// Every valid block must end with exactly one occurrence of this transaction.
#[must_use]
pub fn clock_invocation(timestamp: clock_core::Instruction) -> lee::PublicTransaction {
    let message = lee::public_transaction::Message::try_new(
        lee::program::Program::clock().id(),
        clock_core::CLOCK_PROGRAM_ACCOUNT_IDS.to_vec(),
        vec![],
        timestamp,
    )
    .expect("Clock invocation message should always be constructable");
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

fn validate_doesnt_modify_account(
    state: &V03State,
    diff: &ValidatedStateDiff,
    account_id: AccountId,
) -> Result<(), lee::error::LeeError> {
    if diff
        .public_diff()
        .get(&account_id)
        .is_some_and(|post| *post != state.get_account_by_id(account_id))
    {
        Err(lee::error::LeeError::InvalidInput(format!(
            "Transaction modifies restricted system account {account_id}"
        )))
    } else {
        Ok(())
    }
}

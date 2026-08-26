use borsh::{BorshDeserialize, BorshSerialize};
use lee::{AccountId, V03State, ValidatedStateDiff};
use lee_core::{BlockId, Timestamp, account::SlotRef};
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
    pub const fn kind(&self) -> TxKind {
        match self {
            Self::Public(_) => TxKind::Public,
            Self::PrivacyPreserving(_) => TxKind::PrivacyPreserving,
            Self::ProgramDeployment(_) => TxKind::ProgramDeployment,
        }
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
        let diff = self.compute_state_diff(state, block_id, timestamp)?;

        let restricted_modification_accounts = system_accounts::clock_account_ids()
            .into_iter()
            .chain(std::iter::once(system_accounts::faucet_account_id()));
        for account_id in restricted_modification_accounts {
            validate_doesnt_modify_account(state, &diff, account_id)?;
        }

        self.validate_bridge_account_modification(state, &diff)?;

        Ok(diff)
    }

    /// Computes the validated state diff. Shared by [`Self::validate_on_state`]
    /// (which adds the system-account guards) and [`Self::execute_on_state`].
    fn compute_state_diff(
        &self,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<ValidatedStateDiff, lee::error::LeeError> {
        match self {
            Self::Public(tx) => {
                ValidatedStateDiff::from_public_transaction(tx, state, block_id, timestamp)
            }
            Self::PrivacyPreserving(tx) => ValidatedStateDiff::from_privacy_preserving_transaction(
                tx, state, block_id, timestamp,
            ),
            Self::ProgramDeployment(tx) => {
                ValidatedStateDiff::from_program_deployment_transaction(tx, state)
            }
        }
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

    /// Executes the transaction against the current state and applies the resulting diff,
    /// without the system-account guards enforced by [`Self::execute_check_on_state`].
    ///
    /// The indexer replays blocks the sequencer already validated and inscribed on Bedrock,
    /// so it trusts those inscriptions and re-derives state without re-validating them.
    pub fn execute_on_state(
        self,
        state: &mut V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, lee::error::LeeError> {
        let diff = self
            .compute_state_diff(state, block_id, timestamp)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        state.apply_state_diff(diff);
        Ok(self)
    }

    fn validate_bridge_account_modification(
        &self,
        state: &V03State,
        diff: &ValidatedStateDiff,
    ) -> Result<(), lee::error::LeeError> {
        let bridge_account_id = system_accounts::bridge_account_id();
        let pre = state.get_account_by_id(bridge_account_id);
        let Some(post) = diff.public_diff().get(&bridge_account_id).cloned() else {
            return Ok(());
        };

        let Self::Public(_) = self else {
            return Err(lee::error::LeeError::InvalidInput(format!(
                "Non-public transaction cannot modify system bridge account {bridge_account_id}"
            )));
        };

        let only_balance_increased = {
            // Rebuild the pre-image implied by "post is pre plus credits": copy post, wind
            // every slot balance back to its pre value, and prune. Any data/nonce/key change
            // then shows up as a mismatch, and debits are refused explicitly per slot.
            let mut expected_pre = post.clone();
            for (program_id, slot) in &mut expected_pre.slots {
                slot.balance = pre.balance(*program_id);
            }
            expected_pre.prune();

            let no_debit = post
                .slots
                .iter()
                .all(|(program_id, slot)| slot.balance >= pre.balance(*program_id));
            let some_credit = post
                .slots
                .iter()
                .any(|(program_id, slot)| slot.balance > pre.balance(*program_id));
            expected_pre == pre && no_debit && some_credit
        };

        if only_balance_increased {
            Ok(())
        } else {
            Err(lee::error::LeeError::InvalidInput(format!(
                "Transaction modifies restricted system bridge account {bridge_account_id}"
            )))
        }
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
    #[error("Failed to decode transaction with hash: {tx:?}")]
    FailedToDecode { tx: HashType },
    #[error("Transaction size {size} exceeds maximum allowed size of {max} bytes")]
    TransactionTooLarge { size: usize, max: usize },
}

/// Returns the canonical Clock Program invocation transaction for the given block timestamp.
/// Every valid block must end with exactly one occurrence of this transaction.
#[must_use]
pub fn clock_invocation(timestamp: clock_core::Instruction) -> lee::PublicTransaction {
    let message = lee::public_transaction::Message::try_new(
        programs::clock().id(),
        clock_core::CLOCK_PROGRAM_ACCOUNT_IDS
            .iter()
            .map(|account_id| SlotRef::new(*account_id, programs::clock().id()))
            .collect(),
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

#[cfg(test)]
mod tests {
    use lee::{Account, AccountId, PrivateKey, PublicKey, V03State};
    use lee_core::account::Nonce;

    use super::validate_doesnt_modify_account;
    use crate::test_utils::{
        any_public_transaction, create_transaction_native_token_transfer, state_and_diff,
    };

    #[test]
    fn bridge_guard_allows_balance_only_increase() {
        // A diff that *only* increases the bridge balance (the legitimate deposit shape)
        // must be accepted.
        let bridge_id = system_accounts::bridge_account_id();
        let native = programs::native();
        let pre = Account::single(native, 500, lee::Data::default(), Nonce(7));
        let mut post = pre.clone();
        post.slot_mut(native).balance = 600;
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        let tx = any_public_transaction();
        assert!(
            tx.validate_bridge_account_modification(&state, &diff)
                .is_ok(),
            "a balance-only increase of the bridge account must be allowed",
        );
    }

    #[test]
    fn bridge_guard_rejects_data_modification_even_when_balance_increases() {
        // A diff that changes the bridge account's data (here: the nonce) while *also*
        // increasing its balance must be rejected.
        let bridge_id = system_accounts::bridge_account_id();
        let native = programs::native();
        let pre = Account::single(native, 500, lee::Data::default(), Nonce(7));
        let mut post = pre.clone();
        post.slot_mut(native).balance = 600;
        post.nonce = Nonce(8);
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        let tx = any_public_transaction();
        assert!(
            tx.validate_bridge_account_modification(&state, &diff)
                .is_err(),
            "modifying bridge account data must be rejected even if the balance increases",
        );
    }

    #[test]
    fn bridge_guard_rejects_zero_value_deposit() {
        // A diff that touches the bridge account without *strictly* increasing its balance
        // must be rejected — a zero-value deposit is not a real credit.
        let bridge_id = system_accounts::bridge_account_id();
        let native = programs::native();
        let pre = Account::single(native, 500, lee::Data::default(), Nonce(7));
        let post = pre.clone();
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        let tx = any_public_transaction();
        assert!(
            tx.validate_bridge_account_modification(&state, &diff)
                .is_err(),
            "a bridge diff that does not strictly increase the balance must be rejected",
        );
    }

    #[test]
    fn validate_doesnt_modify_account_flags_a_changed_account() {
        // Directly exercise the system-account guard with a diff that genuinely changes a
        // clock account, then with one that leaves it untouched. The inverted comparison would
        // treat a changed account as unchanged and wave it through (and would flag an *unchanged*
        // account instead).
        let clock_id = system_accounts::clock_account_ids()[0];
        let native = programs::native();
        let pre = Account::single(native, 1_000, lee::Data::default(), Nonce::default());

        let mut changed = pre.clone();
        changed.slot_mut(native).balance = 2_000;
        let (state, diff) = state_and_diff(clock_id, pre.clone(), changed);
        assert!(
            validate_doesnt_modify_account(&state, &diff, clock_id).is_err(),
            "a diff that changes a system account must be rejected",
        );

        let (unchanged_state, unchanged_diff) = state_and_diff(clock_id, pre.clone(), pre);
        assert!(
            validate_doesnt_modify_account(&unchanged_state, &unchanged_diff, clock_id).is_ok(),
            "a diff that leaves a system account unchanged must be accepted",
        );
    }

    #[test]
    fn system_account_ids_are_distinct_and_non_default() {
        let faucet = system_accounts::faucet_account_id();
        let bridge = system_accounts::bridge_account_id();
        assert_ne!(faucet, AccountId::default());
        assert_ne!(bridge, AccountId::default());
        assert_ne!(faucet, bridge);
    }

    #[test]
    fn validate_on_state_rejects_modifying_a_system_account() {
        // A native transfer that credits a clock system account *changes* that
        // account, so `validate_doesnt_modify_account` must reject it.  Catches
        // the `!=` → `==` inversion at `validate_doesnt_modify_account` (a changed
        // account would no longer be flagged) and `public_diff → HashMap::new()`
        // (an empty diff hides the modification).
        let sender_key = PrivateKey::try_new([5_u8; 32]).expect("valid key");
        let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
        let state = V03State::new().with_public_account_balances(
            programs::authenticated_transfer().id(),
            [(sender_id, 10_000)],
        );

        let tx = create_transaction_native_token_transfer(
            sender_id,
            0,
            system_accounts::clock_account_ids()[0],
            100,
            &sender_key,
        );

        assert!(
            tx.validate_on_state(&state, 1, 0).is_err(),
            "validate_on_state must reject a transfer that credits a clock system account",
        );
    }
}

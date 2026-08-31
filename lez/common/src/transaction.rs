use borsh::{BorshDeserialize, BorshSerialize};
use lee::{AccountId, V03State, ValidatedStateDiff};
use lee_core::{BlockId, Timestamp, program::TransactionEvent};
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
        validate_no_restricted_account_modification(state, &diff)?;
        validate_bridge_account_modification(state, &diff, matches!(self, Self::Public(_)))?;
        Ok(diff)
    }

    /// Computes the validated state diff. Shared by [`Self::validate_on_state`]
    /// (which adds the system-account guards) and [`Self::execute_on_state`].
    pub fn compute_state_diff(
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
        drop(state.apply_state_diff(diff));
        Ok(self)
    }

    /// Executes the transaction against the current state and applies the resulting diff,
    /// without the system-account guards enforced by [`Self::execute_check_on_state`].
    ///
    /// The indexer replays blocks the sequencer already validated and inscribed on Bedrock,
    /// so it trusts those inscriptions and re-derives state without re-validating them.
    ///
    /// Returns the events the transaction emitted.
    pub fn execute_on_state(
        &self,
        state: &mut V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Vec<TransactionEvent>, lee::error::LeeError> {
        let diff = self
            .compute_state_diff(state, block_id, timestamp)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        Ok(state.apply_state_diff(diff))
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

/// A struct encoding a vector of transaction events alongside a fingerprint of a
/// transaction which emitted it relative to the block it was in.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxEvents {
    // Index of an emitting transaction in a block.
    pub tx_index: u32,
    // Hash of the emitting transaction.
    pub tx_hash: HashType,
    // Vector of events in the order of emission.
    pub events: Vec<TransactionEvent>,
}

/// Returns the canonical Clock Program invocation transaction for the given block timestamp.
/// Every valid block must end with exactly one occurrence of this transaction.
#[must_use]
pub fn clock_invocation(timestamp: clock_core::Instruction) -> lee::PublicTransaction {
    let message = lee::public_transaction::Message::try_new(
        programs::clock().id(),
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

/// Whether `tx` is a sequencer-injected or account-less system transaction.
///
/// Identified by shape: an empty witness set invoking the bridge deposit, the
/// cross-zone inbox dispatch, or the `ping_sender` cross-zone send. Fee- and
/// cap-exempt. Shared by the sequencer (build) and the transition (replay) so
/// the two can never disagree.
///
/// Cross-zone traffic is exempt by design, not as a stopgap: an outbound send
/// is account-less (there is no payer to charge) and an inbound dispatch is
/// sequencer-injected, so neither can carry a fee.
#[must_use]
pub fn is_system_injection(tx: &LeeTransaction) -> bool {
    let LeeTransaction::Public(public_tx) = tx else {
        return false;
    };
    if !public_tx
        .witness_set()
        .signatures_and_public_keys()
        .is_empty()
    {
        return false;
    }
    let message = public_tx.message();
    if message.program_id == programs::bridge().id() {
        return matches!(
            borsh::from_slice::<bridge_core::Instruction>(&message.instruction_data),
            Ok(bridge_core::Instruction::Deposit { .. })
        );
    }
    if message.program_id == programs::cross_zone_inbox().id() {
        return matches!(
            borsh::from_slice::<cross_zone_inbox_core::Instruction>(&message.instruction_data),
            Ok(cross_zone_inbox_core::Instruction::Dispatch(_))
        );
    }
    if message.program_id == programs::ping_sender().id() {
        return matches!(
            borsh::from_slice::<ping_core::SenderInstruction>(&message.instruction_data),
            Ok(ping_core::SenderInstruction::Send { .. })
        );
    }
    false
}

/// Whether `tx` is a full-sweep vault claim.
///
/// A `vault::Claim` whose amount equals the vault's entire balance in `state`.
/// Fee-exempt by the bootstrap decision — all funding lands in vaults while
/// fees debit account balances, so a charged first claim could never pay.
/// Asked against the working state at the transaction's turn.
///
/// FIXME: this can be removed after Vault is removed.
#[must_use]
pub fn is_full_vault_sweep(tx: &LeeTransaction, state: &V03State) -> bool {
    let LeeTransaction::Public(public_tx) = tx else {
        return false;
    };

    let message = public_tx.message();
    if message.program_id != programs::vault().id() {
        return false;
    }

    let Ok(vault_core::Instruction::Claim { amount }) =
        borsh::from_slice::<vault_core::Instruction>(&message.instruction_data)
    else {
        return false;
    };

    let [owner_id, vault_id] = message.account_ids.as_slice() else {
        return false;
    };
    if *vault_id != vault_core::compute_vault_account_id(programs::vault().id(), *owner_id) {
        return false;
    }

    amount != 0 && amount == state.get_account_by_id(*vault_id).balance
}

/// Returns the canonical Fee Program invocation transaction for the given block fee summary.
///
/// Every valid block must contain exactly one occurrence of this transaction as its
/// second-to-last transaction, immediately before the clock invocation. The producer
/// account rides as the fourth account so the guest can pay it.
#[must_use]
pub fn fee_invocation(
    summary: fee_core::BlockFeeSummary,
    producer: lee::AccountId,
) -> lee::PublicTransaction {
    let mut account_ids = system_accounts::fee_account_ids().to_vec();
    account_ids.push(producer); // this is the 4th account
    let message = lee::public_transaction::Message::try_new(
        programs::fee().id(),
        account_ids,
        vec![],
        fee_core::Instruction::Distribute(summary),
    )
    .expect("Fee invocation message should always be constructable");
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

/// The producer account a [`fee_invocation`] credits: the entry riding after
/// the fixed fee accounts. `None` if the transaction is too short to carry one.
/// Shared by settlement and the follower's producer check so both read the
/// reward target the same way.
#[must_use]
pub fn fee_invocation_producer(fee_tx: &lee::PublicTransaction) -> Option<lee::AccountId> {
    fee_tx
        .message()
        .account_ids
        // get the 4th account, which is the producer
        .get(system_accounts::fee_account_ids().len())
        .copied()
}

/// The fee reserve: hold `amount` from `payer` in the fee inbox.
///
/// Runs `authenticated_transfer` as a fee-settlement invocation authorized by
/// the payer's fee declaration; the returned message carries only the program,
/// accounts, and instruction the invocation needs.
#[must_use]
pub fn fee_reserve_invocation(payer: AccountId, amount: u128) -> lee::public_transaction::Message {
    lee::public_transaction::Message::try_new(
        programs::authenticated_transfer().id(),
        vec![payer, system_accounts::fee_inbox_account_id()],
        vec![],
        authenticated_transfer_core::Instruction::Transfer { amount },
    )
    .expect("Fee reserve message should always be constructable")
}

/// The fee refund: return `amount` from the fee inbox to `payer`.
///
/// Runs the fee program as a fee-settlement invocation needing no authorization
/// — the fee program owns the inbox it debits.
#[must_use]
pub fn fee_refund_invocation(payer: AccountId, amount: u128) -> lee::public_transaction::Message {
    lee::public_transaction::Message::try_new(
        programs::fee().id(),
        vec![system_accounts::fee_inbox_account_id(), payer],
        vec![],
        fee_core::Instruction::Refund { amount },
    )
    .expect("Fee refund message should always be constructable")
}

/// Rejects a diff that modifies any always-restricted system account (the clock
/// accounts, the faucet, or the fee subsystem's accounts).
///
/// These are written only by their sequencer-forced invocations, never by a user
/// transaction. Enforcing this on the apply/settlement path as well as the
/// builder is what stops a block author from draining the fee inbox/escrow with a
/// user-section fee-program invocation that honest followers would otherwise
/// apply. The bridge account has its own increase-only rule
/// ([`validate_bridge_account_modification`]) and is not included here.
pub fn validate_no_restricted_account_modification(
    state: &V03State,
    diff: &ValidatedStateDiff,
) -> Result<(), lee::error::LeeError> {
    let restricted_modification_accounts = system_accounts::clock_account_ids()
        .into_iter()
        .chain(std::iter::once(system_accounts::faucet_account_id()))
        .chain(system_accounts::fee_account_ids());
    for account_id in restricted_modification_accounts {
        validate_doesnt_modify_account(state, diff, account_id)?;
    }
    Ok(())
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

pub fn validate_bridge_account_modification(
    state: &V03State,
    diff: &ValidatedStateDiff,
    is_public_tx: bool,
) -> Result<(), lee::error::LeeError> {
    let bridge_account_id = system_accounts::bridge_account_id();
    let pre = state.get_account_by_id(bridge_account_id);
    let Some(post) = diff.public_diff().get(&bridge_account_id).cloned() else {
        return Ok(());
    };

    if !is_public_tx {
        return Err(lee::error::LeeError::InvalidInput(format!(
            "Non-public transaction cannot modify system bridge account {bridge_account_id}"
        )));
    }

    if bridge_balance_only_increased(&pre, &post) {
        Ok(())
    } else {
        Err(lee::error::LeeError::InvalidInput(format!(
            "Transaction modifies restricted system bridge account {bridge_account_id}"
        )))
    }
}

/// Whether the bridge escrow went from `pre` to `post` by a pure balance
/// increase (only bridge modification a public transaction may make).
///
/// Legit deposits debit the escrow, but they are sequencer-injected, never
/// user-submitted, so a user transaction that fails this is a forgery attempt.
#[must_use]
pub fn bridge_balance_only_increased(pre: &lee::Account, post: &lee::Account) -> bool {
    let expected_pre = lee::Account {
        balance: pre.balance,
        ..post.clone()
    };
    (expected_pre == *pre) && (pre.balance < post.balance)
}

#[cfg(test)]
mod tests {
    use lee::{Account, AccountId, PrivateKey, PublicKey, V03State};
    use lee_core::account::Nonce;

    use super::{validate_bridge_account_modification, validate_doesnt_modify_account};
    use crate::test_utils::{create_transaction_native_token_transfer, state_and_diff};

    #[test]
    fn bridge_guard_allows_balance_only_increase() {
        // A diff that *only* increases the bridge balance (the legitimate deposit shape)
        // must be accepted.
        let bridge_id = system_accounts::bridge_account_id();
        let pre = Account {
            balance: 500,
            nonce: Nonce(7),
            ..Account::default()
        };
        let post = Account {
            balance: 600,
            ..pre.clone()
        };
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        assert!(
            validate_bridge_account_modification(&state, &diff, true).is_ok(),
            "a balance-only increase of the bridge account must be allowed",
        );
    }

    #[test]
    fn bridge_guard_rejects_data_modification_even_when_balance_increases() {
        // A diff that changes the bridge account's data (here: the nonce) while *also*
        // increasing its balance must be rejected.
        let bridge_id = system_accounts::bridge_account_id();
        let pre = Account {
            balance: 500,
            nonce: Nonce(7),
            ..Account::default()
        };
        let post = Account {
            balance: 600,
            nonce: Nonce(8),
            ..pre.clone()
        };
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        assert!(
            validate_bridge_account_modification(&state, &diff, true).is_err(),
            "modifying bridge account data must be rejected even if the balance increases",
        );
    }

    #[test]
    fn bridge_guard_rejects_zero_value_deposit() {
        // A diff that touches the bridge account without *strictly* increasing its balance
        // must be rejected — a zero-value deposit is not a real credit.
        let bridge_id = system_accounts::bridge_account_id();
        let pre = Account {
            balance: 500,
            nonce: Nonce(7),
            ..Account::default()
        };
        let post = pre.clone();
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        assert!(
            validate_bridge_account_modification(&state, &diff, true).is_err(),
            "a bridge diff that does not strictly increase the balance must be rejected",
        );
    }

    #[test]
    fn bridge_guard_rejects_non_public_modification() {
        // Only a public transaction may touch the bridge account at all; a
        // non-public tx (private/deployment) that produces a bridge diff — even
        // a balance-only increase — must be rejected.
        let bridge_id = system_accounts::bridge_account_id();
        let pre = Account {
            balance: 500,
            ..Account::default()
        };
        let post = Account {
            balance: 600,
            ..pre.clone()
        };
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        assert!(
            validate_bridge_account_modification(&state, &diff, false).is_err(),
            "a non-public transaction must not be allowed to modify the bridge account",
        );
    }

    #[test]
    fn bridge_guard_rejects_balance_decrease() {
        // The drain: a diff that debits the bridge account. This is the attack a
        // malicious block author would attempt, and the guard must reject it on
        // the apply path so followers do not accept the drained state.
        let bridge_id = system_accounts::bridge_account_id();
        let pre = Account {
            balance: 1_000,
            ..Account::default()
        };
        let post = Account {
            balance: 400,
            ..pre.clone()
        };
        let (state, diff) = state_and_diff(bridge_id, pre, post);

        assert!(
            validate_bridge_account_modification(&state, &diff, true).is_err(),
            "a debit of the bridge account (a drain) must be rejected",
        );
    }

    #[test]
    fn validate_doesnt_modify_account_flags_a_changed_account() {
        // Directly exercise the system-account guard with a diff that genuinely changes a
        // clock account, then with one that leaves it untouched. The inverted comparison would
        // treat a changed account as unchanged and wave it through (and would flag an *unchanged*
        // account instead).
        let clock_id = system_accounts::clock_account_ids()[0];
        let pre = Account {
            balance: 1_000,
            ..Account::default()
        };

        let changed = Account {
            balance: 2_000,
            ..Account::default()
        };
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
    fn validate_on_state_rejects_modifying_a_fee_account() {
        // Fee accounts are restricted the same way clock accounts are: a native
        // transfer crediting any of them must be rejected.
        let sender_key = PrivateKey::try_new([5_u8; 32]).expect("valid key");
        let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
        let state = V03State::new().with_public_account_balances([(sender_id, 10_000)]);

        for fee_id in system_accounts::fee_account_ids() {
            let tx =
                create_transaction_native_token_transfer(sender_id, 0, fee_id, 100, &sender_key);
            assert!(
                tx.validate_on_state(&state, 1, 0).is_err(),
                "validate_on_state must reject a transfer that credits fee account {fee_id}",
            );
        }
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
        let state = V03State::new().with_public_account_balances([(sender_id, 10_000)]);

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

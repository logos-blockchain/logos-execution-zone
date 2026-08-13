use borsh::{BorshDeserialize, BorshSerialize};
pub use fee_core::params::MAX_GAS_EXEC;
use lee::{AccountId, ExecutionOutcome, V03State, ValidatedStateDiff};
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
            Self::ProgramDeployment(tx) => {
                if tx.witness_set().is_valid_for(tx.message()) {
                    Ok(Self::ProgramDeployment(tx))
                } else {
                    Err(TransactionMalformationError::InvalidSignature)
                }
            }
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
        cycle_budget: u64,
    ) -> Result<(ValidatedStateDiff, ExecutionOutcome), lee::error::LeeError> {
        let (diff, outcome) = self.compute_state_diff(state, block_id, timestamp, cycle_budget)?;

        let restricted_modification_accounts = system_accounts::clock_account_ids()
            .into_iter()
            .chain(std::iter::once(system_accounts::faucet_account_id()));
        for account_id in restricted_modification_accounts {
            validate_doesnt_modify_account(state, &diff, account_id)?;
        }

        self.validate_bridge_account_modification(state, &diff)?;

        Ok((diff, outcome))
    }

    /// Computes the validated state diff and the transaction's execution outcome. Shared by
    /// [`Self::validate_on_state`] (which adds the system-account guards) and
    /// [`Self::execute_on_state`].
    ///
    /// Only public transactions run the zkVM; the other kinds are metering-free, so they ignore
    /// `cycle_budget`. Charged transactions pass their own `gas_limit`; fee-exempt ones pass
    /// [`MAX_GAS_EXEC`], the only bound that applies to them.
    fn compute_state_diff(
        &self,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
    ) -> Result<(ValidatedStateDiff, ExecutionOutcome), lee::error::LeeError> {
        match self {
            Self::Public(tx) => ValidatedStateDiff::from_public_transaction(
                tx,
                state,
                block_id,
                timestamp,
                cycle_budget,
            ),
            Self::PrivacyPreserving(tx) => ValidatedStateDiff::from_privacy_preserving_transaction(
                tx, state, block_id, timestamp,
            )
            .map(|diff| (diff, ExecutionOutcome::FREE)),
            Self::ProgramDeployment(tx) => {
                ValidatedStateDiff::from_program_deployment_transaction(tx, state)
                    .map(|diff| (diff, ExecutionOutcome::FREE))
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
        cycle_budget: u64,
    ) -> Result<(Self, ExecutionOutcome), lee::error::LeeError> {
        let (diff, outcome) = self
            .validate_on_state(state, block_id, timestamp, cycle_budget)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        state.apply_state_diff(diff);
        Ok((self, outcome))
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
        cycle_budget: u64,
    ) -> Result<(Self, ExecutionOutcome), lee::error::LeeError> {
        let (diff, outcome) = self
            .compute_state_diff(state, block_id, timestamp, cycle_budget)
            .inspect_err(|err| warn!("Error at transition {err:#?}"))?;
        state.apply_state_diff(diff);
        Ok((self, outcome))
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
            let expected_pre = lee::Account {
                balance: pre.balance,
                ..post.clone()
            };
            (expected_pre == pre) && (pre.balance < post.balance)
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
        clock_core::CLOCK_PROGRAM_ACCOUNT_IDS.to_vec(),
        vec![],
        timestamp,
        lee::FeeFields::ZERO,
    )
    .expect("Clock invocation message should always be constructable");
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

/// Whether `tx` is a **system transaction**: injected by the sequencer rather than submitted by a
/// user.
///
/// Such a transaction is exempt from fees *and* from both block gas caps (tokenomics rulings
/// Q6/Q10; this deviates from SPECS invariant 6 as written, which is a decided deviation).
///
/// Recognized structurally, never by the payer field: [`lee::FeeFields::ZERO`] designates
/// [`lee::SYSTEM_PAYER`], which any user could copy. The trailing clock invocation and every
/// transaction in the genesis block are the other two system cases; both are block-level
/// properties, so the block transition classifies them itself.
///
/// The instruction shape alone is *not* enough: a bridge `Deposit` and an inbox `Dispatch` are
/// both shapes a user could craft, and a user-crafted one that classified as system would ride for
/// free and outside the block caps. So the witness set must also be **empty**. The sequencer's own
/// injections are unsigned — `build_bridge_deposit_tx_from_event` and `build_inbox_dispatch_tx`
/// both close over `WitnessSet::from_raw_parts(vec![])` — whereas a user transaction the sequencer
/// would accept has to be signed by the accounts it debits. A user *can* still submit an unsigned
/// deposit-shaped transaction, but the bridge and inbox programs reject one that does not
/// correspond to a real L1 event, so it only ever wastes the block space it rides for free on.
///
/// Lives here rather than in the sequencer so the sequencer (building) and the indexer (replaying)
/// classify identically — a disagreement would be a consensus split.
#[must_use]
pub fn is_system_transaction(tx: &LeeTransaction) -> bool {
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
    extract_bridge_deposit_id(tx).is_some() || extract_cross_zone_dispatch(tx).is_some()
}

/// Whether `tx` is a vault claim that sweeps the payer's **entire** vault balance.
///
/// Such a claim is fee-exempt. It is the bootstrap transaction of the whole ledger: genesis supply
/// and L1 bridge deposits both credit a vault PDA, never the owner's account, so the owner's own
/// balance — the balance fees are debited from — is zero until this transaction lands. Charging it
/// would make every genesis-funded account and every bridged-in deposit permanently unspendable.
///
/// The exemption is deliberately narrow: only a claim that moves a *non-zero* amount equal to the
/// vault's full balance qualifies. A partial claim is charged like any other public transaction
/// (and will usually fail its reservation, which is accepted — a payer full-sweeps first). The
/// vault account id is re-derived from the owner rather than trusted from the account list, so a
/// forged pair cannot manufacture the exemption.
///
/// `vault_core::Instruction::Claim` carries an explicit `amount` and has no sweep variant, so the
/// determination is **state-dependent**: `amount` is compared against the vault balance in `state`.
/// Callers pass the *working* state at this transaction's turn in the block — not the block's
/// opening state — so an earlier transaction that moved the vault balance is visible here. Both the
/// block transition and the sequencer's block builder ask it that way (see
/// `sequencer_core::drain_ordered_candidates`), so they classify identically.
///
/// This is the single place the bootstrap exemption is decided.
// TBA(fee-bootstrap): tokenomics may replace this with deferred settlement, where a claim pays its
// fee out of the funds it sweeps. That would remove the exemption entirely; keeping the decision
// here means it is one function to delete.
#[must_use]
pub fn is_full_vault_sweep(tx: &LeeTransaction, state: &V03State) -> bool {
    let vault_program_id = programs::vault().id();
    let Some(vault_core::Instruction::Claim { amount }) =
        decode_instruction::<vault_core::Instruction>(tx, vault_program_id)
    else {
        return false;
    };
    let LeeTransaction::Public(public_tx) = tx else {
        return false;
    };
    let [owner_id, vault_id] = public_tx.message().account_ids[..] else {
        return false;
    };
    if vault_id != vault_core::compute_vault_account_id(vault_program_id, owner_id) {
        return false;
    }
    // A zero-amount claim moves nothing, so exempting it would be free block space.
    amount != 0 && amount == state.get_account_by_id(vault_id).balance
}

/// The L1 deposit operation id a bridge deposit-mint transaction carries, or `None` if `tx` is not
/// one.
#[must_use]
pub fn extract_bridge_deposit_id(tx: &LeeTransaction) -> Option<HashType> {
    let bridge_core::Instruction::Deposit {
        l1_deposit_op_id, ..
    } = decode_instruction::<bridge_core::Instruction>(tx, programs::bridge().id())?
    else {
        return None;
    };
    Some(HashType(l1_deposit_op_id))
}

/// The cross-zone message an inbox dispatch delivers, or `None` if `tx` is not a dispatch.
#[must_use]
pub fn extract_cross_zone_dispatch(
    tx: &LeeTransaction,
) -> Option<cross_zone_inbox_core::CrossZoneMessage> {
    let cross_zone_inbox_core::Instruction::Dispatch(message) =
        decode_instruction::<cross_zone_inbox_core::Instruction>(
            tx,
            programs::cross_zone_inbox().id(),
        )?
    else {
        return None;
    };
    Some(message)
}

/// Decodes `tx`'s instruction as `I`, provided `tx` is a public invocation of `program_id`.
fn decode_instruction<I: serde::de::DeserializeOwned>(
    tx: &LeeTransaction,
    program_id: lee::ProgramId,
) -> Option<I> {
    let LeeTransaction::Public(tx) = tx else {
        return None;
    };
    let message = tx.message();
    if message.program_id != program_id {
        return None;
    }
    risc0_zkvm::serde::from_slice::<I, u32>(&message.instruction_data).ok()
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

    use super::{
        MAX_GAS_EXEC, clock_invocation, is_system_transaction, validate_doesnt_modify_account,
    };
    use crate::test_utils::{
        any_public_transaction, create_transaction_native_token_transfer, state_and_diff,
    };

    /// The clock transaction is canonical and unsigned, and `apply_block_to_state`
    /// checks it by equality — so the build side and the check side must agree
    /// byte for byte, fee fields included. It is a system transaction, hence
    /// zeroed fees and the system payer.
    #[test]
    fn clock_invocation_is_canonical_and_carries_zeroed_fees() {
        let tx = clock_invocation(1234);
        let rebuilt = clock_invocation(1234);
        assert_eq!(tx, rebuilt);
        assert_eq!(tx.hash(), rebuilt.hash());
        assert_ne!(tx, clock_invocation(1235));

        assert_eq!(tx.message().fees(), lee::FeeFields::ZERO);
        assert_eq!(tx.message().payer, lee::SYSTEM_PAYER);
        assert!(tx.witness_set().signatures_and_public_keys().is_empty());
        assert!(tx.witness_set().fee_witness().is_none());
    }

    /// The system exemption is fee-*and*-cap exempt, so it must not be reachable by anything a
    /// user can put in the mempool. A bridge `Deposit` is just an instruction shape; the thing
    /// only the sequencer can produce is an *unsigned* one, because a user transaction the
    /// sequencer accepts is signed by the accounts it debits. Same message, same instruction —
    /// only the witness set differs, and only the unsigned one is a system transaction.
    #[test]
    fn a_signed_deposit_shaped_transaction_is_not_a_system_transaction() {
        let signing_key = PrivateKey::try_new([9_u8; 32]).expect("valid key");
        let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&signing_key));
        let bridge_program_id = programs::bridge().id();
        let vault_program_id = programs::vault().id();

        let message = lee::public_transaction::Message::try_new(
            bridge_program_id,
            vec![
                system_accounts::bridge_account_id(),
                vault_core::compute_vault_account_id(vault_program_id, recipient_id),
                bridge_core::deposit_receipt_account_id(bridge_program_id, [3_u8; 32]),
            ],
            vec![],
            bridge_core::Instruction::Deposit {
                l1_deposit_op_id: [3_u8; 32],
                vault_program_id,
                recipient_id,
                amount: 1_000,
            },
            lee::FeeFields::ZERO,
        )
        .expect("deposit message should be constructable");

        let injected = super::LeeTransaction::Public(lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ));
        assert!(
            is_system_transaction(&injected),
            "the sequencer's own unsigned deposit mint must stay exempt",
        );

        let forged = super::LeeTransaction::Public(lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::for_message(&message, &[&signing_key]),
        ));
        assert!(
            !is_system_transaction(&forged),
            "a user-signed deposit-shaped transaction must be charged and capped like any other",
        );
    }

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
        let pre = Account {
            balance: 500,
            nonce: Nonce(7),
            ..Account::default()
        };
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

    /// The private transaction's `data_bytes` — the bytes a block body carries — is the
    /// `LeeTransaction` discriminant plus the transaction's own encoding. This pins the
    /// discriminant width that `lee`'s envelope measurement
    /// (`privacy_preserving_transaction::sizes`) has to assume, since `lee` cannot see
    /// this enum.
    #[test]
    fn private_tx_wire_size_is_tag_plus_transaction() {
        use lee::privacy_preserving_transaction::{
            Message, PrivacyPreservingTransaction, WitnessSet, circuit::Proof,
        };
        use lee_core::program::{BlockValidityWindow, TimestampValidityWindow};

        use super::LeeTransaction;

        let message = Message {
            public_actions: vec![],
            nonces: vec![],
            private_actions: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };
        let tx = PrivacyPreservingTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        );
        let inner_len = borsh::to_vec(&tx).unwrap().len();
        let wire = borsh::to_vec(&LeeTransaction::PrivacyPreserving(tx)).unwrap();

        assert_eq!(wire.len(), inner_len + 1);
        assert_eq!(wire[0], 1, "PrivacyPreserving is the second enum variant");
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
            tx.validate_on_state(&state, 1, 0, MAX_GAS_EXEC).is_err(),
            "validate_on_state must reject a transfer that credits a clock system account",
        );
    }
}

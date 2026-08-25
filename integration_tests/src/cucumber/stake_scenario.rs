//! Node-level (L3) scenario state backing the sequencer registration Cucumber
//! scenarios.
//!
//! The scenarios run against a deployed LEZ stack: transactions are signed and
//! submitted through the scenario wallet and every assertion reads state back
//! through the sequencer's RPC API. This module owns only the per-scenario
//! bookkeeping — the cast of account ids, the amount vocabulary, instruction
//! builders and the record of the last submission. Chain access lives in the
//! step helpers.
//!
//! A submission handed to the node is admitted to the mempool first and only
//! executed during block building; a rejected transaction is dropped from the
//! block without any error surfacing through the RPC API. Rejection scenarios
//! therefore assert non-inclusion plus unchanged accounts instead of the
//! in-program rejection message.

use common::HashType;
use lee::{Account, AccountId, program::Program};
use lee_core::program::InstructionData;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_stake_core::SequencerKey;

use crate::cucumber::error::StepError;

/// Deterministic Bedrock signing seeds: each scenario runs against a fresh
/// chain, so fixed seeds cannot collide across scenarios.
const SEQUENCER_KEY_SEED: u8 = 0x51;
const SECOND_SEQUENCER_KEY_SEED: u8 = 0x52;

/// Padding account used to inflate `Stake`'s pre-state list (case P-20).
pub const EXTRA_ACCOUNT_ID: [u8; 32] = [0xEE; 32];

/// The last transaction handed to the sequencer, kept for the
/// inclusion/non-inclusion assertions.
pub struct SubmissionRecord {
    /// Transaction hash returned by the mempool admission.
    pub hash: HashType,
    /// Amount the submission attempted to move.
    pub amount: u128,
    /// Sequencer tip observed immediately before submission.
    pub submitted_at_block: u64,
}

/// Pre-submission snapshot of every account the submission can touch, so
/// balance deltas and atomicity can be asserted against exact pre-states.
pub struct AccountsSnapshot {
    accounts: Vec<(AccountId, Account)>,
}

impl AccountsSnapshot {
    /// Creates a snapshot from `(account id, pre-state)` pairs.
    #[must_use]
    pub const fn new(accounts: Vec<(AccountId, Account)>) -> Self {
        Self { accounts }
    }

    /// Returns the snapshotted accounts.
    #[must_use]
    pub fn accounts(&self) -> &[(AccountId, Account)] {
        &self.accounts
    }

    /// Returns the snapshotted state of one account, or a typed error if the
    /// account was not part of the snapshot.
    pub fn account(&self, account_id: AccountId) -> Result<&Account, StepError> {
        self.accounts
            .iter()
            .find_map(|(id, account)| (*id == account_id).then_some(account))
            .ok_or_else(|| StepError::LogicalError {
                message: format!("account {account_id} is not part of the pre-state snapshot"),
            })
    }
}

/// Per-scenario cast of a registration scenario: one funding account, one
/// ownership account, one sequencer key, plus the observations recorded by
/// earlier steps.
pub struct StakeScenario {
    minimum_stake: u128,
    sequencer_key: SequencerKey,
    second_sequencer_key: SequencerKey,
    funding_id: Option<AccountId>,
    ownership_id: Option<AccountId>,
    second_ownership_id: Option<AccountId>,
    off_curve_bytes: Option<[u8; 32]>,
    snapshot: Option<AccountsSnapshot>,
    last_submission: Option<SubmissionRecord>,
}

impl StakeScenario {
    /// Creates the scenario cast against the deployed chain's configured
    /// minimum stake.
    #[must_use]
    pub fn new(minimum_stake: u128) -> Self {
        Self {
            minimum_stake,
            sequencer_key: sequencer_key_from_seed(SEQUENCER_KEY_SEED),
            second_sequencer_key: sequencer_key_from_seed(SECOND_SEQUENCER_KEY_SEED),
            funding_id: None,
            ownership_id: None,
            second_ownership_id: None,
            off_curve_bytes: None,
            snapshot: None,
            last_submission: None,
        }
    }

    /// Returns the chain's configured minimum sequencer stake.
    #[must_use]
    pub const fn minimum_stake(&self) -> u128 {
        self.minimum_stake
    }

    /// Returns the scenario's sequencer key.
    #[must_use]
    pub const fn sequencer_key(&self) -> SequencerKey {
        self.sequencer_key
    }

    /// Returns the sequencer key staked by the second-registration setup step.
    #[must_use]
    pub const fn second_sequencer_key(&self) -> SequencerKey {
        self.second_sequencer_key
    }

    /// Stores the funding account created by a setup step, replacing any
    /// earlier funding account.
    pub const fn set_funding_id(&mut self, account_id: AccountId) {
        self.funding_id = Some(account_id);
    }

    /// Returns the funding account id, or a typed error before setup.
    pub fn funding_id(&self) -> Result<AccountId, StepError> {
        self.funding_id.ok_or(StepError::MissingObservation {
            field: "funding account",
        })
    }

    /// Stores the ownership account created by a setup step.
    pub const fn set_ownership_id(&mut self, account_id: AccountId) {
        self.ownership_id = Some(account_id);
    }

    /// Returns the ownership account id, or a typed error before setup.
    pub fn ownership_id(&self) -> Result<AccountId, StepError> {
        self.ownership_id.ok_or(StepError::MissingObservation {
            field: "ownership account",
        })
    }

    /// Stores the ownership account of the second staked key.
    pub const fn set_second_ownership_id(&mut self, account_id: AccountId) {
        self.second_ownership_id = Some(account_id);
    }

    /// Returns the ownership account of the second staked key, or a typed
    /// error before that setup step ran.
    pub fn second_ownership_id(&self) -> Result<AccountId, StepError> {
        self.second_ownership_id
            .ok_or(StepError::MissingObservation {
                field: "second staked sequencer key",
            })
    }

    /// Stores the off-curve byte string used by the `SequencerKey` decoding
    /// scenario.
    pub const fn set_off_curve_bytes(&mut self, bytes: [u8; 32]) {
        self.off_curve_bytes = Some(bytes);
    }

    /// Returns the stored off-curve bytes, or a typed error before setup.
    pub fn off_curve_bytes(&self) -> Result<[u8; 32], StepError> {
        self.off_curve_bytes.ok_or(StepError::MissingObservation {
            field: "off-curve key bytes",
        })
    }

    /// Stores the pre-submission account snapshot.
    pub fn set_snapshot(&mut self, snapshot: AccountsSnapshot) {
        self.snapshot = Some(snapshot);
    }

    /// Returns the pre-submission snapshot, or a typed error before any
    /// submission.
    pub fn snapshot(&self) -> Result<&AccountsSnapshot, StepError> {
        self.snapshot.as_ref().ok_or(StepError::MissingObservation {
            field: "pre-submission snapshot",
        })
    }

    /// Records the last transaction handed to the sequencer.
    pub const fn record_submission(&mut self, record: SubmissionRecord) {
        self.last_submission = Some(record);
    }

    /// Returns the last submission, or a typed error before any transaction
    /// was submitted.
    pub fn last_submission(&self) -> Result<&SubmissionRecord, StepError> {
        self.last_submission
            .as_ref()
            .ok_or(StepError::MissingObservation {
                field: "stake submission",
            })
    }

    /// Resolves a Gherkin stake-amount expression against the configured
    /// minimum. Plain integers are accepted as a fallback.
    pub fn amount(&self, expression: &str) -> Result<u128, StepError> {
        let minimum = self.minimum_stake;
        let amount = match expression.trim().to_lowercase().as_str() {
            "the minimum stake" => Some(minimum),
            "one below the minimum stake" => minimum.checked_sub(1),
            "twice the minimum stake" => minimum.checked_mul(2),
            "ten times the minimum stake" => minimum.checked_mul(10),
            other => other.parse::<u128>().ok(),
        };
        amount.ok_or_else(|| StepError::InvalidArgument {
            message: format!("unsupported stake amount expression '{expression}'"),
        })
    }
}

/// Serde mirror of `sequencer_stake_core::Instruction::Stake` with the
/// `SequencerKey` field widened to raw bytes, so an off-curve key can be
/// serialized into otherwise well-formed instruction data (case P-24). The
/// variant index and field order match the real instruction.
#[derive(serde::Serialize)]
enum RawStakeInstruction {
    Stake {
        sequencer_key: [u8; 32],
        amount: u128,
        mover_program_id: lee_core::program::ProgramId,
        mover_instruction_data: InstructionData,
    },
}

/// Derives the Bedrock-style sequencer key for a fixed seed byte.
fn sequencer_key_from_seed(seed: u8) -> SequencerKey {
    let bytes = Ed25519Key::from_bytes(&[seed; 32]).public_key().to_bytes();
    SequencerKey::new(bytes).expect("a Bedrock public key is a valid Ed25519 public key")
}

/// Serialized `authenticated_transfer::Transfer` moving `amount`.
pub fn transfer_instruction(amount: u128) -> Result<InstructionData, StepError> {
    Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer { amount })
        .map_err(|error| StepError::LogicalError {
            message: format!("failed to serialize the mover instruction: {error}"),
        })
}

/// Serialized `sequencer_stake::Stake` for `sequencer_key` through the
/// `authenticated_transfer` mover.
pub fn stake_instruction(
    sequencer_key: SequencerKey,
    amount: u128,
) -> Result<InstructionData, StepError> {
    Program::serialize_instruction(sequencer_stake_core::Instruction::Stake {
        sequencer_key,
        amount,
        mover_program_id: programs::authenticated_transfer().id(),
        mover_instruction_data: transfer_instruction(amount)?,
    })
    .map_err(|error| StepError::LogicalError {
        message: format!("failed to serialize the Stake instruction: {error}"),
    })
}

/// Serialized `sequencer_stake::ConfirmStake` expecting
/// `expected_balance_after` on the ownership account.
pub fn confirm_stake_instruction(
    expected_balance_after: u128,
) -> Result<InstructionData, StepError> {
    Program::serialize_instruction(sequencer_stake_core::Instruction::ConfirmStake {
        expected_balance_after,
    })
    .map_err(|error| StepError::LogicalError {
        message: format!("failed to serialize the ConfirmStake instruction: {error}"),
    })
}

/// Serialized `Stake` carrying `key_bytes` in the `SequencerKey` position
/// (case P-24).
pub fn raw_stake_instruction(
    key_bytes: [u8; 32],
    amount: u128,
) -> Result<InstructionData, StepError> {
    Program::serialize_instruction(RawStakeInstruction::Stake {
        sequencer_key: key_bytes,
        amount,
        mover_program_id: programs::authenticated_transfer().id(),
        mover_instruction_data: transfer_instruction(amount)?,
    })
    .map_err(|error| StepError::LogicalError {
        message: format!("failed to serialize the raw Stake instruction: {error}"),
    })
}

/// Whether instruction data carrying `key_bytes` in the `SequencerKey`
/// position fails host-side deserialization as a `sequencer_stake`
/// instruction (the serde half of case P-24).
pub fn raw_key_instruction_fails_to_decode(
    key_bytes: [u8; 32],
    amount: u128,
) -> Result<bool, StepError> {
    let words = raw_stake_instruction(key_bytes, amount)?;
    Ok(risc0_zkvm::serde::from_slice::<sequencer_stake_core::Instruction, u32>(&words).is_err())
}

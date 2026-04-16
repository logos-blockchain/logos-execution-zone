use std::collections::HashSet;

#[cfg(any(feature = "host", test))]
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::{DeserializeOwned, guest::env, serde::Deserializer};
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, NullifierPublicKey, Timestamp,
    account::{Account, AccountId, AccountWithMetadata},
};

pub const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];
pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

pub type ProgramId = [u32; 8];
pub type InstructionData = Vec<u32>;
pub struct ProgramInput<T> {
    pub self_program_id: ProgramId,
    pub caller_program_id: Option<ProgramId>,
    pub pre_states: Vec<AccountWithMetadata>,
    pub instruction: T,
}

/// A 32-byte seed used to compute a *Program-Derived `AccountId`* (PDA).
///
/// Each program can derive up to `2^256` unique account IDs by choosing different
/// seeds. PDAs allow programs to control namespaced account identifiers without
/// collisions between programs.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct PdaSeed([u8; 32]);

impl PdaSeed {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<(&ProgramId, &PdaSeed)> for AccountId {
    fn from(value: (&ProgramId, &PdaSeed)) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PROGRAM_DERIVED_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/NSSA/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = [0; 96];
        bytes[0..32].copy_from_slice(PROGRAM_DERIVED_ACCOUNT_ID_PREFIX);
        let program_id_bytes: &[u8] =
            bytemuck::try_cast_slice(value.0).expect("ProgramId should be castable to &[u8]");
        bytes[32..64].copy_from_slice(program_id_bytes);
        bytes[64..].copy_from_slice(&value.1.0);
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChainedCall {
    /// The program ID of the program to execute.
    pub program_id: ProgramId,
    pub pre_states: Vec<AccountWithMetadata>,
    /// The instruction data to pass.
    pub instruction_data: InstructionData,
    /// Public PDA seeds authorized for the callee. Each derives an `AccountId` via
    /// `AccountId::from((&caller_program_id, seed))`.
    pub pda_seeds: Vec<PdaSeed>,
    /// Private PDA `(seed, npk)` pairs authorized for the callee. Each derives an `AccountId`
    /// via `private_pda_account_id(&caller_program_id, seed, npk)`. The npk binds the
    /// authorization to a specific group of controllers and is part of the caller program's
    /// Risc0-proven output, so the outer circuit can trust it.
    pub private_pda_seeds: Vec<(PdaSeed, NullifierPublicKey)>,
}

impl ChainedCall {
    /// Creates a new chained call serializing the given instruction.
    pub fn new<I: Serialize>(
        program_id: ProgramId,
        pre_states: Vec<AccountWithMetadata>,
        instruction: &I,
    ) -> Self {
        Self {
            program_id,
            pre_states,
            instruction_data: risc0_zkvm::serde::to_vec(instruction)
                .expect("Serialization to Vec<u32> should not fail"),
            pda_seeds: Vec::new(),
            private_pda_seeds: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_pda_seeds(mut self, pda_seeds: Vec<PdaSeed>) -> Self {
        self.pda_seeds = pda_seeds;
        self
    }

    #[must_use]
    pub fn with_private_pda_seeds(
        mut self,
        private_pda_seeds: Vec<(PdaSeed, NullifierPublicKey)>,
    ) -> Self {
        self.private_pda_seeds = private_pda_seeds;
        self
    }
}

/// Represents the final state of an `Account` after a program execution.
///
/// A post state may optionally request that the executing program
/// becomes the owner of the account (a “claim”). This is used to signal
/// that the program intends to take ownership of the account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(PartialEq, Eq))]
pub struct AccountPostState {
    account: Account,
    claim: Option<Claim>,
}

/// A claim request for an account, indicating that the executing program intends to take ownership
/// of the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Claim {
    /// The program requests ownership of the account which was authorized by the signer.
    ///
    /// Note that it's possible to successfully execute program outputting [`AccountPostState`] with
    /// `is_authorized == false` and `claim == Some(Claim::Authorized)`.
    /// This will give no error if program had authorization in pre state and may be useful
    /// if program decides to give up authorization for a chained call.
    Authorized,
    /// The program requests ownership of the account through a public PDA. The `AccountId` is
    /// `AccountId::from((&program_id, &seed))`.
    Pda(PdaSeed),
    /// The program requests ownership of the account through a private PDA. The `AccountId` is
    /// `private_pda_account_id(&program_id, &seed, &npk)`. The npk is part of the program's
    /// Risc0-proven output, so the outer circuit can trust it.
    PrivatePda {
        seed: PdaSeed,
        npk: NullifierPublicKey,
    },
}

impl AccountPostState {
    /// Creates a post state without a claim request.
    /// The executing program is not requesting ownership of the account.
    #[must_use]
    pub const fn new(account: Account) -> Self {
        Self {
            account,
            claim: None,
        }
    }

    /// Creates a post state that requests ownership of the account.
    /// This indicates that the executing program intends to claim the
    /// account as its own and is allowed to mutate it.
    #[must_use]
    pub const fn new_claimed(account: Account, claim: Claim) -> Self {
        Self {
            account,
            claim: Some(claim),
        }
    }

    /// Creates a post state that requests ownership of the account
    /// if the account's program owner is the default program ID.
    #[must_use]
    pub fn new_claimed_if_default(account: Account, claim: Claim) -> Self {
        let is_default_owner = account.program_owner == DEFAULT_PROGRAM_ID;
        Self {
            account,
            claim: is_default_owner.then_some(claim),
        }
    }

    /// Returns whether this post state requires a claim.
    #[must_use]
    pub const fn required_claim(&self) -> Option<Claim> {
        self.claim
    }

    /// Returns the underlying account.
    #[must_use]
    pub const fn account(&self) -> &Account {
        &self.account
    }

    /// Returns the underlying account.
    #[must_use]
    pub const fn account_mut(&mut self) -> &mut Account {
        &mut self.account
    }

    /// Consumes the post state and returns the underlying account.
    #[must_use]
    pub fn into_account(self) -> Account {
        self.account
    }
}

pub type BlockValidityWindow = ValidityWindow<BlockId>;
pub type TimestampValidityWindow = ValidityWindow<Timestamp>;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)
)]
pub struct ValidityWindow<T> {
    from: Option<T>,
    to: Option<T>,
}

impl<T> ValidityWindow<T> {
    /// Creates a window with no bounds.
    #[must_use]
    pub const fn new_unbounded() -> Self {
        Self {
            from: None,
            to: None,
        }
    }
}

impl<T: Copy + PartialOrd> ValidityWindow<T> {
    /// Valid for values in the range [from, to), where `from` is included and `to` is excluded.
    #[must_use]
    pub fn is_valid_for(&self, value: T) -> bool {
        self.from.is_none_or(|start| value >= start) && self.to.is_none_or(|end| value < end)
    }

    /// Returns `Err(InvalidWindow)` if both bounds are set and `from >= to`.
    fn check_window(&self) -> Result<(), InvalidWindow> {
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from >= to
        {
            return Err(InvalidWindow);
        }
        Ok(())
    }

    /// Inclusive lower bound. `None` means no lower bound.
    #[must_use]
    pub const fn start(&self) -> Option<T> {
        self.from
    }

    /// Exclusive upper bound. `None` means no upper bound.
    #[must_use]
    pub const fn end(&self) -> Option<T> {
        self.to
    }
}

impl<T: Copy + PartialOrd> TryFrom<(Option<T>, Option<T>)> for ValidityWindow<T> {
    type Error = InvalidWindow;

    fn try_from(value: (Option<T>, Option<T>)) -> Result<Self, Self::Error> {
        let this = Self {
            from: value.0,
            to: value.1,
        };
        this.check_window()?;
        Ok(this)
    }
}

impl<T: Copy + PartialOrd> TryFrom<std::ops::Range<T>> for ValidityWindow<T> {
    type Error = InvalidWindow;

    fn try_from(value: std::ops::Range<T>) -> Result<Self, Self::Error> {
        (Some(value.start), Some(value.end)).try_into()
    }
}

impl<T: Copy + PartialOrd> From<std::ops::RangeFrom<T>> for ValidityWindow<T> {
    fn from(value: std::ops::RangeFrom<T>) -> Self {
        Self {
            from: Some(value.start),
            to: None,
        }
    }
}

impl<T: Copy + PartialOrd> From<std::ops::RangeTo<T>> for ValidityWindow<T> {
    fn from(value: std::ops::RangeTo<T>) -> Self {
        Self {
            from: None,
            to: Some(value.end),
        }
    }
}

impl<T> From<std::ops::RangeFull> for ValidityWindow<T> {
    fn from(_: std::ops::RangeFull) -> Self {
        Self::new_unbounded()
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("Invalid window")]
pub struct InvalidWindow;

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
#[must_use = "ProgramOutput does nothing unless written"]
pub struct ProgramOutput {
    /// The program ID of the program that produced this output.
    pub self_program_id: ProgramId,
    /// The program ID of the caller that invoked this program via a chained call,
    /// or `None` if this is a top-level call.
    pub caller_program_id: Option<ProgramId>,
    /// The instruction data the program received to produce this output.
    pub instruction_data: InstructionData,
    /// The account pre states the program received to produce this output.
    pub pre_states: Vec<AccountWithMetadata>,
    /// The account post states the program execution produced.
    pub post_states: Vec<AccountPostState>,
    /// The list of chained calls to other programs.
    pub chained_calls: Vec<ChainedCall>,
    /// The block ID window where the program output is valid.
    pub block_validity_window: BlockValidityWindow,
    /// The timestamp window where the program output is valid.
    pub timestamp_validity_window: TimestampValidityWindow,
}

impl ProgramOutput {
    pub const fn new(
        self_program_id: ProgramId,
        caller_program_id: Option<ProgramId>,
        instruction_data: InstructionData,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountPostState>,
    ) -> Self {
        Self {
            self_program_id,
            caller_program_id,
            instruction_data,
            pre_states,
            post_states,
            chained_calls: Vec::new(),
            block_validity_window: ValidityWindow::new_unbounded(),
            timestamp_validity_window: ValidityWindow::new_unbounded(),
        }
    }

    pub fn write(self) {
        env::commit(&self);
    }

    pub fn with_chained_calls(mut self, chained_calls: Vec<ChainedCall>) -> Self {
        self.chained_calls = chained_calls;
        self
    }

    /// Sets the block ID validity window from an infallible range conversion (`1..`, `..5`, `..`).
    pub fn with_block_validity_window<W: Into<BlockValidityWindow>>(mut self, window: W) -> Self {
        self.block_validity_window = window.into();
        self
    }

    /// Sets the block ID validity window from a fallible range conversion (`1..5`).
    /// Returns `Err` if the range is empty.
    pub fn try_with_block_validity_window<
        W: TryInto<BlockValidityWindow, Error = InvalidWindow>,
    >(
        mut self,
        window: W,
    ) -> Result<Self, InvalidWindow> {
        self.block_validity_window = window.try_into()?;
        Ok(self)
    }

    /// Sets the timestamp validity window from an infallible range conversion.
    pub fn with_timestamp_validity_window<W: Into<TimestampValidityWindow>>(
        mut self,
        window: W,
    ) -> Self {
        self.timestamp_validity_window = window.into();
        self
    }

    /// Sets the timestamp validity window from a fallible range conversion.
    /// Returns `Err` if the range is empty.
    pub fn try_with_timestamp_validity_window<
        W: TryInto<TimestampValidityWindow, Error = InvalidWindow>,
    >(
        mut self,
        window: W,
    ) -> Result<Self, InvalidWindow> {
        self.timestamp_validity_window = window.try_into()?;
        Ok(self)
    }

    pub fn valid_from_timestamp(mut self, ts: Option<Timestamp>) -> Result<Self, InvalidWindow> {
        self.timestamp_validity_window = (ts, self.timestamp_validity_window.end()).try_into()?;
        Ok(self)
    }

    pub fn valid_until_timestamp(mut self, ts: Option<Timestamp>) -> Result<Self, InvalidWindow> {
        self.timestamp_validity_window = (self.timestamp_validity_window.start(), ts).try_into()?;
        Ok(self)
    }
}

/// Representation of a number as `lo + hi * 2^128`.
#[derive(Debug, PartialEq, Eq)]
pub struct WrappedBalanceSum {
    lo: u128,
    hi: u128,
}

impl WrappedBalanceSum {
    /// Constructs a [`WrappedBalanceSum`] from an iterator of balances.
    ///
    /// Returns [`None`] if balance sum overflows `lo + hi * 2^128` representation, which is not
    /// expected in practical scenarios.
    pub fn from_balances(balances: impl Iterator<Item = u128>) -> Option<Self> {
        let mut wrapped = Self { lo: 0, hi: 0 };

        for balance in balances {
            let (new_sum, did_overflow) = wrapped.lo.overflowing_add(balance);
            if did_overflow {
                wrapped.hi = wrapped.hi.checked_add(1)?;
            }
            wrapped.lo = new_sum;
        }

        Some(wrapped)
    }
}

impl std::fmt::Display for WrappedBalanceSum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.hi == 0 {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{} * 2^128 + {}", self.hi, self.lo)
        }
    }
}

impl From<u128> for WrappedBalanceSum {
    fn from(value: u128) -> Self {
        Self { lo: value, hi: 0 }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ExecutionValidationError {
    #[error("Pre-state account IDs are not unique")]
    PreStateAccountIdsNotUnique,

    #[error(
        "Pre-state and post-state lengths do not match: pre-state length {pre_state_length}, post-state length {post_state_length}"
    )]
    MismatchedPreStatePostStateLength {
        pre_state_length: usize,
        post_state_length: usize,
    },

    #[error("Unallowed modification of nonce for account {account_id}")]
    ModifiedNonce { account_id: AccountId },

    #[error("Unallowed modification of program owner for account {account_id}")]
    ModifiedProgramOwner { account_id: AccountId },

    #[error(
        "Trying to decrease balance of account {account_id} owned by {owner_program_id:?} in a program {executing_program_id:?} which is not the owner"
    )]
    UnauthorizedBalanceDecrease {
        account_id: AccountId,
        owner_program_id: ProgramId,
        executing_program_id: ProgramId,
    },

    #[error(
        "Unauthorized modification of data for account {account_id} which is not default and not owned by executing program {executing_program_id:?}"
    )]
    UnauthorizedDataModification {
        account_id: AccountId,
        executing_program_id: ProgramId,
    },

    #[error(
        "Post-state for account {account_id} has default program owner but pre-state was not default"
    )]
    NonDefaultAccountWithDefaultOwner { account_id: AccountId },

    #[error("Total balance across accounts overflowed 2^256 - 1")]
    BalanceSumOverflow,

    #[error(
        "Total balance across accounts is not preserved: total balance in pre-states {total_balance_pre_states}, total balance in post-states {total_balance_post_states}"
    )]
    MismatchedTotalBalance {
        total_balance_pre_states: WrappedBalanceSum,
        total_balance_post_states: WrappedBalanceSum,
    },
}

/// Derives an [`AccountId`] for a private PDA from the program ID, seed, and nullifier public key.
///
/// Unlike public PDAs (`AccountId::from((&ProgramId, &PdaSeed))`), this includes the `npk` in the
/// derivation, making the address unique per group of controllers sharing viewing keys.
#[must_use]
pub fn private_pda_account_id(
    program_id: &ProgramId,
    seed: &PdaSeed,
    npk: &NullifierPublicKey,
) -> AccountId {
    use risc0_zkvm::sha::{Impl, Sha256 as _};
    const PRIVATE_PDA_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00";

    let mut bytes = [0_u8; 128];
    bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
    let program_id_bytes: &[u8] =
        bytemuck::try_cast_slice(program_id).expect("ProgramId should be castable to &[u8]");
    bytes[32..64].copy_from_slice(program_id_bytes);
    bytes[64..96].copy_from_slice(&seed.0);
    bytes[96..128].copy_from_slice(&npk.to_byte_array());
    AccountId::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

/// Computes the set of PDA `AccountId`s the callee is authorized to mutate.
///
/// `pda_seeds` produces public PDAs. `private_pda_seeds` produces private PDAs whose derivation
/// includes the caller-supplied npk. All seeds and npks must come from the caller's Risc0-proven
/// [`ChainedCall`], so the outer circuit can trust them.
#[must_use]
pub fn compute_authorized_pdas(
    caller_program_id: Option<ProgramId>,
    pda_seeds: &[PdaSeed],
    private_pda_seeds: &[(PdaSeed, NullifierPublicKey)],
) -> HashSet<AccountId> {
    let Some(caller) = caller_program_id else {
        return HashSet::new();
    };
    let public = pda_seeds
        .iter()
        .map(|seed| AccountId::from((&caller, seed)));
    let private = private_pda_seeds
        .iter()
        .map(|(seed, npk)| private_pda_account_id(&caller, seed, npk));
    public.chain(private).collect()
}

/// Reads the NSSA inputs from the guest environment.
#[must_use]
pub fn read_nssa_inputs<T: DeserializeOwned>() -> (ProgramInput<T>, InstructionData) {
    let self_program_id: ProgramId = env::read();
    let caller_program_id: Option<ProgramId> = env::read();
    let pre_states: Vec<AccountWithMetadata> = env::read();
    let instruction_words: InstructionData = env::read();
    let instruction = T::deserialize(&mut Deserializer::new(instruction_words.as_ref())).unwrap();
    (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    )
}

/// Validates well-behaved program execution.
///
/// # Parameters
/// - `pre_states`: The list of input accounts, each annotated with authorization metadata.
/// - `post_states`: The list of resulting accounts after executing the program logic.
/// - `executing_program_id`: The identifier of the program that was executed.
pub fn validate_execution(
    pre_states: &[AccountWithMetadata],
    post_states: &[AccountPostState],
    executing_program_id: ProgramId,
) -> Result<(), ExecutionValidationError> {
    // 1. Check account ids are all different
    if !validate_uniqueness_of_account_ids(pre_states) {
        return Err(ExecutionValidationError::PreStateAccountIdsNotUnique);
    }

    // 2. Lengths must match
    if pre_states.len() != post_states.len() {
        return Err(
            ExecutionValidationError::MismatchedPreStatePostStateLength {
                pre_state_length: pre_states.len(),
                post_state_length: post_states.len(),
            },
        );
    }

    for (pre, post) in pre_states.iter().zip(post_states) {
        // 3. Nonce must remain unchanged
        if pre.account.nonce != post.account.nonce {
            return Err(ExecutionValidationError::ModifiedNonce {
                account_id: pre.account_id,
            });
        }

        // 4. Program ownership changes are not allowed
        if pre.account.program_owner != post.account.program_owner {
            return Err(ExecutionValidationError::ModifiedProgramOwner {
                account_id: pre.account_id,
            });
        }

        let account_program_owner = pre.account.program_owner;

        // 5. Decreasing balance only allowed if owned by executing program
        if post.account.balance < pre.account.balance
            && account_program_owner != executing_program_id
        {
            return Err(ExecutionValidationError::UnauthorizedBalanceDecrease {
                account_id: pre.account_id,
                owner_program_id: account_program_owner,
                executing_program_id,
            });
        }

        // 6. Data changes only allowed if owned by executing program or if account pre state has
        //    default values
        if pre.account.data != post.account.data
            && pre.account != Account::default()
            && account_program_owner != executing_program_id
        {
            return Err(ExecutionValidationError::UnauthorizedDataModification {
                account_id: pre.account_id,
                executing_program_id,
            });
        }

        // 7. If a post state has default program owner, the pre state must have been a default
        //    account
        if post.account.program_owner == DEFAULT_PROGRAM_ID && pre.account != Account::default() {
            return Err(
                ExecutionValidationError::NonDefaultAccountWithDefaultOwner {
                    account_id: pre.account_id,
                },
            );
        }
    }

    // 8. Total balance is preserved

    let Some(total_balance_pre_states) =
        WrappedBalanceSum::from_balances(pre_states.iter().map(|pre| pre.account.balance))
    else {
        return Err(ExecutionValidationError::BalanceSumOverflow);
    };

    let Some(total_balance_post_states) =
        WrappedBalanceSum::from_balances(post_states.iter().map(|post| post.account.balance))
    else {
        return Err(ExecutionValidationError::BalanceSumOverflow);
    };

    if total_balance_pre_states != total_balance_post_states {
        return Err(ExecutionValidationError::MismatchedTotalBalance {
            total_balance_pre_states,
            total_balance_post_states,
        });
    }

    Ok(())
}

fn validate_uniqueness_of_account_ids(pre_states: &[AccountWithMetadata]) -> bool {
    let number_of_accounts = pre_states.len();
    let number_of_account_ids = pre_states
        .iter()
        .map(|account| &account.account_id)
        .collect::<HashSet<_>>()
        .len();

    number_of_accounts == number_of_account_ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_window_unbounded_accepts_any_value() {
        let w: ValidityWindow<u64> = ValidityWindow::new_unbounded();
        assert!(w.is_valid_for(0));
        assert!(w.is_valid_for(u64::MAX));
    }

    #[test]
    fn validity_window_bounded_range_includes_from_excludes_to() {
        let w: ValidityWindow<u64> = (Some(5), Some(10)).try_into().unwrap();
        assert!(!w.is_valid_for(4));
        assert!(w.is_valid_for(5));
        assert!(w.is_valid_for(9));
        assert!(!w.is_valid_for(10));
    }

    #[test]
    fn validity_window_only_from_bound() {
        let w: ValidityWindow<u64> = (Some(5), None).try_into().unwrap();
        assert!(!w.is_valid_for(4));
        assert!(w.is_valid_for(5));
        assert!(w.is_valid_for(u64::MAX));
    }

    #[test]
    fn validity_window_only_to_bound() {
        let w: ValidityWindow<u64> = (None, Some(5)).try_into().unwrap();
        assert!(w.is_valid_for(0));
        assert!(w.is_valid_for(4));
        assert!(!w.is_valid_for(5));
    }

    #[test]
    fn validity_window_adjacent_bounds_are_invalid() {
        // [5, 5) is an empty range — from == to
        assert!(ValidityWindow::<u64>::try_from((Some(5), Some(5))).is_err());
    }

    #[test]
    fn validity_window_inverted_bounds_are_invalid() {
        assert!(ValidityWindow::<u64>::try_from((Some(10), Some(5))).is_err());
    }

    #[test]
    fn validity_window_getters_match_construction() {
        let w: ValidityWindow<u64> = (Some(3), Some(7)).try_into().unwrap();
        assert_eq!(w.start(), Some(3));
        assert_eq!(w.end(), Some(7));
    }

    #[test]
    fn validity_window_getters_for_unbounded() {
        let w: ValidityWindow<u64> = ValidityWindow::new_unbounded();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), None);
    }

    #[test]
    fn validity_window_from_range() {
        let w: ValidityWindow<u64> = ValidityWindow::try_from(5_u64..10).unwrap();
        assert_eq!(w.start(), Some(5));
        assert_eq!(w.end(), Some(10));
    }

    #[test]
    fn validity_window_from_range_empty_is_invalid() {
        assert!(ValidityWindow::<u64>::try_from(5_u64..5).is_err());
    }

    #[test]
    fn validity_window_from_range_inverted_is_invalid() {
        let from = 10_u64;
        let to = 5_u64;
        assert!(ValidityWindow::<u64>::try_from(from..to).is_err());
    }

    #[test]
    fn validity_window_from_range_from() {
        let w: ValidityWindow<u64> = (5_u64..).into();
        assert_eq!(w.start(), Some(5));
        assert_eq!(w.end(), None);
    }

    #[test]
    fn validity_window_from_range_to() {
        let w: ValidityWindow<u64> = (..10_u64).into();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), Some(10));
    }

    #[test]
    fn validity_window_from_range_full() {
        let w: ValidityWindow<u64> = (..).into();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), None);
    }

    #[test]
    fn program_output_try_with_block_validity_window_range() {
        let output = ProgramOutput::new(DEFAULT_PROGRAM_ID, None, vec![], vec![], vec![])
            .try_with_block_validity_window(10_u64..100)
            .unwrap();
        assert_eq!(output.block_validity_window.start(), Some(10));
        assert_eq!(output.block_validity_window.end(), Some(100));
    }

    #[test]
    fn program_output_with_block_validity_window_range_from() {
        let output = ProgramOutput::new(DEFAULT_PROGRAM_ID, None, vec![], vec![], vec![])
            .with_block_validity_window(10_u64..);
        assert_eq!(output.block_validity_window.start(), Some(10));
        assert_eq!(output.block_validity_window.end(), None);
    }

    #[test]
    fn program_output_with_block_validity_window_range_to() {
        let output = ProgramOutput::new(DEFAULT_PROGRAM_ID, None, vec![], vec![], vec![])
            .with_block_validity_window(..100_u64);
        assert_eq!(output.block_validity_window.start(), None);
        assert_eq!(output.block_validity_window.end(), Some(100));
    }

    #[test]
    fn program_output_try_with_block_validity_window_empty_range_fails() {
        let result = ProgramOutput::new(DEFAULT_PROGRAM_ID, None, vec![], vec![], vec![])
            .try_with_block_validity_window(5_u64..5);
        assert!(result.is_err());
    }

    #[test]
    fn post_state_new_with_claim_constructor() {
        let account = Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            balance: 1337,
            data: vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(),
            nonce: 10_u128.into(),
        };

        let account_post_state = AccountPostState::new_claimed(account.clone(), Claim::Authorized);

        assert_eq!(account, account_post_state.account);
        assert_eq!(account_post_state.required_claim(), Some(Claim::Authorized));
    }

    #[test]
    fn post_state_new_without_claim_constructor() {
        let account = Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            balance: 1337,
            data: vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(),
            nonce: 10_u128.into(),
        };

        let account_post_state = AccountPostState::new(account.clone());

        assert_eq!(account, account_post_state.account);
        assert!(account_post_state.required_claim().is_none());
    }

    #[test]
    fn post_state_account_getter() {
        let mut account = Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            balance: 1337,
            data: vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(),
            nonce: 10_u128.into(),
        };

        let mut account_post_state = AccountPostState::new(account.clone());

        assert_eq!(account_post_state.account(), &account);
        assert_eq!(account_post_state.account_mut(), &mut account);
    }

    // ---- private_pda_account_id tests ----

    /// Pins `private_pda_account_id` against a hardcoded expected output for a specific
    /// `(program_id, seed, npk)` triple. Any change to `PRIVATE_PDA_PREFIX`, byte ordering,
    /// or the underlying hash breaks this test.
    #[test]
    fn private_pda_account_id_matches_pinned_value() {
        let program_id: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let expected = AccountId::new([
            132, 198, 103, 173, 244, 211, 188, 217, 249, 99, 126, 205, 152, 120, 192, 47, 13,
            53, 133, 3, 17, 69, 92, 243, 140, 94, 182, 211, 218, 75, 215, 45,
        ]);
        assert_eq!(private_pda_account_id(&program_id, &seed, &npk), expected);
    }

    /// Two groups with different viewing keys at the same (program, seed) get different addresses.
    #[test]
    fn private_pda_account_id_differs_for_different_npk() {
        let program_id: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk_a = NullifierPublicKey([3; 32]);
        let npk_b = NullifierPublicKey([4; 32]);
        assert_ne!(
            private_pda_account_id(&program_id, &seed, &npk_a),
            private_pda_account_id(&program_id, &seed, &npk_b),
        );
    }

    /// Different seeds produce different addresses, even with the same program and npk.
    #[test]
    fn private_pda_account_id_differs_for_different_seed() {
        let program_id: ProgramId = [1; 8];
        let seed_a = PdaSeed::new([2; 32]);
        let seed_b = PdaSeed::new([5; 32]);
        let npk = NullifierPublicKey([3; 32]);
        assert_ne!(
            private_pda_account_id(&program_id, &seed_a, &npk),
            private_pda_account_id(&program_id, &seed_b, &npk),
        );
    }

    /// Different programs produce different addresses, even with the same seed and npk.
    #[test]
    fn private_pda_account_id_differs_for_different_program_id() {
        let program_id_a: ProgramId = [1; 8];
        let program_id_b: ProgramId = [9; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        assert_ne!(
            private_pda_account_id(&program_id_a, &seed, &npk),
            private_pda_account_id(&program_id_b, &seed, &npk),
        );
    }

    /// A private PDA at the same (program, seed) has a different address than a public PDA,
    /// because the private formula uses a different prefix and includes npk.
    #[test]
    fn private_pda_account_id_differs_from_public_pda() {
        let program_id: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let private_id = private_pda_account_id(&program_id, &seed, &npk);
        let public_id = AccountId::from((&program_id, &seed));
        assert_ne!(private_id, public_id);
    }

    /// A private PDA address differs from a standard private account address at the same `npk`,
    /// because the private PDA formula includes `program_id` and `seed`.
    #[test]
    fn private_pda_account_id_differs_from_standard_private() {
        let program_id: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let private_pda_id = private_pda_account_id(&program_id, &seed, &npk);
        let standard_private_id = AccountId::from(&npk);
        assert_ne!(private_pda_id, standard_private_id);
    }

    // ---- compute_authorized_pdas tests ----

    /// With no private PDA seeds, `compute_authorized_pdas` returns public PDA addresses only.
    #[test]
    fn compute_authorized_pdas_public_only() {
        let caller: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let result = compute_authorized_pdas(Some(caller), &[seed], &[]);
        let expected = AccountId::from((&caller, &seed));
        assert!(result.contains(&expected));
        assert_eq!(result.len(), 1);
    }

    /// Private PDA seeds produce private PDA `AccountId`s via the `npk`-inclusive derivation.
    #[test]
    fn compute_authorized_pdas_private_only() {
        let caller: ProgramId = [1; 8];
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let result = compute_authorized_pdas(Some(caller), &[], &[(seed, npk)]);
        let expected = private_pda_account_id(&caller, &seed, &npk);
        assert!(result.contains(&expected));
        let public_id = AccountId::from((&caller, &seed));
        assert!(!result.contains(&public_id));
        assert_eq!(result.len(), 1);
    }

    /// Public and private seeds can coexist in a single chained call; both are authorized.
    #[test]
    fn compute_authorized_pdas_public_and_private() {
        let caller: ProgramId = [1; 8];
        let pub_seed = PdaSeed::new([2; 32]);
        let priv_seed = PdaSeed::new([4; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let result = compute_authorized_pdas(Some(caller), &[pub_seed], &[(priv_seed, npk)]);
        assert!(result.contains(&AccountId::from((&caller, &pub_seed))));
        assert!(result.contains(&private_pda_account_id(&caller, &priv_seed, &npk)));
        assert_eq!(result.len(), 2);
    }

    /// With no caller (top-level call), the result is always empty.
    #[test]
    fn compute_authorized_pdas_no_caller_returns_empty() {
        let seed = PdaSeed::new([2; 32]);
        let npk = NullifierPublicKey([3; 32]);
        let result = compute_authorized_pdas(None, &[seed], &[(seed, npk)]);
        assert!(result.is_empty());
    }
}

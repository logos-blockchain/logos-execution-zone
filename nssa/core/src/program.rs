use std::collections::HashSet;

#[cfg(any(feature = "host", test))]
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::{DeserializeOwned, guest::env, serde::Deserializer};
use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountId, AccountWithMetadata};

pub const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];
pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

pub type ProgramId = [u32; 8];
pub type InstructionData = Vec<u32>;
pub struct ProgramInput<T> {
    pub pre_states: Vec<AccountWithMetadata>,
    pub instruction: T,
}

/// A 32-byte seed used to compute a *Program-Derived `AccountId`* (PDA).
///
/// Each program can derive up to `2^256` unique account IDs by choosing different
/// seeds. PDAs allow programs to control namespaced account identifiers without
/// collisions between programs.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
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
    pub pda_seeds: Vec<PdaSeed>,
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
        }
    }

    #[must_use]
    pub fn with_pda_seeds(mut self, pda_seeds: Vec<PdaSeed>) -> Self {
        self.pda_seeds = pda_seeds;
        self
    }
}

/// Represents the final state of an `Account` after a program execution.
///
/// A post state may optionally request that the executing program
/// becomes the owner of the account (a “claim”). This is used to signal
/// that the program intends to take ownership of the account.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(feature = "host", test), derive(PartialEq, Eq))]
pub struct AccountPostState {
    account: Account,
    claim: bool,
}

impl AccountPostState {
    /// Creates a post state without a claim request.
    /// The executing program is not requesting ownership of the account.
    #[must_use]
    pub const fn new(account: Account) -> Self {
        Self {
            account,
            claim: false,
        }
    }

    /// Creates a post state that requests ownership of the account.
    /// This indicates that the executing program intends to claim the
    /// account as its own and is allowed to mutate it.
    #[must_use]
    pub const fn new_claimed(account: Account) -> Self {
        Self {
            account,
            claim: true,
        }
    }

    /// Creates a post state that requests ownership of the account
    /// if the account's program owner is the default program ID.
    #[must_use]
    pub fn new_claimed_if_default(account: Account) -> Self {
        let claim = account.program_owner == DEFAULT_PROGRAM_ID;
        Self { account, claim }
    }

    /// Returns `true` if this post state requests that the account
    /// be claimed (owned) by the executing program.
    #[must_use]
    pub const fn requires_claim(&self) -> bool {
        self.claim
    }

    /// Returns the underlying account.
    #[must_use]
    pub const fn account(&self) -> &Account {
        &self.account
    }

    /// Returns the underlying account.
    pub const fn account_mut(&mut self) -> &mut Account {
        &mut self.account
    }

    /// Consumes the post state and returns the underlying account.
    #[must_use]
    pub fn into_account(self) -> Account {
        self.account
    }
}

pub type BlockId = u64;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)
)]
pub struct ValidityWindow {
    from: Option<BlockId>,
    to: Option<BlockId>,
}

impl ValidityWindow {
    /// Creates a window with no bounds, valid for every block ID.
    #[must_use]
    pub const fn new_unbounded() -> Self {
        Self {
            from: None,
            to: None,
        }
    }

    /// Returns `true` if `id` falls within the half-open range `[from, to)`.
    /// A `None` bound on either side is treated as unbounded in that direction.
    #[must_use]
    pub fn is_valid_for_block_id(&self, id: BlockId) -> bool {
        self.from.is_none_or(|start| id >= start) && self.to.is_none_or(|end| id < end)
    }

    /// Returns `Err(InvalidWindow)` if both bounds are set and `from >= to`.
    const fn check_window(&self) -> Result<(), InvalidWindow> {
        if let (Some(from_id), Some(until_id)) = (self.from, self.to)
            && from_id >= until_id
        {
            Err(InvalidWindow)
        } else {
            Ok(())
        }
    }

    /// Inclusive lower bound. `None` means the window starts at the beginning of the chain.
    #[must_use]
    pub const fn start(&self) -> Option<BlockId> {
        self.from
    }

    /// Exclusive upper bound. `None` means the window has no expiry.
    #[must_use]
    pub const fn end(&self) -> Option<BlockId> {
        self.to
    }
}

impl TryFrom<(Option<BlockId>, Option<BlockId>)> for ValidityWindow {
    type Error = InvalidWindow;

    fn try_from(value: (Option<BlockId>, Option<BlockId>)) -> Result<Self, Self::Error> {
        let this = Self {
            from: value.0,
            to: value.1,
        };
        this.check_window()?;
        Ok(this)
    }
}

impl TryFrom<std::ops::Range<BlockId>> for ValidityWindow {
    type Error = InvalidWindow;

    fn try_from(value: std::ops::Range<BlockId>) -> Result<Self, Self::Error> {
        (Some(value.start), Some(value.end)).try_into()
    }
}

impl From<std::ops::RangeFrom<BlockId>> for ValidityWindow {
    fn from(value: std::ops::RangeFrom<BlockId>) -> Self {
        Self {
            from: Some(value.start),
            to: None,
        }
    }
}

impl From<std::ops::RangeTo<BlockId>> for ValidityWindow {
    fn from(value: std::ops::RangeTo<BlockId>) -> Self {
        Self {
            from: None,
            to: Some(value.end),
        }
    }
}

impl From<std::ops::RangeFull> for ValidityWindow {
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
    /// The instruction data the program received to produce this output.
    pub instruction_data: InstructionData,
    /// The account pre states the program received to produce this output.
    pub pre_states: Vec<AccountWithMetadata>,
    /// The account post states the program execution produced.
    pub post_states: Vec<AccountPostState>,
    /// The list of chained calls to other programs.
    pub chained_calls: Vec<ChainedCall>,
    /// The window where the program output is valid.
    pub validity_window: ValidityWindow,
}

impl ProgramOutput {
    pub const fn new(
        instruction_data: InstructionData,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountPostState>,
    ) -> Self {
        Self {
            instruction_data,
            pre_states,
            post_states,
            chained_calls: Vec::new(),
            validity_window: ValidityWindow::new_unbounded(),
        }
    }

    pub fn write(self) {
        env::commit(&self);
    }

    pub fn with_chained_calls(mut self, chained_calls: Vec<ChainedCall>) -> Self {
        self.chained_calls = chained_calls;
        self
    }

    /// Sets the validity window from an infallible range conversion (`1..`, `..5`, `..`).
    pub fn with_validity_window<W: Into<ValidityWindow>>(mut self, window: W) -> Self {
        self.validity_window = window.into();
        self
    }

    /// Sets the validity window from a fallible range conversion (`1..5`).
    /// Returns `Err` if the range is empty.
    pub fn try_with_validity_window<W: TryInto<ValidityWindow, Error = InvalidWindow>>(
        mut self,
        window: W,
    ) -> Result<Self, InvalidWindow> {
        self.validity_window = window.try_into()?;
        Ok(self)
    }
}

/// Representation of a number as `lo + hi * 2^128`.
#[derive(PartialEq, Eq)]
struct WrappedBalanceSum {
    lo: u128,
    hi: u128,
}

impl WrappedBalanceSum {
    /// Constructs a [`WrappedBalanceSum`] from an iterator of balances.
    ///
    /// Returns [`None`] if balance sum overflows `lo + hi * 2^128` representation, which is not
    /// expected in practical scenarios.
    fn from_balances(balances: impl Iterator<Item = u128>) -> Option<Self> {
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

#[must_use]
pub fn compute_authorized_pdas(
    caller_program_id: Option<ProgramId>,
    pda_seeds: &[PdaSeed],
) -> HashSet<AccountId> {
    caller_program_id
        .map(|caller_program_id| {
            pda_seeds
                .iter()
                .map(|pda_seed| AccountId::from((&caller_program_id, pda_seed)))
                .collect()
        })
        .unwrap_or_default()
}

/// Reads the NSSA inputs from the guest environment.
#[must_use]
pub fn read_nssa_inputs<T: DeserializeOwned>() -> (ProgramInput<T>, InstructionData) {
    let pre_states: Vec<AccountWithMetadata> = env::read();
    let instruction_words: InstructionData = env::read();
    let instruction = T::deserialize(&mut Deserializer::new(instruction_words.as_ref())).unwrap();
    (
        ProgramInput {
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
#[must_use]
pub fn validate_execution(
    pre_states: &[AccountWithMetadata],
    post_states: &[AccountPostState],
    executing_program_id: ProgramId,
) -> bool {
    // 1. Check account ids are all different
    if !validate_uniqueness_of_account_ids(pre_states) {
        return false;
    }

    // 2. Lengths must match
    if pre_states.len() != post_states.len() {
        return false;
    }

    for (pre, post) in pre_states.iter().zip(post_states) {
        // 3. Nonce must remain unchanged
        if pre.account.nonce != post.account.nonce {
            return false;
        }

        // 4. Program ownership changes are not allowed
        if pre.account.program_owner != post.account.program_owner {
            return false;
        }

        let account_program_owner = pre.account.program_owner;

        // 5. Decreasing balance only allowed if owned by executing program
        if post.account.balance < pre.account.balance
            && account_program_owner != executing_program_id
        {
            return false;
        }

        // 6. Data changes only allowed if owned by executing program or if account pre state has
        //    default values
        if pre.account.data != post.account.data
            && pre.account != Account::default()
            && account_program_owner != executing_program_id
        {
            return false;
        }

        // 7. If a post state has default program owner, the pre state must have been a default
        //    account
        if post.account.program_owner == DEFAULT_PROGRAM_ID && pre.account != Account::default() {
            return false;
        }
    }

    // 8. Total balance is preserved

    let Some(total_balance_pre_states) =
        WrappedBalanceSum::from_balances(pre_states.iter().map(|pre| pre.account.balance))
    else {
        return false;
    };

    let Some(total_balance_post_states) =
        WrappedBalanceSum::from_balances(post_states.iter().map(|post| post.account.balance))
    else {
        return false;
    };

    if total_balance_pre_states != total_balance_post_states {
        return false;
    }

    true
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
    fn validity_window_unbounded_accepts_any_block() {
        let w = ValidityWindow::new_unbounded();
        assert!(w.is_valid_for_block_id(0));
        assert!(w.is_valid_for_block_id(u64::MAX));
    }

    #[test]
    fn validity_window_bounded_range_includes_from_excludes_to() {
        let w: ValidityWindow = (Some(5), Some(10)).try_into().unwrap();
        assert!(!w.is_valid_for_block_id(4));
        assert!(w.is_valid_for_block_id(5));
        assert!(w.is_valid_for_block_id(9));
        assert!(!w.is_valid_for_block_id(10));
    }

    #[test]
    fn validity_window_only_from_bound() {
        let w: ValidityWindow = (Some(5), None).try_into().unwrap();
        assert!(!w.is_valid_for_block_id(4));
        assert!(w.is_valid_for_block_id(5));
        assert!(w.is_valid_for_block_id(u64::MAX));
    }

    #[test]
    fn validity_window_only_to_bound() {
        let w: ValidityWindow = (None, Some(5)).try_into().unwrap();
        assert!(w.is_valid_for_block_id(0));
        assert!(w.is_valid_for_block_id(4));
        assert!(!w.is_valid_for_block_id(5));
    }

    #[test]
    fn validity_window_adjacent_bounds_are_invalid() {
        // [5, 5) is an empty range — from == to
        assert!(ValidityWindow::try_from((Some(5), Some(5))).is_err());
    }

    #[test]
    fn validity_window_inverted_bounds_are_invalid() {
        assert!(ValidityWindow::try_from((Some(10), Some(5))).is_err());
    }

    #[test]
    fn validity_window_getters_match_construction() {
        let w: ValidityWindow = (Some(3), Some(7)).try_into().unwrap();
        assert_eq!(w.start(), Some(3));
        assert_eq!(w.end(), Some(7));
    }

    #[test]
    fn validity_window_getters_for_unbounded() {
        let w = ValidityWindow::new_unbounded();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), None);
    }

    #[test]
    fn validity_window_from_range() {
        let w = ValidityWindow::try_from(5_u64..10).unwrap();
        assert_eq!(w.start(), Some(5));
        assert_eq!(w.end(), Some(10));
    }

    #[test]
    fn validity_window_from_range_empty_is_invalid() {
        assert!(ValidityWindow::try_from(5_u64..5).is_err());
    }

    #[test]
    fn validity_window_from_range_inverted_is_invalid() {
        let from = 10_u64;
        let to = 5_u64;
        assert!(ValidityWindow::try_from(from..to).is_err());
    }

    #[test]
    fn validity_window_from_range_from() {
        let w: ValidityWindow = (5_u64..).into();
        assert_eq!(w.start(), Some(5));
        assert_eq!(w.end(), None);
    }

    #[test]
    fn validity_window_from_range_to() {
        let w: ValidityWindow = (..10_u64).into();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), Some(10));
    }

    #[test]
    fn validity_window_from_range_full() {
        let w: ValidityWindow = (..).into();
        assert_eq!(w.start(), None);
        assert_eq!(w.end(), None);
    }

    #[test]
    fn program_output_try_with_validity_window_range() {
        let output = ProgramOutput::new(vec![], vec![], vec![])
            .try_with_validity_window(10_u64..100)
            .unwrap();
        assert_eq!(output.validity_window.start(), Some(10));
        assert_eq!(output.validity_window.end(), Some(100));
    }

    #[test]
    fn program_output_with_validity_window_range_from() {
        let output = ProgramOutput::new(vec![], vec![], vec![]).with_validity_window(10_u64..);
        assert_eq!(output.validity_window.start(), Some(10));
        assert_eq!(output.validity_window.end(), None);
    }

    #[test]
    fn program_output_with_validity_window_range_to() {
        let output = ProgramOutput::new(vec![], vec![], vec![]).with_validity_window(..100_u64);
        assert_eq!(output.validity_window.start(), None);
        assert_eq!(output.validity_window.end(), Some(100));
    }

    #[test]
    fn program_output_try_with_validity_window_empty_range_fails() {
        let result = ProgramOutput::new(vec![], vec![], vec![]).try_with_validity_window(5_u64..5);
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

        let account_post_state = AccountPostState::new_claimed(account.clone());

        assert_eq!(account, account_post_state.account);
        assert!(account_post_state.requires_claim());
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
        assert!(!account_post_state.requires_claim());
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
}

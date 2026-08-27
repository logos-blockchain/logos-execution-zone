use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, Identifier, NullifierPublicKey, Timestamp,
    account::{Account, AccountDiff, AccountId, AccountWithMetadata, BalanceDiff},
    encryption::ViewingPublicKey,
};

pub const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];

/// TODO: Placeholder `program_owner` for uninitialized `Account`.
pub const DEFAULT_PROGRAM_OWNER: AccountId = AccountId::new([0; 32]);

/// TODO: Temporary placeholder for program deployment program id; this serves as
/// `program_owner` for program `Account`s.
pub const PROGRAM_STORAGE_OWNER: AccountId = AccountId::new([0xFF; 32]);

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

pub type ProgramId = [u32; 8];

/// Derives the `AccountId` under which a program's data is stored, directly from its
/// `ProgramId`, by reinterpreting the 8 little-endian `u32` words as 32 raw bytes.
///
/// A 1:1, information-preserving mapping (both types are exactly 32 bytes) rather than a
/// hash — `ProgramId` is already content-derived (RISC0's `image_id`), so no extra domain
/// separation is needed just to use it as a `HashMap<AccountId, Account>` key.
impl From<ProgramId> for AccountId {
    fn from(program_id: ProgramId) -> Self {
        let bytes: Vec<u8> = program_id
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        Self::new(bytes.try_into().expect("8 u32 words are exactly 32 bytes"))
    }
}

impl From<AccountId> for ProgramId {
    fn from(account_id: AccountId) -> Self {
        let mut program_id = [0_u32; 8];
        for (word, chunk) in program_id
            .iter_mut()
            .zip(account_id.value().chunks_exact(4))
        {
            *word = u32::from_le_bytes(chunk.try_into().expect("chunk is exactly 4 bytes"));
        }
        program_id
    }
}

/// Borsh-encoded program instruction bytes.
pub type InstructionData = Vec<u8>;

/// Struct encoding the input to an LEE program.
#[derive(BorshSerialize, BorshDeserialize)]
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
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct PdaSeed([u8; 32]);

impl PdaSeed {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for PdaSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Discriminates the type of private account a ciphertext belongs to, carrying the data needed
/// to reconstruct the account's [`AccountId`] on the receiver side.
///
/// [`AccountId`]: crate::account::AccountId
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum PrivateAccountKind {
    Regular(Identifier),
    Pda {
        program_id: ProgramId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}

impl PrivateAccountKind {
    /// Borsh layout (all integers little-endian, variant index is u8):
    ///
    /// ```text
    /// Regular(ident):                  0x00 || ident (16 LE) || [0u8; 64]
    /// Pda { program_id, seed, ident }: 0x01 || program_id (32) || seed (32) || ident (16 LE)
    /// ```
    ///
    /// Both variants are zero-padded to the same length so all ciphertexts are the same size,
    /// preventing observers from distinguishing `Regular` from `Pda` via ciphertext length.
    /// `HEADER_LEN` equals the borsh size of the largest variant (`Pda`): 1 + 32 + 32 + 16 = 81.
    pub const HEADER_LEN: usize = 81;

    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        match self {
            Self::Regular(identifier) | Self::Pda { identifier, .. } => *identifier,
        }
    }

    #[must_use]
    pub fn to_header_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut bytes = [0_u8; Self::HEADER_LEN];
        let serialized = borsh::to_vec(self).expect("borsh serialization is infallible");
        bytes[..serialized.len()].copy_from_slice(&serialized);
        bytes
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub fn from_header_bytes(bytes: &[u8; Self::HEADER_LEN]) -> Option<Self> {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).ok()
    }
}

impl AccountId {
    /// Derives an [`AccountId`] for a public PDA from the program ID and seed.
    #[must_use]
    pub fn for_public_pda(program_id: &ProgramId, seed: &PdaSeed) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PROGRAM_DERIVED_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = [0; 96];
        bytes[0..32].copy_from_slice(PROGRAM_DERIVED_ACCOUNT_ID_PREFIX);
        let program_id_bytes: &[u8] =
            bytemuck::try_cast_slice(program_id).expect("ProgramId should be castable to &[u8]");
        bytes[32..64].copy_from_slice(program_id_bytes);
        bytes[64..].copy_from_slice(&seed.0);
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }

    /// Derives an [`AccountId`] for a private PDA from the program ID, seed, nullifier public
    /// key, and identifier.
    ///
    /// Unlike public PDAs ([`AccountId::for_public_pda`]), this includes the `npk` in the
    /// derivation, making the address unique per group of controllers sharing viewing keys.
    /// The `identifier` further diversifies the address, so a single `(program_id, seed, npk)`
    /// tuple controls a family of 2^128 addresses.
    #[must_use]
    pub fn for_private_pda(
        program_id: &ProgramId,
        seed: &PdaSeed,
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PRIVATE_PDA_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00";

        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + ViewingPublicKey::LEN + 16];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        let program_id_bytes: &[u8] =
            bytemuck::try_cast_slice(program_id).expect("ProgramId should be castable to &[u8]");
        bytes[32..64].copy_from_slice(program_id_bytes);
        bytes[64..96].copy_from_slice(&seed.0);
        bytes[96..128].copy_from_slice(&npk.to_byte_array());
        bytes[128..128 + ViewingPublicKey::LEN].copy_from_slice(vpk.to_bytes());
        bytes[128 + ViewingPublicKey::LEN..].copy_from_slice(&identifier.to_le_bytes());
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }

    /// Derives the [`AccountId`] for a private account from the nullifier public key and kind.
    #[must_use]
    pub fn for_private_account(
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        kind: &PrivateAccountKind,
    ) -> Self {
        match kind {
            PrivateAccountKind::Regular(identifier) => {
                Self::for_regular_private_account(npk, vpk, *identifier)
            }
            PrivateAccountKind::Pda {
                program_id,
                seed,
                identifier,
            } => Self::for_private_pda(program_id, seed, npk, vpk, *identifier),
        }
    }
}

#[derive(Debug)]
pub struct CallerData {
    pub program_id: Option<ProgramId>,
    pub authorized_accounts: HashSet<AccountId>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainedCall {
    /// The program ID of the program to execute.
    pub program_id: ProgramId,
    /// The accounts the callee should receive as `pre_states`, named by id only. The protocol
    /// resolves each account's real value and `is_authorized` from its own tracked state — never
    /// supplied by the calling program.
    pub accounts: Vec<AccountId>,
    /// The instruction data to pass.
    pub instruction_data: InstructionData,
    /// PDA seeds authorized for the callee. For each seed, the callee is authorized to
    /// mutate the `AccountId` derived from `(caller_program_id, seed)`, regardless of
    /// whether the account is public or private.
    pub pda_seeds: Vec<PdaSeed>,
}

impl ChainedCall {
    /// Creates a new chained call serializing the given instruction.
    pub fn new<I: BorshSerialize>(
        program_id: ProgramId,
        accounts: Vec<AccountId>,
        instruction: &I,
    ) -> Self {
        Self {
            program_id,
            accounts,
            instruction_data: borsh::to_vec(instruction)
                .expect("borsh serialization is infallible"),
            pda_seeds: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_pda_seeds(mut self, pda_seeds: Vec<PdaSeed>) -> Self {
        self.pda_seeds = pda_seeds;
        self
    }
}

/// A claim request for an account, indicating that the executing program intends to take ownership
/// of the account.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Claim {
    /// The program requests ownership of the account which was authorized by the signer.
    ///
    /// Note that it's possible to successfully execute program outputting [`AccountDiffOutput`]
    /// with `is_authorized == false` and `claim == Some(Claim::Authorized)`.
    /// This will give no error if program had authorization in pre state and may be useful
    /// if program decides to give up authorization for a chained call.
    Authorized,
    /// The program requests ownership of the account through a PDA. The program emits the
    /// seed; the `AccountId` is derived from `(program_id, seed)`, regardless of whether the
    /// account is public or private.
    Pda(PdaSeed),
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(PartialEq, Eq))]
pub struct AccountDiffOutput {
    diff: AccountDiff,
    claim: Option<Claim>,
}

impl AccountDiffOutput {
    #[must_use]
    pub const fn new(diff: AccountDiff) -> Self {
        Self { diff, claim: None }
    }

    #[must_use]
    pub const fn new_claimed(diff: AccountDiff, claim: Claim) -> Self {
        Self {
            diff,
            claim: Some(claim),
        }
    }

    // `AccountDiff` deliberately carries no ownership info, unlike `Account`, so this needs the
    // pre-state's owner passed in explicitly.
    #[must_use]
    pub fn new_claimed_if_default(
        diff: AccountDiff,
        pre_state_program_owner: AccountId,
        claim: Claim,
    ) -> Self {
        let is_default_owner = pre_state_program_owner == DEFAULT_PROGRAM_OWNER;
        Self {
            diff,
            claim: is_default_owner.then_some(claim),
        }
    }

    #[must_use]
    pub const fn claim(&self) -> Option<Claim> {
        self.claim
    }

    #[must_use]
    pub const fn diff(&self) -> &AccountDiff {
        &self.diff
    }

    #[must_use]
    pub const fn diff_mut(&mut self) -> &mut AccountDiff {
        &mut self.diff
    }
}

impl From<AccountDiffOutput> for AccountDiff {
    fn from(output: AccountDiffOutput) -> Self {
        output.diff
    }
}

pub type BlockValidityWindow = ValidityWindow<BlockId>;
pub type TimestampValidityWindow = ValidityWindow<Timestamp>;

#[derive(Clone, Copy, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
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

#[derive(Serialize, Deserialize, Clone, BorshSerialize, BorshDeserialize)]
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
    /// The account diffs the program execution produced.
    pub post_states: Vec<AccountDiffOutput>,
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
        post_states: Vec<AccountDiffOutput>,
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
        env::commit_slice(&crate::to_borsh_frame(&self));
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

    #[error(
        "Trying to decrease balance of account {account_id} owned by {owner_account_id:?} in a program {executing_program_id:?} which is not the owner"
    )]
    UnauthorizedBalanceDecrease {
        account_id: AccountId,
        owner_account_id: AccountId,
        executing_program_id: ProgramId,
    },

    #[error(
        "Unauthorized modification of data for account {account_id} which is not default and not owned by executing program {executing_program_id:?}"
    )]
    UnauthorizedDataModification {
        account_id: AccountId,
        executing_program_id: ProgramId,
    },

    #[error("Total balance across accounts overflowed 2^256 - 1")]
    BalanceSumOverflow,

    #[error(
        "Total balance across accounts is not preserved: total added {total_added}, total subtracted {total_subbed}"
    )]
    MismatchedTotalBalance {
        total_added: WrappedBalanceSum,
        total_subbed: WrappedBalanceSum,
    },
}

/// Discriminates which entrypoint a single guest invocation is for. Written by the (trusted)
/// orchestrator only.
///
/// Currently only ever `Execute`; this exists so a future protocol upgrade can introduce
/// additional entrypoints without changing the shape of a guest invocation's inputs.
///
/// Borsh-encodes by variant index. `Execute` must remain index 0. Future variants must only be
/// appended at the end, never inserted or reordered.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum CallKind {
    Execute,
}

/// The guest-side view of a single invocation.
pub enum ProgramCall<T> {
    Execute(ProgramInput<T>, InstructionData),
}

/// Computes the set of public-PDA `AccountId`s the callee is authorized to mutate.
///
/// Returns only public-form derivations, suitable for contexts where all accounts are public
/// (e.g. the public-execution path). The privacy circuit must additionally check each mask-3
/// `pre_state` against [`AccountId::for_private_pda`] with the supplied npk for that
/// `pre_state`.
#[must_use]
pub fn compute_public_authorized_pdas(
    caller_program_id: Option<ProgramId>,
    pda_seeds: &[PdaSeed],
) -> HashSet<AccountId> {
    let Some(caller) = caller_program_id else {
        return HashSet::new();
    };
    pda_seeds
        .iter()
        .map(|seed| AccountId::for_public_pda(&caller, seed))
        .collect()
}

/// Reads first 4 bytes indicating the length in bytes of the program input bytes.
/// Afterwards, reads exactly that many payload bytes.
#[must_use]
pub fn read_input_frame() -> Vec<u8> {
    let mut len_bytes = [0; 4];
    env::read_slice(&mut len_bytes);
    let len = usize::try_from(u32::from_le_bytes(len_bytes)).expect("frame length fits in usize");
    let mut payload: Vec<u8> = vec![0; len];
    env::read_slice(&mut payload);
    payload
}

/// Reads a single LEE guest invocation, dispatching on [`CallKind`].
///
/// Every guest `main` should match on the returned [`ProgramCall`] rather than assume it was
/// invoked to execute. Each of `CallKind` and the invocation's own payload is read as its own
/// length-prefixed borsh frame (see [`read_input_frame`]), one after the other; the payload frame
/// decodes as `ProgramInput<InstructionData>`, with `T` a second decode of the instruction bytes.
#[must_use]
pub fn read_lee_call<T: BorshDeserialize>() -> ProgramCall<T> {
    let call_kind: CallKind =
        borsh::from_slice(&read_input_frame()).expect("call kind must decode from borsh");
    match call_kind {
        CallKind::Execute => {
            let ProgramInput {
                self_program_id,
                caller_program_id,
                pre_states,
                instruction: instruction_data,
            } = borsh::from_slice::<ProgramInput<InstructionData>>(&read_input_frame())
                .expect("guest input must be valid borsh");
            let instruction =
                borsh::from_slice(&instruction_data).expect("instruction must decode from borsh");
            ProgramCall::Execute(
                ProgramInput {
                    self_program_id,
                    caller_program_id,
                    pre_states,
                    instruction,
                },
                instruction_data,
            )
        }
    }
}

/// Validates well-behaved program execution.
///
/// `AccountDiff` has no `nonce`/`program_owner` field, so a program can't forge either; ownership
/// is checked separately, via claims.
///
/// # Parameters
/// - `pre_states`: The list of input accounts, each annotated with authorization metadata.
/// - `post_diff`: The diff each account underwent, as reported by the executing program.
/// - `executing_program_id`: The identifier of the program that was executed.
pub fn validate_execution(
    pre_states: &[AccountWithMetadata],
    post_diff: &[AccountDiffOutput],
    executing_program_id: ProgramId,
) -> Result<(), ExecutionValidationError> {
    // `program_owner` is `AccountId`-typed; convert once up front rather than at each
    // comparison below (see `From<ProgramId> for AccountId`'s doc comment).
    let executing_account_id = AccountId::from(executing_program_id);

    // 1. Check account ids are all different
    if !validate_uniqueness_of_account_ids(pre_states) {
        return Err(ExecutionValidationError::PreStateAccountIdsNotUnique);
    }

    // 2. Lengths must match
    if pre_states.len() != post_diff.len() {
        return Err(
            ExecutionValidationError::MismatchedPreStatePostStateLength {
                pre_state_length: pre_states.len(),
                post_state_length: post_diff.len(),
            },
        );
    }

    for (pre, diff_output) in pre_states.iter().zip(post_diff) {
        let diff = diff_output.diff();
        let account_program_owner = pre.account.program_owner;

        // 3. Decreasing balance only allowed if owned by executing program
        if matches!(diff.diff_balance, BalanceDiff::Sub(amount) if amount > 0)
            && account_program_owner != executing_account_id
        {
            return Err(ExecutionValidationError::UnauthorizedBalanceDecrease {
                account_id: pre.account_id,
                owner_account_id: account_program_owner,
                executing_program_id,
            });
        }

        // 4. Data changes only allowed if owned by executing program or if account pre state has
        //    default values
        if diff.diff_data.is_some()
            && pre.account != Account::default()
            && account_program_owner != executing_account_id
        {
            return Err(ExecutionValidationError::UnauthorizedDataModification {
                account_id: pre.account_id,
                executing_program_id,
            });
        }
    }

    // 5. Total balance is preserved
    let Some(total_added) =
        WrappedBalanceSum::from_balances(post_diff.iter().filter_map(|diff_output| {
            match diff_output.diff().diff_balance {
                BalanceDiff::Add(amount) => Some(amount),
                BalanceDiff::Sub(_) => None,
            }
        }))
    else {
        return Err(ExecutionValidationError::BalanceSumOverflow);
    };

    let Some(total_subbed) =
        WrappedBalanceSum::from_balances(post_diff.iter().filter_map(|diff_output| {
            match diff_output.diff().diff_balance {
                BalanceDiff::Sub(amount) => Some(amount),
                BalanceDiff::Add(_) => None,
            }
        }))
    else {
        return Err(ExecutionValidationError::BalanceSumOverflow);
    };

    if total_added != total_subbed {
        return Err(ExecutionValidationError::MismatchedTotalBalance {
            total_added,
            total_subbed,
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
mod tests;

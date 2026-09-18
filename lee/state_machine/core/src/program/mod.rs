use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, Identifier, NullifierPublicKey, Timestamp,
    account::{
        Account, AccountId, AccountWithMetadata, BalanceDiff, BalanceDiffError, Data,
        apply_balance_diff,
    },
    encryption::ViewingPublicKey,
};

pub const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];

/// TODO: Placeholder `program_owner` for uninitialized `Account`.
pub const DEFAULT_PROGRAM_OWNER: AccountId = AccountId::new([0; 32]);

/// TODO: Temporary placeholder for program deployment program id; this serves as
/// `program_owner` for program `Account`s.
pub const PROGRAM_STORAGE_OWNER: AccountId = AccountId::new([0xFF; 32]);

/// The well-known dispatch address of the program loader: a native (non-guest) pseudo-program
/// that runs its `Instruction` variants as Rust rather than interpreting a guest ELF.
pub const PROGRAM_LOADER_ACCOUNT_ID: AccountId = AccountId::new([0xFE; 32]);

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

/// Hard cap on a deployed program's segment chain length, bounding a resolution walk.
pub const MAX_PROGRAM_SEGMENTS: usize = 20;

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
    pub self_account_id: AccountId,
    pub caller_account_id: Option<AccountId>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(PartialOrd, Ord))]
pub enum PrivateAccountKind {
    Regular(Identifier),
    Pda {
        account_id: AccountId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}

impl PrivateAccountKind {
    /// Borsh layout (all integers little-endian, variant index is u8):
    ///
    /// ```text
    /// Regular(ident):                 0x00 || ident (16 LE) || [0u8; 64]
    /// Pda { account_id, seed, ident }: 0x01 || account_id (32) || seed (32) || ident (16 LE)
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
    /// Derives an [`AccountId`] for a public PDA from the owning program's account ID and seed.
    #[must_use]
    pub fn for_public_pda(account_id: &Self, seed: &PdaSeed) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PROGRAM_DERIVED_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = [0; 96];
        bytes[0..32].copy_from_slice(PROGRAM_DERIVED_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(account_id.as_ref());
        bytes[64..].copy_from_slice(&seed.0);
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }

    /// Derives an [`AccountId`] for a private PDA from the owning program's account ID, seed,
    /// nullifier public key, and identifier.
    ///
    /// Unlike public PDAs ([`AccountId::for_public_pda`]), this includes the `npk` in the
    /// derivation, making the address unique per group of controllers sharing viewing keys.
    /// The `identifier` further diversifies the address, so a single `(account_id, seed, npk)`
    /// tuple controls a family of 2^128 addresses.
    #[must_use]
    pub fn for_private_pda(
        account_id: &Self,
        seed: &PdaSeed,
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PRIVATE_PDA_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00";

        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + ViewingPublicKey::LEN + 16];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        bytes[32..64].copy_from_slice(account_id.as_ref());
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
                account_id,
                seed,
                identifier,
            } => Self::for_private_pda(account_id, seed, npk, vpk, *identifier),
        }
    }
}

#[derive(Debug)]
pub struct CallerData {
    pub account_id: Option<AccountId>,
    pub authorized_accounts: HashSet<AccountId>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainedCall {
    /// The account ID of the program to execute.
    pub program_account_id: AccountId,
    /// The ids of the accounts the callee should receive as `pre_states`. The protocol
    /// resolves each account's real value and `is_authorized` from its own tracked state — never
    /// supplied by the calling program.
    pub pre_state_ids: Vec<AccountId>,
    /// The instruction data to pass.
    pub instruction_data: InstructionData,
    /// PDA seeds authorized for the callee. For each seed, the callee is authorized to
    /// mutate the `AccountId` derived from `(caller_account_id, seed)`, regardless of
    /// whether the account is public or private.
    pub pda_seeds: Vec<PdaSeed>,
}

impl ChainedCall {
    /// Creates a new chained call serializing the given instruction.
    pub fn new<I: BorshSerialize>(
        program_account_id: AccountId,
        pre_state_ids: Vec<AccountId>,
        instruction: &I,
    ) -> Self {
        Self {
            program_account_id,
            pre_state_ids,
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

/// One deployed program's identity and entry point into its bytecode's segment chain.
///
/// Lives at whatever account address the deployer chose — never a fixed bijection of the
/// bytecode, so the same bytecode may be deployed more than once at different addresses, each a
/// distinct instance for dispatch, PDA-derivation, and ownership purposes.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProgramHeader {
    /// The bytecode's real `image_id`, always recomputed from the segment chain at
    /// deploy/update time — never trusted from a caller-supplied value.
    pub image_id: ProgramId,
    /// The account holding this program's first bytecode segment.
    pub program_first_segment: AccountId,
    /// Once `true`, this header can never be updated again.
    pub immutable: bool,
}

impl ProgramHeader {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("program header serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// One link in a program's bytecode chain: a chunk of the ELF plus where the next chunk lives,
/// tail-to-head — the account itself carries no notion of "first" or "last".
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProgramSegment {
    pub bytecode: Vec<u8>,
    /// The next segment toward the head of the chain, or `None` if this is the head (the first
    /// segment executed, chronologically the last one written).
    pub next_segment: Option<AccountId>,
}

impl ProgramSegment {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("program segment serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// A single account's full pre-state paired with the diff a program's execution applies to it.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(PartialEq, Eq))]
pub struct AccountStateDiff {
    pub pre_state: AccountWithMetadata,
    pub post_balance_diff: BalanceDiff,
    /// `None` means unchanged from `pre_state.account.data` — the common case, kept cheap by not
    /// carrying a second copy of data that's already available via `pre_state`.
    pub post_data: Option<Data>,
}

impl AccountStateDiff {
    /// A diff that leaves `pre_state`'s balance and data untouched.
    #[must_use]
    pub const fn unchanged(pre_state: AccountWithMetadata) -> Self {
        Self {
            pre_state,
            post_balance_diff: BalanceDiff::Add(0),
            post_data: None,
        }
    }

    #[must_use]
    pub fn new(
        pre_state: AccountWithMetadata,
        post_balance_diff: BalanceDiff,
        post_data: Data,
    ) -> Self {
        let post_data = (post_data != pre_state.account.data).then_some(post_data);
        Self {
            pre_state,
            post_balance_diff,
            post_data,
        }
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

/// The event struct emitted by a program.
#[derive(Serialize, Deserialize, Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct ProgramEvent {
    /// Selector bytes allowing to distinguish event type. By convention, the
    /// first 8 bytes of `sha256("<program>::<EventName>")`.
    pub selector: [u8; 8],
    /// The arbitrary event-data emitted in the program output.
    pub data: Vec<u8>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
#[must_use = "ProgramOutput does nothing unless written"]
pub struct ProgramOutput {
    /// The account ID of the program that produced this output.
    pub self_account_id: AccountId,
    /// The account ID of the caller that invoked this program via a chained call,
    /// or `None` if this is a top-level call.
    pub caller_account_id: Option<AccountId>,
    /// Which call kind actually ran to produce this output. A chained call must be `Execute`;
    /// only a top-level call may legitimately be `Unknown`.
    pub call_kind: CallKind,
    /// The instruction data the program received to produce this output.
    pub instruction_data: InstructionData,
    /// Each account's pre-state paired with the diff the program's execution applies to it.
    pub state_diffs: Vec<AccountStateDiff>,
    /// The list of chained calls to other programs.
    pub chained_calls: Vec<ChainedCall>,
    /// The block ID window where the program output is valid.
    pub block_validity_window: BlockValidityWindow,
    /// The timestamp window where the program output is valid.
    pub timestamp_validity_window: TimestampValidityWindow,
    /// A vector of event data. Dropped for private transaction for function
    /// privacy.
    pub events: Vec<ProgramEvent>,
}

impl ProgramOutput {
    pub const fn new(
        self_account_id: AccountId,
        caller_account_id: Option<AccountId>,
        instruction_data: InstructionData,
        state_diffs: Vec<AccountStateDiff>,
    ) -> Self {
        Self {
            self_account_id,
            caller_account_id,
            call_kind: CallKind::Execute,
            instruction_data,
            state_diffs,
            chained_calls: Vec::new(),
            block_validity_window: ValidityWindow::new_unbounded(),
            timestamp_validity_window: ValidityWindow::new_unbounded(),
            events: Vec::new(),
        }
    }

    pub fn write(self) {
        env::commit_slice(&crate::to_borsh_frame(&self));
    }

    pub const fn with_call_kind(mut self, call_kind: CallKind) -> Self {
        self.call_kind = call_kind;
        self
    }

    pub fn with_chained_calls(mut self, chained_calls: Vec<ChainedCall>) -> Self {
        self.chained_calls = chained_calls;
        self
    }

    pub fn with_events(mut self, events: Vec<ProgramEvent>) -> Self {
        self.events = events;
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

/// A struct holding an event-output of a program.
#[cfg(feature = "host")]
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionEvent {
    /// Which program emitted the event.
    pub account_id: AccountId,
    /// Program event-data with selector.
    pub event: ProgramEvent,
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

    #[error("Trying to decrease balance of unauthorized account {account_id}")]
    UnauthorizedBalanceDecrease { account_id: AccountId },

    #[error(
        "Unauthorized modification of data for account {account_id} which is not default and not owned by executing program {executing_account_id}"
    )]
    UnauthorizedDataModification {
        account_id: AccountId,
        executing_account_id: AccountId,
    },

    #[error("Invalid balance diff for account {account_id}: {source}")]
    InvalidBalanceDiff {
        account_id: AccountId,
        #[source]
        source: BalanceDiffError,
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
/// `Execute` is index 0 and must stay index 0; future variants are appended only, never
/// inserted or reordered.
///
/// Decoding is hand-written, not derived: an unrecognized discriminant decodes as `Unknown`
/// rather than failing, so an already-deployed guest survives a call kind introduced after it
/// was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Execute,
    /// An unrecognized discriminant, carrying the raw byte for diagnostics.
    Unknown(u8),
}

impl BorshSerialize for CallKind {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let discriminant: u8 = match *self {
            Self::Execute => 0,
            Self::Unknown(byte) => byte,
        };
        BorshSerialize::serialize(&discriminant, writer)
    }
}

impl BorshDeserialize for CallKind {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let discriminant = u8::deserialize_reader(reader)?;
        Ok(match discriminant {
            0 => Self::Execute,
            other => Self::Unknown(other),
        })
    }
}

/// The guest-side view of a single invocation.
///
/// `#[non_exhaustive]`: any `match` outside this crate must include a wildcard arm, so a guest
/// implementing more than `Execute` is forced to reconsider when a new variant is added.
#[non_exhaustive]
pub enum ProgramCall<T> {
    Execute(ProgramInput<T>, InstructionData),
    /// A call kind this build doesn't implement (an unrecognized `CallKind`), with the raw
    /// discriminant and the envelope common to every call kind.
    Unsupported(ProgramInput<InstructionData>, u8),
}

/// Diagnostic event recorded when a call kind isn't implemented; the call itself is a no-op,
/// not a rejection.
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UnsupportedCallKind {
    /// The discriminant byte this build didn't recognize.
    pub raw_discriminant: u8,
}

impl UnsupportedCallKind {
    pub const SELECTOR: [u8; 8] = [0xb5, 0x9a, 0xac, 0x13, 0xbd, 0xb1, 0xa7, 0x3c];
    pub const SELECTOR_NAME: &str = "lee_core::UnsupportedCallKind";

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("UnsupportedCallKind serializes")
    }
}

/// Computes the set of public-PDA `AccountId`s the callee is authorized to mutate.
///
/// Returns only public-form derivations, suitable for contexts where all accounts are public
/// (e.g. the public-execution path). The privacy circuit must additionally check each mask-3
/// `pre_state` against [`AccountId::for_private_pda`] with the supplied npk for that
/// `pre_state`.
#[must_use]
pub fn compute_public_authorized_pdas(
    caller_account_id: Option<AccountId>,
    pda_seeds: &[PdaSeed],
) -> HashSet<AccountId> {
    let Some(caller) = caller_account_id else {
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

/// Reads a single LEE guest invocation, dispatching on `CallKind`.
#[must_use]
pub fn read_lee_call<T: BorshDeserialize>() -> ProgramCall<T> {
    let call_kind: CallKind =
        borsh::from_slice(&read_input_frame()).expect("call kind must decode from borsh");

    // The envelope's shape doesn't depend on call kind, so it's always readable -- even for a
    // call kind this build doesn't recognize.
    let envelope: ProgramInput<InstructionData> =
        borsh::from_slice(&read_input_frame()).expect("guest input must be valid borsh");

    match call_kind {
        CallKind::Execute => {
            let ProgramInput {
                self_account_id,
                caller_account_id,
                pre_states,
                instruction: instruction_data,
            } = envelope;
            let instruction =
                borsh::from_slice(&instruction_data).expect("instruction must decode from borsh");
            ProgramCall::Execute(
                ProgramInput {
                    self_account_id,
                    caller_account_id,
                    pre_states,
                    instruction,
                },
                instruction_data,
            )
        }
        CallKind::Unknown(raw) => ProgramCall::Unsupported(envelope, raw),
    }
}

/// Responds to a call kind this program doesn't implement with a no-op — a deliberate skip,
/// not a failure.
pub fn respond_unsupported_call<T>(call: ProgramCall<T>) -> ! {
    let ProgramCall::Unsupported(envelope, raw_discriminant) = call else {
        unreachable!("only reached after Execute was already ruled out by the caller");
    };
    let state_diffs = envelope
        .pre_states
        .iter()
        .cloned()
        .map(AccountStateDiff::unchanged)
        .collect();
    ProgramOutput::new(
        envelope.self_account_id,
        envelope.caller_account_id,
        envelope.instruction,
        state_diffs,
    )
    .with_call_kind(CallKind::Unknown(raw_discriminant))
    .with_events(vec![ProgramEvent {
        selector: UnsupportedCallKind::SELECTOR,
        data: UnsupportedCallKind { raw_discriminant }.to_bytes(),
    }])
    .write();
    env::exit(0)
}

/// Whether a callee's journalled `pre_states` name exactly the accounts in the call
/// in the appropriate order.
#[must_use]
pub fn pre_states_match_accounts(
    accounts: &[AccountId],
    pre_states: &[AccountWithMetadata],
) -> bool {
    accounts
        .iter()
        .eq(pre_states.iter().map(|pre| &pre.account_id))
}

/// Resolves a deployed program from whatever account it lives at.
///
/// Verifies the account is loader-owned, decodes its [`ProgramHeader`], and reconstructs its
/// bytecode by walking the segment chain from `program_first_segment`.
///
/// Returns `None` if `account_id` isn't a deployed program — any owner other than the loader,
/// malformed header/segment data, or a chain longer than [`MAX_PROGRAM_SEGMENTS`]. By
/// construction only the loader's own writes can make an account loader-owned, so this can't be
/// spoofed by writing lookalike data as some other program.
///
/// `lookup` resolves an account's current value; callers decide what that means (committed
/// state, a pending diff, or a combination — see call sites).
#[must_use]
pub fn get_program_via(
    account_id: AccountId,
    lookup: impl Fn(AccountId) -> Account,
) -> Option<(ProgramId, Vec<u8>)> {
    let header_account = lookup(account_id);
    if header_account.program_owner != PROGRAM_LOADER_ACCOUNT_ID {
        return None;
    }
    let header = ProgramHeader::from_bytes(&header_account.data)?;

    let mut elf = Vec::new();
    let mut next = Some(header.program_first_segment);
    let mut segment_count = 0_usize;
    while let Some(segment_id) = next {
        segment_count = segment_count.checked_add(1)?;
        if segment_count > MAX_PROGRAM_SEGMENTS {
            return None;
        }
        let segment_account = lookup(segment_id);
        if segment_account.program_owner != PROGRAM_LOADER_ACCOUNT_ID {
            return None;
        }
        let segment = ProgramSegment::from_bytes(&segment_account.data)?;
        elf.extend_from_slice(&segment.bytecode);
        next = segment.next_segment;
    }

    Some((header.image_id, elf))
}

/// Validates well-behaved program execution.
///
/// The diff has no `nonce`/`program_owner` field, so a program can't forge either; ownership
/// follows from the data write, see [`acquire_ownership_on_data_write`].
///
/// # Parameters
/// - `state_diffs`: Each account's pre-state paired with the diff the program applied to it.
/// - `executing_account_id`: The account ID of the program that was executed.
pub fn validate_execution(
    state_diffs: &[AccountStateDiff],
    executing_account_id: AccountId,
) -> Result<(), ExecutionValidationError> {
    // 1. Check account ids are all different
    if !validate_uniqueness_of_account_ids(state_diffs) {
        return Err(ExecutionValidationError::PreStateAccountIdsNotUnique);
    }

    for diff in state_diffs {
        let pre = &diff.pre_state;
        let account_program_owner = pre.account.program_owner;

        // 2. Decreasing balance requires the account to be authorized
        if matches!(diff.post_balance_diff, BalanceDiff::Sub(amount) if amount > 0)
            && !pre.is_authorized
        {
            return Err(ExecutionValidationError::UnauthorizedBalanceDecrease {
                account_id: pre.account_id,
            });
        }

        // 3. Data changes only allowed if owned by executing program or if the account is unowned.
        if diff
            .post_data
            .as_ref()
            .is_some_and(|data| *data != pre.account.data)
            && account_program_owner != DEFAULT_PROGRAM_OWNER
            && account_program_owner != executing_account_id
        {
            return Err(ExecutionValidationError::UnauthorizedDataModification {
                account_id: pre.account_id,
                executing_account_id,
            });
        }

        // 4. Balance diff must be valid against this account's own pre-state balance.
        if let Err(source) = apply_balance_diff(pre.account.balance, Some(diff.post_balance_diff)) {
            return Err(ExecutionValidationError::InvalidBalanceDiff {
                account_id: pre.account_id,
                source,
            });
        }
    }

    // 5. Total balance is preserved
    let Some(total_added) =
        WrappedBalanceSum::from_balances(state_diffs.iter().filter_map(|diff| {
            match diff.post_balance_diff {
                BalanceDiff::Add(amount) => Some(amount),
                BalanceDiff::Sub(_) => None,
            }
        }))
    else {
        return Err(ExecutionValidationError::BalanceSumOverflow);
    };

    let Some(total_subbed) =
        WrappedBalanceSum::from_balances(state_diffs.iter().filter_map(|diff| {
            match diff.post_balance_diff {
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

/// Make any program that has changed the data of a default-owned account its owner.
pub fn acquire_ownership_on_data_write(pre: &Account, post: &mut Account, account_id: AccountId) {
    if pre.program_owner == DEFAULT_PROGRAM_OWNER && post.data != pre.data {
        post.program_owner = account_id;
    }
}

/// An account that ends a transaction unowned must carry no data.
#[must_use]
pub fn is_ownership_settled(post: &Account) -> bool {
    post.program_owner != DEFAULT_PROGRAM_OWNER || post.data.is_empty()
}

/// The account a diff leaves behind: balance and data applied, ownership acquired by the
/// executing program if it wrote data to an unowned account.
pub fn post_state(
    diff: &AccountStateDiff,
    executing_account_id: AccountId,
) -> Result<Account, BalanceDiffError> {
    let pre = &diff.pre_state.account;
    let mut post = Account {
        program_owner: pre.program_owner,
        balance: apply_balance_diff(pre.balance, Some(diff.post_balance_diff))?,
        data: diff.post_data.clone().unwrap_or_else(|| pre.data.clone()),
        nonce: pre.nonce,
    };
    acquire_ownership_on_data_write(pre, &mut post, executing_account_id);
    Ok(post)
}

fn validate_uniqueness_of_account_ids(state_diffs: &[AccountStateDiff]) -> bool {
    let number_of_accounts = state_diffs.len();
    let number_of_account_ids = state_diffs
        .iter()
        .map(|diff| &diff.pre_state.account_id)
        .collect::<HashSet<_>>()
        .len();

    number_of_accounts == number_of_account_ids
}

#[cfg(test)]
mod tests;

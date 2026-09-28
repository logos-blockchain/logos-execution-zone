use std::{borrow::Borrow, collections::HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, Commitment, Identifier, NullifierPublicKey, Timestamp,
    account::{Account, AccountId, ProgramShardSelector, ShardData},
    encryption::ViewingPublicKey,
};

/// The well-known dispatch address of the program loader: a native (non-guest) pseudo-program
/// that runs its `Instruction` variants as Rust rather than interpreting a guest ELF.
pub const PROGRAM_LOADER_ACCOUNT_ID: AccountId = AccountId::new([0xFE; 32]);

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

/// Hard cap on a deployed program's segment chain length, bounding a resolution walk.
pub const MAX_PROGRAM_SEGMENTS: usize = 20;

pub type ProgramId = [u32; 8];

impl AccountId {
    /// Derives a synthetic `AccountId` for seeding a test program in state. A byte
    /// reinterpretation, not a hash, since `ProgramId` is already content-derived.
    #[must_use]
    pub fn from_builtin_program(program_id: ProgramId) -> Self {
        let bytes: Vec<u8> = program_id
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        Self::new(bytes.try_into().expect("8 u32 words are exactly 32 bytes"))
    }

    #[must_use]
    pub fn from_builtin_program_name(name: &[u8]) -> Self {
        use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
        const BUILTIN_PROGRAM_NAME_PREFIX: &[u8; 32] = b"/LEE-BuiltinProgram/v1/AccountId";

        let mut hasher = Sha256::new();
        hasher.update(BUILTIN_PROGRAM_NAME_PREFIX);
        hasher.update(name);
        Self::new(
            hasher
                .finalize()
                .as_slice()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }
}

/// Borsh-encoded program instruction bytes.
pub type InstructionData = Vec<u8>;
pub type EffectData = Vec<u8>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountMeta {
    pub account_id: AccountId,
    pub is_authorized: bool,
    pub program_account_id: AccountId,
}

impl AccountMeta {
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        is_authorized: bool,
        program_account_id: AccountId,
    ) -> Self {
        Self {
            account_id,
            is_authorized,
            program_account_id,
        }
    }

    #[must_use]
    pub const fn native_balance(account_id: AccountId, is_authorized: bool) -> Self {
        Self::new(
            account_id,
            is_authorized,
            crate::native_token::NATIVE_TOKEN_PROGRAM_ID,
        )
    }
}

impl From<&AccountMeta> for ProgramShardSelector {
    fn from(account: &AccountMeta) -> Self {
        Self {
            account_id: account.account_id,
            program_account_id: account.program_account_id,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ShardEffect {
    pub selector: ProgramShardSelector,
    pub data: EffectData,
}

impl ShardEffect {
    #[must_use]
    pub fn new<E: BorshSerialize>(account: &AccountMeta, effect: &E) -> Self {
        Self {
            selector: account.into(),
            data: borsh::to_vec(effect).expect("borsh serialization is infallible"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ApplyInput {
    pub self_account_id: AccountId,
    pub selector: ProgramShardSelector,
    pub pre_data: ShardData,
    pub effect_data: EffectData,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ApplyOutput {
    pub input: ApplyInput,
    pub post_data: Option<ShardData>,
}

/// Struct encoding the input to an LEE program.
#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PlanInput {
    pub self_account_id: AccountId,
    pub caller_account_id: Option<AccountId>,
    pub accounts: Vec<AccountMeta>,
    pub instruction_data: InstructionData,
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
    /// Borsh layout (integers little-endian, variant index is u8; `ident` is `Identifier`'s
    /// opaque 32-byte encoding):
    ///
    /// ```text
    /// Regular(ident):                 0x00 || ident (32) || [0u8; 64]
    /// Pda { account_id, seed, ident }: 0x01 || account_id (32) || seed (32) || ident (32)
    /// ```
    ///
    /// Both variants are zero-padded to the same length so all ciphertexts are the same size,
    /// preventing observers from distinguishing `Regular` from `Pda` via ciphertext length.
    /// `HEADER_LEN` equals the borsh size of the largest variant (`Pda`): 1 + 32 + 32 + 32 = 97.
    pub const HEADER_LEN: usize = 97;

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

    /// Derives the [`AccountId`] for a shadow program from its `image_id` alone.
    #[must_use]
    pub fn for_shadow_program(image_id: &ProgramId) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const SHADOW_PROGRAM_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Shadow/\x00\x00\x00\x00\x00";

        let mut bytes = [0_u8; 64];
        bytes[0..32].copy_from_slice(SHADOW_PROGRAM_PREFIX);
        bytes[32..64].copy_from_slice(Self::from_builtin_program(*image_id).value());
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }

    /// Derives the `AccountId` of the private commitment mirroring an immutable header's
    /// `ProgramHeader`.
    #[must_use]
    pub fn for_immutable_mirror(header_account_id: Self) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const IMMUTABLE_MIRROR_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/ImmutMirror/";

        let mut bytes = [0_u8; 64];
        bytes[0..32].copy_from_slice(IMMUTABLE_MIRROR_PREFIX);
        bytes[32..64].copy_from_slice(header_account_id.as_ref());
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
    /// tuple controls a family of 2^256 addresses.
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

        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + ViewingPublicKey::LEN + 32];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        bytes[32..64].copy_from_slice(account_id.as_ref());
        bytes[64..96].copy_from_slice(&seed.0);
        bytes[96..128].copy_from_slice(&npk.to_byte_array());
        bytes[128..128 + ViewingPublicKey::LEN].copy_from_slice(vpk.to_bytes());
        bytes[128 + ViewingPublicKey::LEN..].copy_from_slice(identifier.value());
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainedCall {
    /// The account ID of the program to execute.
    pub program_account_id: AccountId,
    /// Selects the callee's inputs from the current execution state.
    pub shard_selectors: Vec<ProgramShardSelector>,
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
        shard_selectors: Vec<ProgramShardSelector>,
        instruction: &I,
    ) -> Self {
        Self {
            program_account_id,
            shard_selectors,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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

    pub fn intersect(self, other: Self) -> Result<Self, InvalidWindow> {
        let later = |a: Option<T>, b: Option<T>| match (a, b) {
            (Some(a), Some(b)) => Some(if b > a { b } else { a }),
            (a, None) | (None, a) => a,
        };
        let earlier = |a: Option<T>, b: Option<T>| match (a, b) {
            (Some(a), Some(b)) => Some(if b < a { b } else { a }),
            (a, None) | (None, a) => a,
        };
        (later(self.from, other.from), earlier(self.to, other.to)).try_into()
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
#[must_use = "PlanOutput does nothing unless written"]
pub struct PlanOutput {
    pub input: PlanInput,
    pub effects: Vec<ShardEffect>,
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

impl PlanOutput {
    pub const fn new(input: PlanInput) -> Self {
        Self {
            input,
            effects: Vec::new(),
            chained_calls: Vec::new(),
            block_validity_window: ValidityWindow::new_unbounded(),
            timestamp_validity_window: ValidityWindow::new_unbounded(),
            events: Vec::new(),
        }
    }

    pub fn with_effects(mut self, effects: Vec<ShardEffect>) -> Self {
        self.effects = effects;
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

    /// Sets the timestamp validity window from a fallible range conversion (`4..7`).
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
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
#[must_use = "a GuestOutput does nothing unless written"]
pub enum GuestOutput {
    Plan(PlanOutput),
    Apply(ApplyOutput),
}

impl GuestOutput {
    pub fn write(&self) {
        env::commit_slice(&crate::to_borsh_frame(self));
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

#[derive(thiserror::Error, Debug)]
pub enum ExecutionValidationError {
    #[error("Account shard selectors are not unique")]
    AccountShardSelectorsNotUnique,

    #[error("An effect selects {selector:?}, which is not an input of the call")]
    EffectOutsideInputs { selector: ProgramShardSelector },

    #[error(
        "A program's apply echoed an input it was not given: expected {expected:?}, actual {actual:?}"
    )]
    ApplyInputMismatch {
        expected: Box<ApplyInput>,
        actual: Box<ApplyInput>,
    },

    #[error(
        "A program's plan echoed an input it was not given: expected {expected:?}, actual {actual:?}"
    )]
    PlanInputMismatch {
        expected: Box<PlanInput>,
        actual: Box<PlanInput>,
    },

    #[error(
        "Program {executing_account_id} wrote data on a shard selector of {account_id} that does not name it"
    )]
    ForeignShardWrite {
        account_id: AccountId,
        executing_account_id: AccountId,
    },
}

/// Discriminates which entrypoint a single guest invocation is for. Written by the (trusted)
/// orchestrator only.
///
/// `Plan` is index 0 and must stay index 0; future variants are appended only, never
/// inserted or reordered. An unrecognized discriminant is a decode error: no capability probe
/// exists in this model, so an unknown required operation must not count as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CallKind {
    Plan,
    Apply,
}

pub enum ProgramCall<T> {
    Plan(PlanInput, T),
    Apply(ApplyInput),
}

#[must_use = "a Plan does nothing unless written"]
pub struct Plan {
    output: PlanOutput,
}

impl Plan {
    pub fn new(input: &PlanInput) -> Self {
        Self {
            output: PlanOutput::new(input.clone()),
        }
    }

    /// The plan as built so far, so a program can assert what it emitted without a zkVM.
    pub const fn output(&self) -> &PlanOutput {
        &self.output
    }

    pub fn effect<E: BorshSerialize>(&mut self, account: &AccountMeta, effect: &E) {
        self.inspect(account, self.output.input.self_account_id, effect);
    }

    pub fn inspect<E: BorshSerialize>(
        &mut self,
        account: &AccountMeta,
        owner: AccountId,
        guard: &E,
    ) {
        assert_eq!(
            account.program_account_id, owner,
            "An effect on {} names the shard of {}, not of {owner}",
            account.account_id, account.program_account_id
        );
        self.output.effects.push(ShardEffect::new(account, guard));
    }

    pub fn call(&mut self, call: ChainedCall) {
        self.output.chained_calls.push(call);
    }

    pub fn event(&mut self, event: ProgramEvent) {
        self.output.events.push(event);
    }

    pub fn block_window<W: Into<BlockValidityWindow>>(&mut self, window: W) {
        self.output.block_validity_window = window.into();
    }

    pub fn timestamp_window<W: Into<TimestampValidityWindow>>(&mut self, window: W) {
        self.output.timestamp_validity_window = window.into();
    }

    pub fn write(self) -> ! {
        GuestOutput::Plan(self.output).write();
        env::exit(0)
    }
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
pub fn read_program_call<T: BorshDeserialize>() -> ProgramCall<T> {
    let call_kind: CallKind =
        borsh::from_slice(&read_input_frame()).expect("call kind must decode from borsh");
    let payload = read_input_frame();

    match call_kind {
        CallKind::Plan => {
            let input: PlanInput =
                borsh::from_slice(&payload).expect("guest input must be valid borsh");
            let instruction = borsh::from_slice(&input.instruction_data)
                .expect("instruction must decode from borsh");
            ProgramCall::Plan(input, instruction)
        }
        CallKind::Apply => ProgramCall::Apply(
            borsh::from_slice(&payload).expect("apply input must be valid borsh"),
        ),
    }
}

/// Handles one plan or apply call, then exits.
///
/// `plan` uses instruction data and account metadata to produce effects and chained calls.
/// `apply` receives one effect and its shard's current data (`&[u8]` or `&ShardData`).
/// Missing shards are empty. Return `None` to keep data, or `Some(data)` to replace it.
/// Only the program's own shards may be replaced; empty data clears them.
/// A panic fails the transaction.
pub fn run_program<I, E, P, D>(
    plan: impl FnOnce(&PlanInput, I) -> Plan,
    apply: impl FnOnce(E, &P) -> Option<D>,
) -> !
where
    I: BorshDeserialize,
    E: BorshDeserialize,
    P: ?Sized,
    ShardData: Borrow<P>,
    D: TryInto<ShardData, Error: std::fmt::Debug>,
{
    match read_program_call::<I>() {
        ProgramCall::Plan(input, instruction) => plan(&input, instruction).write(),
        ProgramCall::Apply(input) => {
            let effect = borsh::from_slice(&input.effect_data)
                .expect("a program only applies effects it planned");
            match apply(effect, input.pre_data.borrow()) {
                Some(data) => apply_write(
                    input,
                    data.try_into()
                        .expect("an applied shard fits within the data limit"),
                ),
                None => apply_keep(input),
            }
        }
    }
}

#[must_use]
pub fn write_once(pre_data: &[u8], data: Vec<u8>) -> Vec<u8> {
    assert!(
        pre_data.is_empty() || *pre_data == *data,
        "shard already holds different data"
    );
    data
}

pub fn apply_keep(input: ApplyInput) -> ! {
    GuestOutput::Apply(ApplyOutput {
        input,
        post_data: None,
    })
    .write();
    env::exit(0)
}

pub fn apply_write(input: ApplyInput, data: ShardData) -> ! {
    GuestOutput::Apply(ApplyOutput {
        input,
        post_data: Some(data),
    })
    .write();
    env::exit(0)
}

#[must_use]
pub fn get_program_via<'state>(
    account_id: AccountId,
    loader_shard: impl Fn(AccountId) -> Option<&'state ShardData>,
) -> Option<(ProgramId, Vec<u8>)> {
    let header = ProgramHeader::from_bytes(loader_shard(account_id)?)?;

    let mut elf = Vec::new();
    let mut next = Some(header.program_first_segment);
    let mut segment_count = 0_usize;
    while let Some(segment_id) = next {
        segment_count = segment_count.checked_add(1)?;
        if segment_count > MAX_PROGRAM_SEGMENTS {
            return None;
        }
        let segment = ProgramSegment::from_bytes(loader_shard(segment_id)?)?;
        elf.extend_from_slice(&segment.bytecode);
        next = segment.next_segment;
    }

    Some((header.image_id, elf))
}

pub fn validate_plan(
    expected: &PlanInput,
    output: &PlanOutput,
) -> Result<(), ExecutionValidationError> {
    if output.input != *expected {
        return Err(ExecutionValidationError::PlanInputMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(output.input.clone()),
        });
    }

    let mut named = HashSet::new();
    for account in &expected.accounts {
        if !named.insert(ProgramShardSelector::from(account)) {
            return Err(ExecutionValidationError::AccountShardSelectorsNotUnique);
        }
    }

    for effect in &output.effects {
        if !named.contains(&effect.selector) {
            return Err(ExecutionValidationError::EffectOutsideInputs {
                selector: effect.selector,
            });
        }
    }

    Ok(())
}

/// Builds the `Commitment` mirroring an immutable header's finalized `ProgramHeader` into private
/// state.
#[must_use]
pub fn immutable_mirror_commitment(
    header_account_id: AccountId,
    program_header: &ProgramHeader,
) -> Commitment {
    let mirror_account_id = AccountId::for_immutable_mirror(header_account_id);
    let mirrored_account = Account::default().with_shard(
        PROGRAM_LOADER_ACCOUNT_ID,
        ShardData::try_from(program_header.to_bytes())
            .expect("program header must fit under DATA_MAX_LENGTH"),
    );
    Commitment::new(&mirror_account_id, &mirrored_account)
}

/// Checks that the output repeats the scheduled input exactly, then verifies
/// that any write targets the executing program's shard.
pub fn validate_apply_output(
    expected: &ApplyInput,
    output: &ApplyOutput,
) -> Result<(), ExecutionValidationError> {
    if output.input != *expected {
        return Err(ExecutionValidationError::ApplyInputMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(output.input.clone()),
        });
    }
    if output.post_data.is_some()
        && output.input.selector.program_account_id != output.input.self_account_id
    {
        return Err(ExecutionValidationError::ForeignShardWrite {
            account_id: output.input.selector.account_id,
            executing_account_id: output.input.self_account_id,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests;

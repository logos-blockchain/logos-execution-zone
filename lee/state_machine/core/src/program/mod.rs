use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use hex_literal::hex;
use risc0_zkvm::{DeserializeOwned, guest::env, serde::Deserializer};
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, Identifier, NullifierPublicKey, Timestamp,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::ViewingPublicKey,
};

pub const DEFAULT_PROGRAM_ID: ProgramId = [0; 8];

/// TODO: Placeholder `program_owner` for uninitialized `Account`.
pub const DEFAULT_PROGRAM_OWNER: AccountId = AccountId::new([0; 32]);

/// TODO: Temporary placeholder for program deployment program id; this serves as
/// `program_owner` for program `Account`s.
pub const PROGRAM_STORAGE_OWNER: AccountId = AccountId::new([0xFF; 32]);

/// Reserved `AccountId` for the native "Deploy" dispatch shortcut.
///
/// `SHA256(domain_separator || label)`, where `domain_separator` is
/// `/LEE/v0.3/AccountId/State/` and `label` is `DeploymentProgram`, each padded with trailing
/// zero bytes to 32 bytes before concatenation — the same domain-separation construction used
/// throughout this module, just with no variable input, since this is a single fixed address
/// rather than a per-caller derivation.
///
/// Dispatch recognizes this exact `AccountId` and runs the deploy logic as native Rust instead
/// of interpreting a guest ELF: computing a program's image id inside the zkVM costs roughly
/// 1,400-1,500 cycles per byte of deployed bytecode (measured against every real program in
/// this repo), pushing a real deployment to 500M-900M cycles against the 32M public-execution
/// cap, whereas the equivalent native computation costs low tens of milliseconds. A caller
/// targets this address directly as a `Message`/`ChainedCall`'s `AccountId`, same as any other
/// program.
pub const RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(hex!(
    "599e2c6c2b89ff39bc3094b3276f1fcaa7173800a71d9896a1ba9bd1458a91c9"
));

pub const MAX_NUMBER_CHAINED_CALLS: usize = 10;

pub type ProgramId = [u32; 8];

/// The account-data layout of a program's header account, deployed via the `Deploy` native
/// dispatch shortcut (see [`RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID`]).
///
/// Deliberately holds only small, fixed-size fields — never the program's bytecode, which lives
/// in a separate account (see `program_loader_core::deploy_segment_account_id`). Keeping the two
/// apart means anything that needs to authenticate a program's *identity* (e.g. the
/// privacy-preserving circuit confirming which `image_id` an `AccountId` currently maps to) only
/// ever has to read this handful of bytes, not the full program — the only account-authentication
/// primitive available today is whole-account equality, so what's bundled into one account sets
/// the floor for how cheap that authentication can be.
///
/// `image_id` is read fresh from this account on every dispatch/verification rather than
/// re-derived from the account's address, specifically so that upgrading a program (writing a
/// new `image_id` into the same, stable `AccountId`) is the entire upgrade mechanism — no
/// separate "which version" bookkeeping needed.
///
/// Lives here rather than in `program_loader_core` so that `V03State::get_program` — a generic,
/// program-agnostic lookup — can decode it without depending on a specific program's crate.
/// `program_loader_core` re-exports this type.
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProgramData {
    pub image_id: ProgramId,
    /// How many bytecode segment accounts follow, so a reader knows exactly how many
    /// `loader_core::deploy_segment_account_id(image_id, 0..segment_count, update_auth)`
    /// accounts to fetch without probing.
    pub segment_count: u32,
    pub update_auth: AccountId,
}

impl TryFrom<&crate::account::Data> for ProgramData {
    type Error = std::io::Error;

    fn try_from(data: &crate::account::Data) -> Result<Self, Self::Error> {
        BorshDeserialize::try_from_slice(data.as_ref())
    }
}

impl From<&ProgramData> for crate::account::Data {
    fn from(program_data: &ProgramData) -> Self {
        let mut data = Vec::with_capacity(std::mem::size_of_val(program_data));
        BorshSerialize::serialize(program_data, &mut data)
            .expect("borsh serialization should not fail");
        Self::try_from(data).expect("elf must fit under DATA_MAX_LENGTH")
    }
}

/// TODO: This is a temporary conversion; will be removed once `Program` to `Account`
/// migration is complete.
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

pub type InstructionData = Vec<u32>;
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
        program_account_id: AccountId,
        seed: PdaSeed,
        identifier: Identifier,
    },
}

impl PrivateAccountKind {
    /// Borsh layout (all integers little-endian, variant index is u8):
    ///
    /// ```text
    /// Regular(ident):                         0x00 || ident (16 LE) || [0u8; 64]
    /// Pda { program_account_id, seed, ident }: 0x01 || program_account_id (32) || seed (32)
    ///                                               || ident (16 LE)
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
    /// Derives an [`AccountId`] for a public PDA from the owning program's dispatch address and
    /// a seed.
    ///
    /// Keyed on the program's `AccountId` (its actual dispatch address), not its `ProgramId`
    /// (bytecode image id): two different deployments of identical bytecode get different
    /// `AccountId`s (see `program_loader_core::deploy_header_account_id`'s `update_auth`
    /// parameter), and each must own a disjoint family of PDAs.
    #[must_use]
    pub fn for_public_pda(program_account_id: &Self, seed: &PdaSeed) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PROGRAM_DERIVED_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = [0; 96];
        bytes[0..32].copy_from_slice(PROGRAM_DERIVED_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(program_account_id.value());
        bytes[64..].copy_from_slice(&seed.0);
        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }

    /// Derives an [`AccountId`] for a private PDA from the owning program's dispatch address,
    /// seed, nullifier public key, and identifier.
    ///
    /// Unlike public PDAs ([`AccountId::for_public_pda`]), this includes the `npk` in the
    /// derivation, making the address unique per group of controllers sharing viewing keys.
    /// The `identifier` further diversifies the address, so a single
    /// `(program_account_id, seed, npk)` tuple controls a family of 2^128 addresses. See
    /// `for_public_pda`'s doc for why this is keyed on `AccountId` rather than `ProgramId`.
    #[must_use]
    pub fn for_private_pda(
        program_account_id: &Self,
        seed: &PdaSeed,
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const PRIVATE_PDA_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/PrivatePDA/\x00";

        let mut bytes = [0_u8; 32 + 32 + 32 + 32 + ViewingPublicKey::LEN + 16];
        bytes[0..32].copy_from_slice(PRIVATE_PDA_PREFIX);
        bytes[32..64].copy_from_slice(program_account_id.value());
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
                program_account_id,
                seed,
                identifier,
            } => Self::for_private_pda(program_account_id, seed, npk, vpk, *identifier),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChainedCall {
    /// The `AccountId` of the program to execute.
    pub program_account_id: AccountId,
    pub pre_states: Vec<AccountWithMetadata>,
    /// The instruction data to pass.
    pub instruction_data: InstructionData,
    /// PDA seeds authorized for the callee. For each seed, the callee is authorized to
    /// mutate the `AccountId` derived from `(caller_account_id, seed)`, regardless of
    /// whether the account is public or private.
    pub pda_seeds: Vec<PdaSeed>,
}

impl ChainedCall {
    /// Creates a new chained call serializing the given instruction.
    pub fn new<I: Serialize>(
        program_account_id: AccountId,
        pre_states: Vec<AccountWithMetadata>,
        instruction: &I,
    ) -> Self {
        Self {
            program_account_id,
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
/// becomes the owner of the account (a "claim"). This is used to signal
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
    /// The program requests ownership of the account through a PDA. The program emits the
    /// seed; the `AccountId` is derived from `(program_id, seed)`, regardless of whether the
    /// account is public or private.
    Pda(PdaSeed),
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
        let is_default_owner = account.program_owner == DEFAULT_PROGRAM_OWNER;
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

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
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
    /// The `AccountId` of the program that produced this output.
    pub self_account_id: AccountId,
    /// The `AccountId` of the caller that invoked this program via a chained call,
    /// or `None` if this is a top-level call.
    pub caller_account_id: Option<AccountId>,
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
        self_account_id: AccountId,
        caller_account_id: Option<AccountId>,
        instruction_data: InstructionData,
        pre_states: Vec<AccountWithMetadata>,
        post_states: Vec<AccountPostState>,
    ) -> Self {
        Self {
            self_account_id,
            caller_account_id,
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
        "Trying to decrease balance of account {account_id} owned by {owner_account_id:?} in a program {executing_account_id:?} which is not the owner"
    )]
    UnauthorizedBalanceDecrease {
        account_id: AccountId,
        owner_account_id: AccountId,
        executing_account_id: AccountId,
    },

    #[error(
        "Unauthorized modification of data for account {account_id} which is not default and not owned by executing program {executing_account_id:?}"
    )]
    UnauthorizedDataModification {
        account_id: AccountId,
        executing_account_id: AccountId,
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

/// Reads the LEE inputs from the guest environment.
#[must_use]
pub fn read_lee_inputs<T: DeserializeOwned>() -> (ProgramInput<T>, InstructionData) {
    let self_account_id: AccountId = env::read();
    let caller_account_id: Option<AccountId> = env::read();
    let pre_states: Vec<AccountWithMetadata> = env::read();
    let instruction_words: InstructionData = env::read();
    let instruction = T::deserialize(&mut Deserializer::new(instruction_words.as_ref())).unwrap();
    (
        ProgramInput {
            self_account_id,
            caller_account_id,
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
/// - `executing_account_id`: The `AccountId` of the program that was executed.
pub fn validate_execution(
    pre_states: &[AccountWithMetadata],
    post_states: &[AccountPostState],
    executing_account_id: AccountId,
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
            && account_program_owner != executing_account_id
        {
            return Err(ExecutionValidationError::UnauthorizedBalanceDecrease {
                account_id: pre.account_id,
                owner_account_id: account_program_owner,
                executing_account_id,
            });
        }

        // 6. Data changes only allowed if owned by executing program or if account pre state has
        //    default values
        if pre.account.data != post.account.data
            && pre.account != Account::default()
            && account_program_owner != executing_account_id
        {
            return Err(ExecutionValidationError::UnauthorizedDataModification {
                account_id: pre.account_id,
                executing_account_id,
            });
        }

        // 7. If a post state has default program owner, the pre state must have been a default
        //    account
        if post.account.program_owner == DEFAULT_PROGRAM_OWNER && pre.account != Account::default()
        {
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
mod tests;

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, Commitment, Identifier, NullifierPublicKey, Timestamp,
    account::{Account, AccountId, Actor, ActorState},
    encryption::ViewingPublicKey,
};

/// The well-known dispatch address of the program loader: a native (non-guest) pseudo-program
/// that runs its `Instruction` variants as Rust rather than interpreting a guest ELF.
pub const PROGRAM_LOADER_ACCOUNT_ID: AccountId = AccountId::new([0xFE; 32]);

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

pub type MessageData = Vec<u8>;

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

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct MessageId([u8; 32]);

impl MessageId {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MessageEnvelope<S> {
    pub source: S,
    pub to: Actor,
    pub message: MessageData,
}

pub type MessageBody = MessageEnvelope<AccountId>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct StoredMessage {
    pub sequence: u128,
    pub body: MessageBody,
}

impl StoredMessage {
    #[must_use]
    pub fn id(&self) -> MessageId {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        const MESSAGE_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/MessageId/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let bytes = [
            MESSAGE_ID_PREFIX.as_slice(),
            &self.sequence.to_le_bytes(),
            &borsh::to_vec(&self.body).expect("borsh serialization is infallible"),
        ]
        .concat();
        MessageId(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Hash output must be exactly 32 bytes long"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Call {
    pub to: Actor,
    pub message: MessageData,
    pub pda_seeds: Vec<PdaSeed>,
}

impl Call {
    pub fn new<M: BorshSerialize>(to: Actor, message: &M) -> Self {
        Self {
            to,
            message: borsh::to_vec(message).expect("borsh serialization is infallible"),
            pda_seeds: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_pda_seeds(mut self, pda_seeds: Vec<PdaSeed>) -> Self {
        self.pda_seeds = pda_seeds;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Cast {
    pub to: Actor,
    pub message: MessageData,
}

impl Cast {
    pub fn new<M: BorshSerialize>(to: Actor, message: &M) -> Self {
        Self {
            to,
            message: borsh::to_vec(message).expect("borsh serialization is infallible"),
        }
    }
}

pub trait Sendable {
    fn send_into(self, calls: &mut Vec<Call>, casts: &mut Vec<Cast>);
}

impl Sendable for Call {
    fn send_into(self, calls: &mut Vec<Call>, _casts: &mut Vec<Cast>) {
        calls.push(self);
    }
}

impl Sendable for Cast {
    fn send_into(self, _calls: &mut Vec<Call>, casts: &mut Vec<Cast>) {
        casts.push(self);
    }
}

/// The scheduled input of one turn, echoed whole in the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ReceiveInput {
    pub receiver: Actor,
    /// The program that sent this message; `None` when the transaction itself submitted it.
    pub origin: Option<AccountId>,
    pub is_authorized: bool,
    pub pre_state: ActorState,
    pub message: MessageData,
}

impl ReceiveInput {
    /// Whether the message came from another actor of the receiver's own program.
    #[must_use]
    pub fn from_own_program(&self) -> bool {
        self.origin == Some(self.receiver.program_account_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReadState {
    pub reply_to: Actor,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StateReply {
    pub subject: Actor,
    pub state: ActorState,
}

impl From<&ReceiveInput> for StateReply {
    fn from(input: &ReceiveInput) -> Self {
        Self {
            subject: input.receiver,
            state: input.pre_state.clone(),
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
#[must_use = "a Transition does nothing unless written"]
pub struct Transition {
    pub input: ReceiveInput,
    pub response: Response,
}

impl Transition {
    pub fn write(&self) {
        env::commit_slice(&crate::to_borsh_frame(self));
    }
}

/// What a handler returns. `None` keeps the shard, empty data clears it, other data replaces it.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
#[must_use]
pub struct Response {
    pub post_state: Option<ActorState>,
    pub calls: Vec<Call>,
    pub casts: Vec<Cast>,
    pub events: Vec<ProgramEvent>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
}

impl Response {
    pub const fn keep() -> Self {
        Self {
            post_state: None,
            calls: Vec::new(),
            casts: Vec::new(),
            events: Vec::new(),
            block_validity_window: ValidityWindow::new_unbounded(),
            timestamp_validity_window: ValidityWindow::new_unbounded(),
        }
    }

    pub fn write(data: impl Into<ActorState>) -> Self {
        Self {
            post_state: Some(data.into()),
            ..Self::keep()
        }
    }

    pub fn call<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(Call::new(to, message))
    }

    pub fn cast<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(Cast::new(to, message))
    }

    pub fn send(mut self, message: impl Sendable) -> Self {
        message.send_into(&mut self.calls, &mut self.casts);
        self
    }

    pub fn event(mut self, event: ProgramEvent) -> Self {
        self.events.push(event);
        self
    }

    pub fn block_window<W: Into<BlockValidityWindow>>(mut self, window: W) -> Self {
        self.block_validity_window = window.into();
        self
    }

    pub fn try_block_window<W: TryInto<BlockValidityWindow, Error = InvalidWindow>>(
        mut self,
        window: W,
    ) -> Result<Self, InvalidWindow> {
        self.block_validity_window = window.try_into()?;
        Ok(self)
    }

    pub fn timestamp_window<W: Into<TimestampValidityWindow>>(mut self, window: W) -> Self {
        self.timestamp_validity_window = window.into();
        self
    }

    pub fn try_timestamp_window<W: TryInto<TimestampValidityWindow, Error = InvalidWindow>>(
        mut self,
        window: W,
    ) -> Result<Self, InvalidWindow> {
        self.timestamp_validity_window = window.try_into()?;
        Ok(self)
    }

    pub const fn into_transition(self, input: ReceiveInput) -> Transition {
        Transition {
            input,
            response: self,
        }
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
    #[error(
        "A program's receive echoed an input it was not given: expected {expected:?}, actual {actual:?}"
    )]
    TransitionInputMismatch {
        expected: Box<ReceiveInput>,
        actual: Box<ReceiveInput>,
    },
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

/// Handles one delivery, then exits. A panic fails the transaction.
pub fn run_actor<M: BorshDeserialize>(receive: impl FnOnce(&ReceiveInput, M) -> Response) -> ! {
    run_actor_with(|input| {
        let message = borsh::from_slice(&input.message).expect("message must decode from borsh");
        receive(input, message)
    })
}

/// [`run_actor`] for a handler that decodes the message itself, e.g. by origin.
pub fn run_actor_with(receive: impl FnOnce(&ReceiveInput) -> Response) -> ! {
    let input: ReceiveInput =
        borsh::from_slice(&read_input_frame()).expect("receive input must be valid borsh");
    receive(&input).into_transition(input).write();
    env::exit(0)
}

#[must_use]
pub fn write_once(pre_state: &[u8], data: Vec<u8>) -> Vec<u8> {
    assert!(
        pre_state.is_empty() || *pre_state == *data,
        "shard already holds different data"
    );
    data
}

#[must_use]
pub fn get_program_via<'state>(
    account_id: AccountId,
    loader_shard: impl Fn(AccountId) -> Option<&'state ActorState>,
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
        ActorState::from(program_header.to_bytes()),
    );
    Commitment::new(&mirror_account_id, &mirrored_account)
}

pub fn validate_transition(
    expected: &ReceiveInput,
    transition: &Transition,
) -> Result<(), ExecutionValidationError> {
    if transition.input != *expected {
        return Err(ExecutionValidationError::TransitionInputMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(transition.input.clone()),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests;

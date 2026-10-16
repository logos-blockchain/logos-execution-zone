//! Native program deployment and updates through [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Instructions only change loader actor states. Every write target must be `is_authorized`, and
//! every loader actor state is a tagged [`LoaderEntry`], so a segment and a header can never be
//! read as each other.
//!
//! The loader is protocol code that runs only at public settlement: [`handle_message`] handles each
//! message against the target's live loader actor state.
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{ProgramHeader, immutable_mirror_commitment};
use lee_core::{
    Commitment,
    account::{AccountId, ActorState},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramId, ReceiveInput, Response, Transition},
};

/// Hard cap on a deployed program's segment chain length, bounding a resolution walk.
pub const MAX_PROGRAM_SEGMENTS: usize = 20;

/// Recommended bytecode chunk size for deployment.
///
/// This is a client-side batching choice, not a limit enforced by the program.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

/// Variants are append-only. Borsh encodes the variant as a leading tag byte, so inserting one
/// ahead of `WriteSegment` shifts every existing encoding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// Writes a new segment to the target's empty loader actor state; the target must be
    /// authorized.
    ///
    /// If `next_segment` is `Some`, that account must already hold a valid [`ProgramSegment`].
    /// Segments are immutable and linked from tail to head.
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    UpdateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// [`Message::CreateHeader`], refused unless the chain's image ID is `image_id`.
    CreateHeaderOf {
        first_segment: AccountId,
        image_id: ProgramId,
        immutable: bool,
    },
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

/// What the loader's actor state in an account holds. The tag keeps a header and a segment from
/// decoding as each other; variants are append-only.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum LoaderEntry {
    Header(ProgramHeader),
    Segment(ProgramSegment),
}

impl LoaderEntry {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("loader entry serializes")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// A header or a segment as the loader's actor state holds it: a tagged [`LoaderEntry`].
pub trait LoaderActorState: Sized {
    #[must_use]
    fn to_loader_actor_state(self) -> Vec<u8>;

    #[must_use]
    fn from_loader_actor_state(bytes: &[u8]) -> Option<Self>;
}

impl LoaderActorState for ProgramHeader {
    fn to_loader_actor_state(self) -> Vec<u8> {
        LoaderEntry::Header(self).to_bytes()
    }

    fn from_loader_actor_state(bytes: &[u8]) -> Option<Self> {
        match LoaderEntry::from_bytes(bytes)? {
            LoaderEntry::Header(header) => Some(header),
            LoaderEntry::Segment(_) => None,
        }
    }
}

impl LoaderActorState for ProgramSegment {
    fn to_loader_actor_state(self) -> Vec<u8> {
        LoaderEntry::Segment(self).to_bytes()
    }

    fn from_loader_actor_state(bytes: &[u8]) -> Option<Self> {
        match LoaderEntry::from_bytes(bytes)? {
            LoaderEntry::Segment(segment) => Some(segment),
            LoaderEntry::Header(_) => None,
        }
    }
}

/// Why [`build_segments`] refused a program before any segment was uploaded.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum SegmentChainError {
    #[error("Program bytecode splits into {expected} segment(s) but {actual} were supplied")]
    CountMismatch { expected: usize, actual: usize },
    #[error("Program needs {count} segments, over the {MAX_PROGRAM_SEGMENTS}-segment cap")]
    TooManySegments { count: usize },
}

/// How many segments [`build_segments`] splits `user_elf` into.
#[must_use]
pub const fn segment_count(user_elf: &[u8]) -> usize {
    user_elf.len().div_ceil(MAX_SEGMENT_DATA_LEN)
}

/// The image ID and bytecode of the program whose header is at `account_id`, walking its segment
/// chain through `loader_actor_state`.
#[must_use]
pub fn get_program_via<'state>(
    account_id: AccountId,
    loader_actor_state: impl Fn(AccountId) -> Option<&'state ActorState>,
) -> Option<(ProgramId, Vec<u8>)> {
    let header = ProgramHeader::from_loader_actor_state(loader_actor_state(account_id)?)?;

    let mut elf = Vec::new();
    let mut next = Some(header.program_first_segment);
    let mut segment_count = 0_usize;
    while let Some(segment_id) = next {
        segment_count = segment_count.checked_add(1)?;
        if segment_count > MAX_PROGRAM_SEGMENTS {
            return None;
        }
        let segment = ProgramSegment::from_loader_actor_state(loader_actor_state(segment_id)?)?;
        elf.extend_from_slice(&segment.bytecode);
        next = segment.next_segment;
    }

    Some((header.image_id, elf))
}

/// Splits `user_elf` into a segment chain written to `segment_ids`, each linking to the next.
/// A deployer's pre-check.
pub fn build_segments(
    user_elf: &[u8],
    segment_ids: &[AccountId],
) -> Result<Vec<ProgramSegment>, SegmentChainError> {
    let count = segment_count(user_elf);
    if count != segment_ids.len() {
        return Err(SegmentChainError::CountMismatch {
            expected: count,
            actual: segment_ids.len(),
        });
    }
    if count > MAX_PROGRAM_SEGMENTS {
        return Err(SegmentChainError::TooManySegments { count });
    }
    Ok(user_elf
        .chunks(MAX_SEGMENT_DATA_LEN)
        .enumerate()
        .map(|(index, chunk)| ProgramSegment {
            bytecode: chunk.to_vec(),
            next_segment: segment_ids.get(index.saturating_add(1)).copied(),
        })
        .collect())
}

pub fn handle_message<'state>(
    input: &ReceiveInput,
    actor_state: impl Fn(AccountId) -> &'state ActorState,
) -> (Transition, Option<Commitment>) {
    let message: Message = borsh::from_slice(&input.message).expect("a loader message must decode");
    assert_eq!(
        input.receiver.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
        "a loader message must target (account, PROGRAM_LOADER_ACCOUNT_ID)"
    );
    reject_reserved_target(input.receiver.account_id);

    let (bytes, new_commitment) = match message {
        Message::WriteSegment {
            bytecode,
            next_segment,
        } => {
            assert!(
                input.pre_state.is_empty(),
                "segment target already deployed"
            );
            assert!(
                input.is_authorized,
                "WriteSegment target must be an authorized account"
            );
            if let Some(next) = next_segment {
                assert!(
                    ProgramSegment::from_loader_actor_state(actor_state(next)).is_some(),
                    "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
                );
            }
            let segment = ProgramSegment {
                bytecode,
                next_segment,
            };
            (segment.to_loader_actor_state(), None)
        }
        Message::CreateHeader {
            first_segment,
            immutable,
        } => {
            assert!(input.pre_state.is_empty(), "header target already deployed");
            assert!(
                input.is_authorized,
                "CreateHeader target must be an authorized account"
            );
            header_write(input, first_segment, immutable, None, &actor_state)
        }
        Message::CreateHeaderOf {
            first_segment,
            image_id,
            immutable,
        } => {
            assert!(input.pre_state.is_empty(), "header target already deployed");
            assert!(
                input.is_authorized,
                "CreateHeaderOf target must be an authorized account"
            );
            header_write(
                input,
                first_segment,
                immutable,
                Some(image_id),
                &actor_state,
            )
        }
        Message::UpdateHeader {
            first_segment,
            immutable,
        } => {
            let old_header = ProgramHeader::from_loader_actor_state(&input.pre_state).expect(
                "UpdateHeader target must already hold a valid header \u{2014} use CreateHeader to make one",
            );
            assert!(
                !old_header.immutable,
                "UpdateHeader target is immutable and cannot be updated"
            );
            assert!(
                input.is_authorized,
                "UpdateHeader target must be authorized by the signer"
            );
            header_write(input, first_segment, immutable, None, &actor_state)
        }
    };

    (
        Response::set_state(bytes).into_transition(input.clone()),
        new_commitment,
    )
}

fn reject_reserved_target(account_id: AccountId) {
    assert_ne!(
        account_id, NATIVE_TOKEN_PROGRAM_ID,
        "the native token program has no deployable bytecode"
    );
    // A program at this address would run as the loader, and so could rewrite any program's
    // header or segments.
    assert_ne!(
        account_id, PROGRAM_LOADER_ACCOUNT_ID,
        "the loader's own dispatch address is not a deployable target"
    );
}

fn header_write<'state>(
    input: &ReceiveInput,
    first_segment: AccountId,
    immutable: bool,
    expected_image_id: Option<ProgramId>,
    actor_state: impl Fn(AccountId) -> &'state ActorState,
) -> (Vec<u8>, Option<Commitment>) {
    let header = build_header(first_segment, immutable, actor_state);
    if let Some(expected) = expected_image_id {
        assert_eq!(
            header.image_id, expected,
            "the chain's image ID is not the expected one"
        );
    }
    let new_commitment =
        immutable.then(|| immutable_mirror_commitment(input.receiver.account_id, &header));
    (header.to_loader_actor_state(), new_commitment)
}

fn build_header<'state>(
    first_segment: AccountId,
    immutable: bool,
    actor_state: impl Fn(AccountId) -> &'state ActorState,
) -> ProgramHeader {
    ProgramHeader {
        image_id: compute_image_id(first_segment, actor_state),
        program_first_segment: first_segment,
        immutable,
    }
}

fn compute_image_id<'state>(
    first_segment: AccountId,
    actor_state: impl Fn(AccountId) -> &'state ActorState,
) -> ProgramId {
    let mut elf = Vec::new();
    let mut expected_next = Some(first_segment);
    let mut segment_count = 0_usize;
    while let Some(next) = expected_next {
        segment_count = segment_count.saturating_add(1);
        assert!(
            segment_count <= MAX_PROGRAM_SEGMENTS,
            "segment chain exceeds the {MAX_PROGRAM_SEGMENTS}-segment cap"
        );
        let segment = ProgramSegment::from_loader_actor_state(actor_state(next))
            .expect("every supplied segment account must decode as a valid ProgramSegment");
        elf.extend_from_slice(&segment.bytecode);
        expected_next = segment.next_segment;
    }

    let full_binary =
        risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    risc0_binfmt::compute_image_id(&full_binary)
        .expect("concatenated segment bytecode must decode as a valid RISC0 program binary")
        .into()
}

#[cfg(test)]
mod tests;

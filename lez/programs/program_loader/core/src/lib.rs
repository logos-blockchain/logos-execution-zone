//! Native program deployment and updates through [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Instructions only change loader shards. Writing a fresh segment is permissionless — a
//! still-empty loader shard has no prior claim to violate — but a header target must always be
//! `is_authorized`, whether created or updated, so a real header can't be squatted at an address
//! some other account id (e.g. a shadow program's) will later resolve to.
//!
//! The loader is protocol code that runs only at public settlement: [`receive`] handles each
//! message against the target's live loader shard.
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{
    MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment, immutable_mirror_commitment,
};
use lee_core::{
    Commitment,
    account::{AccountId, ActorState},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramId, ReceiveInput, Response, Transition},
};

/// Recommended bytecode chunk size for deployment.
///
/// This is a client-side batching choice, not a limit enforced by the program.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
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
}

pub fn receive<'state>(
    input: &ReceiveInput,
    shard: impl Fn(AccountId) -> &'state ActorState,
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
            if let Some(next) = next_segment {
                assert!(
                    ProgramSegment::from_bytes(shard(next)).is_some(),
                    "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
                );
            }
            let segment = ProgramSegment {
                bytecode,
                next_segment,
            };
            (segment.to_bytes(), None)
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
            header_write(input, first_segment, immutable, &shard)
        }
        Message::UpdateHeader {
            first_segment,
            immutable,
        } => {
            let old_header = ProgramHeader::from_bytes(&input.pre_state).expect(
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
            header_write(input, first_segment, immutable, &shard)
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
    shard: impl Fn(AccountId) -> &'state ActorState,
) -> (Vec<u8>, Option<Commitment>) {
    let header = build_header(first_segment, immutable, shard);
    let new_commitment =
        immutable.then(|| immutable_mirror_commitment(input.receiver.account_id, &header));
    (header.to_bytes(), new_commitment)
}

fn build_header<'state>(
    first_segment: AccountId,
    immutable: bool,
    shard: impl Fn(AccountId) -> &'state ActorState,
) -> ProgramHeader {
    ProgramHeader {
        image_id: compute_image_id(first_segment, shard),
        program_first_segment: first_segment,
        immutable,
    }
}

fn compute_image_id<'state>(
    first_segment: AccountId,
    shard: impl Fn(AccountId) -> &'state ActorState,
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
        let segment = ProgramSegment::from_bytes(shard(next))
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

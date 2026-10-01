//! Unit tests for the bookkeeping this crate owns directly: segment/header shape, write-once and
//! chain-order enforcement, and `UpdateHeader`'s authorization/immutability gates.
//!
//! A success path through `create_header`/`update_header` needs bytecode that decodes as a real
//! RISC0 program (`compute_image_id` rejects anything else), so those are covered at the
//! state-machine integration level instead, against real guest ELFs.

use std::collections::HashMap;

use lee_core::account::{AccountId, data::DATA_MAX_LENGTH};

use super::*;

/// The live loader shards the planner reads through, standing in for pending/committed state.
#[derive(Default)]
struct Shards(HashMap<AccountId, ShardData>);

impl Shards {
    fn with(mut self, account_id: AccountId, data: ShardData) -> Self {
        self.0.insert(account_id, data);
        self
    }

    fn segment(self, account_id: AccountId, bytecode: Vec<u8>, next: Option<AccountId>) -> Self {
        self.with(
            account_id,
            ShardData::try_from(
                ProgramSegment {
                    bytecode,
                    next_segment: next,
                }
                .to_loader_shard(),
            )
            .unwrap(),
        )
    }

    fn header(self, account_id: AccountId, header: &ProgramHeader) -> Self {
        self.with(
            account_id,
            ShardData::try_from(header.to_loader_shard()).unwrap(),
        )
    }

    fn read<'shards>(&'shards self) -> impl Fn(AccountId) -> &'shards ShardData + 'shards {
        const ABSENT: &ShardData = &ShardData::empty();
        move |account_id| self.0.get(&account_id).unwrap_or(ABSENT)
    }
}

fn handle(account_id: AccountId, is_authorized: bool) -> AccountMeta {
    AccountMeta::new(account_id, is_authorized, PROGRAM_LOADER_ACCOUNT_ID)
}

fn written(effect: &ShardEffect) -> ShardData {
    apply(&ApplyInput {
        self_account_id: PROGRAM_LOADER_ACCOUNT_ID,
        selector: effect.selector,
        pre_data: ShardData::empty(),
        effect_data: effect.data.clone(),
    })
}

#[test]
fn write_segment_writes_the_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default();

    let effects = write_segment(
        &[handle(target_id, true)],
        shards.read(),
        vec![1, 2, 3],
        None,
    );

    let [effect] = <[_; 1]>::try_from(effects).expect("one write, on the target");
    assert_eq!(effect.selector.account_id, target_id);
    assert_eq!(
        effect.selector.program_account_id,
        PROGRAM_LOADER_ACCOUNT_ID
    );
    let segment = ProgramSegment::from_loader_shard(&written(&effect)).expect("valid segment");
    assert_eq!(segment.bytecode, vec![1, 2, 3]);
    assert_eq!(segment.next_segment, None);
}

#[test]
fn write_segment_linking_to_an_existing_segment_leaves_it_unchanged() {
    let next_id = AccountId::new([2; 32]);
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default().segment(next_id, vec![9, 9], None);

    let effects = write_segment(
        &[handle(target_id, true), handle(next_id, false)],
        shards.read(),
        vec![1, 2, 3],
        Some(next_id),
    );

    // The referenced segment is read-only: it is declared, but no effect names it, so nothing
    // can be applied to it.
    let [effect] = <[_; 1]>::try_from(effects).expect("only the target is written");
    assert_eq!(effect.selector.account_id, target_id);
    let segment = ProgramSegment::from_loader_shard(&written(&effect)).expect("valid segment");
    assert_eq!(segment.next_segment, Some(next_id));
}

#[test]
#[should_panic(expected = "WriteSegment target must be an authorized account")]
fn write_segment_rejects_an_unauthorized_target() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default();
    let _effects = write_segment(&[handle(target_id, false)], shards.read(), vec![1], None);
}

/// Issue 181's payloads: bytecode whose untagged segment encoding is exactly a header's. Tagged,
/// they are stored as segments and never read back as headers.
#[test]
fn write_segment_stores_header_sized_bytecode_as_a_segment() {
    let next_id = AccountId::new([1; 32]);
    let shards = Shards::default().segment(next_id, vec![9], None);
    for (bytecode_len, next_segment) in [(60, None), (28, Some(next_id))] {
        let target_id = AccountId::new([2; 32]);
        let mut accounts = vec![handle(target_id, true)];
        accounts.extend(next_segment.map(|id| handle(id, false)));

        let effects = write_segment(
            &accounts,
            shards.read(),
            vec![0; bytecode_len],
            next_segment,
        );

        let stored = written(&effects[0]);
        assert!(ProgramSegment::from_loader_shard(&stored).is_some());
        assert_eq!(ProgramHeader::from_loader_shard(&stored), None);
    }
}

#[test]
#[should_panic(expected = "requires exactly 1 account")]
fn write_segment_rejects_wrong_account_count_without_next() {
    let shards = Shards::default();
    let _effects = write_segment(
        &[
            handle(AccountId::new([1; 32]), false),
            handle(AccountId::new([2; 32]), false),
        ],
        shards.read(),
        vec![1],
        None,
    );
}

#[test]
#[should_panic(expected = "requires exactly 2 account")]
fn write_segment_rejects_wrong_account_count_with_next() {
    let shards = Shards::default();
    let _effects = write_segment(
        &[handle(AccountId::new([1; 32]), false)],
        shards.read(),
        vec![1],
        Some(AccountId::new([2; 32])),
    );
}

#[test]
#[should_panic(expected = "already deployed")]
fn write_segment_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default().segment(target_id, vec![9], None);
    let _effects = write_segment(&[handle(target_id, true)], shards.read(), vec![1], None);
}

#[test]
#[should_panic(expected = "next_segment` points to")]
fn write_segment_rejects_a_second_account_that_is_not_next_segment() {
    let target_id = AccountId::new([1; 32]);
    let declared_next = AccountId::new([2; 32]);
    let wrong_next = AccountId::new([3; 32]);
    let shards = Shards::default().segment(wrong_next, vec![9], None);
    let _effects = write_segment(
        &[handle(target_id, true), handle(wrong_next, false)],
        shards.read(),
        vec![1],
        Some(declared_next),
    );
}

#[test]
#[should_panic(expected = "another program's shard selector")]
fn write_segment_rejects_a_handle_naming_another_shard() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let shards = Shards::default().segment(next_id, vec![9], None);
    let _effects = write_segment(
        &[
            handle(target_id, true),
            AccountMeta::new(next_id, false, AccountId::new([9; 32])),
        ],
        shards.read(),
        vec![1],
        Some(next_id),
    );
}

#[test]
#[should_panic(expected = "must already hold a valid segment")]
fn write_segment_rejects_a_next_segment_with_malformed_data() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let shards = Shards::default().with(next_id, ShardData::try_from(vec![0xff, 0xff]).unwrap());
    let _effects = write_segment(
        &[handle(target_id, true), handle(next_id, false)],
        shards.read(),
        vec![1],
        Some(next_id),
    );
}

#[test]
#[should_panic(expected = "at least the header target account")]
fn create_header_rejects_no_accounts() {
    let shards = Shards::default();
    let _effects = create_header(&[], shards.read(), AccountId::new([1; 32]), false);
}

#[test]
#[should_panic(expected = "header target already deployed")]
fn create_header_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: AccountId::new([2; 32]),
            immutable: false,
        },
    );
    let _effects = create_header(
        &[handle(target_id, false)],
        shards.read(),
        AccountId::new([2; 32]),
        false,
    );
}

#[test]
#[should_panic(expected = "must match the first supplied segment account")]
fn create_header_rejects_a_first_segment_mismatch() {
    let target_id = AccountId::new([1; 32]);
    let declared_first = AccountId::new([2; 32]);
    let actual_segment = AccountId::new([3; 32]);
    let shards = Shards::default().segment(actual_segment, vec![1], None);
    let _effects = create_header(
        &[handle(target_id, true), handle(actual_segment, false)],
        shards.read(),
        declared_first,
        false,
    );
}

#[test]
#[should_panic(expected = "at least the header target account")]
fn update_header_rejects_no_accounts() {
    let shards = Shards::default();
    let _effects = update_header(&[], shards.read(), AccountId::new([1; 32]), false);
}

#[test]
#[should_panic(expected = "use CreateHeader to make one")]
fn update_header_rejects_a_target_with_no_existing_header() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default();
    let _effects = update_header(
        &[handle(target_id, true)],
        shards.read(),
        AccountId::new([2; 32]),
        false,
    );
}

#[test]
#[should_panic(expected = "immutable and cannot be updated")]
fn update_header_rejects_an_immutable_header() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: true,
        },
    );
    let _effects = update_header(
        &[handle(target_id, true)],
        shards.read(),
        first_segment,
        false,
    );
}

#[test]
#[should_panic(expected = "must be authorized by the signer")]
fn update_header_rejects_an_unauthorized_caller() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: false,
        },
    );
    let _effects = update_header(
        &[handle(target_id, false)],
        shards.read(),
        first_segment,
        false,
    );
}

#[test]
#[should_panic(expected = "the native token program has no deployable bytecode")]
fn a_header_may_not_be_created_for_the_native_token_program() {
    let segment_id = AccountId::new([2; 32]);
    let shards = Shards::default().segment(segment_id, vec![1, 2, 3], None);

    drop(create_header(
        &[
            handle(NATIVE_TOKEN_PROGRAM_ID, true),
            handle(segment_id, false),
        ],
        shards.read(),
        segment_id,
        false,
    ));
}

/// A program at this address would run as the loader and could rewrite any program.
#[test]
#[should_panic(expected = "the loader's own dispatch address")]
fn a_segment_cannot_be_written_at_the_loader_address() {
    let shards = Shards::default();
    let _effects = write_segment(
        &[handle(PROGRAM_LOADER_ACCOUNT_ID, true)],
        shards.read(),
        vec![0_u8; 32],
        None,
    );
}

/// Segments too: a minimal one is header-length and decodes as a header.
#[test]
#[should_panic(expected = "the loader's own dispatch address")]
fn a_header_cannot_be_created_at_the_loader_address() {
    let first_segment = AccountId::new([3; 32]);
    let shards = Shards::default().segment(first_segment, vec![0_u8; 32], None);
    let _effects = create_header(
        &[
            handle(PROGRAM_LOADER_ACCOUNT_ID, true),
            handle(first_segment, false),
        ],
        shards.read(),
        first_segment,
        true,
    );
}

/// Genesis chunks every seeded program by `MAX_SEGMENT_DATA_LEN`, so a full segment must still
/// fit in one shard, or seeding panics.
#[test]
fn a_full_segment_fits_a_shard() {
    // Empty bytecode, so every encoded byte is overhead. `Some` is the worst case: a segment that
    // links onward carries the next id. Built field by field on purpose: a new field fails to
    // compile here instead of being silently defaulted. Set a new field to its largest encoding:
    // an empty `Vec` would count only its length prefix, and hide any overflow. Measured through
    // the stored encoding, so the `LoaderEntry` tag byte is counted too.
    let overhead = ProgramSegment {
        bytecode: Vec::new(),
        next_segment: Some(AccountId::default()),
    }
    .to_loader_shard()
    .len();

    let full = MAX_SEGMENT_DATA_LEN
        .checked_add(overhead)
        .expect("segment size fits in usize");
    assert!(
        u64::try_from(full).expect("usize fits in u64") <= DATA_MAX_LENGTH.as_u64(),
        "a full segment ({full} bytes) must fit under DATA_MAX_LENGTH"
    );
}

#[test]
fn build_segments_links_each_chunk_to_the_next_id() {
    let user_elf: Vec<u8> = (0..=u8::MAX)
        .cycle()
        .take(MAX_SEGMENT_DATA_LEN * 2 + 5)
        .collect();
    let ids = [
        AccountId::new([1; 32]),
        AccountId::new([2; 32]),
        AccountId::new([3; 32]),
    ];

    let segments = build_segments(&user_elf, &ids).expect("valid chain");

    let next: Vec<_> = segments
        .iter()
        .map(|segment| segment.next_segment)
        .collect();
    assert_eq!(next, vec![Some(ids[1]), Some(ids[2]), None]);
    let rejoined: Vec<u8> = segments
        .into_iter()
        .flat_map(|segment| segment.bytecode)
        .collect();
    assert_eq!(rejoined, user_elf);
}

#[test]
fn build_segments_rejects_a_segment_count_mismatch() {
    let user_elf = vec![0; MAX_SEGMENT_DATA_LEN + 1];
    assert_eq!(
        build_segments(&user_elf, &[AccountId::new([1; 32])]),
        Err(SegmentChainError::CountMismatch {
            expected: 2,
            actual: 1
        })
    );
}

/// Caught before upload: the loader itself would only notice at `CreateHeader`, after every
/// segment was paid for.
#[test]
fn build_segments_rejects_a_chain_over_the_segment_cap() {
    let count = MAX_PROGRAM_SEGMENTS + 1;
    let user_elf = vec![0; MAX_SEGMENT_DATA_LEN * count];
    let ids: Vec<_> = (0..count)
        .map(|i| AccountId::new([u8::try_from(i).unwrap(); 32]))
        .collect();
    assert_eq!(
        build_segments(&user_elf, &ids),
        Err(SegmentChainError::TooManySegments { count })
    );
}

/// Finding 1: a chain may not end in a header. A mutable header linked as a segment would let its
/// owner change an immutable program's code by updating that header.
#[test]
#[should_panic(expected = "every supplied segment account must decode as a valid ProgramSegment")]
fn create_header_rejects_a_chain_linking_to_a_header() {
    let target_id = AccountId::new([1; 32]);
    let linked_header_id = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        linked_header_id,
        &ProgramHeader {
            image_id: [60, 0, 0, 0, 0, 0, 0, 0],
            program_first_segment: AccountId::new([3; 32]),
            immutable: false,
        },
    );
    let _effects = create_header(
        &[handle(target_id, true), handle(linked_header_id, false)],
        shards.read(),
        linked_header_id,
        true,
    );
}

#[test]
#[should_panic(expected = "`next_segment` must already hold a valid segment")]
fn write_segment_rejects_linking_to_a_header() {
    let target_id = AccountId::new([1; 32]);
    let linked_header_id = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        linked_header_id,
        &ProgramHeader {
            image_id: [60, 0, 0, 0, 0, 0, 0, 0],
            program_first_segment: AccountId::new([3; 32]),
            immutable: false,
        },
    );
    let _effects = write_segment(
        &[handle(target_id, true), handle(linked_header_id, false)],
        shards.read(),
        vec![1],
        Some(linked_header_id),
    );
}

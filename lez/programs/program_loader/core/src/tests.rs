//! Unit tests for the bookkeeping this crate owns directly: segment/header shape, write-once and
//! chain-order enforcement, and `UpdateHeader`'s authorization/immutability gates.
//!
//! A success path through `create_header`/`update_header` needs bytecode that decodes as a real
//! RISC0 program (`compute_image_id` rejects anything else), so those are covered at the
//! state-machine integration level instead, against real guest ELFs.

use lee_core::account::{AccountId, AccountInput, BalanceDiff};

use super::*;

fn empty_target(account_id: AccountId, is_authorized: bool) -> AccountInput {
    AccountInput::with_shard(
        account_id,
        is_authorized,
        0,
        PROGRAM_LOADER_ACCOUNT_ID,
        Data::empty(),
    )
}

fn segment_pre(
    account_id: AccountId,
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> AccountInput {
    AccountInput::with_shard(
        account_id,
        false,
        0,
        PROGRAM_LOADER_ACCOUNT_ID,
        Data::try_from(
            ProgramSegment {
                bytecode,
                next_segment,
            }
            .to_bytes(),
        )
        .unwrap(),
    )
}

fn header_pre(account_id: AccountId, header: &ProgramHeader, is_authorized: bool) -> AccountInput {
    AccountInput::with_shard(
        account_id,
        is_authorized,
        0,
        PROGRAM_LOADER_ACCOUNT_ID,
        Data::try_from(header.to_bytes()).unwrap(),
    )
}

#[test]
fn write_segment_writes_the_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let pre_states = [empty_target(target_id, false)];

    let diffs = write_segment(&pre_states, vec![1, 2, 3], None);

    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].pre_state.account_id, target_id);
    assert_eq!(diffs[0].post_balance_diff, BalanceDiff::Add(0));
    let segment = ProgramSegment::from_bytes(
        diffs[0]
            .post_data
            .as_ref()
            .expect("the loader shard was written")
            .as_ref(),
    )
    .expect("valid segment");
    assert_eq!(segment.bytecode, vec![1, 2, 3]);
    assert_eq!(segment.next_segment, None);
}

#[test]
fn write_segment_accepts_a_target_holding_balance() {
    let target_id = AccountId::new([1; 32]);
    let pre_states = [AccountInput::with_shard(
        target_id,
        false,
        5,
        PROGRAM_LOADER_ACCOUNT_ID,
        Data::empty(),
    )];

    let diffs = write_segment(&pre_states, vec![1, 2, 3], None);

    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].pre_state.balance, 5);
    assert_eq!(diffs[0].post_balance_diff, BalanceDiff::Add(0));
}

#[test]
fn write_segment_linking_to_an_existing_segment_leaves_it_unchanged() {
    let next_id = AccountId::new([2; 32]);
    let next_pre = segment_pre(next_id, vec![9, 9], None);
    let target_id = AccountId::new([1; 32]);
    let pre_states = [empty_target(target_id, false), next_pre.clone()];

    let diffs = write_segment(&pre_states, vec![1, 2, 3], Some(next_id));

    assert_eq!(diffs.len(), 2);
    let segment = ProgramSegment::from_bytes(
        diffs[0]
            .post_data
            .as_ref()
            .expect("the loader shard was written")
            .as_ref(),
    )
    .expect("valid segment");
    assert_eq!(segment.next_segment, Some(next_id));
    // The referenced segment is read-only: no balance or data change.
    assert_eq!(diffs[1].pre_state, next_pre);
    assert_eq!(diffs[1].post_balance_diff, BalanceDiff::Add(0));
    assert_eq!(diffs[1].post_data, None);
}

#[test]
#[should_panic(expected = "requires exactly 1 account")]
fn write_segment_rejects_wrong_account_count_without_next() {
    let target_id = AccountId::new([1; 32]);
    let extra_id = AccountId::new([2; 32]);
    let pre_states = [
        empty_target(target_id, false),
        empty_target(extra_id, false),
    ];
    let _diffs = write_segment(&pre_states, vec![1], None);
}

#[test]
#[should_panic(expected = "requires exactly 2 account")]
fn write_segment_rejects_wrong_account_count_with_next() {
    let target_id = AccountId::new([1; 32]);
    let pre_states = [empty_target(target_id, false)];
    let _diffs = write_segment(&pre_states, vec![1], Some(AccountId::new([2; 32])));
}

#[test]
#[should_panic(expected = "already deployed")]
fn write_segment_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let pre = segment_pre(target_id, vec![9], None);
    let _diffs = write_segment(&[pre], vec![1], None);
}

#[test]
#[should_panic(expected = "next_segment` points to")]
fn write_segment_rejects_a_second_account_that_is_not_next_segment() {
    let target_id = AccountId::new([1; 32]);
    let declared_next = AccountId::new([2; 32]);
    let wrong_next = segment_pre(AccountId::new([3; 32]), vec![9], None);
    let pre_states = [empty_target(target_id, false), wrong_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(declared_next));
}

#[test]
#[should_panic(expected = "AccountInput carries another program's shard")]
fn write_segment_rejects_a_next_segment_shard_selector_naming_another_shard() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let foreign_next = AccountInput::with_shard(
        next_id,
        false,
        0,
        AccountId::new([9; 32]),
        Data::try_from(vec![1]).unwrap(),
    );
    let pre_states = [empty_target(target_id, false), foreign_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(next_id));
}

#[test]
#[should_panic(expected = "must already hold a valid segment")]
fn write_segment_rejects_a_next_segment_with_malformed_data() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let malformed_next = AccountInput::with_shard(
        next_id,
        false,
        0,
        PROGRAM_LOADER_ACCOUNT_ID,
        Data::try_from(vec![0xff, 0xff]).unwrap(),
    );
    let pre_states = [empty_target(target_id, false), malformed_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(next_id));
}

#[test]
#[should_panic(expected = "at least the header target account")]
fn create_header_rejects_empty_pre_states() {
    let _diffs = create_header(&[], AccountId::new([1; 32]), false);
}

#[test]
#[should_panic(expected = "header target already deployed")]
fn create_header_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let pre = header_pre(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: AccountId::new([2; 32]),
            immutable: false,
        },
        false,
    );
    let _diffs = create_header(&[pre], AccountId::new([2; 32]), false);
}

#[test]
#[should_panic(expected = "must match the first supplied segment account")]
fn create_header_rejects_a_first_segment_mismatch() {
    let target_id = AccountId::new([1; 32]);
    let declared_first = AccountId::new([2; 32]);
    let actual_segment = segment_pre(AccountId::new([3; 32]), vec![1], None);
    let pre_states = [empty_target(target_id, false), actual_segment];
    let _diffs = create_header(&pre_states, declared_first, false);
}

#[test]
#[should_panic(expected = "at least the header target account")]
fn update_header_rejects_empty_pre_states() {
    let _diffs = update_header(&[], AccountId::new([1; 32]), false);
}

#[test]
#[should_panic(expected = "use CreateHeader to make one")]
fn update_header_rejects_a_target_with_no_existing_header() {
    let target_id = AccountId::new([1; 32]);
    let _diffs = update_header(
        &[empty_target(target_id, true)],
        AccountId::new([2; 32]),
        false,
    );
}

#[test]
#[should_panic(expected = "immutable and cannot be updated")]
fn update_header_rejects_an_immutable_header() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let header = ProgramHeader {
        image_id: [0; 8],
        program_first_segment: first_segment,
        immutable: true,
    };
    let _diffs = update_header(
        &[header_pre(target_id, &header, true)],
        first_segment,
        false,
    );
}

#[test]
#[should_panic(expected = "must be authorized by the signer")]
fn update_header_rejects_an_unauthorized_caller() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let header = ProgramHeader {
        image_id: [0; 8],
        program_first_segment: first_segment,
        immutable: false,
    };
    let _diffs = update_header(
        &[header_pre(target_id, &header, false)],
        first_segment,
        false,
    );
}

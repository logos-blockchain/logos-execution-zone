//! Unit tests for the bookkeeping this crate owns directly: segment/header shape, write-once and
//! chain-order enforcement, and `UpdateHeader`'s authorization/immutability gates.
//!
//! A success path through `create_header`/`update_header` needs bytecode that decodes as a real
//! RISC0 program (`compute_image_id` rejects anything else), so those are covered at the
//! state-machine integration level instead, against real guest ELFs.

use lee_core::account::{Account, AccountId, AccountWithMetadata, BalanceDiff};

use super::*;

fn default_pre(account_id: AccountId, is_authorized: bool) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account::default(),
        is_authorized,
        account_id,
    }
}

fn loader_owned_segment_pre(
    account_id: AccountId,
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::try_from(
                ProgramSegment {
                    bytecode,
                    next_segment,
                }
                .to_bytes(),
            )
            .unwrap(),
            ..Account::default()
        },
        is_authorized: false,
        account_id,
    }
}

#[test]
fn write_segment_head_of_chain_claims_the_target() {
    let target_id = AccountId::new([1; 32]);
    let pre_states = [default_pre(target_id, false)];

    let diffs = write_segment(&pre_states, vec![1, 2, 3], None);

    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].pre_state.account_id, target_id);
    assert_eq!(diffs[0].post_balance_diff, BalanceDiff::Add(0));
    let segment = ProgramSegment::from_bytes(
        diffs[0]
            .post_data
            .as_ref()
            .expect("data changed from default")
            .as_ref(),
    )
    .expect("valid segment");
    assert_eq!(segment.bytecode, vec![1, 2, 3]);
    assert_eq!(segment.next_segment, None);
}

#[test]
fn write_segment_linking_to_an_existing_segment_leaves_it_unchanged() {
    let next_id = AccountId::new([2; 32]);
    let next_pre = loader_owned_segment_pre(next_id, vec![9, 9], None);
    let target_id = AccountId::new([1; 32]);
    let pre_states = [default_pre(target_id, false), next_pre.clone()];

    let diffs = write_segment(&pre_states, vec![1, 2, 3], Some(next_id));

    assert_eq!(diffs.len(), 2);
    let segment = ProgramSegment::from_bytes(
        diffs[0]
            .post_data
            .as_ref()
            .expect("data changed from default")
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
    let pre_states = [default_pre(target_id, false), default_pre(extra_id, false)];
    let _diffs = write_segment(&pre_states, vec![1], None);
}

#[test]
#[should_panic(expected = "requires exactly 2 account")]
fn write_segment_rejects_wrong_account_count_with_next() {
    let target_id = AccountId::new([1; 32]);
    let pre_states = [default_pre(target_id, false)];
    let _diffs = write_segment(&pre_states, vec![1], Some(AccountId::new([2; 32])));
}

#[test]
#[should_panic(expected = "already deployed")]
fn write_segment_rejects_a_non_default_target() {
    let target_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata {
        account: Account {
            balance: 1,
            ..Account::default()
        },
        is_authorized: false,
        account_id: target_id,
    };
    let _diffs = write_segment(&[pre], vec![1], None);
}

#[test]
#[should_panic(expected = "next_segment` points to")]
fn write_segment_rejects_a_second_account_that_is_not_next_segment() {
    let target_id = AccountId::new([1; 32]);
    let declared_next = AccountId::new([2; 32]);
    let wrong_next = loader_owned_segment_pre(AccountId::new([3; 32]), vec![9], None);
    let pre_states = [default_pre(target_id, false), wrong_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(declared_next));
}

#[test]
#[should_panic(expected = "must be loader-owned")]
fn write_segment_rejects_a_next_segment_not_owned_by_the_loader() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let unowned_next = default_pre(next_id, false);
    let pre_states = [default_pre(target_id, false), unowned_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(next_id));
}

#[test]
#[should_panic(expected = "must already hold a valid segment")]
fn write_segment_rejects_a_next_segment_with_malformed_data() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let malformed_next = AccountWithMetadata {
        account: Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::try_from(vec![0xff, 0xff]).unwrap(),
            ..Account::default()
        },
        is_authorized: false,
        account_id: next_id,
    };
    let pre_states = [default_pre(target_id, false), malformed_next];
    let _diffs = write_segment(&pre_states, vec![1], Some(next_id));
}

#[test]
#[should_panic(expected = "at least the header target account")]
fn create_header_rejects_empty_pre_states() {
    let _diffs = create_header(&[], AccountId::new([1; 32]), false);
}

#[test]
#[should_panic(expected = "header target already deployed")]
fn create_header_rejects_a_non_default_target() {
    let target_id = AccountId::new([1; 32]);
    let pre = AccountWithMetadata {
        account: Account {
            balance: 1,
            ..Account::default()
        },
        is_authorized: false,
        account_id: target_id,
    };
    let _diffs = create_header(&[pre], AccountId::new([2; 32]), false);
}

#[test]
#[should_panic(expected = "must match the first supplied segment account")]
fn create_header_rejects_a_first_segment_mismatch() {
    let target_id = AccountId::new([1; 32]);
    let declared_first = AccountId::new([2; 32]);
    let actual_segment = loader_owned_segment_pre(AccountId::new([3; 32]), vec![1], None);
    let pre_states = [default_pre(target_id, false), actual_segment];
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
        &[default_pre(target_id, true)],
        AccountId::new([2; 32]),
        false,
    );
}

fn header_pre(
    account_id: AccountId,
    header: &ProgramHeader,
    is_authorized: bool,
) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::try_from(header.to_bytes()).unwrap(),
            ..Account::default()
        },
        is_authorized,
        account_id,
    }
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

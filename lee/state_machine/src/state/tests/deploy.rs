use lee_core::{
    account::Data,
    program::{ProgramData, RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID},
};

use super::*;

/// `insert_program` (genesis) must produce exactly the account shape
/// `program_loader_core::plan_deploy` reports for the same bytecode — the invariant that makes
/// genesis and a live `Deploy` indistinguishable to `get_program`.
#[test]
fn insert_program_matches_plan_deploy() {
    let program = crate::test_methods::claimer();
    let mut state = V03State::new();
    state.insert_program(&program);

    let user_elf = program_loader_core::extract_user_elf(program.elf()).unwrap();
    let plan = program_loader_core::plan_deploy(
        RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID,
        program.id(),
        AccountId::default(),
        &user_elf,
    );
    assert!(
        plan.segments.len() > 1,
        "a real program should span multiple segments at the 96 KiB chunk size"
    );

    assert!(state.public_state.contains_key(&plan.header.account_id));
    for segment in &plan.segments {
        assert!(state.public_state.contains_key(&segment.account_id));
    }
}

/// A genesis-seeded multi-segment program round-trips through `get_program` back to its original
/// full two-ELF binary.
#[test]
fn get_program_reconstructs_a_genesis_seeded_program() {
    let program = crate::test_methods::claimer();
    let mut state = V03State::new();
    state.insert_program(&program);

    let (image_id, elf) = state
        .get_program(program.deployed_account_id())
        .expect("reconstruction should succeed")
        .expect("program should be found");

    assert_eq!(image_id, program.id());
    assert_eq!(elf, program.elf());
}

/// A header pointing at a `segment_count` beyond what's actually been written is treated as
/// absent, not corrupted — the account simply isn't fully deployed.
#[test]
fn get_program_returns_none_for_a_missing_segment() {
    let program = crate::test_methods::claimer();
    let mut state = V03State::new();
    state.insert_program(&program);

    let header_account_id = program.deployed_account_id();
    let mut header_account = state.public_state[&header_account_id].clone();
    let mut header_data = ProgramData::try_from(&header_account.data).unwrap();
    header_data.segment_count += 1; // claims one more segment than actually exists
    header_account.data = Data::from(&header_data);
    state.public_state.insert(header_account_id, header_account);

    let result = state.get_program(header_account_id).unwrap();
    assert_eq!(result, None);
}

/// A corrupted segment's reconstructed `image_id` won't match the header's claim —
/// `get_program` must reject that distinguishably from plain absence.
#[test]
fn get_program_rejects_a_corrupted_segment() {
    let program = crate::test_methods::claimer();
    let mut state = V03State::new();
    state.insert_program(&program);

    let first_segment_account_id = program_loader_core::deploy_segment_account_id(
        RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID,
        program.id(),
        0,
        AccountId::default(),
    );
    let mut first_segment = state.public_state[&first_segment_account_id].clone();
    let mut corrupted = first_segment.data.to_vec();
    corrupted[0] ^= 0xFF;
    first_segment.data = corrupted.try_into().unwrap();
    state
        .public_state
        .insert(first_segment_account_id, first_segment);

    let result = state.get_program(program.deployed_account_id());
    assert!(
        matches!(result, Err(LeeError::InvalidProgramBytecode(_))),
        "expected a bytecode-mismatch error, got: {result:?}"
    );
}

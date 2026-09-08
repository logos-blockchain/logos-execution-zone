use super::*;

#[test]
fn unsupported_call_kind_selector_matches_its_derivation() {
    use sha2::Digest as _;

    assert_eq!(
        UnsupportedCallKind::SELECTOR[..],
        sha2::Sha256::digest(UnsupportedCallKind::SELECTOR_NAME.as_bytes())[..8]
    );
}

#[test]
fn call_kind_round_trips_execute_and_preserves_unknown_discriminants() {
    let execute = borsh::to_vec(&CallKind::Execute).unwrap();
    assert_eq!(
        borsh::from_slice::<CallKind>(&execute).unwrap(),
        CallKind::Execute
    );

    // Any nonzero discriminant must decode as `Unknown`, not fail.
    for byte in 1..=u8::MAX {
        assert_eq!(
            borsh::from_slice::<CallKind>(&[byte]).unwrap(),
            CallKind::Unknown(byte)
        );
    }
}

#[test]
fn validity_window_unbounded_accepts_any_value() {
    let w: ValidityWindow<u64> = ValidityWindow::new_unbounded();
    assert!(w.is_valid_for(0));
    assert!(w.is_valid_for(u64::MAX));
}

#[test]
fn validity_window_bounded_range_includes_from_excludes_to() {
    let w: ValidityWindow<u64> = (Some(5), Some(10)).try_into().unwrap();
    assert!(!w.is_valid_for(4));
    assert!(w.is_valid_for(5));
    assert!(w.is_valid_for(9));
    assert!(!w.is_valid_for(10));
}

#[test]
fn validity_window_only_from_bound() {
    let w: ValidityWindow<u64> = (Some(5), None).try_into().unwrap();
    assert!(!w.is_valid_for(4));
    assert!(w.is_valid_for(5));
    assert!(w.is_valid_for(u64::MAX));
}

#[test]
fn validity_window_only_to_bound() {
    let w: ValidityWindow<u64> = (None, Some(5)).try_into().unwrap();
    assert!(w.is_valid_for(0));
    assert!(w.is_valid_for(4));
    assert!(!w.is_valid_for(5));
}

#[test]
fn validity_window_adjacent_bounds_are_invalid() {
    // [5, 5) is an empty range — from == to
    assert!(ValidityWindow::<u64>::try_from((Some(5), Some(5))).is_err());
}

#[test]
fn validity_window_inverted_bounds_are_invalid() {
    assert!(ValidityWindow::<u64>::try_from((Some(10), Some(5))).is_err());
}

#[test]
fn validity_window_getters_match_construction() {
    let w: ValidityWindow<u64> = (Some(3), Some(7)).try_into().unwrap();
    assert_eq!(w.start(), Some(3));
    assert_eq!(w.end(), Some(7));
}

#[test]
fn validity_window_getters_for_unbounded() {
    let w: ValidityWindow<u64> = ValidityWindow::new_unbounded();
    assert_eq!(w.start(), None);
    assert_eq!(w.end(), None);
}

#[test]
fn validity_window_from_range() {
    let w: ValidityWindow<u64> = ValidityWindow::try_from(5_u64..10).unwrap();
    assert_eq!(w.start(), Some(5));
    assert_eq!(w.end(), Some(10));
}

#[test]
fn validity_window_from_range_empty_is_invalid() {
    assert!(ValidityWindow::<u64>::try_from(5_u64..5).is_err());
}

#[test]
fn validity_window_from_range_inverted_is_invalid() {
    let from = 10_u64;
    let to = 5_u64;
    assert!(ValidityWindow::<u64>::try_from(from..to).is_err());
}

#[test]
fn validity_window_from_range_from() {
    let w: ValidityWindow<u64> = (5_u64..).into();
    assert_eq!(w.start(), Some(5));
    assert_eq!(w.end(), None);
}

#[test]
fn validity_window_from_range_to() {
    let w: ValidityWindow<u64> = (..10_u64).into();
    assert_eq!(w.start(), None);
    assert_eq!(w.end(), Some(10));
}

#[test]
fn validity_window_from_range_full() {
    let w: ValidityWindow<u64> = (..).into();
    assert_eq!(w.start(), None);
    assert_eq!(w.end(), None);
}

#[test]
fn program_output_try_with_block_validity_window_range() {
    let output = ProgramOutput::new(AccountId::default(), None, vec![], vec![])
        .try_with_block_validity_window(10_u64..100)
        .unwrap();
    assert_eq!(output.block_validity_window.start(), Some(10));
    assert_eq!(output.block_validity_window.end(), Some(100));
}

#[test]
fn program_output_with_block_validity_window_range_from() {
    let output = ProgramOutput::new(AccountId::default(), None, vec![], vec![])
        .with_block_validity_window(10_u64..);
    assert_eq!(output.block_validity_window.start(), Some(10));
    assert_eq!(output.block_validity_window.end(), None);
}

#[test]
fn program_output_with_block_validity_window_range_to() {
    let output = ProgramOutput::new(AccountId::default(), None, vec![], vec![])
        .with_block_validity_window(..100_u64);
    assert_eq!(output.block_validity_window.start(), None);
    assert_eq!(output.block_validity_window.end(), Some(100));
}

#[test]
fn program_output_try_with_block_validity_window_empty_range_fails() {
    let result = ProgramOutput::new(AccountId::default(), None, vec![], vec![])
        .try_with_block_validity_window(5_u64..5);
    assert!(result.is_err());
}

#[test]
fn shard_state_diff_constructors() {
    let program = AccountId::new([9; 32]);
    let pre_data: Data = b"record".to_vec().try_into().unwrap();
    let pre = AccountInput::with_shard(AccountId::new([7; 32]), true, 5, program, pre_data.clone());
    let post_data: Data = vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap();

    let unchanged = AccountStateDiff::unchanged(pre.clone());
    assert_eq!(unchanged.post_balance_diff, BalanceDiff::Add(0));
    assert_eq!(unchanged.post_data, None);

    let balance_only = AccountStateDiff::balance_only(pre.clone(), BalanceDiff::Sub(2));
    assert_eq!(balance_only.post_balance_diff, BalanceDiff::Sub(2));
    assert_eq!(balance_only.post_data, None);

    let written = AccountStateDiff::new(pre.clone(), BalanceDiff::Add(1337), pre_data.clone());
    assert_eq!(written.pre_state, pre);
    assert_eq!(written.post_balance_diff, BalanceDiff::Add(1337));
    assert_eq!(written.post_data, Some(pre_data));

    assert_eq!(
        AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data.clone()).post_data,
        Some(post_data)
    );
}

// ---- validate_execution tests ----

#[test]
fn validate_execution_rejects_insufficient_balance_even_if_globally_conserved() {
    let executing_program_id: AccountId = AccountId::from([1; 8]);
    let account_id = AccountId::new([7; 32]);
    let pre = AccountInput::with_shard(account_id, true, 5, executing_program_id, Data::empty());
    let state_diffs = [AccountStateDiff::balance_only(pre, BalanceDiff::Sub(10))];

    let result = validate_execution(&state_diffs, executing_program_id);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::InvalidBalanceDiff { account_id: id, .. }) if id == account_id
    ));
}

#[test]
fn validate_execution_rejects_add_overflow() {
    let executing_program_id: AccountId = AccountId::from([1; 8]);
    let account_id = AccountId::new([7; 32]);
    let pre = AccountInput::with_shard(
        account_id,
        false,
        u128::MAX,
        executing_program_id,
        Data::empty(),
    );
    let state_diffs = [AccountStateDiff::balance_only(pre, BalanceDiff::Add(1))];

    let result = validate_execution(&state_diffs, executing_program_id);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::InvalidBalanceDiff { account_id: id, .. }) if id == account_id
    ));
}

#[test]
fn a_data_write_on_a_foreign_shard_is_rejected() {
    let executing_account_id = AccountId::new([2; 32]);
    let account_id = AccountId::new([7; 32]);
    let pre = AccountInput::with_shard(account_id, true, 5, AccountId::new([1; 32]), Data::empty());
    let state_diffs = [AccountStateDiff::new(
        pre,
        BalanceDiff::Add(0),
        b"record".to_vec().try_into().unwrap(),
    )];

    let result = validate_execution(&state_diffs, executing_account_id);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::ForeignShardWrite {
            account_id: id,
            executing_account_id: executing,
        }) if id == account_id && executing == executing_account_id
    ));
}

#[test]
fn a_data_write_on_the_executing_shard_is_accepted() {
    let executing_account_id = AccountId::new([2; 32]);
    let pre = AccountInput::with_shard(
        AccountId::new([7; 32]),
        true,
        5,
        executing_account_id,
        Data::empty(),
    );
    let state_diffs = [AccountStateDiff::new(
        pre,
        BalanceDiff::Add(0),
        b"record".to_vec().try_into().unwrap(),
    )];

    assert!(validate_execution(&state_diffs, executing_account_id).is_ok());
}

#[test]
fn a_balance_only_shard_selector_cannot_carry_data() {
    let executing_account_id = AccountId::new([2; 32]);
    let account_id = AccountId::new([7; 32]);
    let pre = AccountInput::balance_only(account_id, true, 5);
    let state_diffs = [AccountStateDiff::new(
        pre,
        BalanceDiff::Add(0),
        b"record".to_vec().try_into().unwrap(),
    )];

    let result = validate_execution(&state_diffs, executing_account_id);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::ForeignShardWrite { account_id: id, .. }) if id == account_id
    ));
}

#[test]
fn two_shard_selectors_of_one_account_in_a_call_are_rejected() {
    let executing_account_id = AccountId::new([2; 32]);
    let account_id = AccountId::new([7; 32]);
    let state_diffs = [
        AccountStateDiff::unchanged(AccountInput::with_shard(
            account_id,
            true,
            5,
            executing_account_id,
            Data::empty(),
        )),
        AccountStateDiff::unchanged(AccountInput::balance_only(account_id, true, 5)),
    ];

    let result = validate_execution(&state_diffs, executing_account_id);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::PreStateAccountIdsNotUnique)
    ));
}

#[test]
fn pre_states_match_shard_selectors_compares_program_account_ids() {
    let account_id = AccountId::new([7; 32]);
    let program = AccountId::new([2; 32]);
    let diffs = [AccountStateDiff::unchanged(AccountInput::with_shard(
        account_id,
        true,
        5,
        program,
        Data::empty(),
    ))];

    assert!(pre_states_match_shard_selectors(
        &[ProgramShardSelector::new(account_id, program)],
        &diffs
    ));
    assert!(!pre_states_match_shard_selectors(
        &[ProgramShardSelector::new(
            account_id,
            AccountId::new([3; 32])
        )],
        &diffs
    ));
    assert!(!pre_states_match_shard_selectors(
        &[ProgramShardSelector::balance_only(account_id)],
        &diffs
    ));
}

#[test]
fn apply_diff_keeps_the_pre_shard_when_nothing_is_written() {
    let program = AccountId::new([2; 32]);
    let data: Data = b"record".to_vec().try_into().unwrap();
    let pre = AccountInput::with_shard(AccountId::new([7; 32]), true, 5, program, data.clone());
    let mut account = Account::default();

    account
        .data
        .apply_diff(&AccountStateDiff::balance_only(pre, BalanceDiff::Sub(2)))
        .unwrap();

    assert_eq!(account.data.balance, 3);
    assert_eq!(account.data.shard(program), &data);
}

#[test]
fn apply_diff_of_a_balance_only_shard_selector_carries_no_shard() {
    let pre = AccountInput::balance_only(AccountId::new([7; 32]), true, 5);
    let mut account = Account::default();

    account
        .data
        .apply_diff(&AccountStateDiff::balance_only(pre, BalanceDiff::Add(2)))
        .unwrap();

    assert_eq!(account.data.balance, 7);
    assert!(account.data.shards.is_empty());
}

#[test]
fn apply_diff_replaces_the_written_shard() {
    let program = AccountId::new([2; 32]);
    let pre = AccountInput::with_shard(
        AccountId::new([7; 32]),
        true,
        5,
        program,
        b"old".to_vec().try_into().unwrap(),
    );
    let written: Data = b"new".to_vec().try_into().unwrap();
    let mut account = Account::default();

    account
        .data
        .apply_diff(&AccountStateDiff::new(
            pre,
            BalanceDiff::Add(0),
            written.clone(),
        ))
        .unwrap();

    assert_eq!(account.data.shard(program), &written);
}

#[test]
fn get_program_via_reads_the_loader_shard() {
    let program_account = AccountId::new([1; 32]);
    let segment_account = AccountId::new([2; 32]);
    let header = ProgramHeader {
        image_id: [7; 8],
        program_first_segment: segment_account,
        immutable: false,
    };
    let segment = ProgramSegment {
        bytecode: vec![1, 2, 3],
        next_segment: None,
    };
    let shard = |id: AccountId, bytes: Vec<u8>| {
        Account::default().with_shard(id, bytes.try_into().unwrap())
    };

    let program_shard = shard(PROGRAM_LOADER_ACCOUNT_ID, header.to_bytes());
    let segment_shard = shard(PROGRAM_LOADER_ACCOUNT_ID, segment.to_bytes());
    let lookup = |id| {
        if id == program_account {
            Some(&program_shard)
        } else if id == segment_account {
            Some(&segment_shard)
        } else {
            None
        }
    };
    assert_eq!(
        get_program_via(program_account, lookup),
        Some(([7; 8], vec![1, 2, 3]))
    );

    let elsewhere = shard(AccountId::new([3; 32]), header.to_bytes());
    let foreign_shard = |id| (id == program_account).then_some(&elsewhere);
    assert_eq!(get_program_via(program_account, foreign_shard), None);
}

// ---- AccountId::for_private_pda tests ----

/// Pins `AccountId::for_private_pda` against a hardcoded expected output for a specific
/// `(program_id, seed, npk, identifier)` tuple. Any change to `PRIVATE_PDA_PREFIX`, byte
/// ordering, or the underlying hash breaks this test.
#[test]
fn for_private_pda_matches_pinned_value() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let identifier: Identifier = u128::MAX;
    let expected = AccountId::new([
        5, 87, 128, 244, 206, 244, 65, 130, 178, 88, 225, 183, 0, 159, 201, 201, 212, 206, 6, 156,
        13, 55, 32, 139, 91, 222, 209, 83, 172, 148, 123, 179,
    ]);
    assert_eq!(
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, identifier),
        expected
    );
}

/// Two groups with different viewing keys at the same (program, seed) get different addresses.
#[test]
fn for_private_pda_differs_for_different_npk() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk_a = NullifierPublicKey([3; 32]);
    let npk_b = NullifierPublicKey([4; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed, &npk_a, &vpk, u128::MAX),
        AccountId::for_private_pda(&program_id, &seed, &npk_b, &vpk, u128::MAX),
    );
}

/// Different seeds produce different addresses, even with the same program and npk.
#[test]
fn for_private_pda_differs_for_different_seed() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed_a = PdaSeed::new([2; 32]);
    let seed_b = PdaSeed::new([5; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed_a, &npk, &vpk, u128::MAX),
        AccountId::for_private_pda(&program_id, &seed_b, &npk, &vpk, u128::MAX),
    );
}

/// Different programs produce different addresses, even with the same seed and npk.
#[test]
fn for_private_pda_differs_for_different_program_id() {
    let program_id_a: AccountId = AccountId::from([1; 8]);
    let program_id_b: AccountId = AccountId::from([9; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(&program_id_a, &seed, &npk, &vpk, u128::MAX),
        AccountId::for_private_pda(&program_id_b, &seed, &npk, &vpk, u128::MAX),
    );
}

/// Different identifiers produce different addresses for the same `(program_id, seed, npk)`,
/// confirming that each `(program_id, seed, npk)` tuple controls a family of 2^128 addresses.
#[test]
fn for_private_pda_differs_for_different_identifier() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, 0),
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, 1),
    );
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, 0),
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, u128::MAX),
    );
}

/// A private PDA at the same (program, seed) has a different address than a public PDA,
/// because the private formula uses a different prefix and includes npk.
#[test]
fn for_private_pda_differs_from_public_pda() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let private_id = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, u128::MAX);
    let public_id = AccountId::for_public_pda(&program_id, &seed);
    assert_ne!(private_id, public_id);
}

#[cfg(feature = "host")]
#[test]
fn private_account_kind_header_round_trips() {
    let regular = PrivateAccountKind::Regular(42);
    let pda = PrivateAccountKind::Pda {
        account_id: AccountId::new([1; 32]),
        seed: PdaSeed::new([2_u8; 32]),
        identifier: u128::MAX,
    };
    assert_eq!(
        PrivateAccountKind::from_header_bytes(&regular.to_header_bytes()),
        Some(regular)
    );
    assert_eq!(
        PrivateAccountKind::from_header_bytes(&pda.to_header_bytes()),
        Some(pda)
    );
}

#[cfg(feature = "host")]
#[test]
fn private_account_kind_unknown_discriminant_returns_none() {
    let mut bytes = [0_u8; PrivateAccountKind::HEADER_LEN];
    bytes[0] = 0xFF;
    assert_eq!(PrivateAccountKind::from_header_bytes(&bytes), None);
}

#[test]
fn for_private_account_dispatches_correctly() {
    let program_id: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let identifier: Identifier = 77;

    assert_eq!(
        AccountId::for_private_account(&npk, &vpk, &PrivateAccountKind::Regular(identifier)),
        AccountId::for_regular_private_account(&npk, &vpk, identifier),
    );
    assert_eq!(
        AccountId::for_private_account(
            &npk,
            &vpk,
            &PrivateAccountKind::Pda {
                account_id: program_id,
                seed,
                identifier
            }
        ),
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, identifier),
    );
}

#[test]
fn compute_public_authorized_pdas_with_seeds() {
    let caller: AccountId = AccountId::from([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let result = compute_public_authorized_pdas(Some(caller), &[seed]);
    let expected = AccountId::for_public_pda(&caller, &seed);
    assert!(result.contains(&expected));
    assert_eq!(result.len(), 1);
}

/// With no caller (top-level call), the result is always empty.
#[test]
fn compute_public_authorized_pdas_no_caller_returns_empty() {
    let seed = PdaSeed::new([2; 32]);
    let result = compute_public_authorized_pdas(None, &[seed]);
    assert!(result.is_empty());
}

#[test]
fn account_id_from_program_id_reinterprets_words_as_le_bytes() {
    let program_id: ProgramId = [
        0x0403_0201,
        0x0807_0605,
        0x0c0b_0a09,
        0x100f_0e0d,
        0x1413_1211,
        0x1817_1615,
        0x1c1b_1a19,
        0x201f_1e1d,
    ];
    let expected: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    assert_eq!(AccountId::from(program_id).value(), &expected);
}

#[test]
fn program_id_from_account_id_reinterprets_le_bytes_as_words() {
    let account_id = AccountId::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);
    let expected: ProgramId = [
        0x0403_0201,
        0x0807_0605,
        0x0c0b_0a09,
        0x100f_0e0d,
        0x1413_1211,
        0x1817_1615,
        0x1c1b_1a19,
        0x201f_1e1d,
    ];
    assert_eq!(ProgramId::from(account_id), expected);
}

#[test]
fn program_id_account_id_conversion_round_trips() {
    let program_id: ProgramId = [
        0x1122_3344,
        0x5566_7788,
        0x99aa_bbcc,
        0xddee_ff00,
        0xcafe_babe,
        0xdead_beef,
        0x0bad_f00d,
        0xfeed_face,
    ];
    assert_eq!(ProgramId::from(AccountId::from(program_id)), program_id);
}

fn foreign_shard_with_history() -> AccountInput {
    AccountInput::with_shard(
        AccountId::new([7; 32]),
        true,
        55,
        AccountId::new([2; 32]),
        b"record".to_vec().try_into().unwrap(),
    )
}

#[test]
fn a_foreign_shard_with_history_may_be_echoed_byte_identically() {
    for zero in [BalanceDiff::Add(0), BalanceDiff::Sub(0)] {
        let diff = AccountStateDiff::balance_only(foreign_shard_with_history(), zero);
        assert!(validate_execution(&[diff], AccountId::new([9; 32])).is_ok());
    }
}

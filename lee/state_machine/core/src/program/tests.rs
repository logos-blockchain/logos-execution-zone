use super::*;
use crate::account::Account;

fn empty_input() -> PlanInput {
    PlanInput {
        self_account_id: AccountId::default(),
        caller_account_id: None,
        accounts: Vec::new(),
        instruction_data: Vec::new(),
    }
}

fn plan_of(
    accounts: &[AccountMeta],
    effects: Vec<ShardEffect>,
) -> Result<(), ExecutionValidationError> {
    let input = PlanInput {
        accounts: accounts.to_vec(),
        ..empty_input()
    };
    validate_plan(
        &input,
        &PlanOutput::new(input.clone()).with_effects(effects),
    )
}

#[test]
fn call_kind_discriminants_are_pinned_and_unknown_ones_are_rejected() {
    assert_eq!(borsh::to_vec(&CallKind::Plan).unwrap(), vec![0]);
    assert_eq!(borsh::to_vec(&CallKind::Apply).unwrap(), vec![1]);

    for byte in 2..=u8::MAX {
        assert!(
            borsh::from_slice::<CallKind>(&[byte]).is_err(),
            "{byte} decoded as a call kind"
        );
    }
}

#[test]
fn the_journal_tag_separates_the_two_entrypoints() {
    let execute = GuestOutput::Plan(PlanOutput::new(empty_input()));
    let apply = GuestOutput::Apply(output_of(AccountId::new([2; 32]), None));

    assert_eq!(borsh::to_vec(&execute).unwrap()[0], 0);
    assert_eq!(borsh::to_vec(&apply).unwrap()[0], 1);
    assert_eq!(
        borsh::from_slice::<GuestOutput>(&borsh::to_vec(&execute).unwrap()).unwrap(),
        execute
    );
    assert_eq!(
        borsh::from_slice::<GuestOutput>(&borsh::to_vec(&apply).unwrap()).unwrap(),
        apply
    );
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
    let output = PlanOutput::new(empty_input())
        .try_with_block_validity_window(10_u64..100)
        .unwrap();
    assert_eq!(output.block_validity_window.start(), Some(10));
    assert_eq!(output.block_validity_window.end(), Some(100));
}

#[test]
fn program_output_with_block_validity_window_range_from() {
    let output = PlanOutput::new(empty_input()).with_block_validity_window(10_u64..);
    assert_eq!(output.block_validity_window.start(), Some(10));
    assert_eq!(output.block_validity_window.end(), None);
}

#[test]
fn program_output_with_block_validity_window_range_to() {
    let output = PlanOutput::new(empty_input()).with_block_validity_window(..100_u64);
    assert_eq!(output.block_validity_window.start(), None);
    assert_eq!(output.block_validity_window.end(), Some(100));
}

#[test]
fn program_output_try_with_block_validity_window_empty_range_fails() {
    let result = PlanOutput::new(empty_input()).try_with_block_validity_window(5_u64..5);
    assert!(result.is_err());
}

// ---- validation tests ----

fn output_of(evaluator: AccountId, post_data: Option<ShardData>) -> ApplyOutput {
    ApplyOutput {
        input: ApplyInput {
            self_account_id: evaluator,
            selector: ProgramShardSelector::new(AccountId::new([7; 32]), evaluator),
            pre_data: ShardData::empty(),
            effect_data: Vec::new(),
        },
        post_data,
    }
}

#[test]
fn a_data_write_on_a_shard_the_executing_program_does_not_own_is_rejected() {
    let executing_account_id = AccountId::new([2; 32]);
    let account_id = AccountId::new([7; 32]);
    let mut output = output_of(
        executing_account_id,
        Some(b"record".to_vec().try_into().unwrap()),
    );
    output.input.selector.program_account_id = AccountId::new([1; 32]);

    let expected = output.input.clone();
    let result = validate_apply_output(&expected, &output);

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
    let output = output_of(
        AccountId::new([2; 32]),
        Some(b"record".to_vec().try_into().unwrap()),
    );

    assert!(validate_apply_output(&output.input.clone(), &output).is_ok());
}

#[test]
fn a_guest_cannot_write_the_native_balance_shard() {
    let account_id = AccountId::new([7; 32]);
    let mut output = output_of(
        AccountId::new([2; 32]),
        Some(crate::native_token::encode_balance(50)),
    );
    output.input.selector.program_account_id = crate::native_token::NATIVE_TOKEN_PROGRAM_ID;

    let expected = output.input.clone();
    let result = validate_apply_output(&expected, &output);

    assert!(matches!(
        result,
        Err(ExecutionValidationError::ForeignShardWrite { account_id: id, .. }) if id == account_id
    ));
}

#[test]
fn two_shard_selectors_of_one_account_in_a_call_are_accepted() {
    let account_id = AccountId::new([7; 32]);
    let accounts = [
        AccountMeta::new(account_id, true, AccountId::new([2; 32])),
        AccountMeta::native_balance(account_id, true),
    ];

    assert!(plan_of(&accounts, Vec::new()).is_ok());
}

#[test]
fn a_repeated_shard_selector_in_a_call_is_rejected() {
    let account = AccountMeta::new(AccountId::new([7; 32]), true, AccountId::new([2; 32]));

    assert!(matches!(
        plan_of(&[account.clone(), account], Vec::new()),
        Err(ExecutionValidationError::AccountShardSelectorsNotUnique)
    ));
}

#[test]
fn several_effects_may_name_one_input_handle_but_no_other_selector() {
    let account = AccountMeta::new(AccountId::new([7; 32]), true, AccountId::new([2; 32]));
    let effect = ShardEffect::new(&account, &7_u8);
    let foreign = ShardEffect {
        selector: ProgramShardSelector::native_balance(AccountId::new([7; 32])),
        data: Vec::new(),
    };

    assert!(plan_of(std::slice::from_ref(&account), vec![effect.clone(), effect]).is_ok());
    assert!(matches!(
        plan_of(std::slice::from_ref(&account), vec![foreign]),
        Err(ExecutionValidationError::EffectOutsideInputs { .. })
    ));
}

#[test]
fn apply_output_keeps_the_pre_shard_and_writes_only_the_selected_one() {
    let program = AccountId::new([2; 32]);
    let other = AccountId::new([3; 32]);
    let held: ShardData = b"held".to_vec().try_into().unwrap();
    let untouched: ShardData = b"untouched".to_vec().try_into().unwrap();
    let mut account = Account::default()
        .with_shard(program, held.clone())
        .with_shard(other, untouched.clone());

    account.data.apply_output(&output_of(program, None));

    assert_eq!(account.data.shard(program), &held);

    let written: ShardData = b"new".to_vec().try_into().unwrap();
    account
        .data
        .apply_output(&output_of(program, Some(written.clone())));

    assert_eq!(account.data.shard(program), &written);
    assert_eq!(account.data.shard(other), &untouched);
}

#[test]
fn a_plan_records_its_input_echo_and_every_obligation() {
    let account = AccountMeta::new(AccountId::new([7; 32]), true, AccountId::new([2; 32]));
    let input = PlanInput {
        self_account_id: AccountId::new([2; 32]),
        caller_account_id: Some(AccountId::new([9; 32])),
        accounts: vec![
            account.clone(),
            AccountMeta::native_balance(AccountId::new([7; 32]), false),
        ],
        instruction_data: vec![7],
    };
    let mut plan = Plan::new(&input);

    plan.effect(&account, &b"guard".to_vec());
    plan.effect(&account, &b"write".to_vec());
    plan.block_window(10_u64..);

    assert_eq!(plan.output.input, input);
    assert_eq!(plan.output.block_validity_window.start(), Some(10));
    assert_eq!(
        plan.output.effects,
        vec![
            ShardEffect::new(&account, &b"guard".to_vec()),
            ShardEffect::new(&account, &b"write".to_vec()),
        ]
    );
}

#[test]
#[should_panic(expected = "names the shard of")]
fn a_plan_refuses_an_effect_on_a_shard_its_program_does_not_own() {
    let foreign = AccountMeta::new(AccountId::new([7; 32]), true, AccountId::new([3; 32]));
    let input = PlanInput {
        self_account_id: AccountId::new([2; 32]),
        caller_account_id: None,
        accounts: vec![foreign.clone()],
        instruction_data: Vec::new(),
    };
    let mut plan = Plan::new(&input);

    plan.effect(&foreign, &b"write".to_vec());
}

#[test]
fn an_inspection_selects_the_shard_of_its_declared_owner() {
    let balance = AccountMeta::native_balance(AccountId::new([7; 32]), false);
    let input = PlanInput {
        self_account_id: AccountId::new([2; 32]),
        caller_account_id: None,
        accounts: vec![balance.clone()],
        instruction_data: Vec::new(),
    };
    let mut plan = Plan::new(&input);

    plan.inspect(
        &balance,
        crate::native_token::NATIVE_TOKEN_PROGRAM_ID,
        &b"guard".to_vec(),
    );

    assert_eq!(
        plan.output.effects,
        vec![ShardEffect::new(&balance, &b"guard".to_vec())]
    );
}

#[test]
#[should_panic(expected = "names the shard of")]
fn an_inspection_refuses_a_row_its_declared_owner_does_not_own() {
    // The caller chose the row: it names another program's shard where the guard is declared
    // on the native balance.
    let row = AccountMeta::new(AccountId::new([7; 32]), false, AccountId::new([3; 32]));
    let input = PlanInput {
        self_account_id: AccountId::new([2; 32]),
        caller_account_id: None,
        accounts: vec![row.clone()],
        instruction_data: Vec::new(),
    };
    let mut plan = Plan::new(&input);

    plan.inspect(
        &row,
        crate::native_token::NATIVE_TOKEN_PROGRAM_ID,
        &b"guard".to_vec(),
    );
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
    let program_shard: ShardData = header.to_bytes().try_into().unwrap();
    let segment_shard: ShardData = segment.to_bytes().try_into().unwrap();
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

    let deleted = ShardData::empty();
    let deleted_header = |id| (id == program_account).then_some(&deleted);
    assert_eq!(get_program_via(program_account, deleted_header), None);
}

// ---- AccountId::for_private_pda tests ----

/// Pins `AccountId::for_private_pda` against a hardcoded expected output for a specific
/// `(program_id, seed, npk, identifier)` tuple. Any change to `PRIVATE_PDA_PREFIX`, byte
/// ordering, or the underlying hash breaks this test.
#[test]
fn for_private_pda_matches_pinned_value() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let identifier = Identifier::new([u8::MAX; 32]);
    let expected = AccountId::new([
        188, 37, 183, 176, 226, 199, 53, 66, 190, 178, 237, 19, 231, 11, 203, 112, 68, 22, 164, 23,
        49, 187, 19, 207, 190, 52, 66, 80, 94, 84, 125, 167,
    ]);
    let actual = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, identifier);
    assert_eq!(actual, expected);
}

/// Two groups with different viewing keys at the same (program, seed) get different addresses.
#[test]
fn for_private_pda_differs_for_different_npk() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk_a = NullifierPublicKey([3; 32]);
    let npk_b = NullifierPublicKey([4; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(
            &program_id,
            &seed,
            &npk_a,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
        AccountId::for_private_pda(
            &program_id,
            &seed,
            &npk_b,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
    );
}

/// Different seeds produce different addresses, even with the same program and npk.
#[test]
fn for_private_pda_differs_for_different_seed() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed_a = PdaSeed::new([2; 32]);
    let seed_b = PdaSeed::new([5; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(
            &program_id,
            &seed_a,
            &npk,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
        AccountId::for_private_pda(
            &program_id,
            &seed_b,
            &npk,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
    );
}

/// Different programs produce different addresses, even with the same seed and npk.
#[test]
fn for_private_pda_differs_for_different_program_id() {
    let program_id_a = AccountId::from_builtin_program([1; 8]);
    let program_id_b = AccountId::from_builtin_program([9; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(
            &program_id_a,
            &seed,
            &npk,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
        AccountId::for_private_pda(
            &program_id_b,
            &seed,
            &npk,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
    );
}

/// Different identifiers produce different addresses for the same `(program_id, seed, npk)`,
/// confirming that each `(program_id, seed, npk)` tuple controls a family of 2^256 addresses.
#[test]
fn for_private_pda_differs_for_different_identifier() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, Identifier::ZERO),
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, Identifier::new([1; 32])),
    );
    assert_ne!(
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk, Identifier::ZERO),
        AccountId::for_private_pda(
            &program_id,
            &seed,
            &npk,
            &vpk,
            Identifier::new([u8::MAX; 32])
        ),
    );
}

/// A private PDA at the same (program, seed) has a different address than a public PDA,
/// because the private formula uses a different prefix and includes npk.
#[test]
fn for_private_pda_differs_from_public_pda() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let private_id = AccountId::for_private_pda(
        &program_id,
        &seed,
        &npk,
        &vpk,
        Identifier::new([u8::MAX; 32]),
    );
    let public_id = AccountId::for_public_pda(&program_id, &seed);
    assert_ne!(private_id, public_id);
}

/// Pins `AccountId::for_shadow_program` against a hardcoded expected output for a specific
/// `image_id`.
#[test]
fn for_shadow_program_matches_pinned_value() {
    let image_id: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
    let expected = AccountId::new([
        174, 205, 130, 154, 106, 227, 163, 213, 46, 71, 49, 245, 199, 22, 203, 205, 13, 109, 236,
        148, 159, 162, 140, 162, 209, 40, 88, 0, 109, 131, 184, 45,
    ]);
    assert_eq!(AccountId::for_shadow_program(&image_id), expected);
}

// ---- AccountId::for_immutable_mirror tests ----

#[test]
fn for_immutable_mirror_matches_pinned_value() {
    let header_account_id = AccountId::from_builtin_program([1; 8]);
    let expected = AccountId::new([
        116, 27, 253, 19, 65, 119, 18, 71, 79, 6, 124, 144, 48, 90, 98, 120, 12, 117, 132, 161,
        100, 22, 44, 64, 106, 111, 10, 129, 4, 211, 48, 244,
    ]);
    assert_eq!(AccountId::for_immutable_mirror(header_account_id), expected);
}

#[test]
fn for_immutable_mirror_differs_for_different_header() {
    let header_a = AccountId::from_builtin_program([1; 8]);
    let header_b = AccountId::from_builtin_program([9; 8]);
    assert_ne!(
        AccountId::for_immutable_mirror(header_a),
        AccountId::for_immutable_mirror(header_b),
    );
}

#[cfg(feature = "host")]
#[test]
fn private_account_kind_header_round_trips() {
    let regular = PrivateAccountKind::Regular(Identifier::new([42; 32]));
    let pda = PrivateAccountKind::Pda {
        account_id: AccountId::new([1; 32]),
        seed: PdaSeed::new([2_u8; 32]),
        identifier: Identifier::new([u8::MAX; 32]),
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
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let identifier = Identifier::new([77; 32]);

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
fn account_id_from_builtin_program_reinterprets_words_as_le_bytes() {
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
    assert_eq!(
        AccountId::from_builtin_program(program_id).value(),
        &expected
    );
}

#[test]
fn a_foreign_shard_may_be_inspected_and_kept() {
    let mut output = output_of(AccountId::new([9; 32]), None);
    output.input.selector.program_account_id = AccountId::new([2; 32]);
    output.input.pre_data = b"record".to_vec().try_into().unwrap();

    assert!(validate_apply_output(&output.input.clone(), &output).is_ok());
}

#[test]
fn an_apply_that_echoes_another_input_is_rejected_before_ownership_is_judged() {
    // The echo decides both who owns the shard and where the write lands, so an apply that
    // renames itself the native token program would otherwise mint into the balance shard while
    // passing the ownership check on its own forged pair.
    let scheduled = output_of(AccountId::new([2; 32]), None).input;

    let mut forged = output_of(
        crate::native_token::NATIVE_TOKEN_PROGRAM_ID,
        Some(crate::native_token::encode_balance(1_000_000)),
    );
    forged.input.selector.program_account_id = crate::native_token::NATIVE_TOKEN_PROGRAM_ID;

    assert!(matches!(
        validate_apply_output(&scheduled, &forged),
        Err(ExecutionValidationError::ApplyInputMismatch { .. })
    ));
}

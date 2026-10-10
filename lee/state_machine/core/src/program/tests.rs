use super::*;

fn receive_input() -> ReceiveInput {
    let receiver = Actor::native_balance(AccountId::default());
    ReceiveInput {
        receiver,
        from: None,
        is_authorized: false,
        pre_state: ActorState::empty(),
        message: Vec::new(),
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
fn validity_windows_hold_and_intersect_in_both_dimensions() {
    let windows =
        |blocks: std::ops::Range<u64>, timestamps: std::ops::Range<u64>| ValidityWindows {
            blocks: blocks.try_into().unwrap(),
            timestamps: timestamps.try_into().unwrap(),
        };
    let both = windows(1..10, 1..10);

    assert!(both.is_valid_at(9, 9));
    assert!(!both.is_valid_at(10, 9));
    assert!(!both.is_valid_at(9, 10));
    assert_eq!(
        both.intersect(windows(5..20, 1..5)),
        Ok(windows(5..10, 1..5))
    );
    assert_eq!(both.intersect(windows(10..20, 1..10)), Err(InvalidWindow));
    assert_eq!(both.intersect(windows(1..10, 10..20)), Err(InvalidWindow));
}

#[test]
fn response_try_with_block_validity_window_range() {
    let transition = Response::keep_state()
        .try_block_window(10_u64..100)
        .unwrap()
        .into_transition(receive_input());
    assert_eq!(transition.response.validity.blocks.start(), Some(10));
    assert_eq!(transition.response.validity.blocks.end(), Some(100));
}

#[test]
fn response_with_block_validity_window_range_from() {
    let transition = Response::keep_state()
        .block_window(10_u64..)
        .into_transition(receive_input());
    assert_eq!(transition.response.validity.blocks.start(), Some(10));
    assert_eq!(transition.response.validity.blocks.end(), None);
}

#[test]
fn response_with_block_validity_window_range_to() {
    let transition = Response::keep_state()
        .block_window(..100_u64)
        .into_transition(receive_input());
    assert_eq!(transition.response.validity.blocks.start(), None);
    assert_eq!(transition.response.validity.blocks.end(), Some(100));
}

#[test]
fn response_try_with_block_validity_window_empty_range_fails() {
    let result = Response::keep_state().try_block_window(5_u64..5);
    assert!(result.is_err());
}

#[test]
fn get_program_via_reads_the_loader_actor_state() {
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
    let program_actor_state: ActorState = header.to_bytes().into();
    let segment_actor_state: ActorState = segment.to_bytes().into();
    let lookup = |id| {
        if id == program_account {
            Some(&program_actor_state)
        } else if id == segment_account {
            Some(&segment_actor_state)
        } else {
            None
        }
    };
    assert_eq!(
        get_program_via(program_account, lookup),
        Some(([7; 8], vec![1, 2, 3]))
    );

    let deleted = ActorState::empty();
    let deleted_header = |id| (id == program_account).then_some(&deleted);
    assert_eq!(get_program_via(program_account, deleted_header), None);
}

#[test]
fn blinded_account_id_matches_pinned_value() {
    let expected = AccountId::new([
        148, 161, 160, 119, 29, 201, 192, 211, 184, 174, 163, 247, 46, 96, 251, 199, 214, 114, 33,
        129, 131, 146, 3, 170, 91, 106, 6, 196, 179, 204, 6, 31,
    ]);
    assert_eq!(AccountId::new([1; 32]).blinded(&[2; 32]), expected);
}

#[test]
fn a_zero_factor_still_blinds_the_account() {
    let account_id = AccountId::new([1; 32]);
    assert_ne!(account_id.blinded(&[0; 32]), account_id);
}

// ---- AccountId::for_private_pda tests ----

/// Pins `AccountId::for_private_pda` against a hardcoded expected output for a specific
/// `(program_id, seed, npk, vpk)` tuple. Any change to `PRIVATE_PDA_PREFIX`, byte
/// ordering, or the underlying hash breaks this test.
#[test]
fn for_private_pda_matches_pinned_value() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
    let expected = AccountId::new([
        223, 164, 202, 230, 71, 5, 245, 251, 123, 188, 61, 38, 169, 97, 86, 120, 212, 228, 23, 167,
        86, 215, 250, 1, 163, 54, 188, 71, 1, 216, 182, 174,
    ]);
    let actual = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk);
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
        AccountId::for_private_pda(&program_id, &seed, &npk_a, &vpk),
        AccountId::for_private_pda(&program_id, &seed, &npk_b, &vpk),
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
        AccountId::for_private_pda(&program_id, &seed_a, &npk, &vpk),
        AccountId::for_private_pda(&program_id, &seed_b, &npk, &vpk),
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
        AccountId::for_private_pda(&program_id_a, &seed, &npk, &vpk),
        AccountId::for_private_pda(&program_id_b, &seed, &npk, &vpk),
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
    let private_id = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk);
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
    let regular = PrivateAccountKind::Regular;
    let pda = PrivateAccountKind::Pda {
        account_id: AccountId::new([1; 32]),
        seed: PdaSeed::new([2_u8; 32]),
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
fn a_private_account_kind_header_has_a_pinned_layout() {
    let mut pda = [0; PrivateAccountKind::HEADER_LEN];
    pda[0] = 1;
    pda[1..33].fill(1);
    pda[33..].fill(2);

    assert_eq!(PrivateAccountKind::HEADER_LEN, 65);
    assert_eq!(PrivateAccountKind::Regular.to_header_bytes(), [0; 65]);
    assert_eq!(
        PrivateAccountKind::Pda {
            account_id: AccountId::new([1; 32]),
            seed: PdaSeed::new([2; 32]),
        }
        .to_header_bytes(),
        pda
    );
}

#[test]
fn for_private_account_dispatches_correctly() {
    let program_id = AccountId::from_builtin_program([1; 8]);
    let seed = PdaSeed::new([2; 32]);
    let npk = NullifierPublicKey([3; 32]);
    let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);

    assert_eq!(
        AccountId::for_private_account(&npk, &vpk, &PrivateAccountKind::Regular),
        AccountId::for_regular_private_account(&npk, &vpk),
    );
    assert_eq!(
        AccountId::for_private_account(
            &npk,
            &vpk,
            &PrivateAccountKind::Pda {
                account_id: program_id,
                seed,
            }
        ),
        AccountId::for_private_pda(&program_id, &seed, &npk, &vpk),
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
fn a_transition_journal_frame_has_a_pinned_layout() {
    let receiver = Actor::new(AccountId::new([1; 32]), AccountId::new([2; 32]));
    let transition = Transition {
        input: ReceiveInput {
            receiver,
            from: None,
            is_authorized: true,
            pre_state: ActorState::from(b"ab".to_vec()),
            message: b"m".to_vec(),
        },
        response: Response {
            post_state: Some(ActorState::from(b"xyz".to_vec())),
            calls: vec![Call {
                to: Actor::new(AccountId::new([3; 32]), AccountId::new([4; 32])),
                message: b"q".to_vec(),
                pda_seeds: BTreeSet::from([PdaSeed::new([9; 32])]),
            }],
            casts: Vec::new(),
            events: Vec::new(),
            validity: ValidityWindows::new_unbounded(),
        },
    };

    let expected: Vec<u8> = [
        &[206, 0, 0, 0][..], // frame length: the 206 bytes below
        &[1; 32],            // input.receiver.account_id
        &[2; 32],            // input.receiver.program_account_id
        &[0],                // input.from: None
        &[1],                // input.is_authorized
        &[2, 0, 0, 0],       // input.pre_state
        b"ab",
        &[1, 0, 0, 0], // input.message
        b"m",
        &[1], // post_state: Some
        &[3, 0, 0, 0],
        b"xyz",
        &[1, 0, 0, 0], // calls: one call
        &[3; 32],      // to
        &[4; 32],
        &[1, 0, 0, 0], // message
        b"q",
        &[1, 0, 0, 0], // pda_seeds: one seed
        &[9; 32],
        &[0, 0, 0, 0], // casts: none
        &[0, 0, 0, 0], // events: none
        &[0, 0],       // validity.blocks: from None, to None
        &[0, 0],       // validity.timestamps: from None, to None
    ]
    .concat();

    assert_eq!(crate::to_borsh_frame(&transition), expected);
}

use super::*;

#[test]
fn circuit_fails_if_visibility_masks_have_incorrect_lenght() {
    let program = crate::test_methods::simple_balance_transfer();
    let public_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        AccountId::new([0; 32]),
    );
    let public_account_2 =
        AccountWithMetadata::new(Account::default(), true, AccountId::new([1; 32]));

    // Single account_identity entry for a circuit execution with two pre_state accounts.
    let result = execute_and_prove(
        vec![public_account_1, public_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_fails_if_invalid_auth_keys_are_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        Account::default(),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    // Setting the recipient nsk to authorize the sender.
    // This should be set to the sender private account in a normal circumstance.
    // A regular update derives npk from nsk and asserts equality with
    // `pre_state.account_id`, so a mismatched nsk fails that check.
    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: recipient_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_balance_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        // Non default balance
        Account::single(program.id(), 1, Data::default(), Nonce::default()),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_a_foreign_slot_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        // A slot held by another program: still not a default pre-state
        Account::single(
            [0, 1, 2, 3, 4, 5, 6, 7],
            1,
            Data::default(),
            Nonce::default(),
        ),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_data_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        // Non default data
        Account::single(
            program.id(),
            0,
            b"hola mundo".to_vec().try_into().unwrap(),
            Nonce::default(),
        ),
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_nonce_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        Account {
            // Non default nonce
            nonce: Nonce(0xdead_beef),
            ..Account::default()
        },
        true,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_is_provided_with_default_values_but_marked_as_unauthorized()
 {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let private_account_2 = AccountWithMetadata::new(
        Account::default(),
        // This should be set to true in normal circumstances
        false,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (0, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// Happy path for a private PDA. The circuit reads the npk for that `pre_state` from the
/// witness at the `pre_state`'s position, derives `AccountId` via
/// `AccountId::for_private_pda(authority_program_id, seed, npk, vpk, identifier)`, and asserts
/// it equals the `pre_state`'s `account_id`. The equality binds the supplied npk to the
/// `account_id`.
#[test]
fn private_pda_with_matching_binding_succeeds() {
    let program = crate::test_methods::simple_balance_transfer();
    let authority_id = crate::test_methods::noop().id();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);

    let account_id = AccountId::for_private_pda(&authority_id, &seed, &npk, &keys.vpk(), u128::MAX);
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(0_u128).unwrap(),
        vec![init_pda_witness(&keys, u128::MAX, (authority_id, seed))],
        &program.into(),
    );

    let (output, _proof) = result.expect("a private PDA bound by its witness should succeed");
    assert_eq!(output.private_actions.len(), 1);
    assert!(output.public_actions.is_empty());
}

/// An npk is supplied that does not match the `pre_state`'s `account_id` under
/// `AccountId::for_private_pda(authority, seed, npk, vpk, identifier)`. The binding equality
/// check rejects.
#[test]
fn private_pda_npk_mismatch_fails() {
    // `keys_a` produces the `pre_state`'s `account_id` (the registered pair), `keys_b` is
    // the mismatched pair supplied in the witness for that pre_state.
    let program = crate::test_methods::simple_balance_transfer();
    let authority_id = crate::test_methods::noop().id();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let npk_a = keys_a.npk();
    let seed = PdaSeed::new([42; 32]);

    // `account_id` is derived from `npk_a`, but `npk_b` is supplied for this pre_state.
    // `AccountId::for_private_pda(authority, seed, npk_b, ..) != account_id`, so the binding
    // check in the circuit must reject.
    let account_id =
        AccountId::for_private_pda(&authority_id, &seed, &npk_a, &keys_a.vpk(), u128::MAX);
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(0_u128).unwrap(),
        vec![init_pda_witness(&keys_b, u128::MAX, (authority_id, seed))],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_accounts_can_only_be_initialized_once() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);

    let sender_private_account = Account::single(
        crate::test_methods::simple_balance_transfer().id(),
        100,
        Data::default(),
        sender_nonce,
    );
    let recipient_keys = test_private_account_keys_2();

    let mut state = V03State::new().with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;
    let balance_to_move_2 = 30;

    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        balance_to_move,
        &state,
    );

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let sender_private_account = Account::single(
        crate::test_methods::simple_balance_transfer().id(),
        100,
        Data::default(),
        sender_nonce,
    );

    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        balance_to_move_2,
        &state,
    );

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(matches!(result, Err(LeeError::InvalidInput(_))));
    let LeeError::InvalidInput(error_message) = result.err().unwrap() else {
        panic!("Incorrect message error");
    };
    let expected_error_message = "Nullifier already seen".to_owned();
    assert_eq!(error_message, expected_error_message);
}

#[test]
fn circuit_should_fail_if_there_are_repeated_ids() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let private_account_1 = AccountWithMetadata::new(
        Account::single(program.id(), 100, Data::default(), Nonce::default()),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account_1.clone(), private_account_1],
        Program::serialize_instruction(100_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (1, vec![]),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: (1, vec![]),
                },
            }),
        ],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_authorized_uninitialized_account() {
    let mut state = V03State::new().with_test_programs();

    // Set up keys for the authorized private account
    let private_keys = test_private_account_keys_1();

    // Create an authorized private account with default values (new account being initialized)
    let authorized_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&private_keys.npk(), &private_keys.vpk(), 0),
    );

    let program = crate::test_methods::simple_balance_transfer();

    // Set up parameters for the new account

    let instruction: u128 = 0;

    // Execute and prove the circuit with the authorized account but no commitment proof
    let (output, proof) = execute_and_prove(
        vec![authorized_account],
        Program::serialize_instruction(instruction).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: private_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(private_keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey::from(&private_keys.nsk()),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    // Create message from circuit output
    let message = Message::from_circuit_output(vec![], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[]);

    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(result.is_ok());

    let account_id =
        AccountId::for_regular_private_account(&private_keys.npk(), &private_keys.vpk(), 0);
    let nullifier = Nullifier::for_account_initialization(&account_id);
    assert!(state.private_state.1.contains(&nullifier));
}

#[test]
fn two_private_pda_family_members_receive_and_spend() {
    let funder_keys = test_public_account_keys_1();
    let alice_keys = test_private_account_keys_1();
    let alice_npk = alice_keys.npk();

    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let simple_transfer_id = simple_transfer.id();
    let transfer_program: ProgramWithDependencies = simple_transfer.into();
    let authority_id = crate::test_methods::noop().id();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    let funder_id = funder_keys.account_id();
    let alice_pda_0_id =
        AccountId::for_private_pda(&authority_id, &seed, &alice_npk, &alice_keys.vpk(), 0);
    let alice_pda_1_id =
        AccountId::for_private_pda(&authority_id, &seed, &alice_npk, &alice_keys.vpk(), 1);
    let recipient_id = test_public_account_keys_2().account_id();
    let recipient_signing_key = test_public_account_keys_2().signing_key;

    let mut state =
        V03State::new().with_public_accounts(public_state_from_balances(&[(funder_id, 500)]));

    let alice_pda_0_account = Account::single(
        simple_transfer_id,
        amount,
        Data::default(),
        Nonce::private_account_nonce_init(&alice_pda_0_id),
    );
    let alice_pda_1_account = Account::single(
        simple_transfer_id,
        amount,
        Data::default(),
        Nonce::private_account_nonce_init(&alice_pda_1_id),
    );

    // Fund alice_pda_0 via simple_balance_transfer directly.
    {
        let funder_account = state.get_account_by_id(funder_id);
        let funder_nonce = funder_account.nonce;
        let (output, proof) = execute_and_prove(
            vec![
                AccountWithMetadata::new(funder_account, true, funder_id),
                AccountWithMetadata::new(Account::default(), false, alice_pda_0_id),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Public,
                init_pda_witness(&alice_keys, 0, (authority_id, seed)),
            ],
            &transfer_program,
        )
        .unwrap();
        let message = Message::from_circuit_output(vec![funder_nonce], output);
        let witness_set = WitnessSet::for_message(&message, proof, &[&funder_keys.signing_key]);
        state
            .transition_from_privacy_preserving_transaction(
                &PrivacyPreservingTransaction::new(message, witness_set),
                1,
                0,
            )
            .unwrap();
    }

    // Fund alice_pda_1 the same way with identifier 1.
    {
        let funder_account = state.get_account_by_id(funder_id);
        let funder_nonce = funder_account.nonce;
        let (output, proof) = execute_and_prove(
            vec![
                AccountWithMetadata::new(funder_account, true, funder_id),
                AccountWithMetadata::new(Account::default(), false, alice_pda_1_id),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Public,
                init_pda_witness(&alice_keys, 1, (authority_id, seed)),
            ],
            &transfer_program,
        )
        .unwrap();
        let message = Message::from_circuit_output(vec![funder_nonce], output);
        let witness_set = WitnessSet::for_message(&message, proof, &[&funder_keys.signing_key]);
        state
            .transition_from_privacy_preserving_transaction(
                &PrivacyPreservingTransaction::new(message, witness_set),
                2,
                0,
            )
            .unwrap();
    }

    let commitment_pda_0 = Commitment::new(&alice_pda_0_id, &alice_pda_0_account);
    let commitment_pda_1 = Commitment::new(&alice_pda_1_id, &alice_pda_1_account);

    assert!(state.get_proof_for_commitment(&commitment_pda_0).is_some());
    assert!(state.get_proof_for_commitment(&commitment_pda_1).is_some());

    // Alice spends alice_pda_0 into the public recipient.
    {
        let recipient_account = state.get_account_by_id(recipient_id);
        let (output, proof) = execute_and_prove(
            vec![
                AccountWithMetadata::new(alice_pda_0_account, false, alice_pda_0_id),
                AccountWithMetadata::new(recipient_account, true, recipient_id),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Private(PrivateWitness {
                    vpk: alice_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 0,
                    kind: WitnessKind::Pda {
                        binding: (authority_id, seed),
                    },
                    nullifier: NullifierWitness::Update {
                        view_tag: 0,
                        nsk: alice_keys.nsk(),
                        membership_proof: state
                            .get_proof_for_commitment(&commitment_pda_0)
                            .expect("pda_0 must be in state"),
                    },
                }),
                InputAccountIdentity::Public,
            ],
            &transfer_program,
        )
        .unwrap();
        let message = Message::from_circuit_output(vec![Nonce(0)], output);
        let witness_set = WitnessSet::for_message(&message, proof, &[&recipient_signing_key]);
        state
            .transition_from_privacy_preserving_transaction(
                &PrivacyPreservingTransaction::new(message, witness_set),
                3,
                0,
            )
            .unwrap();
    }

    // Alice spends alice_pda_1 into the same public recipient.
    {
        let recipient_account = state.get_account_by_id(recipient_id);
        let (output, proof) = execute_and_prove(
            vec![
                AccountWithMetadata::new(alice_pda_1_account.clone(), false, alice_pda_1_id),
                AccountWithMetadata::new(recipient_account, false, recipient_id),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Private(PrivateWitness {
                    vpk: alice_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 1,
                    kind: WitnessKind::Pda {
                        binding: (authority_id, seed),
                    },
                    nullifier: NullifierWitness::Update {
                        view_tag: 0,
                        nsk: alice_keys.nsk(),
                        membership_proof: state
                            .get_proof_for_commitment(&commitment_pda_1)
                            .expect("pda_1 must be in state"),
                    },
                }),
                InputAccountIdentity::Public,
            ],
            &transfer_program,
        )
        .unwrap();
        let message = Message::from_circuit_output(vec![], output);
        let witness_set = WitnessSet::for_message(&message, proof, &[]);
        state
            .transition_from_privacy_preserving_transaction(
                &PrivacyPreservingTransaction::new(message, witness_set),
                4,
                0,
            )
            .unwrap();
    }

    assert_eq!(
        state
            .get_account_by_id(recipient_id)
            .balance(simple_transfer_id),
        2 * amount
    );

    // Re-fund alice_pda_1 top-level via simple_transfer using a private-PDA update.
    let alice_pda_1_account_after_spend = Account::single(
        simple_transfer_id,
        0,
        Data::default(),
        alice_pda_1_account
            .nonce
            .private_account_nonce_increment(&alice_keys.nsk()),
    );
    let commitment_pda_1_after_spend =
        Commitment::new(&alice_pda_1_id, &alice_pda_1_account_after_spend);
    {
        let recipient_account = state.get_account_by_id(recipient_id);
        let recipient_nonce = recipient_account.nonce;
        let (output, proof) = execute_and_prove(
            vec![
                AccountWithMetadata::new(recipient_account, true, recipient_id),
                AccountWithMetadata::new(alice_pda_1_account_after_spend, false, alice_pda_1_id),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::Private(PrivateWitness {
                    vpk: alice_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 1,
                    kind: WitnessKind::Pda {
                        binding: (authority_id, seed),
                    },
                    nullifier: NullifierWitness::Update {
                        view_tag: 0,
                        nsk: alice_keys.nsk(),
                        membership_proof: state
                            .get_proof_for_commitment(&commitment_pda_1_after_spend)
                            .expect("pda_1 after spend must be in state"),
                    },
                }),
            ],
            &transfer_program,
        )
        .unwrap();
        let message = Message::from_circuit_output(vec![recipient_nonce], output);
        let witness_set = WitnessSet::for_message(&message, proof, &[&recipient_signing_key]);
        state
            .transition_from_privacy_preserving_transaction(
                &PrivacyPreservingTransaction::new(message, witness_set),
                5,
                0,
            )
            .unwrap();
    }

    assert_eq!(
        state
            .get_account_by_id(recipient_id)
            .balance(simple_transfer_id),
        amount
    );
}

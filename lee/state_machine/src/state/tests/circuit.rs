use lee_core::account::Input;

use super::*;

/// Builds a private-PDA pre state together with the witness that proves its identity, both
/// from the same `(authority_program_id, seed)` binding, so the address and the witness can
/// never disagree.
fn bound_private_pda(
    binding: (ProgramId, PdaSeed),
    keys: &TestPrivateKeys,
    identifier: Identifier,
    is_authorized: bool,
) -> (Input, InputAccountIdentity) {
    let (authority_program_id, seed) = binding;
    let account_id = AccountId::for_private_pda(
        &authority_program_id,
        &seed,
        &keys.npk(),
        &keys.vpk(),
        identifier,
    );
    (
        Input::at(
            SlotRef::new(account_id, authority_program_id),
            is_authorized,
            &Account::default(),
        ),
        init_pda_witness(keys, identifier, binding),
    )
}

#[test]
fn circuit_fails_if_visibility_masks_have_incorrect_lenght() {
    let program = crate::test_methods::simple_balance_transfer();
    let public_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let public_account_1 = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &public_account_1_acc,
    );
    let public_account_2 = Input::at(
        SlotRef::new(AccountId::new([1; 32]), program.id()),
        true,
        &Account::default(),
    );

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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = Account::default();
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_2_acc,
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
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = // Non default balance
        Account::single(program.id(), 1, Data::default(), Nonce::default());
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_2_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = // A slot held by another program: still not a default pre-state
        Account::single(
            [0, 1, 2, 3, 4, 5, 6, 7],
            1,
            Data::default(),
            Nonce::default(),
        );
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_2_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = // Non default data
        Account::single(
            program.id(),
            0,
            b"hola mundo".to_vec().try_into().unwrap(),
            Nonce::default(),
        );
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_2_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = Account {
        // Non default nonce
        nonce: Nonce(0xdead_beef),
        ..Account::default()
    };
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_2_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );
    let private_account_2_acc = Account::default();
    let private_account_2 = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            program.id(),
        ), // This should be set to true in normal circumstances
        false,
        &private_account_2_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1, private_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc,
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
                account: private_account_2_acc,
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
    let pre_state_acc = Account::default();
    let pre_state = Input::at(
        SlotRef::new(account_id, authority_id),
        false,
        &pre_state_acc,
    );

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
    let pre_state_acc = Account::default();
    let pre_state = Input::at(
        SlotRef::new(account_id, authority_id),
        false,
        &pre_state_acc,
    );

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(0_u128).unwrap(),
        vec![init_pda_witness(&keys_b, u128::MAX, (authority_id, seed))],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// Happy path for the caller-seeds authorization of a private PDA. The witness binds the PDA
/// to `(delegator, seed)`, and the delegator chains to a callee delegating that same seed via
/// `ChainedCall.pda_seeds`. In the callee's step the `pre_state`'s authorization is established
/// via the private derivation
/// `AccountId::for_private_pda(delegator, seed, npk, vpk, identifier) == pre.account_id`.
#[test]
fn caller_pda_seeds_authorize_private_pda_for_callee() {
    let delegator = crate::test_methods::private_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, witness) = bound_private_pda((delegator.id(), seed), &keys, u128::MAX, false);

    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(delegator, [(callee_id, callee)].into());

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((seed, callee_id)).unwrap(),
        vec![witness],
        &program_with_deps,
    );

    let (output, _proof) =
        result.expect("caller-seeds authorization of private PDA should succeed");
    assert_eq!(output.private_actions.len(), 1);
}

/// The delegator chains with a different seed than the one the witness binds. In the callee
/// step the private derivation under the delegated seed does not reproduce the address, so no
/// proven source supports the `true` the delegator wrote, and the consistency assertion rejects.
#[test]
fn caller_pda_seeds_with_wrong_seed_rejects_private_pda_for_callee() {
    let delegator = crate::test_methods::private_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let bound_seed = PdaSeed::new([77; 32]);
    let wrong_delegated_seed = PdaSeed::new([88; 32]);

    let (pre_state, witness) =
        bound_private_pda((delegator.id(), bound_seed), &keys, u128::MAX, false);

    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(delegator, [(callee_id, callee)].into());

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((wrong_delegated_seed, callee_id)).unwrap(),
        vec![witness],
        &program_with_deps,
    );

    assert_circuit_proving_failure(&result, "Inconsistent authorization for account");
}

fn sibling_declaring_delegated_pda(pda_is_authorized: bool) -> Result<(), LeeError> {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let sibling = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, witness) = bound_private_pda((delegator.id(), seed), &keys, 0, false);

    let callee_id = callee.id();
    let sibling_id = sibling.id();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((
            seed,
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            Some((sibling_id, Some(pda_is_authorized))),
        ))
        .unwrap(),
        vec![witness],
        &program_with_deps,
    )
    .map(|_| ())
}

#[test]
fn delegated_pda_is_not_authorized_in_sibling_call() {
    let result = sibling_declaring_delegated_pda(true);

    assert_circuit_proving_failure(&result, "Inconsistent authorization for account");
}

#[test]
fn sibling_call_may_declare_delegated_pda_unauthorized() {
    sibling_declaring_delegated_pda(false)
        .expect("a sibling declaring the delegated PDA unauthorized must be accepted");
}

#[test]
fn delegated_pda_stays_authorized_in_delegated_subtree() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, witness) = bound_private_pda((delegator.id(), seed), &keys, 0, false);

    let forwarder_id = forwarder.id();
    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        [(forwarder_id, forwarder), (callee_id, callee)].into(),
    );
    let no_sibling: Option<(ProgramId, Option<bool>)> = None;

    execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((
            seed,
            forwarder_id,
            Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                true,
            ))
            .unwrap(),
            no_sibling,
        ))
        .unwrap(),
        vec![witness],
        &program_with_deps,
    )
    .expect("a callee that forwards without re-delegating must keep the PDA authorized");
}

#[test]
fn holder_authorization_survives_across_sibling_calls() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let sibling = crate::test_methods::noop();
    let pda_keys = test_private_account_keys_1();
    let holder_keys = test_private_account_keys_2();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, pda_witness) = bound_private_pda((delegator.id(), seed), &pda_keys, 0, false);
    let holder_id =
        AccountId::for_regular_private_account(&holder_keys.npk(), &holder_keys.vpk(), 0);
    let holder_pre_state_acc = Account::default();
    let holder_pre_state = Input::at(
        SlotRef::new(holder_id, delegator.id()),
        true,
        &holder_pre_state_acc,
    );

    let callee_id = callee.id();
    let sibling_id = sibling.id();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    execute_and_prove(
        vec![pre_state, holder_pre_state],
        Program::serialize_instruction((
            seed,
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            Some((sibling_id, None::<bool>)),
        ))
        .unwrap(),
        vec![
            pda_witness,
            InputAccountIdentity::Private(PrivateWitness {
                account: holder_pre_state_acc,
                vpk: holder_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(holder_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: holder_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program_with_deps,
    )
    .expect("an account authorized by its own credential stays authorized in a sibling call");
}

#[test]
fn inherited_scope_passes_through_intermediate_calls() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, witness) = bound_private_pda((delegator.id(), seed), &keys, 0, false);

    let forwarder_id = forwarder.id();
    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        [(forwarder_id, forwarder), (callee_id, callee)].into(),
    );
    let no_sibling: Option<(ProgramId, Option<bool>)> = None;
    let forward_through_undeclaring_call = Program::serialize_instruction((
        forwarder_id,
        Program::serialize_instruction((
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            false,
        ))
        .unwrap(),
        true,
    ))
    .unwrap();

    execute_and_prove(vec![pre_state], Program::serialize_instruction((
            seed,
            forwarder_id,
            forward_through_undeclaring_call,
            no_sibling,
        ))
        .unwrap(), vec![witness], &program_with_deps)
    .expect(
        "an account authorized in an ancestor's output stays authorized below a call that never mentions it",
    );
}

fn undeclaring_private_delegation(
    delegated: bool,
    declare_authorized: bool,
    callee: Program,
) -> Result<(), LeeError> {
    let delegator = crate::test_methods::undeclaring_pda_delegator();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);

    let (pre_state, witness) = bound_private_pda((delegator.id(), seed), &keys, 0, false);

    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(delegator, [(callee_id, callee)].into());

    execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((
            delegated.then_some(seed),
            declare_authorized,
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            None::<ProgramId>,
        ))
        .unwrap(),
        vec![witness],
        &program_with_deps,
    )
    .map(|_| ())
}

#[test]
fn delegated_private_pda_first_seen_in_callee_is_authorized() {
    undeclaring_private_delegation(true, true, crate::test_methods::auth_asserting_noop())
        .expect("a caller's pda_seeds must authorize a private PDA it delegates at first sight");
}

#[test]
fn undelegated_private_pda_in_a_callee_may_not_declare_authorization() {
    let result =
        undeclaring_private_delegation(false, true, crate::test_methods::auth_asserting_noop());

    assert_circuit_proving_failure(&result, "Inconsistent authorization for private PDA");
}

#[test]
fn granted_private_pda_may_not_be_declared_unauthorized_at_first_sight() {
    // `noop` tolerates unauthorized pre_states during host-side execution, so the only
    // rejector left is the first-sight consistency assert on the granted edge.
    let result = undeclaring_private_delegation(true, false, crate::test_methods::noop());

    assert_circuit_proving_failure(&result, "Inconsistent authorization for private PDA");
}

fn undeclaring_public_delegation(
    account_id: AccountId,
    delegated_seed: Option<PdaSeed>,
    declare_authorized: bool,
    callee: Program,
    with_sibling: bool,
) -> Result<lee_core::PrivacyPreservingCircuitOutput, LeeError> {
    let delegator = crate::test_methods::undeclaring_pda_delegator();
    let sibling = crate::test_methods::noop();

    let pre_state_acc = Account::default();
    let pre_state = Input::at(
        SlotRef::new(account_id, delegator.id()),
        false,
        &pre_state_acc,
    );

    let callee_id = callee.id();
    let sibling_id = sibling.id();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction((
            delegated_seed,
            declare_authorized,
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            with_sibling.then_some(sibling_id),
        ))
        .unwrap(),
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .map(|(output, _proof)| output)
}

#[test]
fn delegated_public_pda_first_seen_in_callee_is_authorized() {
    let seed = PdaSeed::new([77; 32]);
    let delegator_id = crate::test_methods::undeclaring_pda_delegator().id();
    let pda = AccountId::for_public_pda(&delegator_id, &seed);

    let output = undeclaring_public_delegation(
        pda,
        Some(seed),
        true,
        crate::test_methods::auth_asserting_noop(),
        false,
    )
    .expect("a caller's pda_seeds must authorize a public PDA it delegates at first sight");

    // The callee ran with the PDA authorized (auth_asserting_noop did not panic), while
    // the journal exports the credential view: a seed grant is not a signer-backed claim.
    assert_eq!(output.public_actions.len(), 1);
    assert_eq!(output.public_actions[0].pre.account_id, pda);
    assert!(!output.public_actions[0].pre.is_authorized);
}

#[test]
fn granted_public_pda_may_not_be_declared_unauthorized_at_first_sight() {
    let seed = PdaSeed::new([77; 32]);
    let delegator_id = crate::test_methods::undeclaring_pda_delegator().id();
    let pda = AccountId::for_public_pda(&delegator_id, &seed);

    // `noop` tolerates unauthorized pre_states, so the only rejector left is the
    // first-sight consistency assert on the granted edge.
    let result =
        undeclaring_public_delegation(pda, Some(seed), false, crate::test_methods::noop(), false);

    assert_circuit_proving_failure(
        &result,
        "Caller-seeded public PDA must be declared authorized at first sight",
    );
}

#[test]
fn public_pda_first_sight_grant_does_not_extend_to_sibling_calls() {
    let seed = PdaSeed::new([77; 32]);
    let delegator_id = crate::test_methods::undeclaring_pda_delegator().id();
    let pda = AccountId::for_public_pda(&delegator_id, &seed);

    let result = undeclaring_public_delegation(
        pda,
        Some(seed),
        true,
        crate::test_methods::auth_asserting_noop(),
        true,
    );

    assert_circuit_proving_failure(&result, "Inconsistent authorization for account");
}

#[test]
fn public_account_first_sight_authorization_is_exported_to_the_journal() {
    let seed = PdaSeed::new([77; 32]);

    let output = undeclaring_public_delegation(
        AccountId::new([9; 32]),
        Some(seed),
        true,
        crate::test_methods::auth_asserting_noop(),
        false,
    )
    .expect("a first-sight authorization claim on a plain public account must prove");

    assert!(output.public_actions[0].pre.is_authorized);
}

#[test]
fn wrong_seed_public_pda_first_sight_is_exported_as_credential_claim() {
    let seed = PdaSeed::new([77; 32]);
    let wrong_seed = PdaSeed::new([88; 32]);
    let delegator_id = crate::test_methods::undeclaring_pda_delegator().id();
    let pda = AccountId::for_public_pda(&delegator_id, &seed);

    let output = undeclaring_public_delegation(
        pda,
        Some(wrong_seed),
        true,
        crate::test_methods::auth_asserting_noop(),
        false,
    )
    .expect("an unmatched seed must fall back to the credential-claim path");

    // In-circuit this is indistinguishable from a signer's claim; the exported `true`
    // is what the verifier audits (and rejects — the id is not a signer).
    assert!(output.public_actions[0].pre.is_authorized);
}

/// Exploit-scenario pin. A single `(program_id, seed)` pair derives a family of `AccountId`s,
/// one private PDA per distinct npk. Without the tx-wide family-binding check one delegated
/// seed could authorize several members of that family in the same call and let the callee mix
/// balances across them. Here the delegator hands `seed` to a callee that sees both members:
/// the first grant records `(delegator, seed) -> PDA_a`, the second tries to record
/// `(delegator, seed) -> PDA_b`, and the binding check rejects.
#[test]
fn two_private_pdas_granted_under_same_seed_are_rejected() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed = PdaSeed::new([55; 32]);

    let binding = (delegator.id(), seed);
    let (pre_a, witness_a) = bound_private_pda(binding, &keys_a, 0, false);
    let (pre_b, witness_b) = bound_private_pda(binding, &keys_b, 0, true);

    let callee_id = callee.id();
    let program_with_deps = ProgramWithDependencies::new(delegator, [(callee_id, callee)].into());

    let result = execute_and_prove(
        vec![pre_a, pre_b],
        Program::serialize_instruction((
            seed,
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            None::<(ProgramId, Option<bool>)>,
        ))
        .unwrap(),
        vec![witness_a, witness_b],
        &program_with_deps,
    );

    assert_circuit_proving_failure(
        &result,
        "Two different accounts resolved under the same (program, seed) in one transaction",
    );
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
    let private_account_1_acc =
        Account::single(program.id(), 100, Data::default(), Nonce::default());
    let private_account_1 = Input::at(
        SlotRef::new(
            (&sender_keys.npk(), &sender_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &private_account_1_acc,
    );

    let result = execute_and_prove(
        vec![private_account_1.clone(), private_account_1],
        Program::serialize_instruction(100_u128).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                account: private_account_1_acc.clone(),
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
                account: private_account_1_acc,
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
    let authorized_account_acc = Account::default();
    let program = crate::test_methods::simple_balance_transfer();
    let authorized_account = Input::at(
        SlotRef::new(
            (&private_keys.npk(), &private_keys.vpk(), 0).into(),
            program.id(),
        ),
        true,
        &authorized_account_acc,
    );

    // Set up parameters for the new account

    let instruction: u128 = 0;

    // Execute and prove the circuit with the authorized account but no commitment proof
    let (output, proof) = execute_and_prove(
        vec![authorized_account],
        Program::serialize_instruction(instruction).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            account: authorized_account_acc,
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

    let mut state = V03State::new().with_public_account_balances(native(), [(funder_id, 500)]);

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
                Input::at(
                    SlotRef::new(funder_id, simple_transfer_id),
                    true,
                    &funder_account,
                ),
                Input::at(
                    SlotRef::new(alice_pda_0_id, simple_transfer_id),
                    false,
                    &Account::default(),
                ),
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
                Input::at(
                    SlotRef::new(funder_id, simple_transfer_id),
                    true,
                    &funder_account,
                ),
                Input::at(
                    SlotRef::new(alice_pda_1_id, simple_transfer_id),
                    false,
                    &Account::default(),
                ),
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
                Input::at(
                    SlotRef::new(alice_pda_0_id, simple_transfer_id),
                    false,
                    &alice_pda_0_account,
                ),
                Input::at(
                    SlotRef::new(recipient_id, simple_transfer_id),
                    true,
                    &recipient_account,
                ),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Private(PrivateWitness {
                    account: alice_pda_0_account.clone(),
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
                Input::at(
                    SlotRef::new(alice_pda_1_id, simple_transfer_id),
                    false,
                    &alice_pda_1_account,
                ),
                Input::at(
                    SlotRef::new(recipient_id, simple_transfer_id),
                    false,
                    &recipient_account,
                ),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Private(PrivateWitness {
                    account: alice_pda_1_account.clone(),
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
                Input::at(
                    SlotRef::new(recipient_id, simple_transfer_id),
                    true,
                    &recipient_account,
                ),
                Input::at(
                    SlotRef::new(alice_pda_1_id, simple_transfer_id),
                    false,
                    &alice_pda_1_account_after_spend,
                ),
            ],
            Program::serialize_instruction(amount).unwrap(),
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::Private(PrivateWitness {
                    account: alice_pda_1_account_after_spend.clone(),
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

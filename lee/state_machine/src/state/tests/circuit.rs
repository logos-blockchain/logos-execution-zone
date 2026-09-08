use lee_core::{EncryptionScheme, EphemeralSecretKey, SharedSecretKey};

use super::*;

#[test]
fn an_unused_private_witness_is_rejected() {
    let program = crate::test_methods::noop();
    let touched_keys = test_private_account_keys_1();
    let unused_keys = test_private_account_keys_2();
    let touched_id =
        AccountId::for_regular_private_account(&touched_keys.npk(), &touched_keys.vpk(), 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(touched_id)],
            private_witnesses: vec![
                init_witness(&touched_keys, 0, Account::default()),
                init_witness(&unused_keys, 0, Account::default()),
            ],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(
        matches!(
            &result,
            Err(LeeError::CircuitProvingError(msg))
                if msg.contains("must be touched by the execution")
        ),
        "refused for the wrong reason: {:?}",
        result.err()
    );
}

#[test]
fn a_private_account_keeps_a_stranger_shard_through_an_own_shard_write() {
    let program = crate::test_methods::data_changer();
    let program_id: AccountId = program.id().into();
    let stranger = AccountId::new([9; 32]);
    let stranger_data: Data = b"stranger".to_vec().try_into().unwrap();
    let written = vec![7; 4];
    let keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
    let pre_account = Account {
        nonce: Nonce(9),
        ..Account::funded(42).with_shard(stranger, stranger_data.clone())
    };
    let state = V03State::new().with_private_account(&keys, &pre_account);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&account_id, &pre_account))
        .expect("the account's commitment must be in state");

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, program_id)],
            private_witnesses: vec![update_witness(
                &keys,
                0,
                pre_account.clone(),
                membership_proof,
            )],
            instruction_data: Program::serialize_instruction(written.clone()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .unwrap();

    assert_eq!(output.private_actions.len(), 1);
    let new_nonce = pre_account
        .nonce
        .private_account_nonce_increment(&keys.nsk());
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &new_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let (_kind, post) = EncryptionScheme::decrypt(
        &output.private_actions[0].encrypted_post_state.ciphertext,
        &shared_secret,
        &output.private_actions[0].nullifier,
    )
    .unwrap();

    assert_eq!(
        post,
        Account {
            nonce: new_nonce,
            ..Account::funded(42)
                .with_shard(stranger, stranger_data)
                .with_shard(program_id, written.try_into().unwrap())
        }
    );
}

#[test]
fn circuit_fails_if_invalid_auth_keys_are_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                PrivateWitness {
                    account: Account::funded(100),
                    vpk: sender_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 0,
                    kind: WitnessKind::Regular {
                        ask: Some(recipient_keys.ask),
                    },
                    nullifier: NullifierWitness::Update {
                        view_tag: 0,
                        nsk: sender_keys.nsk(),
                        membership_proof: (0, vec![]),
                    },
                },
                init_witness(&recipient_keys, 0, Account::default()),
            ],
            instruction_data: Program::serialize_instruction(10_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_balance_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                update_witness(&sender_keys, 0, Account::funded(100), (0, vec![])),
                init_witness(&recipient_keys, 0, Account::funded(1)),
            ],
            instruction_data: Program::serialize_instruction(10_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_data_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                update_witness(&sender_keys, 0, Account::funded(100), (0, vec![])),
                init_witness(
                    &recipient_keys,
                    0,
                    Account::default().with_shard(
                        AccountId::new([9; 32]),
                        b"hola mundo".to_vec().try_into().unwrap(),
                    ),
                ),
            ],
            instruction_data: Program::serialize_instruction(10_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn circuit_should_fail_if_new_private_account_with_non_default_nonce_is_provided() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                update_witness(&sender_keys, 0, Account::funded(100), (0, vec![])),
                init_witness(
                    &recipient_keys,
                    0,
                    Account {
                        nonce: Nonce(0xdead_beef),
                        ..Account::default()
                    },
                ),
            ],
            instruction_data: Program::serialize_instruction(10_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// Happy path for a private PDA at top level: the witness carries `binding: (authority, seed)`,
/// so the circuit derives `AccountId::for_private_pda(authority, seed, npk, vpk, identifier)` and
/// treats exactly that address as the witness's own.
#[test]
fn private_pda_witness_binding_succeeds() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);

    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &keys.npk(),
        &keys.vpk(),
        u128::MAX,
    );

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                u128::MAX,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .expect("witness-bound private PDA should succeed");

    assert_eq!(output.private_actions.len(), 1);
    assert!(output.public_actions.is_empty());
}

#[test]
fn private_pda_npk_mismatch_fails() {
    let program = crate::test_methods::noop();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed = PdaSeed::new([42; 32]);

    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &keys_a.npk(),
        &keys_a.vpk(),
        u128::MAX,
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys_b,
                u128::MAX,
                (program.id().into(), seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// Happy path for the caller-seeds authorization of a private PDA. The delegator echoes the
/// private PDA, then chains to a callee delegating the account's own seed via
/// `ChainedCall.pda_seeds`. In the callee's step, the `pre_state`'s authorization is
/// established via the private derivation
/// `AccountId::for_private_pda(delegator, seed, npk) == pre.account_id`.
#[test]
fn caller_pda_seeds_authorize_private_pda_for_callee() {
    let delegator = crate::test_methods::private_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id =
        AccountId::for_private_pda(&delegator_id, &seed, &keys.npk(), &keys.vpk(), u128::MAX);

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(delegator, delegator_id, [(callee_id, callee)].into());

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                u128::MAX,
                (delegator_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((seed, callee_id)).unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("caller-seeds authorization of private PDA should succeed");

    assert_eq!(output.private_actions.len(), 1);
}

/// The delegator chains with a different seed than the one the account was derived under. In
/// the callee step, neither public nor private caller-seeds authorization matches, so the PDA
/// stays unauthorized and the callee's own guest rejects it.
#[test]
fn caller_pda_seeds_with_wrong_seed_rejects_private_pda_for_callee() {
    let delegator = crate::test_methods::private_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let derivation_seed = PdaSeed::new([77; 32]);
    let wrong_delegated_seed = PdaSeed::new([88; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_private_pda(
        &delegator_id,
        &derivation_seed,
        &keys.npk(),
        &keys.vpk(),
        u128::MAX,
    );

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(delegator, delegator_id, [(callee_id, callee)].into());

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                u128::MAX,
                (delegator_id, derivation_seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((wrong_delegated_seed, callee_id))
                .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

#[test]
fn a_private_pda_first_seen_in_a_callee_is_bound_by_its_witness_and_granted_by_the_caller() {
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let forwarder_id: AccountId = forwarder.id().into();

    let account_id = AccountId::for_private_pda(&forwarder_id, &seed, &keys.npk(), &keys.vpk(), 0);

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into());

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (forwarder_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                false,
                vec![seed],
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("a caller's pda_seeds must authorize a private PDA it delegates at first sight");
}

/// Checks authorization and the public journal for a PDA first seen in a callee.
#[test]
fn delegated_public_pda_first_seen_in_callee_is_authorized() {
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let seed = PdaSeed::new([77; 32]);
    let forwarder_id: AccountId = forwarder.id().into();

    let account_id = AccountId::for_public_pda(&forwarder_id, &seed);

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into());

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            instruction_data: Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                false,
                vec![seed],
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("a caller's pda_seeds must authorize a public PDA it delegates at first sight");

    // The callee ran with the PDA authorized (auth_asserting_noop did not panic), while the
    // journal exports the credential view: a seed grant is not a signer-backed claim.
    assert_eq!(output.public_actions.len(), 1);
    assert_eq!(output.public_actions[0].account_id, account_id);
    assert!(!output.public_actions[0].is_authorized);
}

/// A delegated seed that doesn't match the account's real derivation can't be distinguished
/// in-circuit from an ordinary non-PDA account — it falls back to the same first-sight,
/// credential-backed path.
#[test]
fn wrong_seed_public_pda_first_sight_is_exported_as_credential_claim() {
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let seed = PdaSeed::new([77; 32]);
    let wrong_seed = PdaSeed::new([88; 32]);
    let forwarder_id: AccountId = forwarder.id().into();

    let account_id = AccountId::for_public_pda(&forwarder_id, &seed);

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into());

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            signers: [account_id].into(),
            instruction_data: Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                false,
                vec![wrong_seed],
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("an unmatched seed must fall back to the credential-claim path");

    // In-circuit this is indistinguishable from a signer's claim; the exported `true` is
    // what the verifier audits (and rejects, since the id is not actually a signer's).
    assert!(output.public_actions[0].is_authorized);
}

#[test]
fn delegated_pda_is_not_authorized_in_sibling_call() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let sibling = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_private_pda(&delegator_id, &seed, &keys.npk(), &keys.vpk(), 0);

    let callee_id: AccountId = callee.id().into();
    let sibling_id: AccountId = sibling.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    // `callee` gets the PDA's account_id *and* the matching `pda_seeds` — real delegation.
    // `sibling` gets only the account_id (via `include_pda = true`), no `pda_seeds` — it
    // sees `is_authorized == false` and panics on it inside its own guest execution.
    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (delegator_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((
                seed,
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                Some((sibling_id, true)),
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    );

    assert!(
        matches!(result, Err(LeeError::ProgramProveFailed(_))),
        "a sibling handed the PDA's account_id but no pda_seeds must not see it as authorized, \
         but got: {result:?}"
    );
}

#[test]
fn public_pda_first_sight_grant_does_not_extend_to_sibling_calls() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let sibling = crate::test_methods::auth_asserting_noop();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_public_pda(&delegator_id, &seed);

    let callee_id: AccountId = callee.id().into();
    let sibling_id: AccountId = sibling.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            instruction_data: Program::serialize_instruction((
                seed,
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                Some((sibling_id, true)),
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    );

    assert!(
        matches!(result, Err(LeeError::ProgramProveFailed(_))),
        "a sibling handed the public PDA's account_id but no pda_seeds must not see it as \
         authorized, but got: {result:?}"
    );
}

/// Positive mirror of `delegated_pda_is_not_authorized_in_sibling_call`: an unauthorized
/// sibling is only fatal if its own program demands authorization, unlike `noop` here.
#[test]
fn sibling_call_may_declare_delegated_pda_unauthorized() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let callee = crate::test_methods::auth_asserting_noop();
    let sibling = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_private_pda(&delegator_id, &seed, &keys.npk(), &keys.vpk(), 0);

    let callee_id: AccountId = callee.id().into();
    let sibling_id: AccountId = sibling.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (delegator_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((
                seed,
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                Some((sibling_id, true)),
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("a sibling declaring the delegated PDA unauthorized must be accepted");
}

#[test]
fn delegated_pda_stays_authorized_in_delegated_subtree() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_private_pda(&delegator_id, &seed, &keys.npk(), &keys.vpk(), 0);

    let forwarder_id: AccountId = forwarder.id().into();
    let callee_id: AccountId = callee.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(forwarder_id, forwarder), (callee_id, callee)].into(),
    );
    let no_sibling: Option<(ProgramId, bool)> = None;

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (delegator_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((
                seed,
                forwarder_id,
                Program::serialize_instruction((
                    callee_id,
                    Program::serialize_instruction(()).unwrap(),
                    true,
                    Vec::<PdaSeed>::new(),
                ))
                .unwrap(),
                no_sibling,
            ))
            .unwrap(),
            ..Default::default()
        },
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
    let delegator_id: AccountId = delegator.id().into();

    let account_id =
        AccountId::for_private_pda(&delegator_id, &seed, &pda_keys.npk(), &pda_keys.vpk(), 0);
    let holder_id =
        AccountId::for_regular_private_account(&holder_keys.npk(), &holder_keys.vpk(), 0);

    let callee_id: AccountId = callee.id().into();
    let sibling_id: AccountId = sibling.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(callee_id, callee), (sibling_id, sibling)].into(),
    );

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(account_id),
                ProgramShardSelector::balance_only(holder_id),
            ],
            private_witnesses: vec![
                init_pda_witness(&pda_keys, 0, (delegator_id, seed), Account::default()),
                init_witness(&holder_keys, 0, Account::default()),
            ],
            instruction_data: Program::serialize_instruction((
                seed,
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                Some((sibling_id, false)),
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("an account authorized by its own credential stays authorized in a sibling call");
}

#[test]
fn inherited_scope_passes_through_nested_intermediate_calls() {
    let delegator = crate::test_methods::selective_pda_delegator();
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([77; 32]);
    let delegator_id: AccountId = delegator.id().into();

    let account_id = AccountId::for_private_pda(&delegator_id, &seed, &keys.npk(), &keys.vpk(), 0);

    let forwarder_id: AccountId = forwarder.id().into();
    let callee_id: AccountId = callee.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator,
        delegator_id,
        [(forwarder_id, forwarder), (callee_id, callee)].into(),
    );
    let no_sibling: Option<(ProgramId, bool)> = None;
    let forward_through_nested_call = Program::serialize_instruction((
        forwarder_id,
        Program::serialize_instruction((
            callee_id,
            Program::serialize_instruction(()).unwrap(),
            true,
            Vec::<PdaSeed>::new(),
        ))
        .unwrap(),
        true,
        Vec::<PdaSeed>::new(),
    ))
    .unwrap();

    execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_pda_witness(
                &keys,
                0,
                (delegator_id, seed),
                Account::default(),
            )],
            instruction_data: Program::serialize_instruction((
                seed,
                forwarder_id,
                forward_through_nested_call,
                no_sibling,
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect("an account authorized in an ancestor's output stays authorized two calls below it");
}

/// The circuit tracks accounts by `AccountId` across the whole call tree, not per-step: a
/// *private* account handed to an intermediate call but never declared in that step's own
/// `state_diffs` is still correctly resolved — including its private-witness
/// (npk/vpk/nullifier) binding — when a later chained call references it by id.
#[test]
fn unused_private_pre_state_is_pulled_by_a_later_chained_call() {
    let forwarder = crate::test_methods::non_delegating_forwarder();
    let callee = crate::test_methods::noop();
    let callee_id: AccountId = callee.id().into();
    let forwarder_id: AccountId = forwarder.id().into();

    let keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);

    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into());

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(&keys, 0, Account::default())],
            instruction_data: Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(()).unwrap(),
                // declare_pre_states: forwarder's own output never mentions this account.
                false,
                Vec::<PdaSeed>::new(),
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    )
    .expect(
        "a private account never declared in an intermediate step's own pre/post states is \
         still resolved, witness binding included, when a later chained call references it by \
         id",
    );

    assert!(proof.is_valid_for(&output));
}

/// Delegated PDA authorization survives reordered inputs and witnesses.
#[test]
fn top_level_reordering_through_a_passthrough_is_still_provable() {
    let forwarder = crate::test_methods::reorders_and_forwards();
    let callee = crate::test_methods::asserts_specific_account_authorized();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed_a = PdaSeed::new([1; 32]);
    let seed_b = PdaSeed::new([2; 32]);

    let forwarder_id: AccountId = forwarder.id().into();
    let account_a =
        AccountId::for_private_pda(&forwarder_id, &seed_a, &keys_a.npk(), &keys_a.vpk(), 0);
    let account_b =
        AccountId::for_private_pda(&forwarder_id, &seed_b, &keys_b.npk(), &keys_b.vpk(), 0);

    let callee_id: AccountId = callee.id().into();
    let program_with_deps =
        ProgramWithDependencies::new(forwarder, forwarder_id, [(callee_id, callee)].into());

    // Delegate seed_b to the callee — the callee should be authorized for `account_b` alone,
    // and only asserts on `account_b`, ignoring `account_a` (which is genuinely unauthorized).
    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(account_a),
                ProgramShardSelector::balance_only(account_b),
            ],
            private_witnesses: vec![
                init_pda_witness(&keys_b, 0, (forwarder_id, seed_b), Account::default()),
                init_pda_witness(&keys_a, 0, (forwarder_id, seed_a), Account::default()),
            ],
            instruction_data: Program::serialize_instruction((
                callee_id,
                Program::serialize_instruction(account_b).unwrap(),
                vec![seed_b],
            ))
            .unwrap(),
            ..Default::default()
        },
        &program_with_deps,
    );

    result.expect(
        "a private PDA delegated through a reordering, non-reporting top-level program must \
         still be provable",
    );
}

/// Exploit-scenario pin. A single `(program_id, seed)` pair can derive a family of
/// `AccountId`s, one public PDA and one private PDA per distinct npk. Without the tx-wide
/// family-binding check, one transaction could bind `PDA_alice` (`alice_npk`) and
/// `PDA_bob` (`bob_npk`) under the same seed, and a later chained call could delegate both
/// to a callee via `pda_seeds: [S]` and mix balances across them. The binding check rejects
/// the setup here: after the first witness binding records `(program, seed) → PDA_alice`, the
/// second tries to record `(program, seed) → PDA_bob` and panics.
#[test]
fn two_private_pdas_bound_under_same_seed_are_rejected() {
    let program = crate::test_methods::noop();
    let program_id: AccountId = program.id().into();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed = PdaSeed::new([55; 32]);

    let account_a =
        AccountId::for_private_pda(&program_id, &seed, &keys_a.npk(), &keys_a.vpk(), u128::MAX);
    let account_b =
        AccountId::for_private_pda(&program_id, &seed, &keys_b.npk(), &keys_b.vpk(), u128::MAX);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(account_a),
                ProgramShardSelector::balance_only(account_b),
            ],
            private_witnesses: vec![
                init_pda_witness(&keys_a, u128::MAX, (program_id, seed), Account::default()),
                init_pda_witness(&keys_b, u128::MAX, (program_id, seed), Account::default()),
            ],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_accounts_can_only_be_initialized_once() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let recipient_keys = test_private_account_keys_2();

    let mut state = V03State::new().with_private_account(&sender_keys, &sender_private_account);
    state.insert_program(&crate::test_methods::simple_balance_transfer());

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

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };

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
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let witness = update_witness(&sender_keys, 0, Account::funded(100), (1, vec![]));

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(sender_id),
            ],
            private_witnesses: vec![witness.clone(), witness],
            instruction_data: Program::serialize_instruction(100_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_authorized_uninitialized_account() {
    let mut state = V03State::new().with_test_programs();

    // Set up keys for the authorized private account
    let private_keys = test_private_account_keys_1();
    let account_id =
        AccountId::for_regular_private_account(&private_keys.npk(), &private_keys.vpk(), 0);

    let program = crate::test_methods::simple_balance_transfer();

    // Execute and prove the circuit with the authorized account but no commitment proof
    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(&private_keys, 0, Account::default())],
            instruction_data: Program::serialize_instruction(0_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    )
    .unwrap();

    // Create message from circuit output
    let message = Message::from_circuit_output(vec![], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[]);

    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(result.is_ok());

    let nullifier = Nullifier::for_account_initialization(&account_id);
    assert!(state.private_state.1.contains(&nullifier));
}

#[test]
fn private_account_claimed_then_used_without_init_flag_should_fail() {
    let mut state = V03State::new().with_test_programs();

    // Set up keys for the private account
    let private_keys = test_private_account_keys_1();
    let account_id =
        AccountId::for_regular_private_account(&private_keys.npk(), &private_keys.vpk(), 0);

    let writer_program = crate::test_methods::data_changer();
    let writer_id: AccountId = writer_program.id().into();
    let written = vec![7; 4];

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, writer_id)],
            private_witnesses: vec![init_witness(&private_keys, 0, Account::default())],
            instruction_data: Program::serialize_instruction(written.clone()).unwrap(),
            ..Default::default()
        },
        &writer_program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    // The write should succeed
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 1, 0)
            .is_ok()
    );

    // Verify the account is now initialized (nullifier exists)
    let nullifier = Nullifier::for_account_initialization(&account_id);
    assert!(state.private_state.1.contains(&nullifier));

    let noop_program = crate::test_methods::noop();

    let res = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::balance_only(account_id)],
            private_witnesses: vec![init_witness(
                &private_keys,
                0,
                Account::default().with_shard(writer_id, written.try_into().unwrap()),
            )],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &noop_program.into(),
    );

    assert!(matches!(res, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn two_private_pda_family_members_receive_and_spend() {
    let funder_keys = test_public_account_keys_1();
    let alice_keys = test_private_account_keys_1();

    let proxy = crate::test_methods::pda_spend_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let proxy_id: AccountId = proxy.id().into();
    let simple_transfer_id: AccountId = simple_transfer.id().into();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    let spend_with_deps = ProgramWithDependencies::new(
        proxy.clone(),
        proxy_id,
        [(simple_transfer_id, simple_transfer.clone())].into(),
    );

    let funder_id = funder_keys.account_id();
    let alice_pda_0_id =
        AccountId::for_private_pda(&proxy_id, &seed, &alice_keys.npk(), &alice_keys.vpk(), 0);
    let alice_pda_1_id =
        AccountId::for_private_pda(&proxy_id, &seed, &alice_keys.npk(), &alice_keys.vpk(), 1);
    let recipient_id = test_public_account_keys_2().account_id();
    let recipient_signing_key = test_public_account_keys_2().signing_key;

    let mut state = V03State::new().with_public_account_balances([(funder_id, 500)]);
    state.insert_program(&simple_transfer);
    state.insert_program(&proxy);

    let alice_pda_0_account = Account {
        nonce: Nonce::private_account_nonce_init(&alice_pda_0_id),
        ..Account::funded(amount)
    };
    let alice_pda_1_account = Account {
        nonce: Nonce::private_account_nonce_init(&alice_pda_1_id),
        ..Account::funded(amount)
    };

    // Fund alice_pda_0 via a plain balance transfer directly.
    {
        let funder_account = state.get_account_by_id(funder_id);
        let funder_nonce = funder_account.nonce;
        let (output, proof) = execute_and_prove(
            ProvingInput {
                shard_selectors: vec![
                    ProgramShardSelector::balance_only(funder_id),
                    ProgramShardSelector::balance_only(alice_pda_0_id),
                ],
                signers: [funder_id].into(),
                public_accounts: [(funder_id, funder_account)].into(),
                private_witnesses: vec![init_pda_witness(
                    &alice_keys,
                    0,
                    (proxy_id, seed),
                    Account::default(),
                )],
                instruction_data: Program::serialize_instruction(amount).unwrap(),
                ..Default::default()
            },
            &simple_transfer.clone().into(),
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
            ProvingInput {
                shard_selectors: vec![
                    ProgramShardSelector::balance_only(funder_id),
                    ProgramShardSelector::balance_only(alice_pda_1_id),
                ],
                signers: [funder_id].into(),
                public_accounts: [(funder_id, funder_account)].into(),
                private_witnesses: vec![init_pda_witness(
                    &alice_keys,
                    1,
                    (proxy_id, seed),
                    Account::default(),
                )],
                instruction_data: Program::serialize_instruction(amount).unwrap(),
                ..Default::default()
            },
            &simple_transfer.into(),
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
            ProvingInput {
                shard_selectors: vec![
                    ProgramShardSelector::balance_only(alice_pda_0_id),
                    ProgramShardSelector::balance_only(recipient_id),
                ],
                signers: [recipient_id].into(),
                public_accounts: [(recipient_id, recipient_account)].into(),
                private_witnesses: vec![update_pda_witness(
                    &alice_keys,
                    0,
                    (proxy_id, seed),
                    alice_pda_0_account,
                    state
                        .get_proof_for_commitment(&commitment_pda_0)
                        .expect("pda_0 must be in state"),
                )],
                instruction_data: Program::serialize_instruction((
                    seed,
                    amount,
                    simple_transfer_id,
                ))
                .unwrap(),
                ..Default::default()
            },
            &spend_with_deps,
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
            ProvingInput {
                shard_selectors: vec![
                    ProgramShardSelector::balance_only(alice_pda_1_id),
                    ProgramShardSelector::balance_only(recipient_id),
                ],
                public_accounts: [(recipient_id, recipient_account)].into(),
                private_witnesses: vec![update_pda_witness(
                    &alice_keys,
                    1,
                    (proxy_id, seed),
                    alice_pda_1_account.clone(),
                    state
                        .get_proof_for_commitment(&commitment_pda_1)
                        .expect("pda_1 must be in state"),
                )],
                instruction_data: Program::serialize_instruction((
                    seed,
                    amount,
                    simple_transfer_id,
                ))
                .unwrap(),
                ..Default::default()
            },
            &spend_with_deps,
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
        state.get_account_by_id(recipient_id).data.balance,
        2 * amount
    );

    // Re-fund alice_pda_1 top-level via simple_transfer using a private-PDA update.
    let alice_pda_1_account_after_spend = Account {
        nonce: alice_pda_1_account
            .nonce
            .private_account_nonce_increment(&alice_keys.nsk()),
        ..Account::funded(0)
    };
    let commitment_pda_1_after_spend =
        Commitment::new(&alice_pda_1_id, &alice_pda_1_account_after_spend);
    {
        let recipient_account = state.get_account_by_id(recipient_id);
        let recipient_nonce = recipient_account.nonce;
        let (output, proof) = execute_and_prove(
            ProvingInput {
                shard_selectors: vec![
                    ProgramShardSelector::balance_only(recipient_id),
                    ProgramShardSelector::balance_only(alice_pda_1_id),
                ],
                signers: [recipient_id].into(),
                public_accounts: [(recipient_id, recipient_account)].into(),
                private_witnesses: vec![update_pda_witness(
                    &alice_keys,
                    1,
                    (proxy_id, seed),
                    alice_pda_1_account_after_spend,
                    state
                        .get_proof_for_commitment(&commitment_pda_1_after_spend)
                        .expect("pda_1 after spend must be in state"),
                )],
                instruction_data: Program::serialize_instruction(amount).unwrap(),
                ..Default::default()
            },
            &crate::test_methods::simple_balance_transfer().into(),
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

    assert_eq!(state.get_account_by_id(recipient_id).data.balance, amount);
}

/// Unauthorized balance decrease is refused.
#[test]
fn a_private_balance_decrease_without_the_credential_is_refused_in_the_circuit() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_account = Account::funded(100);
    let state = V03State::new().with_private_account(&sender_keys, &sender_account);
    let sender_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&sender_id, &sender_account))
        .expect("sender's commitment must be in state");

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender_id),
                ProgramShardSelector::balance_only(recipient_id),
            ],
            private_witnesses: vec![
                PrivateWitness {
                    account: sender_account,
                    vpk: sender_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 0,
                    kind: WitnessKind::Regular { ask: None },
                    nullifier: NullifierWitness::Update {
                        view_tag: 0,
                        nsk: sender_keys.nsk(),
                        membership_proof,
                    },
                },
                PrivateWitness {
                    account: Account::default(),
                    vpk: recipient_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: 0,
                    kind: WitnessKind::Regular { ask: None },
                    nullifier: NullifierWitness::Init {
                        npk: recipient_keys.npk(),
                        commitment_root: DUMMY_COMMITMENT_HASH,
                    },
                },
            ],
            instruction_data: Program::serialize_instruction(10_u128).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    let Err(err) = result else {
        panic!("the debit went through without the credential");
    };
    assert!(
        matches!(
            &err,
            LeeError::CircuitProvingError(msg)
                if msg.contains("Trying to decrease balance of unauthorized account")
        ),
        "refused for the wrong reason: {err:?}"
    );
}

/// Rejects a proof when an initial shard selector is missing from all program outputs.
#[test]
fn dropped_public_account_through_the_privacy_circuit_is_caught() {
    let program = crate::test_methods::dropped_account();

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(AccountId::new([1; 32])),
                ProgramShardSelector::balance_only(AccountId::new([2; 32])),
            ],
            instruction_data: Program::serialize_instruction(()).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(_))),
        "dropping account2 should prevent a valid proof, got {result:?}"
    );
}

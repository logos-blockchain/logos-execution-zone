use lee_core::{
    EncryptionScheme, Identifier, SharedSecretKey,
    execution_state::Output,
    program::{PrivateAccountKind, ProgramHeader, immutable_mirror_commitment},
};
use program_loader_core::Message as LoaderMessage;

use super::*;

const DELEGATED_SEED: PdaSeed = PdaSeed::new([77; 32]);

fn regular_id(keys: &TestPrivateKeys, identifier: Identifier) -> AccountId {
    AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier)
}

fn shadow_scripted() -> (AccountId, ProgramCatalog) {
    let program = crate::test_methods::scripted();
    let shadow_id = AccountId::for_shadow_program(&program.id());
    (
        shadow_id,
        ProgramCatalog::from([(shadow_id, program)]).with_shadow(shadow_id),
    )
}

fn authorized() -> Script {
    Script::default().authorized()
}

#[test]
fn a_private_account_keeps_a_stranger_shard_through_an_own_shard_write() {
    let program_id = scripted_id();
    let stranger = AccountId::new([9; 32]);
    let stranger_data: ActorState = b"stranger".to_vec().try_into().unwrap();
    let replaced: ActorState = b"replaced".to_vec().try_into().unwrap();
    let written = vec![7; 4];
    let keys = test_private_account_keys_1();
    let account_id = regular_id(&keys, Identifier::ZERO);
    let pre_account = Account {
        nonce: Nonce(9),
        ..Account::funded(42)
            .with_shard(stranger, stranger_data.clone())
            .with_shard(program_id, replaced)
    };
    let state = V03State::new().with_private_account(&keys, &pre_account);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&account_id, &pre_account))
        .expect("the account's commitment must be in state");

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![update_witness(
                &keys,
                Identifier::ZERO,
                pre_account.clone(),
                membership_proof,
            )],
            ..proving_input(root(
                Actor::new(account_id, program_id),
                &Script::write(written.clone()),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();

    let [action] = <[_; 1]>::try_from(output.private_actions).unwrap();
    let expected = Account {
        nonce: pre_account
            .nonce
            .private_account_nonce_increment(&keys.nsk()),
        ..Account::funded(42)
            .with_shard(stranger, stranger_data)
            .with_shard(program_id, written.try_into().unwrap())
    };
    let shared_secret =
        SharedSecretKey::decapsulate(&action.encrypted_post_state.epk, &keys.d, &keys.z)
            .expect("the emitted epk is a well-formed ML-KEM ciphertext");

    assert_eq!(
        EncryptionScheme::decrypt(
            &action.encrypted_post_state.ciphertext,
            &shared_secret,
            &action.nullifier,
        )
        .unwrap(),
        (
            PrivateAccountKind::Regular(Identifier::ZERO),
            expected.clone()
        )
    );
    assert_eq!(action.commitment, Commitment::new(&account_id, &expected));
}

#[test]
fn a_private_account_may_act_under_two_shards_in_one_transaction() {
    let program_id = scripted_id();
    let stranger = AccountId::new([9; 32]);
    let stranger_data: ActorState = b"stranger".to_vec().try_into().unwrap();
    let written = vec![7; 4];
    let amount: u128 = 30;
    let keys = test_private_account_keys_1();
    let sender_id = regular_id(&keys, Identifier::ZERO);
    let recipient = Actor::native_balance(AccountId::new([88; 32]));
    let pre_account = Account {
        nonce: Nonce(9),
        ..Account::funded(100).with_shard(stranger, stranger_data.clone())
    };
    let state = V03State::new().with_private_account(&keys, &pre_account);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&sender_id, &pre_account))
        .expect("the account's commitment must be in state");
    let credit = borsh::to_vec(&NativeMessage::Credit(amount)).unwrap();

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            declared: Declared::new(vec![recipient], []),
            private_witnesses: vec![update_witness(
                &keys,
                Identifier::ZERO,
                pre_account.clone(),
                membership_proof,
            )],
            ..proving_input(root(
                Actor::new(sender_id, program_id),
                &Script::write(written.clone()).send(Call::new(
                    Actor::native_balance(sender_id),
                    &transfer(recipient.account_id, amount),
                )),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();

    let [action] = <[_; 1]>::try_from(output.private_actions).unwrap();
    let expected = Account {
        nonce: pre_account
            .nonce
            .private_account_nonce_increment(&keys.nsk()),
        ..Account::funded(100 - amount)
            .with_shard(stranger, stranger_data)
            .with_shard(program_id, written.try_into().unwrap())
    };
    let shared_secret =
        SharedSecretKey::decapsulate(&action.encrypted_post_state.epk, &keys.d, &keys.z)
            .expect("the emitted epk is a well-formed ML-KEM ciphertext");

    assert_eq!(
        EncryptionScheme::decrypt(
            &action.encrypted_post_state.ciphertext,
            &shared_secret,
            &action.nullifier,
        )
        .unwrap(),
        (
            PrivateAccountKind::Regular(Identifier::ZERO),
            expected.clone()
        )
    );
    assert_eq!(action.commitment, Commitment::new(&sender_id, &expected));

    assert_eq!(
        output.boundary.outputs,
        vec![Output {
            to: recipient,
            message: credit,
            origin: Origin::Program(NATIVE_TOKEN_PROGRAM_ID),
            issuer: Some(NATIVE_TOKEN_PROGRAM_ID),
            grants: Vec::new(),
            pda_seeds: Vec::new(),
        }]
    );
}

#[test]
fn circuit_fails_if_invalid_auth_keys_are_provided() {
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_id = regular_id(&sender_keys, Identifier::ZERO);
    let recipient_id = regular_id(&recipient_keys, Identifier::ZERO);

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                PrivateWitness {
                    vpk: sender_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: Identifier::ZERO,
                    kind: WitnessKind::Regular {
                        ask: Some(recipient_keys.ask),
                    },
                    nullifier: NullifierWitness::Update {
                        account: Account::funded(100),
                        view_tag: 0,
                        nsk: sender_keys.nsk(),
                        membership_proof: (0, vec![]),
                    },
                },
                init_witness(&recipient_keys, Identifier::ZERO),
            ],
            ..proving_input(root(
                Actor::native_balance(sender_id),
                &transfer(recipient_id, 10),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::InvalidAuthorizationKey { account_id } if account_id == sender_id
    ));
}

/// Happy path for a private PDA at the root: the witness carries `binding: (authority, seed)`,
/// so the circuit derives `AccountId::for_private_pda(authority, seed, npk, vpk, identifier)` and
/// treats exactly that address as the witness's own.
#[test]
fn private_pda_witness_binding_succeeds() {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);

    let account_id = AccountId::for_private_pda(
        &scripted_id(),
        &seed,
        &keys.npk(),
        &keys.vpk(),
        Identifier::new([u8::MAX; 32]),
    );

    let (output, _proof) = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::new([u8::MAX; 32]),
                (scripted_id(), seed),
            )],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .expect("witness-bound private PDA should succeed");

    assert_eq!(output.private_actions.len(), 1);
    assert!(output.boundary.outputs.is_empty());
}

#[test]
fn private_pda_npk_mismatch_fails() {
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed = PdaSeed::new([42; 32]);

    let account_id = AccountId::for_private_pda(
        &scripted_id(),
        &seed,
        &keys_a.npk(),
        &keys_a.vpk(),
        Identifier::new([u8::MAX; 32]),
    );

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(
                &keys_b,
                Identifier::new([u8::MAX; 32]),
                (scripted_id(), seed),
            )],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &Script::default(),
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { actor } if actor.account_id == account_id
    ));
}

// The delegated PDA's actor under `program`.
fn delegated_pda(program: AccountId) -> Actor {
    let keys = test_private_account_keys_1();
    Actor::new(
        AccountId::for_private_pda(
            &scripted_id(),
            &DELEGATED_SEED,
            &keys.npk(),
            &keys.vpk(),
            Identifier::ZERO,
        ),
        program,
    )
}

// The `TWIN` actor of a regular private account holding its own credential.
fn credential_holder() -> Actor {
    Actor::new(
        regular_id(&test_private_account_keys_2(), Identifier::ZERO),
        TWIN,
    )
}

// The PDA's `scripted` actor is the root; with `holder`, a credential holder joins the
// transaction.
fn prove_delegation(
    script: &Script,
    holder: bool,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let mut private_witnesses = vec![init_pda_witness(
        &test_private_account_keys_1(),
        Identifier::ZERO,
        (scripted_id(), DELEGATED_SEED),
    )];
    if holder {
        private_witnesses.push(init_witness(
            &test_private_account_keys_2(),
            Identifier::ZERO,
        ));
    }

    execute_and_prove(
        ProvingInput {
            private_witnesses,
            ..proving_input(root(delegated_pda(scripted_id()), script))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
}

/// Happy path for the caller-seeds authorization of a private PDA. The delegator sends to the
/// PDA's callee actor with the account's own seed in `Call.pda_seeds`. In the callee's turn,
/// the actor's authorization is established via the private derivation
/// `AccountId::for_private_pda(delegator, seed, npk) == actor.account_id`.
#[test]
fn caller_pda_seeds_authorize_private_pda_for_callee() {
    let (output, _proof) = prove_delegation(
        &Script::default().send(
            Call::new(delegated_pda(TWIN), &authorized()).with_pda_seeds(vec![DELEGATED_SEED]),
        ),
        false,
    )
    .expect("caller-seeds authorization of private PDA should succeed");

    assert_eq!(output.private_actions.len(), 1);
}

/// The delegator sends a different seed than the one the account was derived under. In the
/// callee's turn, neither public nor private caller-seeds authorization matches, so the PDA stays
/// unauthorized and the callee's own guest rejects it.
#[test]
fn caller_pda_seeds_with_wrong_seed_rejects_private_pda_for_callee() {
    let wrong_delegated_seed = PdaSeed::new([88; 32]);

    let result = prove_delegation(
        &Script::default().send(
            Call::new(delegated_pda(TWIN), &authorized())
                .with_pda_seeds(vec![wrong_delegated_seed]),
        ),
        false,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
}

#[test]
fn delegated_pda_is_not_authorized_in_sibling_call() {
    // The first delivery carries the PDA's seed — real delegation. The sibling carries none, so
    // it sees `is_authorized == false` and panics on it inside its own guest execution.
    let result = prove_delegation(
        &Script::default()
            .send(
                Call::new(delegated_pda(TWIN), &authorized()).with_pda_seeds(vec![DELEGATED_SEED]),
            )
            .send(Call::new(delegated_pda(TWIN), &authorized())),
        false,
    );

    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
        "a sibling handed the PDA but no pda_seeds must not see it as authorized, but got: \
         {result:?}"
    );
}

/// Positive mirror of `delegated_pda_is_not_authorized_in_sibling_call`: an unauthorized
/// sibling is only fatal if its own script demands authorization.
#[test]
fn sibling_call_may_declare_delegated_pda_unauthorized() {
    prove_delegation(
        &Script::default()
            .send(
                Call::new(delegated_pda(TWIN), &authorized()).with_pda_seeds(vec![DELEGATED_SEED]),
            )
            .send(Call::new(delegated_pda(TWIN), &Script::default())),
        false,
    )
    .expect("a sibling declaring the delegated PDA unauthorized must be accepted");
}

#[test]
fn delegated_pda_stays_authorized_in_delegated_subtree() {
    let forward = Script::default().send(Call::new(delegated_pda(scripted_id()), &authorized()));

    prove_delegation(
        &Script::default()
            .send(Call::new(delegated_pda(TWIN), &forward).with_pda_seeds(vec![DELEGATED_SEED])),
        false,
    )
    .expect("a callee that forwards without re-delegating must keep the PDA authorized");
}

#[test]
fn holder_authorization_survives_across_sibling_calls() {
    prove_delegation(
        &Script::default()
            .send(
                Call::new(delegated_pda(TWIN), &authorized()).with_pda_seeds(vec![DELEGATED_SEED]),
            )
            .send(Call::new(credential_holder(), &authorized())),
        true,
    )
    .expect("an account authorized by its own credential stays authorized in a sibling call");
}

#[test]
fn inherited_scope_passes_through_nested_intermediate_calls() {
    let forward_through_nested_call = Script::default().send(Call::new(
        delegated_pda(scripted_id()),
        &Script::default().send(Call::new(delegated_pda(TWIN), &authorized())),
    ));

    prove_delegation(
        &Script::default().send(
            Call::new(delegated_pda(TWIN), &forward_through_nested_call)
                .with_pda_seeds(vec![DELEGATED_SEED]),
        ),
        false,
    )
    .expect("an account authorized in an ancestor's turn stays authorized two turns below it");
}

fn prove_public_outputs(
    script: &Script,
    public_actors: Vec<Actor>,
    signers: HashSet<AccountId>,
) -> (PrivacyPreservingCircuitOutput, Proof) {
    let keys = test_private_account_keys_1();
    // Assumes each public output delivers nothing back, without running it.
    execute_and_prove_assuming(
        ProvingInput {
            declared: Declared::new(public_actors, signers),
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(root(
                Actor::new(regular_id(&keys, Identifier::ZERO), scripted_id()),
                script,
            ))
        },
        vec![Vec::new(); script.sends.len()],
        &scripted_programs(),
    )
    .unwrap()
}

#[test]
fn a_delegated_public_pda_is_authorized_at_settlement_but_not_exported_as_a_grant() {
    let account_id = AccountId::for_public_pda(&scripted_id(), &DELEGATED_SEED);
    let callee = Actor::new(account_id, TWIN);

    let (output, proof) = prove_public_outputs(
        &Script::default()
            .send(Call::new(callee, &authorized()).with_pda_seeds(vec![DELEGATED_SEED])),
        vec![callee],
        HashSet::new(),
    );

    // The statement carries the seed, not a grant: a seed grant is not a signer-backed claim, so
    // settlement re-derives it.
    let [delegated] = <[_; 1]>::try_from(output.boundary.outputs.clone()).unwrap();
    assert_eq!(delegated.to, callee);
    assert!(delegated.grants.is_empty());
    assert_eq!(delegated.pda_seeds, vec![DELEGATED_SEED]);

    V03State::new()
        .with_test_programs()
        .transition_from_privacy_preserving_transaction(
            &private_tx((output, proof), vec![], &[]),
            1,
            0,
        )
        .expect("the seed must authorize the public PDA at settlement");
}

#[test]
fn a_wrong_seed_leaves_a_signer_on_its_credential() {
    let signer_keys = test_public_account_keys_1();
    let signer_id = signer_keys.account_id();
    let callee = Actor::new(signer_id, TWIN);
    let wrong_seed = PdaSeed::new([88; 32]);

    let proven = prove_public_outputs(
        &Script::default().send(Call::new(callee, &authorized()).with_pda_seeds(vec![wrong_seed])),
        vec![callee],
        [signer_id].into(),
    );

    V03State::new()
        .with_test_programs()
        .transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![Nonce(0)], &[&signer_keys.signing_key]),
            1,
            0,
        )
        .expect("an unmatched seed must leave the credential in force");
}

#[test]
fn a_public_pda_seed_from_a_private_turn_does_not_extend_to_a_sibling_output() {
    let account_id = AccountId::for_public_pda(&scripted_id(), &DELEGATED_SEED);
    let callee = Actor::new(account_id, TWIN);

    let proven = prove_public_outputs(
        &Script::default()
            .send(Call::new(callee, &authorized()).with_pda_seeds(vec![DELEGATED_SEED]))
            .send(Call::new(callee, &authorized())),
        vec![callee],
        HashSet::new(),
    );

    let result = V03State::new()
        .with_test_programs()
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 1, 0);

    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
        "a sibling output handed the public PDA but no pda_seeds must not see it as authorized, \
         but got: {result:?}"
    );
}

/// Exploit-scenario pin. A single `(program_id, seed)` pair can derive a family of
/// `AccountId`s, one public PDA and one private PDA per distinct npk. Without the tx-wide
/// family-binding check, one transaction could bind `PDA_alice` (`alice_npk`) and
/// `PDA_bob` (`bob_npk`) under the same seed, and a later send could delegate both
/// to a callee via `pda_seeds: [S]` and mix balances across them. The binding check rejects
/// the setup here: after the first witness binding records `(program, seed) → PDA_alice`, the
/// second tries to record `(program, seed) → PDA_bob` and fails.
#[test]
fn two_private_pdas_bound_under_same_seed_are_rejected() {
    let program_id = scripted_id();
    let keys_a = test_private_account_keys_1();
    let keys_b = test_private_account_keys_2();
    let seed = PdaSeed::new([55; 32]);

    let account_a = AccountId::for_private_pda(
        &program_id,
        &seed,
        &keys_a.npk(),
        &keys_a.vpk(),
        Identifier::new([u8::MAX; 32]),
    );
    let account_b = AccountId::for_private_pda(
        &program_id,
        &seed,
        &keys_b.npk(),
        &keys_b.vpk(),
        Identifier::new([u8::MAX; 32]),
    );

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                init_pda_witness(&keys_a, Identifier::new([u8::MAX; 32]), (program_id, seed)),
                init_pda_witness(&keys_b, Identifier::new([u8::MAX; 32]), (program_id, seed)),
            ],
            ..proving_input(root(Actor::new(account_a, program_id), &Script::default()))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::FamilyBindingConflict { existing, account_id }
            if existing == account_a && account_id == account_b
    ));
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
    let sender_keys = test_private_account_keys_1();
    let sender_id = regular_id(&sender_keys, Identifier::ZERO);
    let witness = update_witness(
        &sender_keys,
        Identifier::ZERO,
        Account::funded(100),
        (1, vec![]),
    );

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![witness.clone(), witness],
            ..proving_input(root(Actor::native_balance(sender_id), &Script::default()))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    );

    assert!(matches!(
        execution_error(result),
        ExecutionError::DuplicateWitness { account_id } if account_id == sender_id
    ));
}

fn prove_scripted_init(keys: &TestPrivateKeys, script: &Script) -> PrivacyPreservingTransaction {
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(keys, Identifier::ZERO)],
            ..proving_input(root(
                Actor::new(regular_id(keys, Identifier::ZERO), scripted_id()),
                script,
            ))
        },
        &Simulation::default(),
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();
    private_tx(proven, vec![], &[])
}

#[test]
fn private_authorized_uninitialized_account() {
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);

    // Set up keys for the authorized private account
    let private_keys = test_private_account_keys_1();
    let account_id = regular_id(&private_keys, Identifier::ZERO);

    // Execute and prove the circuit with the authorized account but no commitment proof
    let tx = prove_scripted_init(&private_keys, &Script::default());
    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(result.is_ok());

    let nullifier = Nullifier::for_account_initialization(&account_id);
    assert!(state.private_state.1.contains(&nullifier));
}

#[test]
fn private_account_claimed_then_used_without_init_flag_should_fail() {
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);

    // Set up keys for the private account
    let private_keys = test_private_account_keys_1();
    let account_id = regular_id(&private_keys, Identifier::ZERO);

    let tx = prove_scripted_init(&private_keys, &Script::write(vec![7; 4]));

    // The write should succeed
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 1, 0)
            .is_ok()
    );

    // Verify the account is now initialized (nullifier exists)
    let nullifier = Nullifier::for_account_initialization(&account_id);
    assert!(state.private_state.1.contains(&nullifier));

    // A second init starts from the default account and proves, but its initialization nullifier
    // is already spent.
    let tx = prove_scripted_init(&private_keys, &Script::default());

    assert!(matches!(
        state.transition_from_privacy_preserving_transaction(&tx, 1, 0),
        Err(LeeError::InvalidInput(message)) if message == "Nullifier already seen"
    ));
}

#[test]
fn two_private_pda_family_members_receive_and_spend() {
    let funder_keys = test_public_account_keys_1();
    let alice_keys = test_private_account_keys_1();

    let proxy_id = scripted_id();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    let funder_id = funder_keys.account_id();
    let funder = Actor::native_balance(funder_id);
    let alice_pda_0_id = AccountId::for_private_pda(
        &proxy_id,
        &seed,
        &alice_keys.npk(),
        &alice_keys.vpk(),
        Identifier::ZERO,
    );
    let alice_pda_1_id = AccountId::for_private_pda(
        &proxy_id,
        &seed,
        &alice_keys.npk(),
        &alice_keys.vpk(),
        Identifier::new([1; 32]),
    );
    let recipient_id = test_public_account_keys_2().account_id();
    let recipient = Actor::native_balance(recipient_id);
    let recipient_signing_key = test_public_account_keys_2().signing_key;

    let mut state = V03State::new().with_public_account_balances([(funder_id, 500)]);
    state.insert_program(&crate::test_methods::scripted(), true);

    let alice_pda_0_account = Account {
        nonce: Nonce::private_account_nonce_init(&alice_pda_0_id),
        ..Account::funded(amount)
    };
    let alice_pda_1_account = Account {
        nonce: Nonce::private_account_nonce_init(&alice_pda_1_id),
        ..Account::funded(amount)
    };

    // A shielding native transfer from `from` into the private PDA.
    let shield = |from: Actor, witness: PrivateWitness, pda_id: AccountId| {
        execute_and_prove(
            ProvingInput {
                declared: Declared::new(vec![from], [from.account_id]),
                private_witnesses: vec![witness],
                ..proving_input(root(from, &transfer(pda_id, amount)))
            },
            &Simulation {
                public_shards: [(from, encode_balance(amount))].into(),
                ..Simulation::default()
            },
            &ProgramCatalog::default(),
        )
        .unwrap()
    };
    // The proxy spends the private PDA's native balance by its seed, into the public recipient.
    let spend = |witness: PrivateWitness, pda_id: AccountId, signers: HashSet<AccountId>| {
        execute_and_prove(
            ProvingInput {
                declared: Declared::new(vec![recipient], signers),
                private_witnesses: vec![witness],
                ..proving_input(root(
                    Actor::new(pda_id, proxy_id),
                    &Script::default().send(
                        Call::new(
                            Actor::native_balance(pda_id),
                            &transfer(recipient.account_id, amount),
                        )
                        .with_pda_seeds(vec![seed]),
                    ),
                ))
            },
            &Simulation::default(),
            &synthetic_program(crate::test_methods::scripted()),
        )
        .unwrap()
    };
    // Fund alice_pda_0 via a plain native transfer directly.
    let proven = shield(
        funder,
        init_pda_witness(&alice_keys, Identifier::ZERO, (proxy_id, seed)),
        alice_pda_0_id,
    );
    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![Nonce(0)], &[&funder_keys.signing_key]),
            1,
            0,
        )
        .unwrap();

    // Fund alice_pda_1 the same way with identifier 1.
    let proven = shield(
        funder,
        init_pda_witness(&alice_keys, Identifier::new([1; 32]), (proxy_id, seed)),
        alice_pda_1_id,
    );
    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![Nonce(1)], &[&funder_keys.signing_key]),
            2,
            0,
        )
        .unwrap();

    let commitment_pda_0 = Commitment::new(&alice_pda_0_id, &alice_pda_0_account);
    let commitment_pda_1 = Commitment::new(&alice_pda_1_id, &alice_pda_1_account);

    assert!(state.get_proof_for_commitment(&commitment_pda_0).is_some());
    assert!(state.get_proof_for_commitment(&commitment_pda_1).is_some());

    // Alice spends alice_pda_0 into the public recipient.
    let proven = spend(
        update_pda_witness(
            &alice_keys,
            Identifier::ZERO,
            (proxy_id, seed),
            alice_pda_0_account,
            state
                .get_proof_for_commitment(&commitment_pda_0)
                .expect("pda_0 must be in state"),
        ),
        alice_pda_0_id,
        [recipient_id].into(),
    );
    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(proven, vec![Nonce(0)], &[&recipient_signing_key]),
            3,
            0,
        )
        .unwrap();

    // Alice spends alice_pda_1 into the same public recipient.
    let proven = spend(
        update_pda_witness(
            &alice_keys,
            Identifier::new([1; 32]),
            (proxy_id, seed),
            alice_pda_1_account.clone(),
            state
                .get_proof_for_commitment(&commitment_pda_1)
                .expect("pda_1 must be in state"),
        ),
        alice_pda_1_id,
        HashSet::new(),
    );
    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 4, 0)
        .unwrap();

    assert_eq!(
        state.get_account_by_id(recipient_id).data.native_balance(),
        Ok(2 * amount)
    );

    // Re-fund alice_pda_1 from the recipient via a native transfer using a private-PDA update.
    let alice_pda_1_account_after_spend = Account {
        nonce: alice_pda_1_account
            .nonce
            .private_account_nonce_increment(&alice_keys.nsk()),
        ..Account::funded(0)
    };
    let commitment_pda_1_after_spend =
        Commitment::new(&alice_pda_1_id, &alice_pda_1_account_after_spend);
    let proven = shield(
        recipient,
        update_pda_witness(
            &alice_keys,
            Identifier::new([1; 32]),
            (proxy_id, seed),
            alice_pda_1_account_after_spend,
            state
                .get_proof_for_commitment(&commitment_pda_1_after_spend)
                .expect("pda_1 after spend must be in state"),
        ),
        alice_pda_1_id,
    );
    state
        .transition_from_privacy_preserving_transaction(
            &private_tx(
                proven,
                vec![state.get_account_by_id(recipient_id).nonce],
                &[&recipient_signing_key],
            ),
            5,
            0,
        )
        .unwrap();

    assert_eq!(
        state.get_account_by_id(recipient_id).data.native_balance(),
        Ok(amount)
    );
}

/// Unauthorized balance decrease is refused.
#[test]
fn a_private_balance_decrease_without_the_credential_is_refused_when_proving() {
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();
    let sender_account = Account::funded(100);
    let state = V03State::new().with_private_account(&sender_keys, &sender_account);
    let sender_id = regular_id(&sender_keys, Identifier::ZERO);
    let recipient_id = regular_id(&recipient_keys, Identifier::ZERO);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&sender_id, &sender_account))
        .expect("sender's commitment must be in state");

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![
                PrivateWitness {
                    vpk: sender_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: Identifier::ZERO,
                    kind: WitnessKind::Regular { ask: None },
                    nullifier: NullifierWitness::Update {
                        account: sender_account,
                        view_tag: 0,
                        nsk: sender_keys.nsk(),
                        membership_proof,
                    },
                },
                PrivateWitness {
                    vpk: recipient_keys.vpk(),
                    random_seed: [0; 32],
                    identifier: Identifier::ZERO,
                    kind: WitnessKind::Regular { ask: None },
                    nullifier: NullifierWitness::Init {
                        npk: recipient_keys.npk(),
                        commitment_root: DUMMY_COMMITMENT_HASH,
                    },
                },
            ],
            ..proving_input(root(
                Actor::native_balance(sender_id),
                &transfer(recipient_id, 10),
            ))
        },
        &Simulation::default(),
        &ProgramCatalog::default(),
    );

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::UnauthorizedSender { account_id }
            )
        )) if account_id == sender_id
    ));
}

#[test]
fn a_forged_echo_is_caught_before_proving() {
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    let keys = test_private_account_keys_1();

    for field in [
        ForgeField::Receiver,
        ForgeField::Origin,
        ForgeField::IsAuthorized,
        ForgeField::PreState,
        ForgeField::Message,
    ] {
        let result = execute_and_prove(
            ProvingInput {
                private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
                ..proving_input(root(
                    Actor::new(regular_id(&keys, Identifier::ZERO), program_id),
                    &field,
                ))
            },
            &Simulation::default(),
            &synthetic_program(crate::test_methods::forges_echo()),
        );

        assert!(matches!(
            execution_error(result),
            ExecutionError::ExecutionValidation {
                program_account_id,
                source: ExecutionValidationError::TransitionInputMismatch { .. },
            } if program_account_id == program_id
        ));
    }
}

/// A program never deployed anywhere, dispatched as a shadow program instead — its identity is
/// established fresh, in this one proof, from its elf supplied as a witness. Confirms the
/// shadow-resolved dispatch address flows into the same private-PDA mechanics every other
/// program uses, and that it never appears in the circuit's `program_image_claims` output.
#[test]
fn shadow_program_claims_a_private_pda_it_legitimately_owns() {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);

    let (shadow_id, programs) = shadow_scripted();

    let account_id = AccountId::for_private_pda(
        &shadow_id,
        &seed,
        &keys.npk(),
        &keys.vpk(),
        Identifier::new([u8::MAX; 32]),
    );

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::new([u8::MAX; 32]),
                (shadow_id, seed),
            )],
            ..proving_input(root(Actor::new(account_id, shadow_id), &Script::default()))
        },
        &Simulation::default(),
        &programs,
    );

    let (output, _proof) = result.expect("shadow program's private PDA claim should succeed");
    assert_eq!(output.private_actions.len(), 1);
    assert!(output.boundary.outputs.is_empty());
    assert!(
        output.program_image_claims.is_empty(),
        "a shadow program must never appear in the circuit's program_image_claims output"
    );
}

/// Same shape as `shadow_program_claims_a_private_pda_it_legitimately_owns`, but for a
/// standalone `Regular` private account instead of a program-derived PDA — `Regular` addresses
/// never depend on the calling program's identity, so this exercises a disjoint code path. Lets
/// a future regression narrow down to the PDA-binding check vs. shadow-identity resolution.
#[test]
fn shadow_program_claims_a_regular_private_account_it_legitimately_owns() {
    let keys = test_private_account_keys_1();
    let identifier = Identifier::new([u8::MAX; 32]);

    let account_id = regular_id(&keys, identifier);
    let (shadow_id, programs) = shadow_scripted();

    let result = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, identifier)],
            ..proving_input(root(Actor::new(account_id, shadow_id), &Script::default()))
        },
        &Simulation::default(),
        &programs,
    );

    let (output, _proof) =
        result.expect("shadow program's regular private account claim should succeed");
    assert_eq!(output.private_actions.len(), 1);
    assert!(output.boundary.outputs.is_empty());
    assert!(
        output.program_image_claims.is_empty(),
        "a shadow program must never appear in the circuit's program_image_claims output"
    );
}

/// A shadow program is never deployed, so settlement cannot run it on a public account.
#[test]
fn a_shadow_programs_public_effect_is_refused_at_settlement() {
    let (shadow_id, programs) = shadow_scripted();
    let public = Actor::new(AccountId::new([7; 32]), shadow_id);
    // A private transaction must nullify or commit something.
    let keys = test_private_account_keys_1();

    let (output, proof) = execute_and_prove(
        ProvingInput {
            declared: Declared::new(vec![public], []),
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(root(public, &Script::write(vec![7; 4])))
        },
        &Simulation::default(),
        &programs,
    )
    .unwrap();
    assert!(
        output.program_image_claims.is_empty(),
        "a shadow program must never appear in the circuit's program_image_claims output"
    );

    let tx = private_tx((output, proof), vec![], &[]);

    let result = V03State::new().transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(
        matches!(result, Err(LeeError::UnknownProgram { chained: false })),
        "expected the shadow program to be unknown at settlement, got {result:?}"
    );
}

fn deploy_immutable_header(state: &mut V03State) -> (AccountId, ProgramHeader) {
    let program = crate::test_methods::scripted();
    let segment_account_ids = force_insert_segment_chain(state, program.elf(), 0x04);

    let header_key = PrivateKey::try_new([0x11; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));
    let header = Actor::new(header_account_id, PROGRAM_LOADER_ACCOUNT_ID);
    let create_tx = public_tx(
        header,
        vec![header],
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&header_key],
    );
    state
        .transition_from_public_transaction(&create_tx, 1, 0)
        .expect("deploying the immutable header should succeed");

    (
        header_account_id,
        ProgramHeader {
            image_id: program.id(),
            program_first_segment: segment_account_ids[0],
            immutable: true,
        },
    )
}

fn prove_undisclosed(
    header_account_id: AccountId,
    program_header: ProgramHeader,
    membership_proof: MembershipProof,
) -> PrivacyPreservingTransaction {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let account_id = AccountId::for_private_pda(
        &header_account_id,
        &seed,
        &keys.npk(),
        &keys.vpk(),
        Identifier::new([u8::MAX; 32]),
    );
    let programs = ProgramCatalog::from([(header_account_id, crate::test_methods::scripted())])
        .with_undisclosed(header_account_id, program_header, membership_proof);

    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(
                &keys,
                Identifier::new([u8::MAX; 32]),
                (header_account_id, seed),
            )],
            ..proving_input(root(
                Actor::new(account_id, header_account_id),
                &Script::default(),
            ))
        },
        &Simulation::default(),
        &programs,
    )
    .expect("the circuit has no live chain state to check the proof against, so proving succeeds");
    private_tx(proven, vec![], &[])
}

/// Deploys a program with an immutable header (landing the private mirror commitment via
/// `CreateHeader`), then references it in a privacy-preserving transaction through a
/// `ProgramImageClaim::Undisclosed` claim instead of a `Disclosed` one. The circuit checks the
/// supplied membership proof against the real commitment itself, so the transaction succeeds
/// without the sequencer ever doing a public lookup for this program.
#[test]
fn private_claim_matching_a_real_commitment_passes_verification() {
    let mut state = V03State::new();
    let (header_account_id, program_header) = deploy_immutable_header(&mut state);

    let membership_proof = state
        .get_proof_for_commitment(&immutable_mirror_commitment(
            header_account_id,
            &program_header,
        ))
        .expect("the header's immutable mirror commitment should be in private state");
    let tx = prove_undisclosed(header_account_id, program_header, membership_proof);

    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .expect("the sequencer should verify the Private claim against the real commitment");
}

/// Same shape as `private_claim_matching_a_real_commitment_passes_verification`, but the header
/// was never actually deployed, so there's no real membership proof to supply — a fabricated one
/// is used instead. Proving still succeeds, since the circuit has no live chain state to check
/// against; the fabricated proof's implied root just won't be one the tree has ever actually had.
#[test]
fn private_claim_with_no_matching_commitment_is_rejected() {
    let mut state = V03State::new();

    let header_account_id = AccountId::new([0x22; 32]);
    let program_header = ProgramHeader {
        image_id: crate::test_methods::scripted().id(),
        program_first_segment: AccountId::new([1; 32]),
        immutable: true,
    };

    let fabricated_membership_proof = (0, vec![[0xab; 32]; 4]);
    let tx = prove_undisclosed(
        header_account_id,
        program_header,
        fabricated_membership_proof,
    );

    let err = state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect_err("a Private claim with a fabricated membership proof must be rejected");
    assert!(
        err.to_string()
            .contains("Unrecognized commitment set digest"),
        "rejection should cite the unrecognized root, got: {err}"
    );
}

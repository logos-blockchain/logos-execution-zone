use super::*;

const CREDIT: u128 = 250;

fn credited_private_account() -> (V03State, TestPrivateKeys, AccountId, Account) {
    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let recipient_keys = test_private_account_keys_1();
    let program = crate::test_methods::simple_balance_transfer();
    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: program.id(),
            balance: 1_000_000,
            ..Account::default()
        },
    );

    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let sender_pre = AccountWithMetadata::new(state.get_account_by_id(sender_id), true, sender_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), false, recipient_id);

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(CREDIT).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![Nonce(0)], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_keys.signing_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let credited = Account {
        balance: CREDIT,
        nonce: Nonce::private_account_nonce_init(&recipient_id),
        ..Account::default()
    };
    (state, recipient_keys, recipient_id, credited)
}

#[test]
fn credited_private_account_burns_its_init_nullifier() {
    let (state, _keys, account_id, credited) = credited_private_account();

    assert!(
        state
            .private_state
            .1
            .contains(&Nullifier::for_account_initialization(&account_id)),
        "the unclaimed credit must burn the account's init nullifier"
    );
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(&account_id, &credited))
            .is_some(),
        "the credited note's commitment must be in state"
    );
}

#[test]
fn replayed_init_over_a_credited_private_account_is_rejected_by_the_verifier() {
    let (mut state, keys, account_id, _credited) = credited_private_account();
    let program = crate::test_methods::claimer();
    let attacker_pre = AccountWithMetadata::new(Account::default(), false, account_id);

    let (output, proof) = execute_and_prove(
        vec![attacker_pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [1; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: state.commitment_root(),
            },
        })],
        &program.into(),
    )
    .expect("the preimage-only re-init must still produce a proof; the verifier is the gate");

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    assert!(
        state
            .check_commitments_are_new(&tx.message.commitments())
            .is_ok(),
        "the claim produces a fresh commitment, so the commitment check cannot preempt"
    );
    assert!(
        tx.message.nullifiers().iter().all(|(_, digest)| state
            .check_nullifiers_are_valid(&[(Nullifier::for_dummy(&[0xAB; 32]), *digest)])
            .is_ok()),
        "the supplied root is a real one, so the root check cannot preempt"
    );

    let error = state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .expect_err("a preimage-only re-init of a credited account must be rejected");
    assert!(
        matches!(&error, LeeError::InvalidInput(message) if message == "Nullifier already seen"),
        "expected the burned init nullifier to reject the replay, got {error:?}"
    );
}

#[test]
fn forged_update_over_a_credited_private_account_fails_in_circuit() {
    let (state, keys, account_id, credited) = credited_private_account();
    let attacker_keys = test_private_account_keys_2();
    let program = crate::test_methods::claimer();

    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&account_id, &credited))
        .expect("the credited note's commitment must be in state");
    let victim_pre = AccountWithMetadata::new(credited, false, account_id);

    let result = execute_and_prove(
        vec![victim_pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [2; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: attacker_keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(_))),
        "a forged update must fail the in-circuit account-id derivation, got {result:?}"
    );
}

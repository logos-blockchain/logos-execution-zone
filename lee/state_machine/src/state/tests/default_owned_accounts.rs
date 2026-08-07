use lee_core::program::DEFAULT_PROGRAM_ID;

use super::*;

fn public_transfer_tx(
    program: &Program,
    sender_keys: &TestPublicKeys,
    recipient_id: AccountId,
    balance_to_move: u128,
) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        program.id(),
        vec![sender_keys.account_id(), recipient_id],
        vec![Nonce(0)],
        balance_to_move,
    )
    .unwrap();
    let witness_set =
        public_transaction::WitnessSet::for_message(&message, &[&sender_keys.signing_key]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn signer_can_authorize_a_claim_free_program_twice() {
    let keys = test_public_account_keys_1();
    let account_id = keys.account_id();
    let program_id = crate::test_methods::auth_asserting_noop().id();
    let mut state = V03State::new().with_test_programs();

    for nonce in 0..2 {
        let message = public_transaction::Message::try_new(
            program_id,
            vec![account_id],
            vec![Nonce(nonce)],
            (),
        )
        .unwrap();
        let witness_set =
            public_transaction::WitnessSet::for_message(&message, &[&keys.signing_key]);
        let tx = PublicTransaction::new(message, witness_set);
        state.transition_from_public_transaction(&tx, 1, 0).unwrap();
    }

    let account = state.get_account_by_id(account_id);
    assert_eq!(account.nonce, Nonce(2));
    assert_eq!(account.program_owner, DEFAULT_PROGRAM_ID);
}

#[test]
fn credit_to_default_owned_account_without_claim_succeeds() {
    let sender_keys = test_public_account_keys_1();
    let recipient_id = AccountId::new([7; 32]);
    let program = crate::test_methods::simple_balance_transfer();
    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_keys.account_id(),
        Account {
            program_owner: program.id(),
            balance: 1_000_000,
            ..Account::default()
        },
    );

    let tx = public_transfer_tx(&program, &sender_keys, recipient_id, 1);
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let recipient = state.get_account_by_id(recipient_id);
    assert_eq!(recipient.program_owner, DEFAULT_PROGRAM_ID);
    assert_eq!(recipient.balance, 1);
    assert!(recipient.data.is_empty());
}

#[test]
fn authorized_debit_from_funded_default_owned_account_succeeds() {
    let sender_keys = test_public_account_keys_1();
    let recipient_id = AccountId::new([9; 32]);
    let program = crate::test_methods::simple_balance_transfer();
    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_keys.account_id(),
        Account {
            balance: 1_000_000,
            ..Account::default()
        },
    );

    let tx = public_transfer_tx(&program, &sender_keys, recipient_id, 1);
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let sender = state.get_account_by_id(sender_keys.account_id());
    assert_eq!(sender.program_owner, DEFAULT_PROGRAM_ID);
    assert_eq!(sender.balance, 1_000_000 - 1);
}

#[test]
fn funded_default_owned_account_can_be_claimed_by_authorized_program() {
    let keys = test_public_account_keys_1();
    let account_id = keys.account_id();
    let program = crate::test_methods::claimer();
    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        account_id,
        Account {
            balance: 500,
            ..Account::default()
        },
    );

    let message =
        public_transaction::Message::try_new(program.id(), vec![account_id], vec![Nonce(0)], ())
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&keys.signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let account = state.get_account_by_id(account_id);
    assert_eq!(account.program_owner, program.id());
    assert_eq!(account.balance, 500);
}

#[test]
fn fresh_private_note_with_balance_and_no_claim_succeeds() {
    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let recipient_keys = test_private_account_keys_1();
    let program = crate::test_methods::modified_transfer_program();
    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: program.id(),
            balance: 1_000_000,
            ..Account::default()
        },
    );

    let sender_pre = AccountWithMetadata::new(state.get_account_by_id(sender_id), true, sender_id);
    let recipient_pre = AccountWithMetadata::new(
        Account::default(),
        false,
        (&recipient_keys.npk(), &recipient_keys.vpk(), 0),
    );

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(1_u128).unwrap(),
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
}

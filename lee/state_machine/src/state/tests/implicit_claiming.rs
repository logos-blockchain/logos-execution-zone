use super::*;

#[test]
fn public_echo_of_a_default_account_leaves_it_unowned() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::noop().id();

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Writing nothing acquires nothing: the account stays unowned.
    assert!(result.is_ok());
    assert_eq!(state.get_account_by_id(account_id), Account::default());
}

#[test]
fn public_data_write_to_a_default_account_claims_it() {
    let initial_data = [];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::data_changer().id();
    let new_data: Vec<u8> = vec![1, 2, 3, 4, 5];

    let message = public_transaction::Message::try_new(
        program_id,
        vec![account_id],
        vec![],
        new_data.clone(),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("writing data to an unowned account is how ownership is acquired");

    assert_eq!(
        state.get_account_by_id(account_id),
        Account {
            program_owner: program_id.into(),
            data: new_data.try_into().unwrap(),
            ..Account::default()
        }
    );
}

#[test]
fn private_echo_of_a_default_account_succeeds() {
    let program = crate::test_methods::noop();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
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
        })],
        &program.into(),
    );

    assert!(result.is_ok());
}

#[test]
fn private_data_write_to_a_default_account_is_accepted() {
    let program = crate::test_methods::data_changer();
    let sender_keys = test_private_account_keys_1();
    let private_account = AccountWithMetadata::new(
        Account::default(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let new_data: Vec<u8> = vec![1, 2, 3, 4, 5];

    let result = execute_and_prove(
        vec![private_account],
        Program::serialize_instruction(new_data).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
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
        })],
        &program.into(),
    );

    // The circuit applies the same implicit rule as the public path.
    assert!(result.is_ok());
}

/// A private sender crediting a public unowned recipient: the recipient gains the balance and
/// stays unowned, exactly as on the public path.
#[test]
fn private_credit_to_a_public_unowned_recipient_leaves_it_unowned() {
    let program = crate::test_methods::simple_balance_transfer();
    let program_id = program.id();
    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        program_owner: program_id.into(),
        balance: 100,
        ..Account::default()
    };
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let sender_init_nullifier = Nullifier::for_account_initialization(&sender_account_id);
    let mut state =
        V03State::new().with_private_accounts([(sender_commitment, sender_init_nullifier)]);
    let sender_pre = AccountWithMetadata::new(
        sender_private_account,
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let recipient_private_key = PrivateKey::try_new([2; 32]).unwrap();
    let recipient_account_id =
        AccountId::from(&PublicKey::new_from_private_key(&recipient_private_key));
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let balance = 37;

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance).unwrap(),
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
                    membership_proof: state
                        .get_proof_for_commitment(&sender_commitment)
                        .expect("sender's commitment must be in state"),
                },
            }),
            InputAccountIdentity::Public,
        ],
        &program.into(),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![Nonce(0)], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[&recipient_private_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let nullifier = Nullifier::for_account_update(&sender_commitment, &sender_keys.nsk());
    assert!(state.private_state.1.contains(&nullifier));

    assert_eq!(
        state.get_account_by_id(recipient_account_id),
        Account {
            balance,
            nonce: Nonce(1),
            ..Account::default()
        }
    );
}

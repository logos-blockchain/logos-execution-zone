use super::*;

#[test]
fn claiming_mechanism() {
    let program = crate::test_methods::simple_balance_transfer();
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let initial_balance = 100;
    let initial_data = [(from, initial_balance)];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let amount: u128 = 37;

    // Check the recipient is an uninitialized account
    assert_eq!(state.get_account_by_id(to), Account::default());

    let expected_recipient_post = Account {
        program_owner: program.id().into(),
        balance: amount,
        nonce: Nonce(1),
        ..Account::default()
    };

    let message = public_transaction::Message::try_new(
        program.id(),
        vec![from, to],
        vec![Nonce(0), Nonce(0)],
        amount,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let recipient_post = state.get_account_by_id(to);

    assert_eq!(recipient_post, expected_recipient_post);
}

#[test]
fn unauthorized_public_account_claiming_fails() {
    let program = crate::test_methods::simple_balance_transfer();
    let account_key = PrivateKey::try_new([9; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&account_key));
    let mut state = V03State::new().with_test_programs();

    assert_eq!(state.get_account_by_id(account_id), Account::default());

    let message =
        public_transaction::Message::try_new(program.id(), vec![account_id], vec![], 0_u128)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(result, Err(LeeError::InvalidProgramBehavior(_))));
    assert_eq!(state.get_account_by_id(account_id), Account::default());
}

#[test]
fn authorized_public_account_claiming_succeeds() {
    let program = crate::test_methods::simple_balance_transfer();
    let account_key = PrivateKey::try_new([10; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&account_key));
    let mut state = V03State::new().with_test_programs();

    assert_eq!(state.get_account_by_id(account_id), Account::default());

    let message = public_transaction::Message::try_new(
        program.id(),
        vec![account_id],
        vec![Nonce(0)],
        0_u128,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&account_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(account_id),
        Account {
            program_owner: program.id().into(),
            nonce: Nonce(1),
            ..Account::default()
        }
    );
}

#[test]
fn public_chained_call() {
    let program = crate::test_methods::chain_caller();
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&key));
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let initial_data = [(from, initial_balance), (to, 0)];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let from_key = key;
    let amount: u128 = 37;
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        2,
        None,
    );

    let expected_to_post = Account {
        program_owner: crate::test_methods::simple_balance_transfer().id().into(),
        balance: amount * 2, // The `chain_caller` chains the program twice
        ..Account::default()
    };

    let message = public_transaction::Message::try_new(
        program.id(),
        vec![to, from], // The chain_caller program permutes the account order in the chain
        // call
        vec![Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let from_post = state.get_account_by_id(from);
    let to_post = state.get_account_by_id(to);
    // The `chain_caller` program calls the program twice
    assert_eq!(from_post.balance, initial_balance - 2 * amount);
    assert_eq!(to_post, expected_to_post);
}

#[test]
fn execution_fails_if_chained_calls_exceeds_depth() {
    let program = crate::test_methods::chain_caller();
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&key));
    let to = AccountId::new([2; 32]);
    let initial_balance = 100;
    let initial_data = [(from, initial_balance), (to, 0)];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let from_key = key;
    let amount: u128 = 0;
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        u32::try_from(MAX_NUMBER_CHAINED_CALLS).expect("MAX_NUMBER_CHAINED_CALLS fits in u32") + 1,
        None,
    );

    let message = public_transaction::Message::try_new(
        program.id(),
        vec![to, from], // The chain_caller program permutes the account order in the chain
        // call
        vec![Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(matches!(
        result,
        Err(LeeError::MaxChainedCallsDepthExceeded)
    ));
}

#[test]
fn execution_that_requires_authentication_of_a_program_derived_account_id_succeeds() {
    let chain_caller = crate::test_methods::chain_caller();
    let pda_seed = PdaSeed::new([37; 32]);
    let from = AccountId::for_public_pda(&chain_caller.id(), &pda_seed);
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let initial_data = [(from, initial_balance), (to, 0)];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let amount: u128 = 58;
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        1,
        Some(pda_seed),
    );

    let expected_to_post = Account {
        program_owner: crate::test_methods::simple_balance_transfer().id().into(),
        balance: amount, // The `chain_caller` chains the program twice
        ..Account::default()
    };
    let message = public_transaction::Message::try_new(
        chain_caller.id(),
        vec![to, from], // The chain_caller program permutes the account order in the chain
        // call
        vec![],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let from_post = state.get_account_by_id(from);
    let to_post = state.get_account_by_id(to);
    assert_eq!(from_post.balance, initial_balance - amount);
    assert_eq!(to_post, expected_to_post);
}

#[test]
fn claiming_mechanism_within_chain_call() {
    // This test calls the authenticated transfer program through the chain_caller program.
    // The transfer is made from an initialized sender to an uninitialized recipient. And
    // it is expected that the recipient account is claimed by the authenticated transfer
    // program and not the chained_caller program.
    let chain_caller = crate::test_methods::chain_caller();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let initial_balance = 100;
    let initial_data = [(from, initial_balance)];
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let amount: u128 = 37;

    // Check the recipient is an uninitialized account
    assert_eq!(state.get_account_by_id(to), Account::default());

    let expected_to_post = Account {
        // The expected program owner is the authenticated transfer program
        program_owner: simple_transfer.id().into(),
        balance: amount,
        nonce: Nonce(1),
        ..Account::default()
    };

    // The transaction executes the chain_caller program, which internally calls the
    // authenticated_transfer program
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        1,
        None,
    );
    let message = public_transaction::Message::try_new(
        chain_caller.id(),
        vec![to, from], // The chain_caller program permutes the account order in the chain
        // call
        vec![Nonce(0), Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let from_post = state.get_account_by_id(from);
    let to_post = state.get_account_by_id(to);
    assert_eq!(from_post.balance, initial_balance - amount);
    assert_eq!(to_post, expected_to_post);
}

#[test]
fn separate_initialize_and_fund_chain_calls_allow_unauthorized_private_recipient() {
    let initializer = crate::test_methods::initialize_then_fund();
    let claimer = crate::test_methods::claimer();
    let claimer_id = claimer.id();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let simple_transfer_id = simple_transfer.id();

    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let initial_balance = 100;
    let amount: u128 = 37;

    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(sender_id, initial_balance)]))
        .with_test_programs();

    let recipient_keys = test_private_account_keys_1();
    let recipient_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let sender_account = state.get_account_by_id(sender_id);
    let sender_nonce = sender_account.nonce;

    let program_with_deps = ProgramWithDependencies::new(
        initializer,
        [(claimer_id, claimer), (simple_transfer_id, simple_transfer)].into(),
    );

    let instruction: (u128, ProgramId, ProgramId) = (amount, claimer_id, simple_transfer_id);
    let (output, proof) = execute_and_prove(
        vec![
            AccountWithMetadata::new(Account::default(), false, recipient_id),
            AccountWithMetadata::new(sender_account, true, sender_id),
        ],
        Program::serialize_instruction(instruction).unwrap(),
        vec![
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
            InputAccountIdentity::Public,
        ],
        &program_with_deps,
    )
    .expect("unauthorized private recipient claim-and-fund should succeed");

    let message = Message::from_circuit_output(vec![sender_nonce], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_keys.signing_key]);
    state
        .transition_from_privacy_preserving_transaction(
            &PrivacyPreservingTransaction::new(message, witness_set),
            1,
            0,
        )
        .unwrap();

    let expected_recipient_post = Account {
        program_owner: claimer_id.into(),
        balance: amount,
        nonce: Nonce::private_account_nonce_init(&recipient_id),
        ..Account::default()
    };
    assert!(
        state
            .get_proof_for_commitment(&Commitment::new(&recipient_id, &expected_recipient_post))
            .is_some()
    );
    assert_eq!(
        state.get_account_by_id(sender_id).balance,
        initial_balance - amount
    );
}

#[test]
fn separate_initialize_and_fund_chain_calls_succeed_publicly_for_public_recipient() {
    let initializer = crate::test_methods::initialize_then_fund();
    let claimer = crate::test_methods::claimer();
    let claimer_id = claimer.id();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let simple_transfer_id = simple_transfer.id();

    let sender_key = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let initial_balance = 100;
    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(sender_id, initial_balance)]))
        .with_test_programs();
    let recipient_key = PrivateKey::try_new([2; 32]).unwrap();
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
    let amount: u128 = 37;

    assert_eq!(state.get_account_by_id(recipient_id), Account::default());

    let instruction: (u128, ProgramId, ProgramId) = (amount, claimer_id, simple_transfer_id);
    let message = public_transaction::Message::try_new(
        initializer.id(),
        vec![recipient_id, sender_id],
        vec![Nonce(0), Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set =
        public_transaction::WitnessSet::for_message(&message, &[&recipient_key, &sender_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let recipient_post = state.get_account_by_id(recipient_id);
    assert_eq!(recipient_post.program_owner, claimer_id.into());
    assert_eq!(recipient_post.balance, amount);
    assert_eq!(
        state.get_account_by_id(sender_id).balance,
        initial_balance - amount
    );
}

#[test]
fn separate_initialize_and_fund_chain_calls_for_public_recipient_privately() {
    let initializer = crate::test_methods::initialize_then_fund();
    let claimer = crate::test_methods::claimer();
    let claimer_id = claimer.id();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let simple_transfer_id = simple_transfer.id();

    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let initial_balance = 100;
    let amount: u128 = 37;

    let mut state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(sender_id, initial_balance)]))
        .with_test_programs();

    let recipient_key = PrivateKey::try_new([2; 32]).unwrap();
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
    let sender_account = state.get_account_by_id(sender_id);
    let sender_nonce = sender_account.nonce;

    // A privacy-preserving transaction requires at least one private action; this account is
    // untouched by any chained call and exists purely to satisfy that.
    let padding_keys = test_private_account_keys_2();
    let padding_id =
        AccountId::for_regular_private_account(&padding_keys.npk(), &padding_keys.vpk(), 0);

    let program_with_deps = ProgramWithDependencies::new(
        initializer,
        [(claimer_id, claimer), (simple_transfer_id, simple_transfer)].into(),
    );

    let instruction: (u128, ProgramId, ProgramId) = (amount, claimer_id, simple_transfer_id);
    let result = execute_and_prove(
        vec![
            AccountWithMetadata::new(Account::default(), true, recipient_id),
            AccountWithMetadata::new(sender_account, true, sender_id),
            AccountWithMetadata::new(Account::default(), false, padding_id),
        ],
        Program::serialize_instruction(instruction).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: padding_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: padding_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program_with_deps,
    );

    match result {
        Ok((output, proof)) => {
            let message = Message::from_circuit_output(vec![Nonce(0), sender_nonce], output);
            let witness_set = WitnessSet::for_message(
                &message,
                proof,
                &[&recipient_key, &sender_keys.signing_key],
            );
            state
                .transition_from_privacy_preserving_transaction(
                    &PrivacyPreservingTransaction::new(message, witness_set),
                    1,
                    0,
                )
                .unwrap();

            let recipient_post = state.get_account_by_id(recipient_id);
            assert_eq!(recipient_post.program_owner, claimer_id.into());
            assert_eq!(recipient_post.balance, amount);
            assert_eq!(
                state.get_account_by_id(sender_id).balance,
                initial_balance - amount
            );
        }
        Err(e) => panic!("expected success, got: {e:?}"),
    }
}

#[test]
fn unauthorized_public_account_claiming_fails_when_executed_privately() {
    let program = crate::test_methods::simple_balance_transfer();
    let account_id = AccountId::new([11; 32]);
    let public_account = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![public_account],
        Program::serialize_instruction(0_u128).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn authorized_public_account_claiming_succeeds_when_executed_privately() {
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
            program_owner: program_id.into(),
            balance,
            nonce: Nonce(1),
            ..Account::default()
        }
    );
}

#[test_case::test_case(1; "single call")]
#[test_case::test_case(2; "two calls")]
fn private_chained_call(number_of_calls: u32) {
    // Arrange
    let chain_caller = crate::test_methods::chain_caller();
    let simple_transfers = crate::test_methods::simple_balance_transfer();
    let from_keys = test_private_account_keys_1();
    let to_keys = test_private_account_keys_2();
    let initial_balance = 100;
    let from_account = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfers.id().into(),
            balance: initial_balance,
            ..Account::default()
        },
        true,
        (&from_keys.npk(), &from_keys.vpk(), 0),
    );
    let to_account = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfers.id().into(),
            ..Account::default()
        },
        true,
        (&to_keys.npk(), &to_keys.vpk(), 0),
    );

    let from_account_id =
        AccountId::for_regular_private_account(&from_keys.npk(), &from_keys.vpk(), 0);
    let to_account_id = AccountId::for_regular_private_account(&to_keys.npk(), &to_keys.vpk(), 0);
    let from_commitment = Commitment::new(&from_account_id, &from_account.account);
    let to_commitment = Commitment::new(&to_account_id, &to_account.account);
    let from_init_nullifier = Nullifier::for_account_initialization(&from_account_id);
    let to_init_nullifier = Nullifier::for_account_initialization(&to_account_id);
    let mut state = V03State::new()
        .with_private_accounts([
            (from_commitment, from_init_nullifier),
            (to_commitment, to_init_nullifier),
        ])
        .with_test_programs();
    let amount: u128 = 37;
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        number_of_calls,
        None,
    );

    let mut dependencies = HashMap::new();

    dependencies.insert(simple_transfers.id(), simple_transfers);
    let program_with_deps = ProgramWithDependencies::new(chain_caller, dependencies);

    let from_new_nonce = Nonce::default().private_account_nonce_increment(&from_keys.nsk());
    let to_new_nonce = Nonce::default().private_account_nonce_increment(&to_keys.nsk());

    let from_expected_post = Account {
        balance: initial_balance - u128::from(number_of_calls) * amount,
        nonce: from_new_nonce,
        ..from_account.account.clone()
    };
    let from_expected_commitment = Commitment::new(&from_account_id, &from_expected_post);

    let to_expected_post = Account {
        balance: u128::from(number_of_calls) * amount,
        nonce: to_new_nonce,
        ..to_account.account.clone()
    };
    let to_expected_commitment = Commitment::new(&to_account_id, &to_expected_post);

    // Act
    let (output, proof) = execute_and_prove(
        vec![to_account, from_account],
        Program::serialize_instruction(instruction).unwrap(),
        // Aligned with the `pre_states` above, not with the order `chain_caller` commits them in.
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: to_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(to_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: to_keys.nsk(),
                    membership_proof: state
                        .get_proof_for_commitment(&to_commitment)
                        .expect("to's commitment must be in state"),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: from_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(from_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: from_keys.nsk(),
                    membership_proof: state
                        .get_proof_for_commitment(&from_commitment)
                        .expect("from's commitment must be in state"),
                },
            }),
        ],
        &program_with_deps,
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let transaction = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&transaction, 1, 0)
        .unwrap();

    // Assert
    assert!(
        state
            .get_proof_for_commitment(&from_expected_commitment)
            .is_some()
    );
    assert!(
        state
            .get_proof_for_commitment(&to_expected_commitment)
            .is_some()
    );
}

#[test]
fn claiming_mechanism_cannot_claim_initialied_accounts() {
    let claimer = crate::test_methods::claimer();
    let mut state = V03State::new().with_test_programs();
    let account_id = AccountId::new([2; 32]);

    // Insert an account with non-default program owner
    state.force_insert_account(
        account_id,
        Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8].into(),
            ..Account::default()
        },
    );

    let message =
        public_transaction::Message::try_new(claimer.id(), vec![account_id], vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Claim(
            ClaimError::ClaimedNonDefaultAccount { account_id: err_account_id }
        ))) if err_account_id == account_id
    ));
}

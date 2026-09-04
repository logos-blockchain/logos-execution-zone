use super::*;

#[test]
fn public_chained_call() {
    let program = crate::test_methods::chain_caller();
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&key));
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance), (to, 0)])
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
        balance: amount * 2, // The `chain_caller` chains the program twice
        ..Account::default()
    };

    let message = public_transaction::Message::try_new(
        program.id().into(),
        // The chain_caller program permutes the account order in the chain call.
        vec![Position::balance_only(to), Position::balance_only(from)],
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
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance), (to, 0)])
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
        program.id().into(),
        // The chain_caller program permutes the account order in the chain call.
        vec![Position::balance_only(to), Position::balance_only(from)],
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
    let from = AccountId::for_public_pda(&AccountId::from(chain_caller.id()), &pda_seed);
    let to = AccountId::new([2; 32]);
    let initial_balance = 1000;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance), (to, 0)])
        .with_test_programs();
    let amount: u128 = 58;
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        1,
        Some(pda_seed),
    );

    let expected_to_post = Account {
        balance: amount,
        ..Account::default()
    };
    let message = public_transaction::Message::try_new(
        chain_caller.id().into(),
        // The chain_caller program permutes the account order in the chain call.
        vec![Position::balance_only(to), Position::balance_only(from)],
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

/// A credit reaches the recipient through a chained call, on a balance-only position: a shard
/// some other program left at that account is never named, so it must survive byte-identical.
#[test]
fn a_credit_leaves_a_stranger_shard_at_the_recipient_untouched() {
    let chain_caller = crate::test_methods::chain_caller();
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let stranger = AccountId::new([9; 32]);
    let stranger_data: Data = b"stranger".to_vec().try_into().unwrap();
    let initial_balance = 100;
    let amount: u128 = 37;
    let mut state = V03State::new()
        .with_public_accounts([
            (
                from,
                Account {
                    balance: initial_balance,
                    ..Account::default()
                },
            ),
            (
                to,
                Account::default().with_shard(stranger, stranger_data.clone()),
            ),
        ])
        .with_test_programs();

    // The transaction executes the chain_caller program, which internally calls the
    // `simple_balance_transfer` program
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        amount,
        crate::test_methods::simple_balance_transfer().id(),
        1,
        None,
    );
    let message = public_transaction::Message::try_new(
        chain_caller.id().into(),
        // The chain_caller program permutes the account order in the chain call.
        vec![Position::balance_only(to), Position::balance_only(from)],
        vec![Nonce(0), Nonce(0)],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(from).balance,
        initial_balance - amount
    );
    assert_eq!(
        state.get_account_by_id(to),
        Account {
            balance: amount,
            nonce: Nonce(1),
            ..Account::default()
        }
        .with_shard(stranger, stranger_data)
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
    let from_pre = Account {
        balance: initial_balance,
        ..Account::default()
    };
    let to_pre = Account::default();

    let from_account_id =
        AccountId::for_regular_private_account(&from_keys.npk(), &from_keys.vpk(), 0);
    let to_account_id = AccountId::for_regular_private_account(&to_keys.npk(), &to_keys.vpk(), 0);
    let from_commitment = Commitment::new(&from_account_id, &from_pre);
    let to_commitment = Commitment::new(&to_account_id, &to_pre);
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

    dependencies.insert(simple_transfers.id().into(), simple_transfers);
    let program_with_deps =
        ProgramWithDependencies::new(chain_caller.clone(), chain_caller.id().into(), dependencies);

    let from_new_nonce = Nonce::default().private_account_nonce_increment(&from_keys.nsk());
    let to_new_nonce = Nonce::default().private_account_nonce_increment(&to_keys.nsk());

    let from_expected_post = Account {
        balance: initial_balance - u128::from(number_of_calls) * amount,
        nonce: from_new_nonce,
        ..Account::default()
    };
    let from_expected_commitment = Commitment::new(&from_account_id, &from_expected_post);

    let to_expected_post = Account {
        balance: u128::from(number_of_calls) * amount,
        nonce: to_new_nonce,
        ..Account::default()
    };
    let to_expected_commitment = Commitment::new(&to_account_id, &to_expected_post);

    // Act
    let (output, proof) = execute_and_prove(
        ProvingInput {
            // The chain_caller program permutes the account order in the chain call.
            positions: vec![
                Position::balance_only(to_account_id),
                Position::balance_only(from_account_id),
            ],
            signers: HashSet::new(),
            public_accounts: HashMap::new(),
            private_witnesses: vec![
                PrivateWitness {
                    account: from_pre,
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
                },
                PrivateWitness {
                    account: to_pre,
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
                },
            ],
            instruction_data: Program::serialize_instruction(instruction).unwrap(),
            dummy_inputs: Vec::new(),
        },
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

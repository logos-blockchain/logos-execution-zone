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
        program_owner: program.id(),
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
            program_owner: program.id(),
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
        program_owner: crate::test_methods::simple_balance_transfer().id(),
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
        program_owner: crate::test_methods::simple_balance_transfer().id(),
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
        program_owner: simple_transfer.id(),
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
        program_owner: program_id,
        balance: 100,
        ..Account::default()
    };
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let sender_init_nullifier = Nullifier::for_account_initialization(&sender_account_id);
    let mut state =
        V03State::new().with_private_accounts([(sender_commitment.clone(), sender_init_nullifier)]);
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
            InputAccountIdentity::PrivateAuthorizedUpdate {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                view_tag: 0,
                nsk: sender_keys.nsk,
                membership_proof: state
                    .get_proof_for_commitment(&sender_commitment)
                    .expect("sender's commitment must be in state"),
                identifier: 0,
            },
            InputAccountIdentity::Public,
        ],
        &program.into(),
    )
    .unwrap();

    let message =
        Message::try_from_circuit_output(vec![recipient_account_id], vec![Nonce(0)], output)
            .unwrap();

    let witness_set = WitnessSet::for_message(&message, proof, &[&recipient_private_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let nullifier = Nullifier::for_account_update(&sender_commitment, &sender_keys.nsk);
    assert!(state.private_state.1.contains(&nullifier));

    assert_eq!(
        state.get_account_by_id(recipient_account_id),
        Account {
            program_owner: program_id,
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
            program_owner: simple_transfers.id(),
            balance: initial_balance,
            ..Account::default()
        },
        true,
        (&from_keys.npk(), &from_keys.vpk(), 0),
    );
    let to_account = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfers.id(),
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
            (from_commitment.clone(), from_init_nullifier),
            (to_commitment.clone(), to_init_nullifier),
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

    let from_new_nonce = Nonce::default().private_account_nonce_increment(&from_keys.nsk);
    let to_new_nonce = Nonce::default().private_account_nonce_increment(&to_keys.nsk);

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
        vec![
            InputAccountIdentity::PrivateAuthorizedUpdate {
                vpk: from_keys.vpk(),
                random_seed: [0; 32],
                view_tag: 0,
                nsk: from_keys.nsk,
                membership_proof: state
                    .get_proof_for_commitment(&from_commitment)
                    .expect("from's commitment must be in state"),
                identifier: 0,
            },
            InputAccountIdentity::PrivateAuthorizedUpdate {
                vpk: to_keys.vpk(),
                random_seed: [0; 32],
                view_tag: 0,
                nsk: to_keys.nsk,
                membership_proof: state
                    .get_proof_for_commitment(&to_commitment)
                    .expect("to's commitment must be in state"),
                identifier: 0,
            },
        ],
        &program_with_deps,
    )
    .unwrap();

    let message = Message::try_from_circuit_output(vec![], vec![], output).unwrap();
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
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
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
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ClaimedNonDefaultAccount { account_id: err_account_id }
        )) if err_account_id == account_id
    ));
}

/// This test ensures that even if a malicious program tries to perform overflow of balances
/// it will not be able to break the balance validation.
#[test]
fn malicious_program_cannot_break_balance_validation_if_not_in_genesis() {
    let sender_key = PrivateKey::try_new([37; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let sender_init_balance: u128 = 10;

    let recipient_key = PrivateKey::try_new([42; 32]).unwrap();
    let recipient_id = AccountId::from(&PublicKey::new_from_private_key(&recipient_key));
    let recipient_init_balance: u128 = 10;

    let modified_transfer_id = crate::test_methods::modified_transfer_program().id();

    let mut state = V03State::new()
        .with_public_accounts([
            (
                sender_id,
                Account {
                    program_owner: modified_transfer_id,
                    balance: sender_init_balance,
                    ..Account::default()
                },
            ),
            (
                recipient_id,
                Account {
                    program_owner: modified_transfer_id,
                    balance: recipient_init_balance,
                    ..Account::default()
                },
            ),
        ])
        .with_test_programs();

    let balance_to_move: u128 = 4;

    let sender = AccountWithMetadata::new(state.get_account_by_id(sender_id), true, sender_id);

    let sender_nonce = sender.account.nonce;

    let _recipient =
        AccountWithMetadata::new(state.get_account_by_id(recipient_id), false, sender_id);

    let message = public_transaction::Message::try_new(
        modified_transfer_id,
        vec![sender_id, recipient_id],
        vec![sender_nonce],
        balance_to_move,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);
    let tx = PublicTransaction::new(message, witness_set);
    let res = state.transition_from_public_transaction(&tx, 2, 0);
    let expected_total_balance_pre_states =
        WrappedBalanceSum::from_balances([sender_init_balance, recipient_init_balance].into_iter())
            .unwrap();
    let expected_total_balance_post_states = WrappedBalanceSum::from_balances(
        [sender_init_balance, recipient_init_balance, u128::MAX, 1].into_iter(),
    )
    .unwrap();
    assert!(matches!(
        res,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::MismatchedTotalBalance { total_balance_pre_states, total_balance_post_states }
            )
        )) if total_balance_pre_states == expected_total_balance_pre_states && total_balance_post_states == expected_total_balance_post_states
    ));

    let sender_post = state.get_account_by_id(sender_id);
    let recipient_post = state.get_account_by_id(recipient_id);

    let expected_sender_post = {
        let mut this = state.get_account_by_id(sender_id);
        this.balance = sender_init_balance;
        this.nonce = Nonce(0);
        this
    };

    let expected_recipient_post = {
        let mut this = state.get_account_by_id(sender_id);
        this.balance = recipient_init_balance;
        this.nonce = Nonce(0);
        this
    };

    assert_eq!(expected_sender_post, sender_post);
    assert_eq!(expected_recipient_post, recipient_post);
}

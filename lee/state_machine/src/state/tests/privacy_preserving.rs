use super::*;

#[test]
fn transition_from_privacy_preserving_transaction_shielded() {
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();
    let program_id = crate::test_methods::simple_balance_transfer().id();

    let mut state = V03State::new().with_public_accounts([(
        sender_keys.account_id(),
        Account::single(program_id, 200, Data::default(), Nonce::default()),
    )]);

    let balance_to_move = 37;

    let tx =
        shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, balance_to_move, &state);

    let expected_sender_post = {
        let mut this = state.get_account_by_id(sender_keys.account_id());
        this.slot_mut(program_id).balance -= balance_to_move;
        this.nonce.public_account_nonce_increment();
        this
    };

    let [expected_new_commitment] = tx.message().commitments().try_into().unwrap();
    assert!(!state.private_state.0.contains(&expected_new_commitment));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let sender_post = state.get_account_by_id(sender_keys.account_id());
    assert_eq!(sender_post, expected_sender_post);
    assert!(state.private_state.0.contains(&expected_new_commitment));

    assert_eq!(
        state
            .get_account_by_id(sender_keys.account_id())
            .balance(program_id),
        200 - balance_to_move
    );
}

#[test]
fn transition_from_privacy_preserving_transaction_private() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);
    let program_id = crate::test_methods::simple_balance_transfer().id();

    let sender_private_account = Account::single(program_id, 100, Data::default(), sender_nonce);
    let recipient_keys = test_private_account_keys_2();

    let mut state = V03State::new().with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;

    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        balance_to_move,
        &state,
    );

    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let expected_new_commitment_1 = Commitment::new(
        &sender_account_id,
        &Account::single(
            program_id,
            sender_private_account.balance(program_id) - balance_to_move,
            Data::default(),
            sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ),
    );

    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let expected_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk());

    let expected_new_commitment_2 = Commitment::new(
        &recipient_account_id,
        &Account::single(
            program_id,
            balance_to_move,
            Data::default(),
            Nonce::private_account_nonce_init(&recipient_account_id),
        ),
    );

    let previous_public_state = state.public_state.clone();
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(!state.private_state.0.contains(&expected_new_commitment_1));
    assert!(!state.private_state.0.contains(&expected_new_commitment_2));
    assert!(!state.private_state.1.contains(&expected_new_nullifier));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(state.public_state, previous_public_state);
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(state.private_state.0.contains(&expected_new_commitment_1));
    assert!(state.private_state.0.contains(&expected_new_commitment_2));
    assert!(state.private_state.1.contains(&expected_new_nullifier));
}

/// After a valid fully-private tx is proven, tampering with a note's epk should
/// make the shielding proof invalid.
#[test]
fn privacy_tampered_epk_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let (state, mut tx) = valid_private_transfer_tx_and_state();

    // Baseline: the untampered tx verifies
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified private transfer must verify"
    );

    // Flip a byte of the first note's epk
    tx.message.private_actions[0].encrypted_post_state.epk.0[0] ^= 0xFF;

    assert!(
        matches!(
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
            Err(LeeError::InvalidPrivacyPreservingProof)
        ),
        "a tampered epk must be rejected by proof verification"
    );
}

/// After a valid fully-private tx is proven, tampering with a note's view tag should
/// make the shielding proof invalid.
#[test]
fn privacy_tampered_view_tag_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let (state, mut tx) = valid_private_transfer_tx_and_state();

    // Baseline: the untampered tx verifies.
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified private transfer must verify"
    );

    // Flip the first note's view_tag
    tx.message.private_actions[0].encrypted_post_state.view_tag ^= 0xFF;

    assert!(
        matches!(
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
            Err(LeeError::InvalidPrivacyPreservingProof)
        ),
        "a tampered view_tag must be rejected by proof verification"
    );
}

#[test]
fn transition_from_privacy_preserving_transaction_deshielded() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);
    let program_id = crate::test_methods::simple_balance_transfer().id();

    let sender_private_account = Account::single(program_id, 100, Data::default(), sender_nonce);
    let recipient_keys = test_public_account_keys_1();
    let recipient_initial_balance = 400;
    let mut state = V03State::new()
        .with_public_accounts([(
            recipient_keys.account_id(),
            Account::single(
                program_id,
                recipient_initial_balance,
                Data::default(),
                Nonce::default(),
            ),
        )])
        .with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;

    let expected_recipient_post = {
        let mut this = state.get_account_by_id(recipient_keys.account_id());
        this.slot_mut(program_id).balance += balance_to_move;
        this
    };

    let tx = deshielded_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys.account_id(),
        balance_to_move,
        &state,
    );

    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let expected_new_commitment = Commitment::new(
        &sender_account_id,
        &Account::single(
            program_id,
            sender_private_account.balance(program_id) - balance_to_move,
            Data::default(),
            sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ),
    );

    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let expected_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk());

    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(!state.private_state.0.contains(&expected_new_commitment));
    assert!(!state.private_state.1.contains(&expected_new_nullifier));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let recipient_post = state.get_account_by_id(recipient_keys.account_id());
    assert_eq!(recipient_post, expected_recipient_post);
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(state.private_state.0.contains(&expected_new_commitment));
    assert!(state.private_state.1.contains(&expected_new_nullifier));
    assert_eq!(
        state
            .get_account_by_id(recipient_keys.account_id())
            .balance(program_id),
        recipient_initial_balance + balance_to_move
    );
}

#[test]
fn burner_program_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::burner();
    let public_account_acc = Account::single(program.id(), 100, Data::default(), Nonce::default());
    let public_account = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &public_account_acc,
    );

    let result = execute_and_prove(
        vec![public_account],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(&result, "Total balance across accounts is not preserved");
}

#[test]
fn minter_program_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::minter();
    let public_account = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &Account::default(),
    );

    let result = execute_and_prove(
        vec![public_account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(&result, "Total balance across accounts is not preserved");
}

#[test]
fn data_changer_program_should_fail_for_too_large_data_in_privacy_preserving_circuit() {
    let program = crate::test_methods::data_changer();
    let public_account = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &Account::default(),
    );

    let large_data: Vec<u8> =
        vec![
            0;
            usize::try_from(lee_core::account::data::DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];

    let result = execute_and_prove(
        vec![public_account],
        Program::serialize_instruction(large_data).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert_program_prove_failure(&result, "provided data should fit into data limit");
}

#[test]
fn extra_output_program_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::extra_output();
    let public_account = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &Account::default(),
    );

    let result = execute_and_prove(
        vec![public_account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(
        &result,
        "Pre-state and post-state lengths do not match: pre-state length 1, post-state length 2",
    );
}

#[test]
fn missing_output_program_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::missing_output();
    let public_account_1 = Input::at(
        SlotRef::new(AccountId::new([0; 32]), program.id()),
        true,
        &Account::default(),
    );
    let public_account_2 = Input::at(
        SlotRef::new(AccountId::new([1; 32]), program.id()),
        true,
        &Account::default(),
    );

    let result = execute_and_prove(
        vec![public_account_1, public_account_2],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(
        &result,
        "Pre-state and post-state lengths do not match: pre-state length 2, post-state length 1",
    );
}

#[test]
fn transfer_from_a_foreign_slot_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::simple_balance_transfer();
    // The balance sits in another program's slot, which `simple_balance_transfer` may not
    // debit: it only ever touches `slots[self]`, which is empty here.
    let public_account_1_acc = Account::single(
        [0, 1, 2, 3, 4, 5, 6, 7],
        100,
        Data::default(),
        Nonce::default(),
    );
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

    let result = execute_and_prove(
        vec![public_account_1, public_account_2],
        Program::serialize_instruction(10_u128).unwrap(),
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program.into(),
    );

    assert_program_prove_failure(&result, "Not enough balance to transfer");
}

#[test]
fn malicious_authorization_changer_should_fail_in_privacy_preserving_circuit() {
    // Arrange
    let malicious_program = crate::test_methods::malicious_authorization_changer();
    let simple_transfers = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();

    let sender_account_acc = Account::single(
        simple_transfers.id(),
        100,
        Data::default(),
        Nonce::default(),
    );
    // The balance lives in the transfer program's namespace, and that is the program the
    // chained call hands these positions to — the changer only orchestrates.
    let sender_account = Input::at(
        SlotRef::new(sender_keys.account_id(), simple_transfers.id()),
        false,
        &sender_account_acc,
    );
    let recipient_account_acc = Account::default();
    let recipient_account = Input::at(
        SlotRef::new(
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0).into(),
            simple_transfers.id(),
        ),
        true,
        &recipient_account_acc,
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient_commitment = Commitment::new(&recipient_account_id, &recipient_account_acc);
    let recipient_init_nullifier = Nullifier::for_account_initialization(&recipient_account_id);
    let state = V03State::new()
        .with_public_account_balances(
            native(),
            [(
                sender_account.account_id,
                sender_account.balance(simple_transfers.id()),
            )],
        )
        .with_private_accounts([(recipient_commitment, recipient_init_nullifier)])
        .with_test_programs();

    let balance_to_transfer = 10_u128;
    let instruction = (balance_to_transfer, simple_transfers.id());

    let mut dependencies = HashMap::new();
    dependencies.insert(simple_transfers.id(), simple_transfers);
    let program_with_deps = ProgramWithDependencies::new(malicious_program, dependencies);

    // Act - execute the malicious program - this should fail during proving
    let result = execute_and_prove(
        vec![sender_account, recipient_account],
        Program::serialize_instruction(instruction).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                account: Account::default(),
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: recipient_keys.nsk(),
                    membership_proof: state
                        .get_proof_for_commitment(&recipient_commitment)
                        .expect("recipient's commitment must be in state"),
                },
            }),
        ],
        &program_with_deps,
    );

    // Assert - should fail because the malicious program tries to manipulate is_authorized
    assert_circuit_proving_failure(&result, "Inconsistent authorization for account");
}

/// Rule 4 must hold identically in the circuit: the shared `validate_execution` is what makes
/// the two paths agree, and without a guest that violates it neither side is exercised.
#[test]
fn writing_a_foreign_slot_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::foreign_slot_writer();
    let foreign_program_id: lee_core::program::ProgramId = [0, 1, 2, 3, 4, 5, 6, 7];
    let account_acc = Account::single(foreign_program_id, 100, Data::default(), Nonce::default());
    // The position names the foreign namespace, which is the slot the writer then reaches for.
    let account = Input::at(
        SlotRef::new(AccountId::new([0; 32]), foreign_program_id),
        true,
        &account_acc,
    );

    let result = execute_and_prove(
        vec![account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(
        &result,
        "modified data or decreased balance of a foreign slot",
    );
}

#[test]
fn draining_a_foreign_slot_should_fail_in_privacy_preserving_circuit() {
    let program = crate::test_methods::foreign_slot_drainer();
    let foreign_program_id: lee_core::program::ProgramId = [0, 1, 2, 3, 4, 5, 6, 7];
    let account_id = AccountId::new([0; 32]);
    let account_acc = Account::single(foreign_program_id, 100, Data::default(), Nonce::default());
    // `[the foreign slot it drains, its own slot it drains into]`, both at one account.
    let foreign = Input::at(
        SlotRef::new(account_id, foreign_program_id),
        true,
        &account_acc,
    );
    let own = Input::at(SlotRef::new(account_id, program.id()), true, &account_acc);

    let result = execute_and_prove(
        vec![foreign, own],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program.into(),
    );

    assert_circuit_proving_failure(
        &result,
        "modified data or decreased balance of a foreign slot",
    );
}

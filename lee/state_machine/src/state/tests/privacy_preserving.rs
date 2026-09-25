use super::*;

fn assert_circuit_proving_failure<T>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(msg)) if msg.contains(expected)),
        "expected CircuitProvingError containing {expected:?}, got: {:?}",
        result.as_ref().err()
    );
}

fn assert_program_prove_failure<T>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(result, Err(LeeError::ProgramProveFailed(msg)) if msg.contains(expected)),
        "expected ProgramProveFailed containing {expected:?}, got: {:?}",
        result.as_ref().err()
    );
}

#[test]
fn transition_from_privacy_preserving_transaction_shielded() {
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();

    let mut state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 200)]);

    let balance_to_move = 37;

    let tx =
        shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, balance_to_move, &state);

    let expected_sender_post = {
        let mut this = state.get_account_by_id(sender_keys.account_id());
        let post_balance = this.data.balance().unwrap() - balance_to_move;
        this.data
            .set_shard(NATIVE_TOKEN_PROGRAM_ID, encode_balance(post_balance));
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
            .data
            .balance(),
        Ok(200 - balance_to_move)
    );
}

#[test]
fn privacy_preserving_witness_set_cannot_have_dulicate_signers() {
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();

    let mut state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 200)]);

    let tx = shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, 37, &state);

    // Re-sign the same message with the sender twice; both nonces match the
    // current state, so only the repeat is at fault.
    let (_, proof) = tx.witness_set.into_raw_parts();
    let mut message = tx.message;
    let nonce = message.nonces[0];
    message.nonces = vec![nonce, nonce];
    let witness_set = WitnessSet::for_message(
        &message,
        proof,
        &[&sender_keys.signing_key, &sender_keys.signing_key],
    );
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(msg)) if msg.contains("Duplicate signers")
    ));
}

#[test]
fn transition_from_privacy_preserving_transaction_private() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
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

    let sender_account_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::default(),
    );
    let recipient_account_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::default(),
    );
    let expected_new_commitment_1 = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(sender_private_account.data.balance().unwrap() - balance_to_move)
        },
    );

    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let expected_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk());

    let expected_new_commitment_2 = Commitment::new(
        &recipient_account_id,
        &Account {
            nonce: Nonce::private_account_nonce_init(&recipient_account_id),
            ..Account::funded(balance_to_move)
        },
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

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let recipient_keys = test_public_account_keys_1();
    let recipient_initial_balance = 400;
    let mut state = V03State::new()
        .with_public_account_balances([(recipient_keys.account_id(), recipient_initial_balance)])
        .with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;

    let expected_recipient_post = {
        let mut this = state.get_account_by_id(recipient_keys.account_id());
        let post_balance = this.data.balance().unwrap() + balance_to_move;
        this.data
            .set_shard(NATIVE_TOKEN_PROGRAM_ID, encode_balance(post_balance));
        this
    };

    let tx = deshielded_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys.account_id(),
        balance_to_move,
        &state,
    );

    let sender_account_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::default(),
    );
    let expected_new_commitment = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(sender_private_account.data.balance().unwrap() - balance_to_move)
        },
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
            .data
            .balance(),
        Ok(recipient_initial_balance + balance_to_move)
    );
}

#[test]
fn a_data_write_on_a_shard_the_executing_program_does_not_own_is_rejected_in_the_circuit() {
    let program = crate::test_methods::data_changer();
    let target_id = AccountId::new([0; 32]);
    let foreign_program_account_id =
        AccountId::from_builtin_program(crate::test_methods::noop().id());
    // Another program's shard and the native balance shard are both foreign to the executing
    // program; the circuit refuses each for the same reason the public path does.
    let cases = [
        (
            "another program's shard",
            ProgramShardSelector::new(target_id, foreign_program_account_id),
            vec![7_u8; 4],
        ),
        (
            "the native balance shard",
            ProgramShardSelector::balance(target_id),
            encode_balance(500).to_vec(),
        ),
    ];

    for (shard, selector, written) in cases {
        let result = execute_and_prove(
            ProvingInput {
                shard_selectors: vec![selector],
                instruction_data: Program::serialize_instruction(written).unwrap(),
                ..Default::default()
            },
            &program.clone().into(),
        );

        assert_circuit_proving_failure(&result, "wrote data on a shard selector of");
        assert!(result.is_err(), "writing {shard} must be refused");
    }
}

#[test]
fn data_changer_program_should_fail_for_too_large_data_in_privacy_preserving_circuit() {
    let program = crate::test_methods::data_changer();
    let program_id = AccountId::from_builtin_program(program.id());
    let account_id = AccountId::new([0; 32]);

    let large_data: Vec<u8> =
        vec![
            0;
            usize::try_from(lee_core::account::data::DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![ProgramShardSelector::new(account_id, program_id)],
            signers: [account_id].into(),
            instruction_data: Program::serialize_instruction(large_data).unwrap(),
            ..Default::default()
        },
        &program.into(),
    );

    assert_program_prove_failure(&result, "provided data should fit into data limit");
}

#[test]
fn unauthorized_debit_should_fail_in_privacy_preserving_circuit() {
    let sender_id = AccountId::new([0; 32]);
    let recipient_id = AccountId::new([1; 32]);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance(sender_id),
                ProgramShardSelector::balance(recipient_id),
            ],
            signers: [recipient_id].into(),
            public_accounts: [(sender_id, Account::funded(100))].into(),
            instruction_data: Program::serialize_instruction(NativeInstruction::Transfer {
                amount: 10,
            })
            .unwrap(),
            ..Default::default()
        },
        &ProgramWithDependencies::native(),
    );

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(
                    TransferError::UnauthorizedSender { .. }
                )
            ))
        ),
        "refused for the wrong reason: {:?}",
        result.err()
    );
}
